package kh.eco.istad.authorizationserver.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.net.URI;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import kh.eco.istad.authorizationserver.tenant.TenantComponentRegistry;

@Configuration
public class JwtConfig {
    private static final Set<String> APPLICATION_ROLES = Set.of("ROLE_USER", "ROLE_ADMIN");

    @Bean
    KeyPair signingKeyPair() throws Exception {
        return generateSigningKeyPair();
    }

    @Bean
    KeyPair tenantBSigningKeyPair() throws Exception {
        return generateSigningKeyPair();
    }

    private static KeyPair generateSigningKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    @Bean
    JWKSource<SecurityContext> jwkSource(
            @Qualifier("signingKeyPair") KeyPair signingKeyPair,
            @Qualifier("tenantBSigningKeyPair") KeyPair tenantBSigningKeyPair,
            TenantComponentRegistry tenants) {
        tenants.register(TenantComponentRegistry.DEFAULT_TENANT, JWKSet.class, jwkSet(signingKeyPair));
        tenants.register(TenantComponentRegistry.SECOND_TENANT, JWKSet.class, jwkSet(tenantBSigningKeyPair));
        return (JWKSelector selector, SecurityContext context) -> selector.select(tenants.get(JWKSet.class));
    }

    @Bean
    JwtDecoder jwtDecoder(
            @Qualifier("signingKeyPair") KeyPair signingKeyPair,
            @Qualifier("tenantBSigningKeyPair") KeyPair tenantBSigningKeyPair,
            @Value("${app.oauth.issuer}") String baseIssuer) {
        URI trustedBase = URI.create(baseIssuer);
        ConcurrentMap<String, JwtDecoder> decoders = new ConcurrentHashMap<>();
        return token -> {
            final String issuer;
            try {
                issuer = SignedJWT.parse(token).getJWTClaimsSet().getIssuer();
            } catch (Exception exception) {
                throw new BadJwtException("Invalid JWT issuer", exception);
            }
            if (issuer == null) {
                throw new BadJwtException("JWT is missing its issuer");
            }
            URI issuerUri;
            String tenantId;
            try {
                issuerUri = URI.create(issuer);
                validateIssuerOrigin(trustedBase, issuerUri);
                tenantId = TenantComponentRegistry.tenantIdForIssuer(issuer);
            } catch (RuntimeException exception) {
                throw new BadJwtException("JWT issuer is not registered", exception);
            }
            KeyPair keyPair = TenantComponentRegistry.SECOND_TENANT.equals(tenantId)
                    ? tenantBSigningKeyPair : signingKeyPair;
            JwtDecoder decoder = decoders.computeIfAbsent(issuer, key -> {
                NimbusJwtDecoder created = NimbusJwtDecoder.withPublicKey((RSAPublicKey) keyPair.getPublic()).build();
                created.setJwtValidator(JwtValidators.createDefaultWithIssuer(key));
                return created;
            });
            return decoder.decode(token);
        };
    }

    private static JWKSet jwkSet(KeyPair keyPair) {
        RSAKey key = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .build();
        return new JWKSet(key);
    }

    private static void validateIssuerOrigin(URI trustedBase, URI candidate) {
        String baseHost = trustedBase.getHost();
        String candidateHost = candidate.getHost();
        boolean sameHost = baseHost != null && baseHost.equalsIgnoreCase(candidateHost);
        boolean loopbackAlias = ("127.0.0.1".equalsIgnoreCase(baseHost) && "localhost".equalsIgnoreCase(candidateHost))
                || ("localhost".equalsIgnoreCase(baseHost) && "127.0.0.1".equalsIgnoreCase(candidateHost));
        if (!("http".equalsIgnoreCase(candidate.getScheme()) || "https".equalsIgnoreCase(candidate.getScheme()))
                || !trustedBase.getScheme().equalsIgnoreCase(candidate.getScheme())
                || !(sameHost || loopbackAlias)
                || trustedBase.getPort() != candidate.getPort()
                || candidate.getUserInfo() != null || candidate.getQuery() != null || candidate.getFragment() != null) {
            throw new IllegalArgumentException("Untrusted issuer origin");
        }
    }

    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                List<String> roles = context.getPrincipal().getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .filter(APPLICATION_ROLES::contains)
                        .distinct()
                        .sorted()
                        .toList();
                context.getClaims().claim("roles", roles);
            }
        };
    }

    @Bean
    OAuth2TokenGenerator<?> oauth2TokenGenerator(
            JWKSource<SecurityContext> jwkSource,
            OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer) {
        JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource));
        jwtGenerator.setJwtCustomizer(jwtTokenCustomizer);
        return new DelegatingOAuth2TokenGenerator(
                jwtGenerator, new OAuth2AccessTokenGenerator(), new OAuth2RefreshTokenGenerator());
    }
}
