package kh.eco.istad.authorizationserver.config;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.net.URI;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
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
    KeyPair signingKeyPair(PersistentRsaKeyStore keyStore) throws Exception {
        return keyStore.loadOrCreate(TenantComponentRegistry.DEFAULT_TENANT);
    }

    @Bean
    KeyPair tenantBSigningKeyPair(PersistentRsaKeyStore keyStore) throws Exception {
        return keyStore.loadOrCreate(TenantComponentRegistry.SECOND_TENANT);
    }

    @Bean
    @Primary
    JWKSource<SecurityContext> jwkSource(
            @Qualifier("signingKeyPair") KeyPair signingKeyPair,
            @Qualifier("tenantBSigningKeyPair") KeyPair tenantBSigningKeyPair,
            PersistentRsaKeyStore keyStore,
            TenantComponentRegistry tenants) {
        tenants.register(TenantComponentRegistry.DEFAULT_TENANT, JWKSet.class,
                jwkSet(TenantComponentRegistry.DEFAULT_TENANT, signingKeyPair, keyStore));
        tenants.register(TenantComponentRegistry.SECOND_TENANT, JWKSet.class,
                jwkSet(TenantComponentRegistry.SECOND_TENANT, tenantBSigningKeyPair, keyStore));
        return (JWKSelector selector, SecurityContext context) -> selector.select(tenants.get(JWKSet.class));
    }

    @Bean("signingJwkSource")
    JWKSource<SecurityContext> signingJwkSource(
            @Qualifier("signingKeyPair") KeyPair signingKeyPair,
            @Qualifier("tenantBSigningKeyPair") KeyPair tenantBSigningKeyPair) {
        return (JWKSelector selector, SecurityContext context) -> {
            String tenantId = TenantComponentRegistry.currentTenantId();
            KeyPair keyPair;
            if (TenantComponentRegistry.DEFAULT_TENANT.equals(tenantId)) {
                keyPair = signingKeyPair;
            } else if (TenantComponentRegistry.SECOND_TENANT.equals(tenantId)) {
                keyPair = tenantBSigningKeyPair;
            } else {
                throw new IllegalStateException("Signing key is not configured for issuer tenant " + tenantId);
            }
            return selector.select(new JWKSet(activeJwk(keyPair)));
        };
    }

    @Bean
    JwtDecoder jwtDecoder(
            @Qualifier("signingKeyPair") KeyPair signingKeyPair,
            @Qualifier("tenantBSigningKeyPair") KeyPair tenantBSigningKeyPair,
            PersistentRsaKeyStore keyStore,
            @Value("${app.oauth.issuer}") String baseIssuer,
            @Value("${app.oauth.api-audience}") String apiAudience) {
        URI trustedBase = URI.create(baseIssuer);
        ConcurrentMap<String, JwtDecoder> decoders = new ConcurrentHashMap<>();
        return token -> {
            final String issuer;
            try {
                SignedJWT parsed = SignedJWT.parse(token);
                issuer = parsed.getJWTClaimsSet().getIssuer();
                String keyId = parsed.getHeader().getKeyID();
                if (issuer == null) {
                    throw new BadJwtException("JWT is missing its issuer");
                }
                URI issuerUri = URI.create(issuer);
                validateIssuerOrigin(trustedBase, issuerUri);
                String tenantId = TenantComponentRegistry.tenantIdForIssuer(issuer);
                KeyPair activeKeyPair = TenantComponentRegistry.SECOND_TENANT.equals(tenantId)
                        ? tenantBSigningKeyPair : signingKeyPair;
                RSAPublicKey publicKey = keyStore.publicKey(tenantId, keyId, activeKeyPair);
                JwtDecoder decoder = decoders.computeIfAbsent(issuer + "|" + keyId, ignored -> {
                    NimbusJwtDecoder created = NimbusJwtDecoder.withPublicKey(publicKey).build();
                    OAuth2TokenValidator<Jwt> audienceValidator = jwt -> jwt.getAudience().contains(apiAudience)
                            ? OAuth2TokenValidatorResult.success()
                            : OAuth2TokenValidatorResult.failure(new OAuth2Error(
                                    "invalid_token", "Token audience is not accepted by this API", null));
                    created.setJwtValidator(new org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator<>(
                            JwtValidators.createDefaultWithIssuer(issuer), audienceValidator));
                    return created;
                });
                return decoder.decode(token);
            } catch (Exception exception) {
                if (exception instanceof BadJwtException badJwtException) {
                    throw badJwtException;
                }
                throw new BadJwtException("Invalid JWT", exception);
            }
        };
    }

    private static JWKSet jwkSet(String tenantId, KeyPair keyPair, PersistentRsaKeyStore keyStore) {
        try {
            List<RSAPublicKey> publicKeys = keyStore.publicKeys(tenantId, keyPair);
            List<JWK> jwks = new java.util.ArrayList<>();
            RSAPublicKey activePublicKey = (RSAPublicKey) keyPair.getPublic();
            jwks.add(new RSAKey.Builder(activePublicKey)
                    .privateKey((RSAPrivateKey) keyPair.getPrivate())
                    .keyID(PersistentRsaKeyStore.keyId(activePublicKey))
                    .keyUse(KeyUse.SIGNATURE)
                    .build());
            for (RSAPublicKey publicKey : publicKeys) {
                if (!publicKey.equals(activePublicKey)) {
                    jwks.add(new RSAKey.Builder(publicKey)
                            .keyID(PersistentRsaKeyStore.keyId(publicKey))
                            .keyUse(KeyUse.SIGNATURE)
                            .build());
                }
            }
            return new JWKSet(jwks);
        } catch (Exception exception) {
            throw new IllegalStateException("Could not load signing keys for tenant " + tenantId, exception);
        }
    }

    private static RSAKey activeJwk(KeyPair keyPair) {
        try {
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            return new RSAKey.Builder(publicKey)
                    .privateKey((RSAPrivateKey) keyPair.getPrivate())
                    .keyID(PersistentRsaKeyStore.keyId(publicKey))
                    .keyUse(KeyUse.SIGNATURE)
                    .build();
        } catch (Exception exception) {
            throw new IllegalStateException("Could not initialize active RSA signing key", exception);
        }
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
    OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer(
            @Value("${app.oauth.api-audience}") String apiAudience) {
        return context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                List<String> roles = context.getPrincipal().getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .filter(APPLICATION_ROLES::contains)
                        .distinct()
                        .sorted()
                        .toList();
                context.getClaims().claim("roles", roles);
                context.getClaims().audience(List.of(apiAudience));
            }
        };
    }

    @Bean
    OAuth2TokenGenerator<?> oauth2TokenGenerator(
            @Qualifier("signingJwkSource") JWKSource<SecurityContext> jwkSource,
            OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer) {
        JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource));
        jwtGenerator.setJwtCustomizer(jwtTokenCustomizer);
        return new DelegatingOAuth2TokenGenerator(
                jwtGenerator, new OAuth2AccessTokenGenerator(), new OAuth2RefreshTokenGenerator());
    }
}
