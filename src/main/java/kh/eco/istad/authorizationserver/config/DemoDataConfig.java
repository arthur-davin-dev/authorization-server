package kh.eco.istad.authorizationserver.config;

import java.util.Set;
import java.util.UUID;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.LinkedHashSet;
import java.time.Duration;

import kh.eco.istad.authorizationserver.user.entity.AppUserEntity;
import kh.eco.istad.authorizationserver.user.repository.AppUserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

@Configuration
public class DemoDataConfig {
    @Bean
    ApplicationRunner registerSpaClient(
            RegisteredClientRepository clients,
            PasswordEncoder passwordEncoder,
            @Value("${app.oauth.spa-redirect-uri}") String redirectUri,
            @Value("${app.oauth.access-token-ttl-seconds}") long accessTokenTtlSeconds,
            @Value("${app.oauth.refresh-token-ttl-seconds}") long refreshTokenTtlSeconds,
            @Value("${app.oauth.custom-grant-client-secret}") String customGrantClientSecret,
            @Value("${app.oauth.registrar-client-secret}") String registrarClientSecret) {
        return args -> {
            Set<String> allowedRedirectUris = loopbackRedirectUris(redirectUri);
            TokenSettings tokenSettings = TokenSettings.builder()
                    .authorizationCodeTimeToLive(Duration.ofMinutes(5))
                    .accessTokenTimeToLive(Duration.ofSeconds(accessTokenTtlSeconds))
                    .refreshTokenTimeToLive(Duration.ofSeconds(refreshTokenTtlSeconds))
                    .reuseRefreshTokens(false)
                    .build();
            RegisteredClient spaClient = RegisteredClient.withId("authorization-spa-v1")
                    .clientId("authorization-spa")
                    .clientName("Local PKCE SPA")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUris(uris -> uris.addAll(allowedRedirectUris))
                    .postLogoutRedirectUris(uris -> uris.addAll(allowedRedirectUris))
                    .scope(OidcScopes.OPENID)
                    .scope(OidcScopes.PROFILE)
                    .scope("api.read")
                    .clientSettings(ClientSettings.builder()
                            .requireAuthorizationConsent(true)
                            .requireProofKey(true)
                            .build())
                    .tokenSettings(tokenSettings)
                    .build();
            clients.save(spaClient);

            RegisteredClient customGrantClient = RegisteredClient.withId("custom-grant-client-v1")
                    .clientId("custom-grant-client")
                    .clientName("Local Custom Grant Client")
                    .clientSecret(passwordEncoder.encode(customGrantClientSecret))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(kh.eco.istad.authorizationserver.grant.CustomCodeGrantAuthenticationToken.GRANT_TYPE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .scope("message.read")
                    .scope("message.write")
                    .tokenSettings(tokenSettings)
                    .build();
            clients.save(customGrantClient);

            RegisteredClient registrarClient = RegisteredClient.withId("client-registrar-v1")
                    .clientId("client-registrar")
                    .clientName("Local Dynamic Client Registrar")
                    .clientSecret(passwordEncoder.encode(registrarClientSecret))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .scope("client.create")
                    .scope("client.read")
                    .tokenSettings(tokenSettings)
                    .build();
            clients.save(registrarClient);
        };
    }

    private static Set<String> loopbackRedirectUris(String configuredRedirectUri) {
        Set<String> redirectUris = new LinkedHashSet<>();
        redirectUris.add(configuredRedirectUri);
        URI uri = URI.create(configuredRedirectUri);
        String host = uri.getHost();
        String alternateHost = "127.0.0.1".equalsIgnoreCase(host)
                ? "localhost"
                : "localhost".equalsIgnoreCase(host) ? "127.0.0.1" : null;
        if (alternateHost != null) {
            try {
                redirectUris.add(new URI(uri.getScheme(), uri.getUserInfo(), alternateHost, uri.getPort(),
                        uri.getPath(), uri.getQuery(), uri.getFragment()).toString());
            } catch (URISyntaxException exception) {
                throw new IllegalArgumentException("Invalid SPA redirect URI", exception);
            }
        }
        return redirectUris;
    }

    @Bean
    ApplicationRunner bootstrapDemoUser(
            AppUserRepository users,
            PasswordEncoder passwordEncoder,
            @Value("${app.bootstrap-user.enabled}") boolean enabled,
            @Value("${app.bootstrap-user.username}") String username,
            @Value("${app.bootstrap-user.password}") String password) {
        return args -> {
            if (!enabled || password.isBlank()) {
                return;
            }
            AppUserEntity existingUser = users.findByUsername(username).orElse(null);
            String encodedPassword = passwordEncoder.encode(password);
            if (existingUser == null) {
                users.save(new AppUserEntity(
                        UUID.randomUUID(), username, encodedPassword, true, Set.of("ROLE_USER")));
            } else if (!passwordEncoder.matches(password, existingUser.getPasswordHash())) {
                existingUser.setPasswordHash(encodedPassword);
                users.save(existingUser);
            }
        };
    }

}
