package kh.eco.istad.authorizationserver.tenant;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import java.time.Duration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import kh.eco.istad.authorizationserver.authorization.service.JpaOAuth2AuthorizationService;
import kh.eco.istad.authorizationserver.client.service.JpaRegisteredClientRepository;
import kh.eco.istad.authorizationserver.consent.service.JpaOAuth2AuthorizationConsentService;

@Configuration(proxyBeanMethods = false)
public class TenantAuthorizationComponentsConfig {
    @Bean
    @Primary
    RegisteredClientRepository tenantAwareRegisteredClientRepository(
            JpaRegisteredClientRepository defaultRepository,
            TenantComponentRegistry registry,
            PasswordEncoder passwordEncoder,
            @Value("${app.oauth.access-token-ttl-seconds}") long accessTtl,
            @Value("${app.oauth.refresh-token-ttl-seconds}") long refreshTtl,
            @Value("${app.oauth.tenant-b-client-secret}") String tenantClientSecret,
            @Value("${app.oauth.tenant-b-registrar-secret}") String tenantRegistrarSecret) {
        registry.register(TenantComponentRegistry.DEFAULT_TENANT, RegisteredClientRepository.class, defaultRepository);
        TokenSettings tokenSettings = TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofSeconds(accessTtl))
                .refreshTokenTimeToLive(Duration.ofSeconds(refreshTtl))
                .reuseRefreshTokens(false)
                .build();
        RegisteredClient tenantClient = RegisteredClient.withId("tenant-b-client-v1")
                .clientId("tenant-b-client")
                .clientName("Tenant B Postman Client")
                .clientSecret(passwordEncoder.encode(tenantClientSecret))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("tenant.read")
                .tokenSettings(tokenSettings)
                .build();
        defaultRepository.saveForTenant(TenantComponentRegistry.SECOND_TENANT, tenantClient);
        RegisteredClient tenantRegistrar = RegisteredClient.withId("tenant-b-client-registrar-v1")
                .clientId("tenant-b-client-registrar")
                .clientName("Tenant B Dynamic Client Registrar")
                .clientSecret(passwordEncoder.encode(tenantRegistrarSecret))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("client.create")
                .scope("client.read")
                .tokenSettings(tokenSettings)
                .build();
        defaultRepository.saveForTenant(TenantComponentRegistry.SECOND_TENANT, tenantRegistrar);
        registry.register(TenantComponentRegistry.SECOND_TENANT, RegisteredClientRepository.class, defaultRepository);
        return new TenantRegisteredClientRepository(registry);
    }

    @Bean
    @Primary
    OAuth2AuthorizationService tenantAwareAuthorizationService(
            JpaOAuth2AuthorizationService defaultService,
            TenantComponentRegistry registry) {
        registry.register(TenantComponentRegistry.DEFAULT_TENANT, OAuth2AuthorizationService.class, defaultService);
        registry.register(TenantComponentRegistry.SECOND_TENANT, OAuth2AuthorizationService.class, defaultService);
        return new TenantOAuth2AuthorizationService(registry);
    }

    @Bean
    @Primary
    OAuth2AuthorizationConsentService tenantAwareConsentService(
            JpaOAuth2AuthorizationConsentService defaultService,
            TenantComponentRegistry registry) {
        registry.register(TenantComponentRegistry.DEFAULT_TENANT, OAuth2AuthorizationConsentService.class, defaultService);
        registry.register(TenantComponentRegistry.SECOND_TENANT, OAuth2AuthorizationConsentService.class, defaultService);
        return new TenantOAuth2AuthorizationConsentService(registry);
    }

    private record TenantRegisteredClientRepository(TenantComponentRegistry registry)
            implements RegisteredClientRepository {
        @Override public void save(org.springframework.security.oauth2.server.authorization.client.RegisteredClient client) {
            registry.get(RegisteredClientRepository.class).save(client);
        }
        @Override public org.springframework.security.oauth2.server.authorization.client.RegisteredClient findById(String id) {
            return registry.get(RegisteredClientRepository.class).findById(id);
        }
        @Override public org.springframework.security.oauth2.server.authorization.client.RegisteredClient findByClientId(String id) {
            return registry.get(RegisteredClientRepository.class).findByClientId(id);
        }
    }

    private record TenantOAuth2AuthorizationService(TenantComponentRegistry registry)
            implements OAuth2AuthorizationService {
        @Override public void save(org.springframework.security.oauth2.server.authorization.OAuth2Authorization value) {
            registry.get(OAuth2AuthorizationService.class).save(value);
        }
        @Override public void remove(org.springframework.security.oauth2.server.authorization.OAuth2Authorization value) {
            registry.get(OAuth2AuthorizationService.class).remove(value);
        }
        @Override public org.springframework.security.oauth2.server.authorization.OAuth2Authorization findById(String id) {
            return registry.get(OAuth2AuthorizationService.class).findById(id);
        }
        @Override public org.springframework.security.oauth2.server.authorization.OAuth2Authorization findByToken(
                String token, org.springframework.security.oauth2.server.authorization.OAuth2TokenType type) {
            return registry.get(OAuth2AuthorizationService.class).findByToken(token, type);
        }
    }

    private record TenantOAuth2AuthorizationConsentService(TenantComponentRegistry registry)
            implements OAuth2AuthorizationConsentService {
        @Override public void save(org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent value) {
            registry.get(OAuth2AuthorizationConsentService.class).save(value);
        }
        @Override public void remove(org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent value) {
            registry.get(OAuth2AuthorizationConsentService.class).remove(value);
        }
        @Override public org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent findById(
                String clientId, String principalName) {
            return registry.get(OAuth2AuthorizationConsentService.class).findById(clientId, principalName);
        }
    }
}
