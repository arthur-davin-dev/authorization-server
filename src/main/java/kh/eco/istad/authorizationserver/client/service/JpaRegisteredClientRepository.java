package kh.eco.istad.authorizationserver.client.service;

import kh.eco.istad.authorizationserver.client.entity.OAuthClientEntity;
import kh.eco.istad.authorizationserver.client.repository.OAuthClientJpaRepository;
import kh.eco.istad.authorizationserver.common.persistence.OAuthJson;
import kh.eco.istad.authorizationserver.tenant.TenantComponentRegistry;
import java.time.Instant;
import java.util.Map;
import java.util.Set;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

@Component
public class JpaRegisteredClientRepository implements RegisteredClientRepository {
    private final OAuthClientJpaRepository clients;
    private final OAuthJson json;

    public JpaRegisteredClientRepository(OAuthClientJpaRepository clients, OAuthJson json) {
        this.clients = clients;
        this.json = json;
    }

    @Override
    @Transactional
    public void save(RegisteredClient registeredClient) {
        saveForTenant(TenantComponentRegistry.currentTenantId(), registeredClient);
    }

    @Transactional
    public void saveForTenant(String tenantId, RegisteredClient registeredClient) {
        Assert.notNull(registeredClient, "registeredClient cannot be null");
        OAuthClientEntity entity = new OAuthClientEntity();
        entity.id = registeredClient.getId();
        entity.tenantId = tenantId;
        entity.clientId = registeredClient.getClientId();
        entity.clientIdIssuedAt = registeredClient.getClientIdIssuedAt() != null
                ? registeredClient.getClientIdIssuedAt()
                : Instant.now();
        entity.clientSecret = registeredClient.getClientSecret();
        entity.clientSecretExpiresAt = registeredClient.getClientSecretExpiresAt();
        entity.clientName = registeredClient.getClientName();
        entity.clientAuthenticationMethods = StringUtils.collectionToCommaDelimitedString(
                registeredClient.getClientAuthenticationMethods().stream().map(ClientAuthenticationMethod::getValue).toList());
        entity.authorizationGrantTypes = StringUtils.collectionToCommaDelimitedString(
                registeredClient.getAuthorizationGrantTypes().stream().map(AuthorizationGrantType::getValue).toList());
        entity.redirectUris = StringUtils.collectionToCommaDelimitedString(registeredClient.getRedirectUris());
        entity.postLogoutRedirectUris = StringUtils.collectionToCommaDelimitedString(registeredClient.getPostLogoutRedirectUris());
        entity.scopes = StringUtils.collectionToCommaDelimitedString(registeredClient.getScopes());
        entity.clientSettings = json.write(registeredClient.getClientSettings().getSettings());
        entity.tokenSettings = json.write(registeredClient.getTokenSettings().getSettings());
        clients.save(entity);
    }

    @Override
    @Transactional(readOnly = true)
    public RegisteredClient findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        return clients.findByTenantIdAndId(TenantComponentRegistry.currentTenantId(), id)
                .map(this::toDomain).orElse(null);
    }

    @Override
    @Transactional(readOnly = true)
    public RegisteredClient findByClientId(String clientId) {
        Assert.hasText(clientId, "clientId cannot be empty");
        return clients.findByTenantIdAndClientId(TenantComponentRegistry.currentTenantId(), clientId)
                .map(this::toDomain).orElse(null);
    }

    private RegisteredClient toDomain(OAuthClientEntity entity) {
        Set<String> methods = StringUtils.commaDelimitedListToSet(entity.clientAuthenticationMethods);
        Set<String> grantTypes = StringUtils.commaDelimitedListToSet(entity.authorizationGrantTypes);
        RegisteredClient.Builder builder = RegisteredClient.withId(entity.id)
                .clientId(entity.clientId)
                .clientIdIssuedAt(entity.clientIdIssuedAt)
                .clientSecret(entity.clientSecret)
                .clientSecretExpiresAt(entity.clientSecretExpiresAt)
                .clientName(entity.clientName)
                .clientAuthenticationMethods(values -> methods.forEach(value -> values.add(resolveClientAuthenticationMethod(value))))
                .authorizationGrantTypes(values -> grantTypes.forEach(value -> values.add(resolveGrantType(value))))
                .redirectUris(values -> values.addAll(StringUtils.commaDelimitedListToSet(entity.redirectUris)))
                .postLogoutRedirectUris(values -> values.addAll(StringUtils.commaDelimitedListToSet(entity.postLogoutRedirectUris)))
                .scopes(values -> values.addAll(StringUtils.commaDelimitedListToSet(entity.scopes)));
        Map<String, Object> clientSettings = json.readMap(entity.clientSettings);
        Map<String, Object> tokenSettings = json.readMap(entity.tokenSettings);
        builder.clientSettings(ClientSettings.withSettings(clientSettings).build());
        builder.tokenSettings(TokenSettings.withSettings(tokenSettings).build());
        return builder.build();
    }

    private static AuthorizationGrantType resolveGrantType(String value) {
        if (AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(value)) {
            return AuthorizationGrantType.AUTHORIZATION_CODE;
        }
        if (AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(value)) {
            return AuthorizationGrantType.REFRESH_TOKEN;
        }
        return new AuthorizationGrantType(value);
    }

    private static ClientAuthenticationMethod resolveClientAuthenticationMethod(String value) {
        if (ClientAuthenticationMethod.NONE.getValue().equals(value)) {
            return ClientAuthenticationMethod.NONE;
        }
        if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue().equals(value)) {
            return ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
        }
        if (ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue().equals(value)) {
            return ClientAuthenticationMethod.CLIENT_SECRET_POST;
        }
        return new ClientAuthenticationMethod(value);
    }
}
