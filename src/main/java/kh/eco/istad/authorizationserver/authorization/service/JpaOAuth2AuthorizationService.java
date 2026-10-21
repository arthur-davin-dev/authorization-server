package kh.eco.istad.authorizationserver.authorization.service;

import kh.eco.istad.authorizationserver.authorization.entity.OAuthAuthorizationEntity;
import kh.eco.istad.authorizationserver.authorization.repository.OAuthAuthorizationJpaRepository;
import kh.eco.istad.authorizationserver.common.persistence.OAuthJson;
import kh.eco.istad.authorizationserver.grant.CustomCodeGrantAuthenticationToken;
import java.time.Instant;
import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;

import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

@Component
public class JpaOAuth2AuthorizationService implements OAuth2AuthorizationService {
    private final OAuthAuthorizationJpaRepository authorizations;
    private final RegisteredClientRepository clients;
    private final OAuthJson json;

    public JpaOAuth2AuthorizationService(
            OAuthAuthorizationJpaRepository authorizations,
            RegisteredClientRepository clients,
            OAuthJson json) {
        this.authorizations = authorizations;
        this.clients = clients;
        this.json = json;
    }

    @Override
    @Transactional
    public void save(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        authorizations.save(toEntity(authorization));
    }

    @Override
    @Transactional
    public void remove(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        authorizations.deleteById(authorization.getId());
    }

    @Override
    @Transactional(readOnly = true)
    public OAuth2Authorization findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        return authorizations.findById(id).map(this::toDomain).orElse(null);
    }

    @Override
    @Transactional(readOnly = true)
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        Assert.hasText(token, "token cannot be empty");
        Optional<OAuthAuthorizationEntity> result;
        if (tokenType == null) {
            result = authorizations.findByAnyToken(token);
        } else if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
            result = authorizations.findByState(token);
        } else if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
            result = authorizations.findByAuthorizationCodeValue(token);
        } else if (OAuth2ParameterNames.ACCESS_TOKEN.equals(tokenType.getValue())) {
            result = authorizations.findByAccessTokenValue(token);
        } else if (OAuth2ParameterNames.REFRESH_TOKEN.equals(tokenType.getValue())) {
            result = authorizations.findByRefreshTokenValue(token);
        } else if (OidcParameterNames.ID_TOKEN.equals(tokenType.getValue())) {
            result = authorizations.findByOidcIdTokenValue(token);
        } else if (OAuth2ParameterNames.USER_CODE.equals(tokenType.getValue())) {
            result = authorizations.findByUserCodeValue(token);
        } else if (OAuth2ParameterNames.DEVICE_CODE.equals(tokenType.getValue())) {
            result = authorizations.findByDeviceCodeValue(token);
        } else {
            result = Optional.empty();
        }
        return result.map(this::toDomain).orElse(null);
    }

    private OAuth2Authorization toDomain(OAuthAuthorizationEntity entity) {
        RegisteredClient client = clients.findById(entity.registeredClientId);
        if (client == null) {
            throw new DataRetrievalFailureException("Registered client not found: " + entity.registeredClientId);
        }
        Map<String, Object> attributes;
        boolean customGrant = CustomCodeGrantAuthenticationToken.GRANT_TYPE.getValue()
                .equals(entity.authorizationGrantType);
        try {
            attributes = new HashMap<>(json.readMap(entity.attributes));
        } catch (IllegalStateException exception) {
            if (!customGrant) {
                throw exception;
            }
            // Older custom-grant rows stored OAuth2ClientAuthenticationToken directly.
            // Spring Security correctly blocks that type during JSON deserialization.
            // These authorizations only need the client name as their refresh principal.
            attributes = new HashMap<>(json.readUntypedMap(entity.attributes));
        }
        if (customGrant) {
            Object principal = attributes.get(Principal.class.getName());
            String principalName = principal instanceof String name ? name : entity.principalName;
            // Recover both rows written before the principal was stored and rows that
            // stored an OAuth2ClientAuthenticationToken directly.
            attributes.put(Principal.class.getName(), UsernamePasswordAuthenticationToken.authenticated(
                    principalName, null, new ArrayList<>()));
        }
        Map<String, Object> restoredAttributes = attributes;
        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(client)
                .id(entity.id)
                .principalName(entity.principalName)
                .authorizationGrantType(resolveGrantType(entity.authorizationGrantType))
                .authorizedScopes(StringUtils.commaDelimitedListToSet(entity.authorizedScopes))
                .attributes(authorizationAttributes -> authorizationAttributes.putAll(restoredAttributes));
        if (entity.state != null) {
            builder.attribute(OAuth2ParameterNames.STATE, entity.state);
        }
        if (entity.authorizationCodeValue != null) {
            OAuth2AuthorizationCode code = new OAuth2AuthorizationCode(
                    entity.authorizationCodeValue, entity.authorizationCodeIssuedAt, entity.authorizationCodeExpiresAt);
            builder.token(code, metadata -> metadata.putAll(json.readMap(entity.authorizationCodeMetadata)));
        }
        if (entity.accessTokenValue != null) {
            OAuth2AccessToken accessToken = new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    entity.accessTokenValue,
                    entity.accessTokenIssuedAt,
                    entity.accessTokenExpiresAt,
                    StringUtils.commaDelimitedListToSet(entity.accessTokenScopes));
            builder.token(accessToken, metadata -> metadata.putAll(json.readMap(entity.accessTokenMetadata)));
        }
        if (entity.refreshTokenValue != null) {
            OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                    entity.refreshTokenValue, entity.refreshTokenIssuedAt, entity.refreshTokenExpiresAt);
            builder.token(refreshToken, metadata -> metadata.putAll(json.readMap(entity.refreshTokenMetadata)));
        }
        if (entity.oidcIdTokenValue != null) {
            OidcIdToken idToken = new OidcIdToken(
                    entity.oidcIdTokenValue,
                    entity.oidcIdTokenIssuedAt,
                    entity.oidcIdTokenExpiresAt,
                    json.readMap(entity.oidcIdTokenClaims));
            builder.token(idToken, metadata -> metadata.putAll(json.readMap(entity.oidcIdTokenMetadata)));
        }
        if (entity.userCodeValue != null) {
            OAuth2UserCode userCode = new OAuth2UserCode(
                    entity.userCodeValue, entity.userCodeIssuedAt, entity.userCodeExpiresAt);
            builder.token(userCode, metadata -> metadata.putAll(json.readMap(entity.userCodeMetadata)));
        }
        if (entity.deviceCodeValue != null) {
            OAuth2DeviceCode deviceCode = new OAuth2DeviceCode(
                    entity.deviceCodeValue, entity.deviceCodeIssuedAt, entity.deviceCodeExpiresAt);
            builder.token(deviceCode, metadata -> metadata.putAll(json.readMap(entity.deviceCodeMetadata)));
        }
        return builder.build();
    }

    private OAuthAuthorizationEntity toEntity(OAuth2Authorization authorization) {
        OAuthAuthorizationEntity entity = new OAuthAuthorizationEntity();
        entity.id = authorization.getId();
        entity.registeredClientId = authorization.getRegisteredClientId();
        entity.principalName = authorization.getPrincipalName();
        entity.authorizationGrantType = authorization.getAuthorizationGrantType().getValue();
        entity.authorizedScopes = StringUtils.collectionToCommaDelimitedString(authorization.getAuthorizedScopes());
        entity.attributes = json.write(authorization.getAttributes());
        entity.state = authorization.getAttribute(OAuth2ParameterNames.STATE);

        setToken(authorization.getToken(OAuth2AuthorizationCode.class),
                value -> entity.authorizationCodeValue = value,
                value -> entity.authorizationCodeIssuedAt = value,
                value -> entity.authorizationCodeExpiresAt = value,
                value -> entity.authorizationCodeMetadata = value);
        OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getToken(OAuth2AccessToken.class);
        setToken(accessToken,
                value -> entity.accessTokenValue = value,
                value -> entity.accessTokenIssuedAt = value,
                value -> entity.accessTokenExpiresAt = value,
                value -> entity.accessTokenMetadata = value);
        if (accessToken != null) {
            Set<String> scopes = accessToken.getToken().getScopes();
            entity.accessTokenScopes = StringUtils.collectionToCommaDelimitedString(scopes);
            entity.accessTokenType = accessToken.getToken().getTokenType().getValue();
        }
        setToken(authorization.getToken(OAuth2RefreshToken.class),
                value -> entity.refreshTokenValue = value,
                value -> entity.refreshTokenIssuedAt = value,
                value -> entity.refreshTokenExpiresAt = value,
                value -> entity.refreshTokenMetadata = value);
        OAuth2Authorization.Token<OidcIdToken> idToken = authorization.getToken(OidcIdToken.class);
        setToken(idToken,
                value -> entity.oidcIdTokenValue = value,
                value -> entity.oidcIdTokenIssuedAt = value,
                value -> entity.oidcIdTokenExpiresAt = value,
                value -> entity.oidcIdTokenMetadata = value);
        if (idToken != null) {
            entity.oidcIdTokenClaims = json.write(idToken.getClaims());
        }
        setToken(authorization.getToken(OAuth2UserCode.class),
                value -> entity.userCodeValue = value,
                value -> entity.userCodeIssuedAt = value,
                value -> entity.userCodeExpiresAt = value,
                value -> entity.userCodeMetadata = value);
        setToken(authorization.getToken(OAuth2DeviceCode.class),
                value -> entity.deviceCodeValue = value,
                value -> entity.deviceCodeIssuedAt = value,
                value -> entity.deviceCodeExpiresAt = value,
                value -> entity.deviceCodeMetadata = value);
        return entity;
    }

    private void setToken(
            OAuth2Authorization.Token<?> token,
            Consumer<String> valueConsumer,
            Consumer<Instant> issuedAtConsumer,
            Consumer<Instant> expiresAtConsumer,
            Consumer<String> metadataConsumer) {
        if (token == null) {
            return;
        }
        OAuth2Token value = token.getToken();
        valueConsumer.accept(value.getTokenValue());
        issuedAtConsumer.accept(value.getIssuedAt());
        expiresAtConsumer.accept(value.getExpiresAt());
        metadataConsumer.accept(json.write(token.getMetadata()));
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
}
