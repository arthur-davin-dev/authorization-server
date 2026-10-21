package kh.eco.istad.authorizationserver.grant;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public final class CustomCodeGrantAuthenticationProvider implements AuthenticationProvider {
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
    private final String configuredCode;

    public CustomCodeGrantAuthenticationProvider(
            OAuth2AuthorizationService authorizationService,
            OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
            @org.springframework.beans.factory.annotation.Value("${app.oauth.custom-grant-code}") String configuredCode) {
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
        this.configuredCode = configuredCode;
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        CustomCodeGrantAuthenticationToken grant = (CustomCodeGrantAuthenticationToken) authentication;
        if (!(grant.getPrincipal() instanceof OAuth2ClientAuthenticationToken client)
                || !client.isAuthenticated()) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }
        org.springframework.security.oauth2.server.authorization.client.RegisteredClient registeredClient =
                client.getRegisteredClient();
        if (registeredClient == null || !registeredClient.getAuthorizationGrantTypes().contains(grant.getGrantType())) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }
        if (!StringUtils.hasText(configuredCode) || !constantTimeMatches(grant.getCode(), configuredCode)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }

        Set<String> scopes = requestedScopes(grant.getAdditionalParameters(), registeredClient.getScopes());
        OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(client)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizedScopes(scopes)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(grant.getGrantType())
                .authorizationGrant(grant)
                .build();
        OAuth2Token generatedToken = tokenGenerator.generate(tokenContext);
        if (generatedToken == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error(
                    OAuth2ErrorCodes.SERVER_ERROR, "The token generator failed to generate the access token.", null));
        }
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER, generatedToken.getTokenValue(),
                generatedToken.getIssuedAt(), generatedToken.getExpiresAt(), scopes);
        OAuth2RefreshToken refreshToken = null;
        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)
                && !registeredClient.getClientAuthenticationMethods().contains(
                        org.springframework.security.oauth2.core.ClientAuthenticationMethod.NONE)) {
            OAuth2Token generatedRefreshToken = tokenGenerator.generate(DefaultOAuth2TokenContext.builder()
                    .registeredClient(registeredClient)
                    .principal(client)
                    .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                    .authorizedScopes(scopes)
                    .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                    .authorizationGrantType(grant.getGrantType())
                    .authorizationGrant(grant)
                    .build());
            if (!(generatedRefreshToken instanceof OAuth2RefreshToken generatedRefresh)) {
                throw new OAuth2AuthenticationException(new OAuth2Error(
                        OAuth2ErrorCodes.SERVER_ERROR,
                        "The token generator failed to generate the refresh token.", null));
            }
            refreshToken = generatedRefresh;
        }
        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(client.getName())
                // Persist a simple value here. OAuth2ClientAuthenticationToken is not
                // in Spring Security's Jackson allowlist; the JPA service reconstructs
                // an Authentication from this name when loading the authorization.
                .attribute(java.security.Principal.class.getName(), client.getName())
                .authorizedScopes(scopes)
                .authorizationGrantType(grant.getGrantType())
                .accessToken(accessToken);
        if (refreshToken != null) {
            authorizationBuilder.refreshToken(refreshToken);
        }
        authorizationService.save(authorizationBuilder.build());
        return new OAuth2AccessTokenAuthenticationToken(registeredClient, client, accessToken, refreshToken);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return CustomCodeGrantAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private static Set<String> requestedScopes(Map<String, Object> parameters, Set<String> allowedScopes) {
        Object rawScope = parameters.get(OAuth2ParameterNames.SCOPE);
        Set<String> requested = new LinkedHashSet<>();
        if (rawScope instanceof String scope && StringUtils.hasText(scope)) {
            for (String value : scope.split("\\s+")) {
                if (!allowedScopes.contains(value)) {
                    throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
                }
                requested.add(value);
            }
        } else {
            requested.addAll(allowedScopes);
        }
        if (requested.isEmpty()) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
        }
        return Set.copyOf(requested);
    }

    private static boolean constantTimeMatches(String presented, String expected) {
        return MessageDigest.isEqual(
                presented.getBytes(StandardCharsets.UTF_8), expected.getBytes(StandardCharsets.UTF_8));
    }
}
