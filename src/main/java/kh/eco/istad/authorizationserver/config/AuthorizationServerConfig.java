package kh.eco.istad.authorizationserver.config;

import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

import kh.eco.istad.authorizationserver.grant.CustomCodeGrantAuthenticationConverter;
import kh.eco.istad.authorizationserver.grant.CustomCodeGrantAuthenticationProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationValidator;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

@Configuration
public class AuthorizationServerConfig {
    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerFilterChain(
            HttpSecurity http,
            CustomCodeGrantAuthenticationConverter converter,
            CustomCodeGrantAuthenticationProvider provider) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();
        http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, server -> server
                        .oidc(oidc -> oidc
                                .clientRegistrationEndpoint(registration -> registration
                                        .authenticationProviders(dynamicRegistrationValidator())))
                        .tokenEndpoint(token -> token
                                .accessTokenRequestConverter(converter)
                                .authenticationProvider(provider)))
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .exceptionHandling(exceptions -> exceptions.defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"),
                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)));
        return http.cors(Customizer.withDefaults()).build();
    }

    private static Consumer<List<AuthenticationProvider>> dynamicRegistrationValidator() {
        Set<String> allowedScopes = Set.of(OidcScopes.OPENID, OidcScopes.PROFILE, "api.read");
        return providers -> providers.forEach(authenticationProvider -> {
            if (authenticationProvider instanceof OidcClientRegistrationAuthenticationProvider provider) {
                provider.setAuthenticationValidator(context -> {
                    OidcClientRegistrationAuthenticationValidator.DEFAULT_REDIRECT_URI_VALIDATOR.accept(context);
                    OidcClientRegistrationAuthenticationValidator.DEFAULT_POST_LOGOUT_REDIRECT_URI_VALIDATOR.accept(context);
                    OidcClientRegistrationAuthenticationValidator.DEFAULT_JWK_SET_URI_VALIDATOR.accept(context);

                    var registration = ((OidcClientRegistrationAuthenticationToken) context.getAuthentication())
                            .getClientRegistration();
                    List<String> redirects = registration.getRedirectUris();
                    List<String> scopes = registration.getScopes();
                    List<String> grants = registration.getGrantTypes();
                    if (redirects == null || redirects.isEmpty()) {
                        throw invalidClientMetadata("redirect_uris must contain at least one URI");
                    }
                    if (scopes == null || !scopes.contains(OidcScopes.OPENID)
                            || !allowedScopes.containsAll(scopes)) {
                        throw invalidClientMetadata("scope must contain openid and only approved scopes");
                    }
                    if (grants != null && !Set.of("authorization_code").containsAll(grants)) {
                        throw invalidClientMetadata("only authorization_code clients are accepted");
                    }
                    if (!"client_secret_basic".equals(registration.getTokenEndpointAuthenticationMethod())) {
                        throw invalidClientMetadata("token_endpoint_auth_method must be client_secret_basic");
                    }
                });
            }
        });
    }

    private static OAuth2AuthenticationException invalidClientMetadata(String description) {
        return new OAuth2AuthenticationException(new OAuth2Error("invalid_client_metadata", description, null));
    }

    @Bean
    AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().multipleIssuersAllowed(true).build();
    }
}
