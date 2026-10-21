package kh.eco.istad.authorizationserver.grant;

import java.util.Map;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

public final class CustomCodeGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {
    public static final AuthorizationGrantType GRANT_TYPE =
            new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:custom_code");

    public CustomCodeGrantAuthenticationToken(
            String code, Authentication clientPrincipal, Map<String, Object> additionalParameters) {
        super(GRANT_TYPE, clientPrincipal, additionalParameters);
        this.code = code;
    }

    private final String code;

    public String getCode() {
        return code;
    }
}
