package kh.eco.istad.authorizationserver.grant;

import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

@Component
public final class CustomCodeGrantAuthenticationConverter implements AuthenticationConverter {
    @Override
    public Authentication convert(HttpServletRequest request) {
        if (!CustomCodeGrantAuthenticationToken.GRANT_TYPE.getValue()
                .equals(request.getParameter(OAuth2ParameterNames.GRANT_TYPE))) {
            return null;
        }

        MultiValueMap<String, String> parameters = getParameters(request);
        String code = parameters.getFirst("code");
        if (!StringUtils.hasText(code) || parameters.get("code").size() != 1) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }

        Map<String, Object> additionalParameters = new HashMap<>();
        parameters.forEach((key, values) -> {
            if (!OAuth2ParameterNames.GRANT_TYPE.equals(key)
                    && !OAuth2ParameterNames.CLIENT_ID.equals(key)
                    && !"code".equals(key)) {
                if (values.size() != 1) {
                    throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
                }
                additionalParameters.put(key, values.getFirst());
            }
        });
        return new CustomCodeGrantAuthenticationToken(
                code, SecurityContextHolder.getContext().getAuthentication(), additionalParameters);
    }

    private static MultiValueMap<String, String> getParameters(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>(parameterMap.size());
        parameterMap.forEach((key, values) -> {
            for (String value : values) {
                parameters.add(key, value);
            }
        });
        return parameters;
    }
}
