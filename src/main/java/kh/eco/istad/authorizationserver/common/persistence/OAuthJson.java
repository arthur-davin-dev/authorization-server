package kh.eco.istad.authorizationserver.common.persistence;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.stereotype.Component;

@Component
public class OAuthJson {
    private final ObjectMapper mapper;

    public OAuthJson() {
        this.mapper = new ObjectMapper();
        ClassLoader classLoader = OAuthJson.class.getClassLoader();
        List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
        this.mapper.registerModules(securityModules);
        this.mapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
    }

    public String write(Object value) {
        try {
            return mapper.writeValueAsString(value);
        } catch (Exception exception) {
            throw new IllegalStateException("Could not serialize OAuth data", exception);
        }
    }

    public Map<String, Object> readMap(String value) {
        if (value == null || value.isBlank()) {
            return Map.of();
        }
        try {
            return mapper.readValue(value, new TypeReference<Map<String, Object>>() { });
        } catch (Exception exception) {
            throw new IllegalStateException("Could not deserialize OAuth data", exception);
        }
    }

    /**
     * Reads legacy attributes without resolving embedded Java type identifiers.
     * Used only to recover custom-grant authorizations written before their
     * principal was persisted as a simple client name.
     */
    public Map<String, Object> readUntypedMap(String value) {
        if (value == null || value.isBlank()) {
            return Map.of();
        }
        try {
            return new ObjectMapper().readValue(value, new TypeReference<Map<String, Object>>() { });
        } catch (Exception exception) {
            throw new IllegalStateException("Could not deserialize legacy OAuth data", exception);
        }
    }
}
