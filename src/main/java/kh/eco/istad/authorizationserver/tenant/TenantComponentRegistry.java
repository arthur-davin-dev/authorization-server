package kh.eco.istad.authorizationserver.tenant;

import java.net.URI;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

/** Registry of issuer-specific authorization-server components. Only registered tenant paths resolve. */
@Component
public final class TenantComponentRegistry {
    public static final String DEFAULT_TENANT = "default";
    public static final String SECOND_TENANT = "tenant-b";

    private final ConcurrentMap<String, Map<Class<?>, Object>> components = new ConcurrentHashMap<>();

    public <T> void register(String tenantId, Class<T> type, T component) {
        Assert.hasText(tenantId, "tenantId cannot be empty");
        Assert.notNull(type, "component type cannot be null");
        Assert.notNull(component, "component cannot be null");
        components.computeIfAbsent(tenantId, ignored -> new ConcurrentHashMap<>()).put(type, component);
    }

    public <T> T get(Class<T> type) {
        String tenantId = currentTenantId();
        Object component = components.getOrDefault(tenantId, Map.of()).get(type);
        if (component == null) {
            throw new IllegalStateException(type.getSimpleName() + " is not configured for issuer tenant " + tenantId);
        }
        return type.cast(component);
    }

    public <T> T get(String tenantId, Class<T> type) {
        Object component = components.getOrDefault(tenantId, Map.of()).get(type);
        return component == null ? null : type.cast(component);
    }

    public static String currentTenantId() {
        AuthorizationServerContext context = AuthorizationServerContextHolder.getContext();
        if (context == null || context.getIssuer() == null) {
            return DEFAULT_TENANT;
        }
        return tenantIdForIssuer(context.getIssuer());
    }

    public static String tenantIdForIssuer(String issuer) {
        String path = URI.create(issuer).getPath();
        if (path == null || path.isBlank() || "/".equals(path)) {
            return DEFAULT_TENANT;
        }
        if (("/" + SECOND_TENANT).equals(path)) {
            return SECOND_TENANT;
        }
        throw new IllegalStateException("Issuer path is not registered: " + path);
    }
}
