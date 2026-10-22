package kh.eco.istad.authorizationserver.resource.controller;

import java.util.Map;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.security.OAuthFlow;
import io.swagger.v3.oas.annotations.security.OAuthFlows;
import io.swagger.v3.oas.annotations.security.OAuthScope;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@SecurityScheme(
        name = "oauth2",
        type = SecuritySchemeType.OAUTH2,
        flows = @OAuthFlows(authorizationCode = @OAuthFlow(
                authorizationUrl = "/oauth2/authorize",
                tokenUrl = "/oauth2/token",
                scopes = {
                    @OAuthScope(name = "openid"),
                    @OAuthScope(name = "profile"),
                    @OAuthScope(name = "api.read")
                })))
public class HelloController {
    @GetMapping("/api/public/hello")
    public Map<String, String> publicHello() {
        return Map.of("message", "Hello from the public API");
    }

    @GetMapping("/api/private/hello")
    @SecurityRequirement(name = "oauth2", scopes = {"openid", "profile", "api.read"})
    public Map<String, String> privateHello(Authentication authentication) {
        return Map.of("message", "Hello, " + authentication.getName());
    }

    @GetMapping("/api/users/me")
    @SecurityRequirement(name = "oauth2", scopes = {"openid", "profile", "api.read"})
    public Map<String, Object> currentUser(Authentication authentication) {
        Set<String> authorities = authentication.getAuthorities().stream()
                .map(authority -> authority.getAuthority())
                .collect(Collectors.toUnmodifiableSet());
        return Map.of("username", authentication.getName(), "authorities", authorities);
    }

    @GetMapping("/api/products")
    @SecurityRequirement(name = "oauth2", scopes = {"openid", "profile", "api.read"})
    public List<Map<String, Object>> products() {
        return List.of(
                Map.of("id", "demo-1", "name", "Sample Product", "price", 9.99),
                Map.of("id", "demo-2", "name", "Another Product", "price", 19.99));
    }

    @GetMapping("/api/admin")
    @SecurityRequirement(name = "oauth2", scopes = {"openid", "profile", "api.read"})
    public Map<String, String> admin(Authentication authentication) {
        return Map.of("message", "Admin access for " + authentication.getName());
    }

    @GetMapping("/api/admin/hello")
    @SecurityRequirement(name = "oauth2", scopes = {"openid", "profile", "api.read"})
    public Map<String, String> adminHello(Authentication authentication) {
        return Map.of("message", "Admin access for " + authentication.getName());
    }

    @GetMapping("/api/scoped/hello")
    @SecurityRequirement(name = "oauth2", scopes = {"openid", "profile", "api.read"})
    public Map<String, String> scopeHello(Authentication authentication) {
        return Map.of("message", "Scope api.read granted to " + authentication.getName());
    }
}
