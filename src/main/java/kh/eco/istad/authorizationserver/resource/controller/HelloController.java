package kh.eco.istad.authorizationserver.resource.controller;

import java.util.Map;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {
    @GetMapping("/api/public/hello")
    Map<String, String> publicHello() {
        return Map.of("message", "Hello from the public API");
    }

    @GetMapping("/api/private/hello")
    Map<String, String> privateHello(Authentication authentication) {
        return Map.of("message", "Hello, " + authentication.getName());
    }

    @GetMapping("/api/users/me")
    Map<String, Object> currentUser(Authentication authentication) {
        Set<String> authorities = authentication.getAuthorities().stream()
                .map(authority -> authority.getAuthority())
                .collect(Collectors.toUnmodifiableSet());
        return Map.of("username", authentication.getName(), "authorities", authorities);
    }

    @GetMapping("/api/products")
    List<Map<String, Object>> products() {
        return List.of(
                Map.of("id", "demo-1", "name", "Sample Product", "price", 9.99),
                Map.of("id", "demo-2", "name", "Another Product", "price", 19.99));
    }

    @GetMapping("/api/admin")
    Map<String, String> admin(Authentication authentication) {
        return Map.of("message", "Admin access for " + authentication.getName());
    }

    @GetMapping("/api/admin/hello")
    Map<String, String> adminHello(Authentication authentication) {
        return Map.of("message", "Admin access for " + authentication.getName());
    }

    @GetMapping("/api/scoped/hello")
    Map<String, String> scopeHello(Authentication authentication) {
        return Map.of("message", "Scope api.read granted to " + authentication.getName());
    }
}
