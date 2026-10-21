package kh.eco.istad.authorizationserver.resource.controller;

import java.util.Map;

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

    @GetMapping("/api/admin/hello")
    Map<String, String> adminHello(Authentication authentication) {
        return Map.of("message", "Admin access for " + authentication.getName());
    }

    @GetMapping("/api/scoped/hello")
    Map<String, String> scopeHello(Authentication authentication) {
        return Map.of("message", "Scope api.read granted to " + authentication.getName());
    }
}
