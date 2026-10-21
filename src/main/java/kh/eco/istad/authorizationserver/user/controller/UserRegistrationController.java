package kh.eco.istad.authorizationserver.user.controller;

import java.net.URI;
import java.util.Map;

import jakarta.validation.Valid;
import kh.eco.istad.authorizationserver.user.dto.UserRegistrationRequest;
import kh.eco.istad.authorizationserver.user.dto.UserRegistrationResponse;
import kh.eco.istad.authorizationserver.user.service.UserRegistrationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserRegistrationController {
    private final UserRegistrationService registrations;

    public UserRegistrationController(UserRegistrationService registrations) {
        this.registrations = registrations;
    }

    @PostMapping("/api/auth/register")
    public ResponseEntity<UserRegistrationResponse> register(@Valid @RequestBody UserRegistrationRequest request) {
        UserRegistrationResponse response = new UserRegistrationResponse(
                registrations.register(request).getUsername());
        return ResponseEntity.created(URI.create("/api/auth/register")).body(response);
    }
}
