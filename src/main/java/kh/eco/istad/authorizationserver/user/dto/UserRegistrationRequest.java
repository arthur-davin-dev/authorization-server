package kh.eco.istad.authorizationserver.user.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record UserRegistrationRequest(
        @NotBlank
        @Size(min = 3, max = 100)
        @Pattern(regexp = "[A-Za-z0-9._-]+", message = "username may contain letters, digits, dot, underscore, and hyphen only")
        String username,
        @NotBlank
        @Size(min = 8, max = 72, message = "password must contain between 8 and 72 characters")
        String password) {
}
