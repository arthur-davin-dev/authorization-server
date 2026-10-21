package kh.eco.istad.authorizationserver.user.service;

import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.UUID;

import kh.eco.istad.authorizationserver.user.dto.UserRegistrationRequest;
import kh.eco.istad.authorizationserver.user.entity.AppUserEntity;
import kh.eco.istad.authorizationserver.user.repository.AppUserRepository;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Service
public class UserRegistrationService {
    private static final int BCRYPT_MAX_PASSWORD_BYTES = 72;

    private final AppUserRepository users;
    private final PasswordEncoder passwordEncoder;

    public UserRegistrationService(AppUserRepository users, PasswordEncoder passwordEncoder) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public AppUserEntity register(UserRegistrationRequest request) {
        String username = request.username().trim();
        String password = request.password();
        if (password.getBytes(StandardCharsets.UTF_8).length > BCRYPT_MAX_PASSWORD_BYTES) {
            throw new IllegalArgumentException("password exceeds the supported 72 UTF-8 byte limit");
        }
        if (!StringUtils.hasText(username)) {
            throw new IllegalArgumentException("username must not be blank");
        }
        if (users.existsByUsername(username)) {
            throw new DuplicateUsernameException();
        }

        AppUserEntity user = new AppUserEntity(
                UUID.randomUUID(), username, passwordEncoder.encode(password), true, Set.of("ROLE_USER"));
        try {
            return users.saveAndFlush(user);
        } catch (DataIntegrityViolationException exception) {
            // The unique database constraint is the authority when registrations race.
            throw new DuplicateUsernameException();
        }
    }
}
