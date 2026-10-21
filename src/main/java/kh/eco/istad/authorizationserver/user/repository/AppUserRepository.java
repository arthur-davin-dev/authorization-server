package kh.eco.istad.authorizationserver.user.repository;

import kh.eco.istad.authorizationserver.user.entity.AppUserEntity;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserRepository extends JpaRepository<AppUserEntity, UUID> {
    Optional<AppUserEntity> findByUsername(String username);
    boolean existsByUsername(String username);
}
