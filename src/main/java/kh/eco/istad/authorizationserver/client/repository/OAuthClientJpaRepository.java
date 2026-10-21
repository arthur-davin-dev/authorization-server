package kh.eco.istad.authorizationserver.client.repository;

import kh.eco.istad.authorizationserver.client.entity.OAuthClientEntity;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface OAuthClientJpaRepository extends JpaRepository<OAuthClientEntity, String> {
    Optional<OAuthClientEntity> findByClientId(String clientId);
}
