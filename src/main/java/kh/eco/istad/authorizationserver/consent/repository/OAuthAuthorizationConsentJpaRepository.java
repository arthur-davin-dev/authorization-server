package kh.eco.istad.authorizationserver.consent.repository;

import kh.eco.istad.authorizationserver.consent.entity.AuthorizationConsentId;
import kh.eco.istad.authorizationserver.consent.entity.OAuthAuthorizationConsentEntity;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface OAuthAuthorizationConsentJpaRepository
        extends JpaRepository<OAuthAuthorizationConsentEntity, AuthorizationConsentId> {
    Optional<OAuthAuthorizationConsentEntity> findByRegisteredClientIdAndPrincipalName(
            String registeredClientId, String principalName);
    void deleteByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);
}
