package kh.eco.istad.authorizationserver.authorization.repository;

import kh.eco.istad.authorizationserver.authorization.entity.OAuthAuthorizationEntity;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface OAuthAuthorizationJpaRepository extends JpaRepository<OAuthAuthorizationEntity, String> {
    Optional<OAuthAuthorizationEntity> findByState(String state);
    Optional<OAuthAuthorizationEntity> findByAuthorizationCodeValue(String value);
    Optional<OAuthAuthorizationEntity> findByAccessTokenValue(String value);
    Optional<OAuthAuthorizationEntity> findByRefreshTokenValue(String value);
    Optional<OAuthAuthorizationEntity> findByOidcIdTokenValue(String value);
    Optional<OAuthAuthorizationEntity> findByUserCodeValue(String value);
    Optional<OAuthAuthorizationEntity> findByDeviceCodeValue(String value);

    @Query("select a from OAuthAuthorizationEntity a where a.state = :value"
            + " or a.authorizationCodeValue = :value"
            + " or a.accessTokenValue = :value"
            + " or a.refreshTokenValue = :value"
            + " or a.oidcIdTokenValue = :value"
            + " or a.userCodeValue = :value"
            + " or a.deviceCodeValue = :value")
    Optional<OAuthAuthorizationEntity> findByAnyToken(@Param("value") String value);
}
