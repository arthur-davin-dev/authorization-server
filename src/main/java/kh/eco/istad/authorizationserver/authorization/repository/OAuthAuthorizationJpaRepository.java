package kh.eco.istad.authorizationserver.authorization.repository;

import kh.eco.istad.authorizationserver.authorization.entity.OAuthAuthorizationEntity;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface OAuthAuthorizationJpaRepository extends JpaRepository<OAuthAuthorizationEntity, String> {
    Optional<OAuthAuthorizationEntity> findByTenantIdAndId(String tenantId, String id);
    Optional<OAuthAuthorizationEntity> findByTenantIdAndState(String tenantId, String state);
    Optional<OAuthAuthorizationEntity> findByTenantIdAndAuthorizationCodeValue(String tenantId, String value);
    Optional<OAuthAuthorizationEntity> findByTenantIdAndAccessTokenValue(String tenantId, String value);
    Optional<OAuthAuthorizationEntity> findByTenantIdAndRefreshTokenValue(String tenantId, String value);
    Optional<OAuthAuthorizationEntity> findByTenantIdAndOidcIdTokenValue(String tenantId, String value);
    Optional<OAuthAuthorizationEntity> findByTenantIdAndUserCodeValue(String tenantId, String value);
    Optional<OAuthAuthorizationEntity> findByTenantIdAndDeviceCodeValue(String tenantId, String value);
    void deleteByIdAndTenantId(String id, String tenantId);

    @Query("select a from OAuthAuthorizationEntity a where a.tenantId = :tenantId and (a.state = :value"
            + " or a.authorizationCodeValue = :value"
            + " or a.accessTokenValue = :value"
            + " or a.refreshTokenValue = :value"
            + " or a.oidcIdTokenValue = :value"
            + " or a.userCodeValue = :value"
            + " or a.deviceCodeValue = :value)")
    Optional<OAuthAuthorizationEntity> findByAnyTokenAndTenantId(
            @Param("value") String value, @Param("tenantId") String tenantId);
}
