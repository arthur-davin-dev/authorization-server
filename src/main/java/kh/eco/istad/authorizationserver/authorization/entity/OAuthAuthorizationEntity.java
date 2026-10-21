package kh.eco.istad.authorizationserver.authorization.entity;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "oauth_authorization")
public class OAuthAuthorizationEntity {
    @Id
    @Column(length = 100)
    public String id;
    @Column(name = "tenant_id", nullable = false, length = 64)
    public String tenantId;
    @Column(name = "registered_client_id", nullable = false, length = 100)
    public String registeredClientId;
    @Column(name = "principal_name", nullable = false, length = 200)
    public String principalName;
    @Column(name = "authorization_grant_type", nullable = false, length = 100)
    public String authorizationGrantType;
    @Column(name = "authorized_scopes", columnDefinition = "text")
    public String authorizedScopes;
    @Column(columnDefinition = "text")
    public String attributes;
    @Column(columnDefinition = "text")
    public String state;

    @Column(name = "authorization_code_value", columnDefinition = "text")
    public String authorizationCodeValue;
    @Column(name = "authorization_code_issued_at")
    public Instant authorizationCodeIssuedAt;
    @Column(name = "authorization_code_expires_at")
    public Instant authorizationCodeExpiresAt;
    @Column(name = "authorization_code_metadata", columnDefinition = "text")
    public String authorizationCodeMetadata;

    @Column(name = "access_token_value", columnDefinition = "text")
    public String accessTokenValue;
    @Column(name = "access_token_issued_at")
    public Instant accessTokenIssuedAt;
    @Column(name = "access_token_expires_at")
    public Instant accessTokenExpiresAt;
    @Column(name = "access_token_metadata", columnDefinition = "text")
    public String accessTokenMetadata;
    @Column(name = "access_token_type", length = 50)
    public String accessTokenType;
    @Column(name = "access_token_scopes", columnDefinition = "text")
    public String accessTokenScopes;

    @Column(name = "refresh_token_value", columnDefinition = "text")
    public String refreshTokenValue;
    @Column(name = "refresh_token_issued_at")
    public Instant refreshTokenIssuedAt;
    @Column(name = "refresh_token_expires_at")
    public Instant refreshTokenExpiresAt;
    @Column(name = "refresh_token_metadata", columnDefinition = "text")
    public String refreshTokenMetadata;

    @Column(name = "oidc_id_token_value", columnDefinition = "text")
    public String oidcIdTokenValue;
    @Column(name = "oidc_id_token_issued_at")
    public Instant oidcIdTokenIssuedAt;
    @Column(name = "oidc_id_token_expires_at")
    public Instant oidcIdTokenExpiresAt;
    @Column(name = "oidc_id_token_metadata", columnDefinition = "text")
    public String oidcIdTokenMetadata;
    @Column(name = "oidc_id_token_claims", columnDefinition = "text")
    public String oidcIdTokenClaims;

    @Column(name = "user_code_value", columnDefinition = "text")
    public String userCodeValue;
    @Column(name = "user_code_issued_at")
    public Instant userCodeIssuedAt;
    @Column(name = "user_code_expires_at")
    public Instant userCodeExpiresAt;
    @Column(name = "user_code_metadata", columnDefinition = "text")
    public String userCodeMetadata;

    @Column(name = "device_code_value", columnDefinition = "text")
    public String deviceCodeValue;
    @Column(name = "device_code_issued_at")
    public Instant deviceCodeIssuedAt;
    @Column(name = "device_code_expires_at")
    public Instant deviceCodeExpiresAt;
    @Column(name = "device_code_metadata", columnDefinition = "text")
    public String deviceCodeMetadata;

}
