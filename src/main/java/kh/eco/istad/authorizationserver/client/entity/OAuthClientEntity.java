package kh.eco.istad.authorizationserver.client.entity;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "oauth_client")
public class OAuthClientEntity {
    @Id
    @Column(length = 100)
    public String id;
    @Column(name = "client_id", nullable = false, unique = true, length = 200)
    public String clientId;
    @Column(name = "client_id_issued_at", nullable = false)
    public Instant clientIdIssuedAt;
    @Column(name = "client_secret", columnDefinition = "text")
    public String clientSecret;
    @Column(name = "client_secret_expires_at")
    public Instant clientSecretExpiresAt;
    @Column(name = "client_name", nullable = false, length = 200)
    public String clientName;
    @Column(name = "client_authentication_methods", nullable = false, columnDefinition = "text")
    public String clientAuthenticationMethods;
    @Column(name = "authorization_grant_types", nullable = false, columnDefinition = "text")
    public String authorizationGrantTypes;
    @Column(name = "redirect_uris", nullable = false, columnDefinition = "text")
    public String redirectUris;
    @Column(name = "post_logout_redirect_uris", columnDefinition = "text")
    public String postLogoutRedirectUris;
    @Column(nullable = false, columnDefinition = "text")
    public String scopes;
    @Column(name = "client_settings", nullable = false, columnDefinition = "text")
    public String clientSettings;
    @Column(name = "token_settings", nullable = false, columnDefinition = "text")
    public String tokenSettings;
}
