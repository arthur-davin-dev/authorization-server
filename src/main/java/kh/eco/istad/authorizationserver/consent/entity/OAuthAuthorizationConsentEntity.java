package kh.eco.istad.authorizationserver.consent.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;

@Entity
@Table(name = "oauth_authorization_consent")
@IdClass(AuthorizationConsentId.class)
public class OAuthAuthorizationConsentEntity {
    @Id
    @Column(name = "registered_client_id", length = 100)
    public String registeredClientId;
    @Id
    @Column(name = "principal_name", length = 200)
    public String principalName;
    @Column(nullable = false, columnDefinition = "text")
    public String authorities;

}
