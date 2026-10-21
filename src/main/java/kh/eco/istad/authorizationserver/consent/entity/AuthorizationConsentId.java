package kh.eco.istad.authorizationserver.consent.entity;

import java.io.Serializable;
import java.util.Objects;

public class AuthorizationConsentId implements Serializable {
    private String registeredClientId;
    private String principalName;

    public AuthorizationConsentId() {
    }

    public AuthorizationConsentId(String registeredClientId, String principalName) {
        this.registeredClientId = registeredClientId;
        this.principalName = principalName;
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (!(object instanceof AuthorizationConsentId other)) {
            return false;
        }
        return Objects.equals(registeredClientId, other.registeredClientId)
                && Objects.equals(principalName, other.principalName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(registeredClientId, principalName);
    }
}
