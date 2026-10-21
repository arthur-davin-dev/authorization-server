package kh.eco.istad.authorizationserver.consent.service;

import kh.eco.istad.authorizationserver.consent.entity.OAuthAuthorizationConsentEntity;
import kh.eco.istad.authorizationserver.consent.repository.OAuthAuthorizationConsentJpaRepository;
import kh.eco.istad.authorizationserver.tenant.TenantComponentRegistry;
import java.util.HashSet;
import java.util.Set;

import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

@Component
public class JpaOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService {
    private final OAuthAuthorizationConsentJpaRepository consents;
    private final RegisteredClientRepository clients;

    public JpaOAuth2AuthorizationConsentService(
            OAuthAuthorizationConsentJpaRepository consents,
            RegisteredClientRepository clients) {
        this.consents = consents;
        this.clients = clients;
    }

    @Override
    @Transactional
    public void save(OAuth2AuthorizationConsent consent) {
        Assert.notNull(consent, "authorizationConsent cannot be null");
        OAuthAuthorizationConsentEntity entity = new OAuthAuthorizationConsentEntity();
        entity.tenantId = TenantComponentRegistry.currentTenantId();
        entity.registeredClientId = consent.getRegisteredClientId();
        entity.principalName = consent.getPrincipalName();
        Set<String> authorities = new HashSet<>();
        for (GrantedAuthority authority : consent.getAuthorities()) {
            authorities.add(authority.getAuthority());
        }
        entity.authorities = StringUtils.collectionToCommaDelimitedString(authorities);
        consents.save(entity);
    }

    @Override
    @Transactional
    public void remove(OAuth2AuthorizationConsent consent) {
        Assert.notNull(consent, "authorizationConsent cannot be null");
        consents.deleteByTenantIdAndRegisteredClientIdAndPrincipalName(
                TenantComponentRegistry.currentTenantId(), consent.getRegisteredClientId(), consent.getPrincipalName());
    }

    @Override
    @Transactional(readOnly = true)
    public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
        Assert.hasText(registeredClientId, "registeredClientId cannot be empty");
        Assert.hasText(principalName, "principalName cannot be empty");
        return consents.findByTenantIdAndRegisteredClientIdAndPrincipalName(
                TenantComponentRegistry.currentTenantId(), registeredClientId, principalName)
                .map(this::toDomain).orElse(null);
    }

    private OAuth2AuthorizationConsent toDomain(OAuthAuthorizationConsentEntity entity) {
        RegisteredClient client = clients.findById(entity.registeredClientId);
        if (client == null) {
            throw new DataRetrievalFailureException("Registered client not found: " + entity.registeredClientId);
        }
        OAuth2AuthorizationConsent.Builder builder = OAuth2AuthorizationConsent.withId(
                entity.registeredClientId, entity.principalName);
        for (String authority : StringUtils.commaDelimitedListToSet(entity.authorities)) {
            builder.authority(new SimpleGrantedAuthority(authority));
        }
        return builder.build();
    }
}
