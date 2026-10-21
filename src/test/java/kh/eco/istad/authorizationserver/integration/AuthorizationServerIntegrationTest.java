package kh.eco.istad.authorizationserver.integration;

import kh.eco.istad.authorizationserver.authorization.service.JpaOAuth2AuthorizationService;
import kh.eco.istad.authorizationserver.consent.service.JpaOAuth2AuthorizationConsentService;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.List;
import java.util.Set;

import kh.eco.istad.authorizationserver.user.repository.AppUserRepository;
import kh.eco.istad.authorizationserver.user.entity.AppUserEntity;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@SpringBootTest(properties = {
        "app.bootstrap-user.username=integration-user",
        "app.bootstrap-user.password=correct-password"
})
@AutoConfigureMockMvc
@Testcontainers(disabledWithoutDocker = true)
class AuthorizationServerIntegrationTest {
    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("authorization_test")
            .withUsername("authorization_test")
            .withPassword("authorization_test");

    @DynamicPropertySource
    static void databaseProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
    }

    @Autowired
    private RegisteredClientRepository registeredClients;

    @Autowired
    private JpaOAuth2AuthorizationService authorizationService;

    @Autowired
    private JpaOAuth2AuthorizationConsentService consentService;

    @Autowired
    private AppUserRepository users;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private MockMvc mockMvc;

    @Test
    void spaClientIsStoredWithPublicPkceAndAllowedScopes() {
        RegisteredClient client = registeredClients.findByClientId("authorization-spa");

        assertThat(client).isNotNull();
        assertThat(client.getClientAuthenticationMethods()).contains(ClientAuthenticationMethod.NONE);
        assertThat(client.getClientIdIssuedAt()).isNotNull();
        assertThat(client.getAuthorizationGrantTypes()).contains(AuthorizationGrantType.AUTHORIZATION_CODE);
        assertThat(client.getClientSettings().isRequireProofKey()).isTrue();
        assertThat(client.getClientSettings().isRequireAuthorizationConsent()).isTrue();
        assertThat(client.getRedirectUris()).containsExactlyInAnyOrder(
                "http://127.0.0.1:9000/", "http://localhost:9000/");
        assertThat(client.getScopes()).contains("openid", "profile", "api.read");
    }

    @Test
    void databaseUsersUseBcryptAndRejectWrongPasswords() {
        AppUserEntity user = users.findByUsername("integration-user").orElseThrow();

        assertThat(user.getPasswordHash()).doesNotContain("correct-password");
        assertThat(passwordEncoder.matches("correct-password", user.getPasswordHash())).isTrue();
        assertThat(user.getRoles()).containsOnly("ROLE_USER");
        DaoAuthenticationProvider userAuthenticationProvider = new DaoAuthenticationProvider();
        userAuthenticationProvider.setUserDetailsService(userDetailsService);
        userAuthenticationProvider.setPasswordEncoder(passwordEncoder);
        assertThat(userAuthenticationProvider.authenticate(
                new UsernamePasswordAuthenticationToken("integration-user", "correct-password")).isAuthenticated()).isTrue();
        assertThrows(BadCredentialsException.class, () -> userAuthenticationProvider.authenticate(
                new UsernamePasswordAuthenticationToken("integration-user", "incorrect-password")));
    }

    @Test
    void authorizationsAndConsentRoundTripThroughPostgres() {
        RegisteredClient client = registeredClients.findByClientId("authorization-spa");
        Instant now = Instant.now();
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(client)
                .principalName("integration-user")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(Set.of("api.read"))
                .attribute(OAuth2ParameterNames.STATE, "test-state")
                .attribute("test-attribute", "persisted")
                .token(new OAuth2AuthorizationCode("test-code", now, now.plusSeconds(300)))
                .build();

        authorizationService.save(authorization);

        OAuth2Authorization reloaded = authorizationService.findByToken(
                "test-code", new OAuth2TokenType(OAuth2ParameterNames.CODE));
        assertThat(reloaded).isNotNull();
        assertThat(reloaded.getRegisteredClientId()).isEqualTo(client.getId());
        String restoredAttribute = reloaded.getAttribute("test-attribute");
        assertThat(restoredAttribute).isEqualTo("persisted");
        assertThat(reloaded.getToken(OAuth2AuthorizationCode.class).getToken().getTokenValue()).isEqualTo("test-code");
        String restoredState = reloaded.getAttribute(OAuth2ParameterNames.STATE);
        assertThat(restoredState).isEqualTo("test-state");

        OAuth2AuthorizationConsent consent = OAuth2AuthorizationConsent.withId(client.getId(), "integration-user")
                .authority(new SimpleGrantedAuthority("SCOPE_api.read"))
                .authority(new SimpleGrantedAuthority("ROLE_USER"))
                .build();
        consentService.save(consent);
        OAuth2AuthorizationConsent reloadedConsent = consentService.findById(client.getId(), "integration-user");
        assertThat(reloadedConsent.getAuthorities()).extracting("authority")
                .containsExactlyInAnyOrder("SCOPE_api.read", "ROLE_USER");
    }

    @Test
    void apiSeparatesPublicAuthenticatedRoleAndScopeEndpoints() throws Exception {
        mockMvc.perform(get("/api/public/hello")).andExpect(status().isOk());
        mockMvc.perform(get("/api/private/hello")).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/private/hello").header("Authorization", "Bearer not-a-jwt"))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/private/hello").with(SecurityMockMvcRequestPostProcessors.jwt()
                        .jwt(jwt -> jwt.subject("integration-user").claim("roles", List.of("ROLE_USER")))
                        .authorities(new SimpleGrantedAuthority("ROLE_USER"))))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/scoped/hello").with(SecurityMockMvcRequestPostProcessors.jwt()
                        .authorities(new SimpleGrantedAuthority("SCOPE_api.read"))))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/admin/hello").with(SecurityMockMvcRequestPostProcessors.jwt()
                        .authorities(new SimpleGrantedAuthority("ROLE_USER"))))
                .andExpect(status().isForbidden());
    }

    @Test
    void metadataAndJwkEndpointsAreAvailable() throws Exception {
        mockMvc.perform(get("/")).andExpect(status().isOk());
        mockMvc.perform(get("/not-public")).andExpect(status().is3xxRedirection());
        mockMvc.perform(get("/.well-known/oauth-authorization-server")).andExpect(status().isOk());
        mockMvc.perform(get("/.well-known/openid-configuration")).andExpect(status().isOk());
        mockMvc.perform(get("/oauth2/jwks")).andExpect(status().isOk());
    }
}
