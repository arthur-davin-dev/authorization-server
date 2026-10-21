package kh.eco.istad.authorizationserver.integration;

import kh.eco.istad.authorizationserver.authorization.service.JpaOAuth2AuthorizationService;
import kh.eco.istad.authorizationserver.authorization.repository.OAuthAuthorizationJpaRepository;
import kh.eco.istad.authorizationserver.client.repository.OAuthClientJpaRepository;
import kh.eco.istad.authorizationserver.consent.service.JpaOAuth2AuthorizationConsentService;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
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
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.web.util.UriComponentsBuilder;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
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

    @Autowired
    private JwtDecoder jwtDecoder;

    @Autowired
    private KeyPair signingKeyPair;

    @Autowired
    private OAuthAuthorizationJpaRepository authorizationRows;

    @Autowired
    private OAuthClientJpaRepository clientRows;

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
    void standardLoginAcceptsCorrectPasswordRejectsWrongPasswordAndSupportsLogout() throws Exception {
        mockMvc.perform(post("/login")
                        .param("username", "integration-user")
                        .param("password", "correct-password")
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().is3xxRedirection());
        mockMvc.perform(post("/login")
                        .param("username", "integration-user")
                        .param("password", "wrong-password")
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl("/login?error"));
        mockMvc.perform(post("/logout")
                        .with(SecurityMockMvcRequestPostProcessors.user("integration-user"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl("/login?logout"));
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
        mockMvc.perform(get("/api/products").with(SecurityMockMvcRequestPostProcessors.jwt()
                        .authorities(new SimpleGrantedAuthority("ROLE_USER"))))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/api/products").with(SecurityMockMvcRequestPostProcessors.jwt()
                        .authorities(new SimpleGrantedAuthority("SCOPE_api.read"))))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/admin/hello").with(SecurityMockMvcRequestPostProcessors.jwt()
                        .authorities(new SimpleGrantedAuthority("ROLE_USER"))))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/api/admin").with(SecurityMockMvcRequestPostProcessors.jwt()
                        .jwt(jwt -> jwt.subject("administrator"))
                        .authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Admin access for administrator"));
        mockMvc.perform(get("/api/users/me").with(SecurityMockMvcRequestPostProcessors.jwt()
                        .jwt(jwt -> jwt.subject("integration-user"))
                        .authorities(new SimpleGrantedAuthority("ROLE_USER"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("integration-user"));
        mockMvc.perform(get("/api/admin").with(SecurityMockMvcRequestPostProcessors.jwt()
                        .authorities(new SimpleGrantedAuthority("ROLE_USER"))))
                .andExpect(status().isForbidden());
    }

    @Test
    void publicRegistrationHashesPasswordsAndAlwaysAssignsOnlyUserRole() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType("application/json")
                        .content("""
                                {"username":"new-user","password":"secure-password-1","roles":["ROLE_ADMIN"]}
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.username").value("new-user"))
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.roles").doesNotExist());

        AppUserEntity user = users.findByUsername("new-user").orElseThrow();
        assertThat(user.getRoles()).containsExactly("ROLE_USER");
        assertThat(user.getPasswordHash()).isNotEqualTo("secure-password-1");
        assertThat(passwordEncoder.matches("secure-password-1", user.getPasswordHash())).isTrue();
    }

    @Test
    void publicRegistrationRejectsDuplicateNamesAndInvalidInput() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType("application/json")
                        .content("""
                                {"username":"duplicate-user","password":"secure-password-1"}
                                """))
                .andExpect(status().isCreated());
        mockMvc.perform(post("/api/auth/register")
                        .contentType("application/json")
                        .content("""
                                {"username":"duplicate-user","password":"secure-password-2"}
                                """))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("username_unavailable"));
        mockMvc.perform(post("/api/auth/register")
                        .contentType("application/json")
                        .content("""
                                {"username":"x","password":"short"}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith("application/json"));
    }

    @Test
    void dynamicClientRegistrationPersistsPkceClientAndReturnsRegistrationCredentials() throws Exception {
        String registrarTokenResponse = mockMvc.perform(post("http://127.0.0.1:9000/oauth2/token")
                        .with(SecurityMockMvcRequestPostProcessors.httpBasic(
                                "client-registrar", "client-registrar-secret"))
                        .contentType("application/x-www-form-urlencoded")
                        .param("grant_type", "client_credentials")
                        .param("scope", "client.create"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String registrarToken = new com.fasterxml.jackson.databind.ObjectMapper()
                .readTree(registrarTokenResponse).get("access_token").asText();

        String registrationResponse = mockMvc.perform(post("http://127.0.0.1:9000/connect/register")
                        .header("Authorization", "Bearer " + registrarToken)
                        .contentType("application/json")
                        .content("""
                                {
                                  "client_name":"Integration Registered Client",
                                  "redirect_uris":["https://oauth.pstmn.io/v1/callback"],
                                  "grant_types":["authorization_code"],
                                  "response_types":["code"],
                                  "scope":"openid profile api.read",
                                  "token_endpoint_auth_method":"client_secret_basic"
                                }
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.client_id").isNotEmpty())
                .andExpect(jsonPath("$.client_secret").isNotEmpty())
                .andExpect(jsonPath("$.registration_access_token").isNotEmpty())
                .andReturn().getResponse().getContentAsString();
        com.fasterxml.jackson.databind.JsonNode registration = new com.fasterxml.jackson.databind.ObjectMapper()
                .readTree(registrationResponse);
        RegisteredClient registered = registeredClients.findByClientId(registration.get("client_id").asText());
        assertThat(registered).isNotNull();
        assertThat(registered.getAuthorizationGrantTypes()).contains(AuthorizationGrantType.AUTHORIZATION_CODE);
        assertThat(registered.getClientAuthenticationMethods()).contains(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        assertThat(registered.getClientSettings().isRequireProofKey()).isTrue();
        assertThat(registered.getClientSettings().isRequireAuthorizationConsent()).isTrue();
        assertThat(registered.getAuthorizationGrantTypes()).doesNotContain(AuthorizationGrantType.REFRESH_TOKEN);

        mockMvc.perform(get(URI.create(registration.get("registration_client_uri").asText()).getPath())
                        .header("Authorization", "Bearer " + registration.get("registration_access_token").asText()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.client_id").value(registration.get("client_id").asText()));
    }

    @Test
    void customGrantRefreshPrincipalSurvivesJpaRoundTrip() throws Exception {
        String tokenResponse = mockMvc.perform(post("http://127.0.0.1:9000/oauth2/token")
                        .with(SecurityMockMvcRequestPostProcessors.httpBasic(
                                "custom-grant-client", "custom-grant-secret"))
                        .contentType("application/x-www-form-urlencoded")
                        .param("grant_type", "urn:ietf:params:oauth:grant-type:custom_code")
                        .param("code", "local-demo-code")
                        .param("scope", "message.read message.write"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        com.fasterxml.jackson.databind.JsonNode token = new com.fasterxml.jackson.databind.ObjectMapper()
                .readTree(tokenResponse);
        String refreshToken = token.get("refresh_token").asText();

        String rotatedResponse = mockMvc.perform(post("http://127.0.0.1:9000/oauth2/token")
                        .with(SecurityMockMvcRequestPostProcessors.httpBasic(
                                "custom-grant-client", "custom-grant-secret"))
                        .contentType("application/x-www-form-urlencoded")
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", refreshToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andExpect(jsonPath("$.refresh_token").isNotEmpty())
                .andReturn().getResponse().getContentAsString();
        String rotatedRefreshToken = new com.fasterxml.jackson.databind.ObjectMapper()
                .readTree(rotatedResponse).get("refresh_token").asText();
        assertThat(rotatedRefreshToken).isNotEqualTo(refreshToken);
        String secondRotationResponse = mockMvc.perform(post("http://127.0.0.1:9000/oauth2/token")
                        .with(SecurityMockMvcRequestPostProcessors.httpBasic(
                                "custom-grant-client", "custom-grant-secret"))
                        .contentType("application/x-www-form-urlencoded")
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", rotatedRefreshToken))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String latestRefreshToken = new com.fasterxml.jackson.databind.ObjectMapper()
                .readTree(secondRotationResponse).get("refresh_token").asText();
        mockMvc.perform(post("http://127.0.0.1:9000/oauth2/token")
                        .with(SecurityMockMvcRequestPostProcessors.httpBasic(
                                "custom-grant-client", "custom-grant-secret"))
                        .contentType("application/x-www-form-urlencoded")
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", refreshToken))
                .andExpect(status().isBadRequest());
        mockMvc.perform(post("http://127.0.0.1:9000/oauth2/revoke")
                        .with(SecurityMockMvcRequestPostProcessors.httpBasic(
                                "custom-grant-client", "custom-grant-secret"))
                        .contentType("application/x-www-form-urlencoded")
                        .param("token", latestRefreshToken)
                        .param("token_type_hint", "refresh_token"))
                .andExpect(status().isOk());
        mockMvc.perform(post("http://127.0.0.1:9000/oauth2/token")
                        .with(SecurityMockMvcRequestPostProcessors.httpBasic(
                                "custom-grant-client", "custom-grant-secret"))
                        .contentType("application/x-www-form-urlencoded")
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", latestRefreshToken))
                .andExpect(status().isBadRequest());
    }

    @Test
    void customGrantDoesNotIssueRefreshTokenUnlessClientRegisteredThatGrant() throws Exception {
        RegisteredClient noRefreshClient = RegisteredClient.withId("custom-no-refresh-client-v1")
                .clientId("custom-no-refresh-client")
                .clientSecret(passwordEncoder.encode("custom-no-refresh-secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(kh.eco.istad.authorizationserver.grant.CustomCodeGrantAuthenticationToken.GRANT_TYPE)
                .scope("message.read")
                .build();
        registeredClients.save(noRefreshClient);

        String response = mockMvc.perform(post("http://127.0.0.1:9000/oauth2/token")
                        .with(SecurityMockMvcRequestPostProcessors.httpBasic(
                                "custom-no-refresh-client", "custom-no-refresh-secret"))
                        .contentType("application/x-www-form-urlencoded")
                        .param("grant_type", "urn:ietf:params:oauth:grant-type:custom_code")
                        .param("code", "local-demo-code")
                        .param("scope", "message.read"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andExpect(jsonPath("$.refresh_token").doesNotExist())
                .andReturn().getResponse().getContentAsString();

        String accessToken = new com.fasterxml.jackson.databind.ObjectMapper()
                .readTree(response).get("access_token").asText();
        OAuth2Authorization authorization = authorizationService.findByToken(
                accessToken, OAuth2TokenType.ACCESS_TOKEN);
        assertThat(authorization.getToken(org.springframework.security.oauth2.core.OAuth2RefreshToken.class))
                .isNull();
    }

    @Test
    void refreshEndpointRejectsExpiredPersistedRefreshToken() throws Exception {
        RegisteredClient client = registeredClients.findByClientId("custom-grant-client");
        Instant now = Instant.now();
        OAuth2Authorization expiredAuthorization = OAuth2Authorization.withRegisteredClient(client)
                .principalName(client.getClientId())
                .authorizationGrantType(
                        kh.eco.istad.authorizationserver.grant.CustomCodeGrantAuthenticationToken.GRANT_TYPE)
                .authorizedScopes(Set.of("message.read"))
                .refreshToken(new org.springframework.security.oauth2.core.OAuth2RefreshToken(
                        "expired-persisted-refresh-token", now.minusSeconds(7200), now.minusSeconds(3600)))
                .build();
        authorizationService.save(expiredAuthorization);

        mockMvc.perform(post("http://127.0.0.1:9000/oauth2/token")
                        .with(SecurityMockMvcRequestPostProcessors.httpBasic(
                                "custom-grant-client", "custom-grant-secret"))
                        .contentType("application/x-www-form-urlencoded")
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", "expired-persisted-refresh-token"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    void authorizationCodePkceIssuesOidcTokensAndProtectsApis() throws Exception {
        RegisteredClient client = registeredClients.findByClientId("authorization-spa");
        MvcResult loginResponse = mockMvc.perform(post("/login")
                        .param("username", "integration-user")
                        .param("password", "correct-password")
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        MockHttpSession authenticatedSession = (MockHttpSession) loginResponse.getRequest().getSession(false);
        assertThat(authenticatedSession).isNotNull();

        String verifier = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("test-verifier-value-that-is-long-enough".getBytes(StandardCharsets.UTF_8));
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        String state = "pkce-integration-state";
        mockMvc.perform(get("http://127.0.0.1:9000/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", "authorization-spa")
                        .param("redirect_uri", "http://127.0.0.1:9000/")
                        .param("scope", "openid profile api.read")
                        .param("state", state)
                        .param("code_challenge", challenge)
                        .param("code_challenge_method", "S256")
                        .session(authenticatedSession))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Consent required")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("api.read")));

        MvcResult authorizationResponse = mockMvc.perform(post("http://127.0.0.1:9000/oauth2/authorize")
                        .param("client_id", "authorization-spa")
                        .param("state", state)
                        .param("scope", "profile")
                        .param("scope", "api.read")
                        .session(authenticatedSession))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        assertThat(consentService.findById(client.getId(), "integration-user")).isNotNull();
        String callback = authorizationResponse.getResponse().getRedirectedUrl();
        org.assertj.core.api.Assertions.assertThat(callback).isNotNull();
        org.assertj.core.api.Assertions.assertThat(URI.create(callback).getHost()).isEqualTo("127.0.0.1");
        org.springframework.util.MultiValueMap<String, String> callbackParameters =
                UriComponentsBuilder.fromUriString(callback).build(true).getQueryParams();
        String code = callbackParameters.getFirst("code");
        org.assertj.core.api.Assertions.assertThat(callbackParameters.getFirst("state")).isEqualTo(state);

        String tokenResponse = mockMvc.perform(post("http://127.0.0.1:9000/oauth2/token")
                        .contentType("application/x-www-form-urlencoded")
                        .param("grant_type", "authorization_code")
                        .param("client_id", "authorization-spa")
                        .param("redirect_uri", "http://127.0.0.1:9000/")
                        .param("code", code)
                        .param("code_verifier", verifier))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        com.fasterxml.jackson.databind.JsonNode token = new com.fasterxml.jackson.databind.ObjectMapper()
                .readTree(tokenResponse);
        String accessToken = token.get("access_token").asText();
        String idToken = token.get("id_token").asText();
        org.assertj.core.api.Assertions.assertThat(token.has("refresh_token")).isFalse();

        Jwt decoded = jwtDecoder.decode(accessToken);
        org.assertj.core.api.Assertions.assertThat(decoded.getSubject()).isEqualTo("integration-user");
        org.assertj.core.api.Assertions.assertThat(decoded.getAudience()).containsExactly("api://authorization-server");
        org.assertj.core.api.Assertions.assertThat(decoded.getClaimAsStringList("roles")).contains("ROLE_USER");
        mockMvc.perform(get("/api/users/me").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("integration-user"));
        mockMvc.perform(get("/api/products").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/admin").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/userinfo").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sub").value("integration-user"));

        SignedJWT parsedIdToken = SignedJWT.parse(idToken);
        org.assertj.core.api.Assertions.assertThat(parsedIdToken.verify(
                new RSASSAVerifier((RSAPublicKey) signingKeyPair.getPublic()))).isTrue();
        org.assertj.core.api.Assertions.assertThat(parsedIdToken.getJWTClaimsSet().getIssuer())
                .isEqualTo("http://127.0.0.1:9000");
        org.assertj.core.api.Assertions.assertThat(parsedIdToken.getJWTClaimsSet().getAudience())
                .contains("authorization-spa");
        org.assertj.core.api.Assertions.assertThat(parsedIdToken.getJWTClaimsSet().getExpirationTime())
                .isAfter(java.util.Date.from(Instant.now()));

        mockMvc.perform(post("http://127.0.0.1:9000/oauth2/token")
                        .contentType("application/x-www-form-urlencoded")
                        .param("grant_type", "authorization_code")
                        .param("client_id", "authorization-spa")
                        .param("redirect_uri", "http://127.0.0.1:9000/")
                        .param("code", code)
                        .param("code_verifier", verifier))
                .andExpect(status().isBadRequest());
    }

    @Test
    void authorizationCodePkceRejectsAnIncorrectVerifier() throws Exception {
        RegisteredClient client = registeredClients.findByClientId("authorization-spa");
        consentService.save(OAuth2AuthorizationConsent.withId(client.getId(), "integration-user")
                .authority(new SimpleGrantedAuthority("SCOPE_openid"))
                .authority(new SimpleGrantedAuthority("SCOPE_profile"))
                .authority(new SimpleGrantedAuthority("SCOPE_api.read"))
                .build());
        String verifier = "correct-test-verifier-value-123456789";
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        MvcResult response = mockMvc.perform(get("http://127.0.0.1:9000/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", "authorization-spa")
                        .param("redirect_uri", "http://127.0.0.1:9000/")
                        .param("scope", "openid profile api.read")
                        .param("state", "invalid-verifier-state")
                        .param("code_challenge", challenge)
                        .param("code_challenge_method", "S256")
                        .with(SecurityMockMvcRequestPostProcessors.user("integration-user").roles("USER")))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        String callback = response.getResponse().getRedirectedUrl();
        String code = UriComponentsBuilder.fromUriString(callback).build(true).getQueryParams().getFirst("code");

        mockMvc.perform(post("http://127.0.0.1:9000/oauth2/token")
                        .contentType("application/x-www-form-urlencoded")
                        .param("grant_type", "authorization_code")
                        .param("client_id", "authorization-spa")
                        .param("redirect_uri", "http://127.0.0.1:9000/")
                        .param("code", code)
                        .param("code_verifier", verifier + "wrong"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    void authorizationRequestsRejectUnregisteredRedirectAndMissingPkceChallenge() throws Exception {
        mockMvc.perform(get("http://127.0.0.1:9000/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", "authorization-spa")
                        .param("redirect_uri", "https://attacker.example/callback")
                        .param("scope", "openid profile api.read")
                        .param("state", "unregistered-redirect-state")
                        .param("code_challenge", "AAAA")
                        .param("code_challenge_method", "S256")
                        .with(SecurityMockMvcRequestPostProcessors.user("integration-user").roles("USER")))
                .andExpect(status().isBadRequest());

        MvcResult response = mockMvc.perform(get("http://127.0.0.1:9000/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", "authorization-spa")
                        .param("redirect_uri", "http://127.0.0.1:9000/")
                        .param("scope", "openid profile api.read")
                        .param("state", "missing-pkce-state")
                        .with(SecurityMockMvcRequestPostProcessors.user("integration-user").roles("USER")))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        String callback = response.getResponse().getRedirectedUrl();
        assertThat(UriComponentsBuilder.fromUriString(callback).build(true).getQueryParams().getFirst("error"))
                .isEqualTo("invalid_request");
    }

    @Test
    void tokenEndpointRejectsExpiredPersistedAuthorizationCode() throws Exception {
        RegisteredClient client = registeredClients.findByClientId("authorization-spa");
        Instant now = Instant.now();
        OAuth2Authorization expiredAuthorization = OAuth2Authorization.withRegisteredClient(client)
                .principalName("integration-user")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(Set.of("openid", "profile", "api.read"))
                .token(new OAuth2AuthorizationCode(
                        "expired-persisted-authorization-code", now.minusSeconds(600), now.minusSeconds(300)))
                .build();
        authorizationService.save(expiredAuthorization);

        mockMvc.perform(post("http://127.0.0.1:9000/oauth2/token")
                        .contentType("application/x-www-form-urlencoded")
                        .param("grant_type", "authorization_code")
                        .param("client_id", "authorization-spa")
                        .param("redirect_uri", "http://127.0.0.1:9000/")
                        .param("code", "expired-persisted-authorization-code")
                        .param("code_verifier", "a-verifier-that-is-long-enough-for-this-test"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    void jwtDecoderRejectsMalformedTokens() {
        assertThrows(JwtException.class, () -> jwtDecoder.decode("not.a.jwt"));
    }

    @Test
    void jwtDecoderRejectsExpiredWrongAudienceWrongIssuerAndInvalidSignature() throws Exception {
        String keyId = kh.eco.istad.authorizationserver.config.PersistentRsaKeyStore.keyId(signingKeyPair.getPublic());
        String issuer = "http://127.0.0.1:9000";
        String expired = signedJwt(issuer, "api://authorization-server", Instant.now().minusSeconds(30),
                signingKeyPair, keyId);
        String wrongAudience = signedJwt(issuer, "another-api", Instant.now().plusSeconds(60), signingKeyPair, keyId);
        String wrongIssuer = signedJwt("http://attacker.invalid", "api://authorization-server",
                Instant.now().plusSeconds(60), signingKeyPair, keyId);
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair attackerKey = generator.generateKeyPair();
        String invalidSignature = signedJwt(issuer, "api://authorization-server", Instant.now().plusSeconds(60),
                attackerKey, keyId);

        assertThrows(JwtException.class, () -> jwtDecoder.decode(expired));
        assertThrows(JwtException.class, () -> jwtDecoder.decode(wrongAudience));
        assertThrows(JwtException.class, () -> jwtDecoder.decode(wrongIssuer));
        assertThrows(JwtException.class, () -> jwtDecoder.decode(invalidSignature));
    }

    private static String signedJwt(String issuer, String audience, Instant expiresAt, KeyPair pair, String keyId)
            throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject("integration-user")
                .audience(audience)
                .issueTime(java.util.Date.from(Instant.now().minusSeconds(1)))
                .expirationTime(java.util.Date.from(expiresAt))
                .build();
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(keyId).build(), claims);
        jwt.sign(new RSASSASigner((RSAPrivateKey) pair.getPrivate()));
        return jwt.serialize();
    }

    @Test
    void metadataAndJwkEndpointsAreAvailable() throws Exception {
        mockMvc.perform(get("/")).andExpect(status().isOk());
        mockMvc.perform(get("/not-public")).andExpect(status().is3xxRedirection());
        mockMvc.perform(get("/.well-known/oauth-authorization-server")).andExpect(status().isOk());
        mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userinfo_endpoint").value("http://127.0.0.1:9000/userinfo"));
        mockMvc.perform(get("/oauth2/jwks"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kid").isNotEmpty())
                .andExpect(jsonPath("$.keys[0].d").doesNotExist());
    }

    @Test
    void tenantBClientsAndAuthorizationsPersistSeparatelyInPostgres() throws Exception {
        assertThat(clientRows.findByTenantIdAndClientId("tenant-b", "tenant-b-client")).isPresent();
        assertThat(clientRows.findByTenantIdAndClientId("default", "tenant-b-client")).isEmpty();
        RegisteredClient sameClientIdInRoot = RegisteredClient.withId("tenant-b-client-root-test-v1")
                .clientId("tenant-b-client")
                .clientName("Root Tenant Client ID Isolation Test")
                .clientSecret(passwordEncoder.encode("root-tenant-isolation-secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("root.test")
                .build();
        registeredClients.save(sameClientIdInRoot);
        assertThat(clientRows.findByTenantIdAndClientId("default", "tenant-b-client")).isPresent();
        assertThat(clientRows.findByTenantIdAndClientId("tenant-b", "tenant-b-client")).isPresent();

        String tokenResponse = mockMvc.perform(post("http://127.0.0.1:9000/tenant-b/oauth2/token")
                        .with(SecurityMockMvcRequestPostProcessors.httpBasic("tenant-b-client", "tenant-b-secret"))
                        .contentType("application/x-www-form-urlencoded")
                        .param("grant_type", "client_credentials")
                        .param("scope", "tenant.read"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String accessToken = new com.fasterxml.jackson.databind.ObjectMapper()
                .readTree(tokenResponse).get("access_token").asText();
        Jwt tenantToken = jwtDecoder.decode(accessToken);
        assertThat(tenantToken.getIssuer().toString()).isEqualTo("http://127.0.0.1:9000/tenant-b");

        assertThat(authorizationRows.findByTenantIdAndAccessTokenValue("tenant-b", accessToken)).isPresent();
        assertThat(authorizationRows.findByTenantIdAndAccessTokenValue("default", accessToken)).isEmpty();
    }
}
