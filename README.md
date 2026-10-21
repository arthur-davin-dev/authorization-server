# Spring Authorization Server with PostgreSQL

A local Servlet-based OAuth 2.0 Authorization Server using Spring Boot 3.5, Spring Authorization Server, PostgreSQL/JPA, Flyway, a public SPA client with Authorization Code + PKCE, and RSA-signed JWTs. It also exposes a small JWT-protected API for demonstration.

## Compatibility

The build pins Spring Boot **3.5.16**, which manages Spring Security, Spring Authorization Server and their compatible versions. It uses the Boot-managed `spring-boot-starter-oauth2-authorization-server` rather than overriding Spring Security dependencies. Java toolchains target Java **25** and the wrapper uses Gradle **9.1.0**, the first Gradle release that officially supports running on Java 25. Spring Boot 3.5's published build support currently lists Gradle 8.x, so using Gradle 9.1 with Boot 3.5 is necessary for the Java 25 Gradle runtime requested here but is outside Boot 3.5's documented Gradle support matrix. Validate the Boot Gradle plugin tasks after syncing. See [Boot system requirements](https://docs.spring.io/spring-boot/3.5/system-requirements.html), [Boot dependency versions](https://docs.spring.io/spring-boot/3.5/appendix/dependency-versions/coordinates.html), and the [Gradle Java compatibility matrix](https://docs.gradle.org/current/userguide/compatibility.html).

## Start locally

Requirements: JDK 25, Docker Compose, and a browser. The compose file starts only PostgreSQL; Spring Boot runs on the host and serves the demo SPA itself.

```sh
cp .env.example .env
docker compose up -d postgres
set -a
. ./.env
set +a
./gradlew bootRun
```

On Windows, copy `.env.example` to `.env`, set the same variables in the terminal or IDE run configuration, then run `docker compose up -d postgres` and `gradlew.bat bootRun`. Docker Compose reads `.env` automatically; Spring Boot reads the exported process environment.

The server listens on `http://127.0.0.1:9000`; its root page is the embedded PKCE SPA, so no second web server is needed. When authorization is required, the server shows the custom responsive login form at `/login`, with CSRF protection and a generic error on failed credentials. Local demo credentials are **username `demo` / password `demo12345`**. The password is BCrypt-encoded in PostgreSQL. At startup the local bootstrap user is synchronized to `BOOTSTRAP_PASSWORD` (default `demo12345`), so changing the configured password updates the demo account. For production, set `BOOTSTRAP_USER_ENABLED=false` and replace all local defaults. The default DB credentials in compose and `application.yaml` are for local development only. Configure `DB_URL`, `DB_USER`, `DB_PASSWORD`, `OAUTH_ISSUER`, `SPA_ORIGIN`, `SPA_REDIRECT_URI`, and `BOOTSTRAP_USER` / `BOOTSTRAP_PASSWORD` in the environment as needed. Do not expose these local defaults on a network.

The RSA key pair is generated in memory when the process starts. Restarting the server rotates this development key, so tokens from before a restart stop validating. Supply a managed, persistent signing key before production use.

## Demo routes and endpoints

| Purpose | URL |
| --- | --- |
| Authorization Server metadata | `http://127.0.0.1:9000/.well-known/oauth-authorization-server` |
| OpenID Provider metadata | `http://127.0.0.1:9000/.well-known/openid-configuration` |
| JWK Set | `http://127.0.0.1:9000/oauth2/jwks` |
| Authorization | `http://127.0.0.1:9000/oauth2/authorize` |
| Token | `http://127.0.0.1:9000/oauth2/token` |
| OIDC UserInfo | `http://127.0.0.1:9000/userinfo` |
| PKCE demo SPA | `http://127.0.0.1:9000/` |
| Public API | `GET http://127.0.0.1:9000/api/public/hello` |
| Authenticated API | `GET http://127.0.0.1:9000/api/private/hello` |
| Scope restricted (`api.read`) | `GET http://127.0.0.1:9000/api/scoped/hello` |
| Role restricted (`ROLE_ADMIN`) | `GET http://127.0.0.1:9000/api/admin/hello` |
| Custom grant token | `POST http://127.0.0.1:9000/oauth2/token` |

The registered SPA has client ID `authorization-spa`, authentication method `none`, authorization-code grant, scopes `openid profile api.read`, user consent enabled, and PKCE required. There is no client secret. The local configuration explicitly allows `http://127.0.0.1:9000/` and `http://localhost:9000/`; the SPA uses whichever origin opened it for both authorization and callback. Keep the same hostname before and after login because browsers isolate `sessionStorage` by origin. CORS permits only the configured SPA origin, with credentials disabled.

## Multitenancy

The authorization server accepts two allowlisted issuers: the root issuer (default tenant) and `http://127.0.0.1:9000/tenant-b`. The tenant ID comes from the issuer path. Each issuer has separate registered clients, authorization/consent storage, and RSA signing keys. Default-tenant state uses PostgreSQL; the `tenant-b` demonstration stores OAuth state in memory and loses it on restart. The existing application user table is shared between issuers. `OAUTH_ISSUER` configures the trusted base origin; requests and tokens should use that host consistently (the loopback aliases `localhost` and `127.0.0.1` are both accepted).

Tenant B's authorization-server metadata is available at `http://127.0.0.1:9000/tenant-b/.well-known/openid-configuration`. It registers a separate client `tenant-b-client` with local secret `tenant-b-secret` and scope `tenant.read`. To request a tenant B token in Postman, send `POST http://127.0.0.1:9000/tenant-b/oauth2/token`, use **Basic Auth** with that client and secret, and set **Body → x-www-form-urlencoded** to `grant_type=client_credentials` and `scope=tenant.read`. The resulting JWT has issuer `http://127.0.0.1:9000/tenant-b` and is signed with tenant B's key. `tenant-b-client` is not registered at the root issuer; conversely, root-tenant clients are not registered under `/tenant-b`.

## Dynamic client registration

OpenID Connect Dynamic Client Registration is enabled at `/connect/register` for each issuer. A registrar client must first obtain an access token with only the `client.create` scope. Local root-tenant credentials are `client-registrar` / `client-registrar-secret`; Tenant B credentials are `tenant-b-client-registrar` / `tenant-b-registrar-secret`. Registration requests are restricted to authorization-code clients using `client_secret_basic`, at least one safe redirect URI, `openid`, and only the approved scopes `openid`, `profile`, and `api.read`. New clients require PKCE and user consent. Import `postman/dynamic-client-registration.postman_collection.json` to obtain a registrar token, register a client, and retrieve its metadata. Root-tenant client registrations persist in PostgreSQL; Tenant B registrations are in memory.

## Extension grant type

The token endpoint also demonstrates a custom extension grant using `urn:ietf:params:oauth:grant-type:custom_code`. The server registers confidential client `custom-grant-client` with local demo secret `custom-grant-secret`. Its grant code is configured by `CUSTOM_GRANT_CODE` (default `local-demo-code`) and checked with a constant-time comparison. Set a unique value outside local development. This fixed-code example is for learning only; a production grant should validate a short-lived, single-use code against its issuing system and avoid sharing one code across clients.

In Postman, create a POST request to `http://127.0.0.1:9000/oauth2/token`, choose **Authorization → Basic Auth** with username `custom-grant-client` and password `custom-grant-secret`, then set **Body → x-www-form-urlencoded**:

| Key | Value |
| --- | --- |
| `grant_type` | `urn:ietf:params:oauth:grant-type:custom_code` |
| `code` | `local-demo-code` (or your `CUSTOM_GRANT_CODE`) |
| `scope` | `message.read message.write` (optional; defaults to both client scopes) |

The response contains a bearer access token and refresh token. The client is explicitly registered for the refresh-token grant, and the custom-grant provider stores both tokens in the authorization service. To refresh, POST `grant_type=refresh_token` and the returned `refresh_token` to the same token endpoint with the same Basic Auth client credentials. An unknown custom code returns `invalid_grant`, a scope outside the registered client scopes returns `invalid_scope`, and this client cannot use the SPA's authorization-code grant.

## Browser PKCE walkthrough

Open `http://127.0.0.1:9000/` and click **Login with Authorization Server**. The SPA creates a random `code_verifier`, computes `BASE64URL(SHA256(code_verifier))`, and sends the challenge with `code_challenge_method=S256` to `/oauth2/authorize`. Log in with `demo` / `demo12345` (or the value configured in `BOOTSTRAP_PASSWORD`), approve requested consent, and the server redirects back with a short-lived authorization `code` and the original `state`. The SPA checks `state`, then posts `grant_type=authorization_code`, `client_id`, exact `redirect_uri`, `code`, and the original `code_verifier` to `/oauth2/token`. It holds the access token in memory and calls the API.

To verify PKCE rejection, select **Send an invalid verifier (PKCE negative test)** before sign-in. Authorization is still requested with the real challenge, but the token exchange deliberately sends a modified verifier. The token endpoint should return HTTP 400 with `invalid_grant`; no API token is issued. Clear the browser session and repeat with the checkbox off for a successful exchange.

To check API failures and success independently:

```sh
curl -i http://127.0.0.1:9000/api/public/hello
curl -i http://127.0.0.1:9000/api/private/hello
curl -i -H 'Authorization: Bearer not-a-jwt' http://127.0.0.1:9000/api/private/hello
curl -i -H "Authorization: Bearer $ACCESS_TOKEN" http://127.0.0.1:9000/api/private/hello
```

Expected results are public `200`, missing or invalid bearer token `401`, valid user token `200`, and regular user accessing the admin endpoint `403`. A user token with scope `api.read` receives `200` from `/api/scoped/hello`.

An example decoded access token payload (dummy values):

```json
{
  "iss": "http://127.0.0.1:9000",
  "sub": "demo",
  "client_id": "authorization-spa",
  "scope": ["openid", "profile", "api.read"],
  "roles": ["ROLE_USER"],
  "iat": 1792587600,
  "exp": 1792587900
}
```

Actual standard claims and scope representation may vary with the protocol request and Spring Authorization Server version. Roles come from the database-backed authenticated principal; only `ROLE_USER` and `ROLE_ADMIN` are copied to access tokens. The converter preserves OAuth scopes as `SCOPE_*` authorities.

## Persistence

Flyway migration `V1__authorization_schema.sql` creates the user, client, authorization, consent and user-role tables. Hibernate runs in `validate` mode. Registered client settings, authorization attributes, token values/metadata/claims and consent authorities are stored in JSON/text columns. The OAuth JSON mapper registers the Spring Security and Authorization Server Jackson modules, following the official JPA guide; it does not use Java native serialization or global polymorphic default typing. PostgreSQL data persists in the `authorization-postgres-data` volume across application restarts.

## Tests

```sh
./gradlew test
```

The integration test uses Testcontainers PostgreSQL 16 and verifies DB persistence/reconstruction, client PKCE settings, BCrypt authentication, API authorization outcomes, and metadata/JWK endpoints. Docker must be available to run it; `disabledWithoutDocker=true` skips the class when Docker is unavailable. Use the browser walkthrough to exercise the real authorization-code and PKCE exchange.

## OAuth flow

```mermaid
sequenceDiagram
    participant U as User / Browser
    participant SPA as Public SPA
    participant AS as Authorization Server
    participant DB as PostgreSQL
    participant API as Protected API
    SPA->>SPA: Generate verifier; derive S256 challenge
    SPA->>AS: /oauth2/authorize + challenge + state
    AS->>DB: Authenticate database user; persist authorization/consent
    AS-->>SPA: Redirect with authorization code + state
    SPA->>AS: /oauth2/token + code + verifier
    AS->>AS: Validate verifier and sign JWT with RSA key
    AS-->>SPA: Access token
    SPA->>API: Bearer JWT
    API->>API: Verify signature, issuer, expiry, scope and role
    API-->>SPA: Protected response
```

## Source layout

Packages follow feature boundaries so related persistence and service code stays together:

```text
src/main/java/kh/eco/istad/authorizationserver/
├── config/                 # authorization-server, web security, JWT, CORS and demo bootstrap
├── user/                   # database user entity, repository and UserDetailsService
├── client/                 # JPA registered-client repository and client persistence
├── authorization/          # authorization entity, repository and OAuth2AuthorizationService
├── consent/                # consent entity, repository and OAuth2AuthorizationConsentService
├── security/               # JWT role/scope authority conversion
├── resource/controller/    # protected API demonstration endpoints
└── common/persistence/     # safe Jackson modules shared by OAuth persistence services
```

`src/test/java/.../integration/` contains the PostgreSQL-backed integration test. Empty `dto`, `mapper`, `exception`, and administration packages are intentionally not present because this demo has no application APIs that need them yet.

## Refresh token and production notes

This public SPA does not receive refresh tokens by default. Keep access tokens short lived and require a new authorization when they expire. If long-lived sessions and refresh tokens are needed, use a Backend for Frontend (BFF) that can keep credentials server-side. The local demo also has an ephemeral signing key, a local DB password, no brute-force protection, and no production key rotation; replace these and add operational protections before deployment.
