# Spring Authorization Server with PostgreSQL

A Servlet-based OAuth 2.0 and OpenID Connect authorization server for an educational project. Spring Authorization Server owns protocol endpoints; Spring Security handles login, sessions, and resource-server authorization; PostgreSQL/JPA persists users and OAuth state; Flyway manages the schema. A same-origin SPA demonstrates Authorization Code with PKCE, and example APIs demonstrate scope and role checks.

## Compatibility

The build uses Spring Boot **3.5.16** and its managed Spring Security/Spring Authorization Server dependencies, Java **24**, Gradle wrapper **8.14.3**, PostgreSQL **17** for local Compose, and PostgreSQL **16** in Testcontainers. This aligns with [Spring Boot 3.5's supported build tools](https://docs.spring.io/spring-boot/3.5/gradle-plugin/index.html) and [Gradle's Java compatibility table](https://docs.gradle.org/8.14.3/userguide/compatibility.html). No Spring Security versions are overridden independently.

## Start locally

Requirements: JDK 24, Docker Compose, and a browser. Docker is used for PostgreSQL and the integration tests. The compose file starts PostgreSQL; Spring Boot runs on the host and serves the demo SPA itself.

```sh
cp .env.example .env
docker compose up -d postgres
set -a
. ./.env
set +a
./gradlew bootRun
```

On Windows, copy `.env.example` to `.env`, set the same variables in the terminal or IDE run configuration, then run `docker compose up -d postgres` and `gradlew.bat bootRun`. Docker Compose reads `.env` automatically; Spring Boot reads the exported process environment.

| Environment variable | Purpose | Local default |
| --- | --- | --- |
| `DB_URL`, `DB_USER`, `DB_PASSWORD` | PostgreSQL connection | local Compose database |
| `OAUTH_ISSUER` | Trusted issuer origin | `http://127.0.0.1:9000` |
| `SPA_ORIGIN`, `SPA_REDIRECT_URI` | Exact SPA CORS origin and callback | loopback origin and `/` |
| `OAUTH_SIGNING_KEY_DIR` | Persistent root and tenant RSA keys | `.local-keys` |
| `API_AUDIENCE` | Required audience for protected API JWTs | `api://authorization-server` |
| `ACCESS_TOKEN_TTL_SECONDS`, `REFRESH_TOKEN_TTL_SECONDS` | Built-in client token lifetimes | `300`, `86400` |
| `BOOTSTRAP_USER_ENABLED`, `BOOTSTRAP_USER`, `BOOTSTRAP_PASSWORD` | Local demo user bootstrap | `true`, `demo`, `demo12345` |
| `CUSTOM_GRANT_CODE` | Local extension-grant fixture | `local-demo-code` |
| `CUSTOM_GRANT_CLIENT_SECRET`, `CLIENT_REGISTRAR_SECRET`, `TENANT_B_CLIENT_SECRET`, `TENANT_B_REGISTRAR_SECRET` | Demo confidential-client credentials | local values documented below |

The server listens on `http://127.0.0.1:9000`; its root page is the embedded PKCE SPA. The standard Spring Security form login is at `/login`, with CSRF protection and a generic failure message. Local demo credentials are username `demo` and password `demo12345`. The bootstrap password is BCrypt-encoded in PostgreSQL. On startup, the local bootstrap user is synchronized to `BOOTSTRAP_PASSWORD`; set `BOOTSTRAP_USER_ENABLED=false` and replace all local defaults outside a local demo. The default database credentials are development-only. Configuration is in `application.yaml` and `.env.example`; compose reads `.env`, while Spring Boot reads exported environment variables.

On first start, persistent RSA keys are created under `.local-keys/default/` and `.local-keys/tenant-b/`. The private files are owner-readable/writable and `.local-keys/` is git-ignored. Do not commit or share these files. Set `OAUTH_SIGNING_KEY_DIR` to a protected persistent directory for other environments. The active signing key remains stable across restarts; retained public keys support a rotation window.

## Components

| Component | Responsibility |
| --- | --- |
| Spring Authorization Server | Authorization, token, metadata, JWKS, UserInfo, revocation, and dynamic registration endpoints |
| Spring Security | BCrypt form login, session logout, endpoint authorization, JWT resource-server authentication |
| Spring MVC | Public registration endpoint and sample protected APIs |
| Spring Data JPA + PostgreSQL | Users, registered clients, authorizations/tokens, and consent |
| Flyway | Versioned schema changes, including tenant-scoped OAuth rows |
| Embedded SPA | Browser demonstration of state and S256 PKCE validation |

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
| Public user registration | `POST http://127.0.0.1:9000/api/auth/register` |
| Current authenticated user | `GET http://127.0.0.1:9000/api/users/me` |
| Scope-protected products | `GET http://127.0.0.1:9000/api/products` |
| Role-protected admin API | `GET http://127.0.0.1:9000/api/admin` |
| Public API | `GET http://127.0.0.1:9000/api/public/hello` |
| Authenticated API | `GET http://127.0.0.1:9000/api/private/hello` |
| Scope restricted (`api.read`) | `GET http://127.0.0.1:9000/api/scoped/hello` |
| Role restricted (`ROLE_ADMIN`) | `GET http://127.0.0.1:9000/api/admin` |
| Custom grant token | `POST http://127.0.0.1:9000/oauth2/token` |

The registered SPA has client ID `authorization-spa`, authentication method `none`, authorization-code grant, scopes `openid profile api.read`, user consent enabled, and PKCE required. There is no client secret. The default exact redirect URIs are `http://127.0.0.1:9000/` and `http://localhost:9000/`; configure a single intended URI through `SPA_REDIRECT_URI` for a deployment. The SPA uses the same origin for authorization and callback. Keep the same hostname before and after login because browser session storage is origin-specific. CORS allows only `SPA_ORIGIN`, without credentials. The API chain is stateless bearer-token auth and disables CSRF only for `/api/**`; browser form login keeps CSRF enabled.

| Built-in client | Grant | Scope | Refresh token |
| --- | --- | --- | --- |
| `authorization-spa` | Authorization Code + PKCE | `openid profile api.read` | No |
| `custom-grant-client` | `custom_code`, refresh | `message.read message.write` | Yes, rotating |
| `client-registrar` | Client Credentials | `client.create client.read` | No |
| `tenant-b-client` | Client Credentials | `tenant.read` | No |
| Tenant B registrar | Client Credentials | `client.create client.read` | No |

## User registration and login

Public registration accepts only a username and password; callers cannot choose roles. New accounts always receive `ROLE_USER`. Username validation is 3–100 characters using letters, digits, dot, underscore, or hyphen. Passwords must be at least 8 characters and fit BCrypt's 72-byte input limit. Duplicate usernames return HTTP 409; invalid requests return HTTP 400. The response contains only the username.

```sh
curl -i http://127.0.0.1:9000/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"student1","password":"a-long-demo-password"}'
```

Then sign in through the normal `/login` form using the new credentials. Postman can use `POST /api/auth/register` with the same JSON, then test the browser Authorization Code flow in a browser. Public registration never creates an administrator; assign roles through trusted database/admin operations only.

## Multitenancy

The server accepts two allowlisted issuers: the root issuer and `http://127.0.0.1:9000/tenant-b`. The issuer path selects tenant-specific clients, authorization/token rows, consent, and signing keys. Both tenants persist OAuth state in PostgreSQL with a tenant ID; application users are shared. Flyway V2 adds tenant columns and scopes client, token, and consent constraints without dropping existing root data. `OAUTH_ISSUER` sets the trusted base origin; use a consistent host (loopback aliases `localhost` and `127.0.0.1` are accepted).

Tenant B's authorization-server metadata is available at `http://127.0.0.1:9000/tenant-b/.well-known/openid-configuration`. It registers a separate client `tenant-b-client` with local secret `tenant-b-secret` and scope `tenant.read`. To request a tenant B token in Postman, send `POST http://127.0.0.1:9000/tenant-b/oauth2/token`, use **Basic Auth** with that client and secret, and set **Body → x-www-form-urlencoded** to `grant_type=client_credentials` and `scope=tenant.read`. The resulting JWT has issuer `http://127.0.0.1:9000/tenant-b` and is signed with tenant B's key. `tenant-b-client` is not registered at the root issuer; conversely, root-tenant clients are not registered under `/tenant-b`.

## Dynamic client registration

OpenID Connect Dynamic Client Registration is enabled at `/connect/register` for each issuer. A registrar first obtains a short-lived access token with only `client.create`; client-credentials tokens do not have refresh tokens. Local credentials are `client-registrar` / `client-registrar-secret`; Tenant B uses `tenant-b-client-registrar` / `tenant-b-registrar-secret`. Registration accepts authorization-code clients using `client_secret_basic`, safe registered redirect URIs, and only `openid`, `profile`, and `api.read`. Registered clients require PKCE and user consent and do not receive a refresh grant. Import `postman/dynamic-client-registration.postman_collection.json` to obtain a registrar token, register a client, and retrieve its metadata. Both tenants' registrations persist in PostgreSQL.

## Extension grant type

The token endpoint also demonstrates a custom extension grant using `urn:ietf:params:oauth:grant-type:custom_code`. The server registers confidential client `custom-grant-client` with local demo secret `custom-grant-secret`. Its grant code is configured by `CUSTOM_GRANT_CODE` (default `local-demo-code`) and checked with a constant-time comparison. Set a unique value outside local development. This fixed-code example is for learning only; a production grant should validate a short-lived, single-use code against its issuing system and avoid sharing one code across clients.

In Postman, create a POST request to `http://127.0.0.1:9000/oauth2/token`, choose **Authorization → Basic Auth** with username `custom-grant-client` and password `custom-grant-secret`, then set **Body → x-www-form-urlencoded**:

| Key | Value |
| --- | --- |
| `grant_type` | `urn:ietf:params:oauth:grant-type:custom_code` |
| `code` | `local-demo-code` (or your `CUSTOM_GRANT_CODE`) |
| `scope` | `message.read message.write` (optional; defaults to both client scopes) |

The response contains a bearer access token and refresh token. This confidential demo client explicitly supports refresh tokens; refresh tokens rotate on use and the previous token becomes invalid. To refresh, POST `grant_type=refresh_token` and the returned `refresh_token` to the same endpoint with the same Basic Auth credentials. The fixed custom code is reusable in this teaching sample; it is not suitable for production. A production extension grant must validate a short-lived, single-use code against its issuing system. Client-credentials tokens for the registrar and tenant demo client do not have refresh tokens.

## Browser PKCE walkthrough

Open `http://127.0.0.1:9000/` and click **Login with Authorization Server**. The SPA creates a random `code_verifier`, computes `BASE64URL(SHA256(code_verifier))`, and sends the challenge with `code_challenge_method=S256` to `/oauth2/authorize`. Log in with `demo` / `demo12345` (or the value configured in `BOOTSTRAP_PASSWORD`), approve requested consent, and the server redirects back with a short-lived authorization `code` and the original `state`. The SPA checks `state`, then posts `grant_type=authorization_code`, `client_id`, exact `redirect_uri`, `code`, and the original `code_verifier` to `/oauth2/token`. It holds the access token in memory and calls the API.

To verify PKCE rejection, select **Send an invalid verifier (PKCE negative test)** before sign-in. Authorization is still requested with the real challenge, but the token exchange deliberately sends a modified verifier. The token endpoint should return HTTP 400 with `invalid_grant`; no API token is issued. Clear the browser session and repeat with the checkbox off for a successful exchange.

Spring Authorization Server's standard consent screen is shown when the user has not already consented. The consent state and selected scopes are stored per tenant in PostgreSQL. Existing consent can be removed from `oauth_authorization_consent` to demonstrate the prompt again.

### Postman API checks

After completing the browser PKCE flow, use its access token as **Authorization → Bearer Token** in Postman:

| Request | Expected result |
| --- | --- |
| `GET /api/users/me` | `200`, authenticated username and authorities |
| `GET /api/products` | `200` with `api.read`; `403` without it |
| `GET /api/admin` | `403` for `ROLE_USER`; requires `ROLE_ADMIN` |
| `GET /api/private/hello` without a token | `401` |
| `GET /api/private/hello` with a malformed/expired token | `401` |

Example request header: `Authorization: Bearer <access_token>`. The access token is a JWT for the API audience `api://authorization-server`; an OIDC ID token is for the client and must not be sent as an API bearer token.

### OIDC endpoints and lifetimes

Discovery is at `/.well-known/openid-configuration`; JWKS is at `/oauth2/jwks`; UserInfo is at `/userinfo` and returns `sub`, plus `preferred_username` when the access token includes `profile`. OIDC ID tokens are signed JWTs with the client as audience, the configured issuer, and an expiration. Built-in clients use five-minute access tokens and five-minute authorization codes. Only the confidential custom-grant client has refresh-token grant enabled; its refresh lifetime is one day and refresh tokens rotate. The public SPA and client-credentials clients do not receive refresh tokens.

## Signing keys and rotation

Local startup creates 2048-bit RSA pairs as PKCS#8 private PEM and X.509 public PEM:

```text
.local-keys/default/active-private.pem
.local-keys/default/active-public.pem
.local-keys/tenant-b/active-private.pem
.local-keys/tenant-b/active-public.pem
```

Back up the directory securely; losing an active private key prevents token issuance with that key. For production, mount a protected persistent directory and set `OAUTH_SIGNING_KEY_DIR`. For multiple instances, provision the same active keys and retained public keys to every instance. Private files are restricted to the owner on POSIX filesystems; use equivalent secret-store permissions elsewhere.

To rotate a tenant key, stop the server, move the old `active-public.pem` to `previous-<kid>.pem` (use the old key ID shown by the tenant's JWKS), archive the old private key securely, then remove the two active filenames and restart. Startup creates a new active pair. The old public key remains in JWKS and is accepted for validation while its `previous-<kid>.pem` file remains. After the maximum lifetime of tokens signed by the old key and the relevant client cache window, remove that previous public key and restart. Perform this separately for `default` and `tenant-b`.

To check API failures and success independently:

```sh
curl -i http://127.0.0.1:9000/api/public/hello
curl -i http://127.0.0.1:9000/api/private/hello
curl -i -H 'Authorization: Bearer not-a-jwt' http://127.0.0.1:9000/api/private/hello
curl -i -H "Authorization: Bearer $ACCESS_TOKEN" http://127.0.0.1:9000/api/private/hello
curl -i -H "Authorization: Bearer $ACCESS_TOKEN" http://127.0.0.1:9000/api/users/me
curl -i -H "Authorization: Bearer $ACCESS_TOKEN" http://127.0.0.1:9000/api/products
```

Expected results are public `200`, missing or invalid bearer token `401`, valid user token `200`, and regular user accessing the admin endpoint `403`. A user token with scope `api.read` receives `200` from `/api/scoped/hello`.

An example decoded access token payload (dummy values):

```json
{
  "iss": "http://127.0.0.1:9000",
  "sub": "demo",
  "aud": ["api://authorization-server"],
  "scope": ["openid", "profile", "api.read"],
  "roles": ["ROLE_USER"],
  "iat": 1792587600,
  "exp": 1792587900
}
```

Roles come from the database-backed authenticated principal; only `ROLE_USER` and `ROLE_ADMIN` are copied to access tokens. The API converter preserves OAuth scopes as `SCOPE_*` authorities. JWT validation checks signature, expiration, issuer origin/path, and API audience.

## Persistence

Flyway V1 creates user, client, authorization, consent and user-role tables. V2 adds tenant IDs, tenant-scoped uniqueness/foreign keys, and lookup indexes while retaining existing root-tenant rows. V3 normalizes older custom-grant principal attributes so refresh-token authorization rows do not need to deserialize a client-authentication object. Hibernate runs in `validate` mode. Client settings, authorization attributes, token values/metadata/claims and consent authorities are persisted through the project JPA repositories and Spring Security/Authorization Server Jackson modules; Java native serialization is not used. PostgreSQL data persists in the `authorization-postgres-data` volume across restarts.

## Tests

```sh
./gradlew test
```

Run the full suite with Docker available:

```sh
./gradlew clean test
```

The Testcontainers integration suite uses PostgreSQL 16 and covers user registration/BCrypt/login/logout, registered-client and tenant persistence, consent and authorization reconstruction, dynamic registration, Authorization Code with S256 PKCE and an actual consent approval, invalid redirect/verifier/missing challenge, expired and replayed authorization codes, OIDC ID token/UserInfo, real access-token API authorization, JWT validation failures, refresh rotation/replay/revocation/expiry, the absence of refresh tokens for clients without that grant, and metadata/JWKS. `disabledWithoutDocker=true` skips that integration class when Docker is unavailable. `PersistentRsaKeyStoreTest` is a unit test and verifies restart persistence, owner-only permissions, and retained-public-key rotation behavior. A successful `javac` compile is not a substitute for running the Gradle test task.

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

`src/test/java/.../integration/` contains PostgreSQL-backed protocol and persistence tests; `src/test/java/.../config/` contains signing-key tests.

## Refresh token and production notes

The SPA uses five-minute access tokens and no refresh grant; users authorize again after expiry. For long-lived browser sessions, use a Backend for Frontend (BFF) and keep refresh tokens server-side. The custom grant's fixed demo code and hardcoded local client credentials are teaching fixtures. Production deployment also needs TLS, strong secret configuration, login throttling/brute-force protection, monitoring, backups, and an operational key-rotation procedure.

## Verification status in this workspace

The Gradle wrapper starts with a writable temporary Gradle home, but `./gradlew clean test` cannot initialize Gradle's file-lock service because this sandbox denies network-interface/socket access. The system Gradle command also failed during native startup. Docker access is denied, and a local PostgreSQL instance could not bind either TCP or a Unix socket, so neither Testcontainers nor direct database migration tests could run. JDK 24 is not installed here; main and test sources compiled with `javac --release 24` using the installed JDK 25 and cached dependencies, and the isolated RSA key-store JUnit test ran successfully (1 test). Run `./gradlew clean test` with JDK 24 and Docker available before treating the integration suite and Flyway migrations as verified.
