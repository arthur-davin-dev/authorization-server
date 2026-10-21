CREATE TABLE app_user (
    id UUID PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(100) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE app_user_role (
    user_id UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL,
    PRIMARY KEY (user_id, role)
);

CREATE TABLE oauth_client (
    id VARCHAR(100) PRIMARY KEY,
    client_id VARCHAR(200) NOT NULL UNIQUE,
    client_id_issued_at TIMESTAMP WITH TIME ZONE NOT NULL,
    client_secret TEXT,
    client_secret_expires_at TIMESTAMP WITH TIME ZONE,
    client_name VARCHAR(200) NOT NULL,
    client_authentication_methods TEXT NOT NULL,
    authorization_grant_types TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,
    post_logout_redirect_uris TEXT,
    scopes TEXT NOT NULL,
    client_settings TEXT NOT NULL,
    token_settings TEXT NOT NULL
);

CREATE TABLE oauth_authorization (
    id VARCHAR(100) PRIMARY KEY,
    registered_client_id VARCHAR(100) NOT NULL REFERENCES oauth_client(id),
    principal_name VARCHAR(200) NOT NULL,
    authorization_grant_type VARCHAR(100) NOT NULL,
    authorized_scopes TEXT,
    attributes TEXT,
    state TEXT,
    authorization_code_value TEXT,
    authorization_code_issued_at TIMESTAMP WITH TIME ZONE,
    authorization_code_expires_at TIMESTAMP WITH TIME ZONE,
    authorization_code_metadata TEXT,
    access_token_value TEXT,
    access_token_issued_at TIMESTAMP WITH TIME ZONE,
    access_token_expires_at TIMESTAMP WITH TIME ZONE,
    access_token_metadata TEXT,
    access_token_type VARCHAR(50),
    access_token_scopes TEXT,
    refresh_token_value TEXT,
    refresh_token_issued_at TIMESTAMP WITH TIME ZONE,
    refresh_token_expires_at TIMESTAMP WITH TIME ZONE,
    refresh_token_metadata TEXT,
    oidc_id_token_value TEXT,
    oidc_id_token_issued_at TIMESTAMP WITH TIME ZONE,
    oidc_id_token_expires_at TIMESTAMP WITH TIME ZONE,
    oidc_id_token_metadata TEXT,
    oidc_id_token_claims TEXT,
    user_code_value TEXT,
    user_code_issued_at TIMESTAMP WITH TIME ZONE,
    user_code_expires_at TIMESTAMP WITH TIME ZONE,
    user_code_metadata TEXT,
    device_code_value TEXT,
    device_code_issued_at TIMESTAMP WITH TIME ZONE,
    device_code_expires_at TIMESTAMP WITH TIME ZONE,
    device_code_metadata TEXT
);

CREATE INDEX ix_oauth_authorization_state ON oauth_authorization (state);
CREATE INDEX ix_oauth_authorization_code ON oauth_authorization (authorization_code_value);
CREATE INDEX ix_oauth_authorization_access_token ON oauth_authorization (access_token_value);
CREATE INDEX ix_oauth_authorization_refresh_token ON oauth_authorization (refresh_token_value);
CREATE INDEX ix_oauth_authorization_id_token ON oauth_authorization (oidc_id_token_value);
CREATE INDEX ix_oauth_authorization_user_code ON oauth_authorization (user_code_value);
CREATE INDEX ix_oauth_authorization_device_code ON oauth_authorization (device_code_value);

CREATE TABLE oauth_authorization_consent (
    registered_client_id VARCHAR(100) NOT NULL REFERENCES oauth_client(id),
    principal_name VARCHAR(200) NOT NULL,
    authorities TEXT NOT NULL,
    PRIMARY KEY (registered_client_id, principal_name)
);
