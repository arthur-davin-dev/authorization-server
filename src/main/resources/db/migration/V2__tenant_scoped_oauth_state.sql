ALTER TABLE oauth_client
    ADD COLUMN tenant_id VARCHAR(64) NOT NULL DEFAULT 'default';

ALTER TABLE oauth_client
    DROP CONSTRAINT IF EXISTS oauth_client_client_id_key;

CREATE UNIQUE INDEX ux_oauth_client_tenant_client_id
    ON oauth_client (tenant_id, client_id);
CREATE UNIQUE INDEX ux_oauth_client_tenant_id
    ON oauth_client (tenant_id, id);

ALTER TABLE oauth_authorization
    ADD COLUMN tenant_id VARCHAR(64) NOT NULL DEFAULT 'default';

CREATE INDEX ix_oauth_authorization_tenant_state
    ON oauth_authorization (tenant_id, state);
CREATE UNIQUE INDEX ux_oauth_authorization_tenant_code
    ON oauth_authorization (tenant_id, authorization_code_value);
CREATE UNIQUE INDEX ux_oauth_authorization_tenant_access_token
    ON oauth_authorization (tenant_id, access_token_value);
CREATE UNIQUE INDEX ux_oauth_authorization_tenant_refresh_token
    ON oauth_authorization (tenant_id, refresh_token_value);
CREATE UNIQUE INDEX ux_oauth_authorization_tenant_id_token
    ON oauth_authorization (tenant_id, oidc_id_token_value);
CREATE UNIQUE INDEX ux_oauth_authorization_tenant_user_code
    ON oauth_authorization (tenant_id, user_code_value);
CREATE UNIQUE INDEX ux_oauth_authorization_tenant_device_code
    ON oauth_authorization (tenant_id, device_code_value);

ALTER TABLE oauth_authorization
    DROP CONSTRAINT oauth_authorization_registered_client_id_fkey;
ALTER TABLE oauth_authorization
    ADD CONSTRAINT fk_oauth_authorization_tenant_client
        FOREIGN KEY (tenant_id, registered_client_id) REFERENCES oauth_client (tenant_id, id);

ALTER TABLE oauth_authorization_consent
    ADD COLUMN tenant_id VARCHAR(64) NOT NULL DEFAULT 'default';

ALTER TABLE oauth_authorization_consent
    DROP CONSTRAINT oauth_authorization_consent_pkey;
ALTER TABLE oauth_authorization_consent
    DROP CONSTRAINT oauth_authorization_consent_registered_client_id_fkey;

ALTER TABLE oauth_authorization_consent
    ADD CONSTRAINT pk_oauth_authorization_consent
        PRIMARY KEY (tenant_id, registered_client_id, principal_name);
ALTER TABLE oauth_authorization_consent
    ADD CONSTRAINT fk_oauth_consent_tenant_client
        FOREIGN KEY (tenant_id, registered_client_id) REFERENCES oauth_client (tenant_id, id);
