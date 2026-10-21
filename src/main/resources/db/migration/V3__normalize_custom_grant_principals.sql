UPDATE oauth_authorization
SET attributes = jsonb_set(
        CASE
            WHEN attributes IS NULL OR btrim(attributes) = '' THEN '{}'::jsonb
            ELSE attributes::jsonb
        END,
        ARRAY['java.security.Principal'],
        to_jsonb(principal_name),
        TRUE
    )::text
WHERE authorization_grant_type = 'urn:ietf:params:oauth:grant-type:custom_code';
