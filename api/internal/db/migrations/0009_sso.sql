-- SSO users authenticate via Google (or future providers) and may not set a
-- password. Password becomes nullable: password auth only works when set.
ALTER TABLE users ALTER COLUMN password DROP NOT NULL;
ALTER TABLE users ADD COLUMN sso_provider text NOT NULL DEFAULT '';

CREATE TABLE oauth_states (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    state      text NOT NULL UNIQUE,
    provider   text NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_oauth_states_expires ON oauth_states (expires_at);