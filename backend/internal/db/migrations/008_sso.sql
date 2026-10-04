-- SSO sign-in for reviewers and admins. Both tables hold only what the
-- server needs: the login attempt carries the PKCE verifier and nonce for
-- one OIDC round trip; a session stores the SHA-256 of its cookie token,
-- never the token itself.
CREATE TABLE IF NOT EXISTS auth_login_attempts (
    state TEXT PRIMARY KEY,
    nonce TEXT NOT NULL,
    code_verifier TEXT NOT NULL,
    return_to TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id_hash TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    email TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions (expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_login_attempts_expires ON auth_login_attempts (expires_at);
