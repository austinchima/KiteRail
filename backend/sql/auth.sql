-- name: CreateLoginAttempt :exec
INSERT INTO auth_login_attempts (state, nonce, code_verifier, return_to, expires_at)
VALUES ($1, $2, $3, $4, $5);

-- name: ConsumeLoginAttempt :one
-- Single use: the row is deleted as it is read, so a replayed callback finds
-- nothing. Expired rows never match.
DELETE FROM auth_login_attempts
WHERE state = $1 AND expires_at > NOW()
RETURNING nonce, code_verifier, return_to;

-- name: DeleteExpiredLoginAttempts :exec
DELETE FROM auth_login_attempts WHERE expires_at <= NOW();

-- name: CreateSession :exec
INSERT INTO sessions (id_hash, subject, email, role, expires_at)
VALUES ($1, $2, $3, $4, $5);

-- name: GetActiveSession :one
-- Active means not revoked, before its absolute expiry, and seen within the
-- idle window ($2 is the idle cutoff).
SELECT id_hash, subject, email, role, created_at, expires_at, last_seen_at
FROM sessions
WHERE id_hash = $1 AND revoked_at IS NULL AND expires_at > NOW() AND last_seen_at > $2;

-- name: TouchSession :exec
UPDATE sessions SET last_seen_at = NOW()
WHERE id_hash = $1 AND revoked_at IS NULL;

-- name: RevokeSession :exec
UPDATE sessions SET revoked_at = NOW()
WHERE id_hash = $1 AND revoked_at IS NULL;

-- name: DeleteExpiredSessions :exec
DELETE FROM sessions WHERE expires_at <= NOW() - INTERVAL '30 days';
