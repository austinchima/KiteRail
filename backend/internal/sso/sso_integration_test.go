package sso

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/austinchima/elodea/internal/db"
	"github.com/austinchima/elodea/internal/dbtest"
)

// TestSessionQueries_Postgres checks the SQL behind the in-memory store used
// by the unit tests: single-use login attempts, expiry, idle cutoff, revoke.
func TestSessionQueries_Postgres(t *testing.T) {
	sqlDB := dbtest.Open(t)
	ctx := context.Background()
	_, err := sqlDB.ExecContext(ctx, "DELETE FROM sessions; DELETE FROM auth_login_attempts")
	require.NoError(t, err)
	q := db.New(sqlDB)

	require.NoError(t, q.CreateLoginAttempt(ctx, db.CreateLoginAttemptParams{
		State: "s1", Nonce: "n1", CodeVerifier: "v1", ReturnTo: "http://console.test/", ExpiresAt: time.Now().Add(time.Minute),
	}))
	require.NoError(t, q.CreateLoginAttempt(ctx, db.CreateLoginAttemptParams{
		State: "old", Nonce: "n", CodeVerifier: "v", ReturnTo: "http://console.test/", ExpiresAt: time.Now().Add(-time.Minute),
	}))
	got, err := q.ConsumeLoginAttempt(ctx, "s1")
	require.NoError(t, err)
	assert.Equal(t, "n1", got.Nonce)
	_, err = q.ConsumeLoginAttempt(ctx, "s1")
	assert.ErrorIs(t, err, sql.ErrNoRows, "login attempts are single use")
	_, err = q.ConsumeLoginAttempt(ctx, "old")
	assert.ErrorIs(t, err, sql.ErrNoRows, "expired attempts never match")

	require.NoError(t, q.CreateSession(ctx, db.CreateSessionParams{
		IDHash: "h1", Subject: "sub", Email: "a@corp.test", Role: "reviewer", ExpiresAt: time.Now().Add(time.Hour),
	}))
	row, err := q.GetActiveSession(ctx, db.GetActiveSessionParams{IDHash: "h1", LastSeenAt: time.Now().Add(-time.Hour)})
	require.NoError(t, err)
	assert.Equal(t, "a@corp.test", row.Email)

	_, err = q.GetActiveSession(ctx, db.GetActiveSessionParams{IDHash: "h1", LastSeenAt: time.Now().Add(time.Minute)})
	assert.ErrorIs(t, err, sql.ErrNoRows, "a session idle past the cutoff is not active")

	require.NoError(t, q.TouchSession(ctx, "h1"))
	require.NoError(t, q.RevokeSession(ctx, "h1"))
	_, err = q.GetActiveSession(ctx, db.GetActiveSessionParams{IDHash: "h1", LastSeenAt: time.Now().Add(-time.Hour)})
	assert.ErrorIs(t, err, sql.ErrNoRows, "revoked sessions are not active")

	require.NoError(t, q.CreateSession(ctx, db.CreateSessionParams{
		IDHash: "h2", Subject: "sub", Email: "a@corp.test", Role: "reviewer", ExpiresAt: time.Now().Add(-time.Second),
	}))
	_, err = q.GetActiveSession(ctx, db.GetActiveSessionParams{IDHash: "h2", LastSeenAt: time.Now().Add(-time.Hour)})
	assert.ErrorIs(t, err, sql.ErrNoRows, "expired sessions are not active")
	require.NoError(t, q.DeleteExpiredLoginAttempts(ctx))
	require.NoError(t, q.DeleteExpiredSessions(ctx))
}
