package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/austinchima/kiterail/internal/auth"
	"github.com/austinchima/kiterail/internal/config"
	"github.com/austinchima/kiterail/internal/db"
	"github.com/austinchima/kiterail/internal/sso"
)

// TestE2E_SSOReviewerApprovalIsAttributedToTheirEmail drives a held action
// through approval with an SSO session (cookie + CSRF header) against the
// real database, and checks the ledger names the signed-in person.
func TestE2E_SSOReviewerApprovalIsAttributedToTheirEmail(t *testing.T) {
	const sessionToken = "e2e-session-token-0123456789abcdef"
	env := newE2EEnvWith(t, func(d *httpDeps, sqlDB *sql.DB) {
		dbtestResetSessions(t, sqlDB)
		queries := db.New(sqlDB)
		sum := sha256.Sum256([]byte(sessionToken))
		require.NoError(t, queries.CreateSession(context.Background(), db.CreateSessionParams{
			IDHash: hex.EncodeToString(sum[:]), Subject: "user-123", Email: "priya.raman@corp.test",
			Role: string(auth.RoleReviewer), ExpiresAt: time.Now().Add(time.Hour),
		}))
		d.sso = sso.New(config.OIDCConfig{
			Issuer: "http://idp.test", RedirectURL: "http://api.test/auth/callback",
			SessionTTL: 8 * time.Hour, SessionIdleTTL: time.Hour,
		}, []string{"http://console.test"}, queries, zap.NewNop())
	})

	status, respBody := env.post(t, "/", e2eAgentToken, toolsCallBody("7", "sensitive_tool"))
	require.Equal(t, http.StatusAccepted, status, respBody)
	var created struct {
		QuarantineID string `json:"quarantine_id"`
	}
	require.NoError(t, json.Unmarshal([]byte(respBody), &created))

	approve := func(withCSRF bool) int {
		req, err := http.NewRequest(http.MethodPost, env.server.URL+"/api/v1/quarantine/"+created.QuarantineID+"/approve", strings.NewReader("{}"))
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "elodea_session", Value: sessionToken})
		if withCSRF {
			req.Header.Set(auth.CSRFHeader, auth.CSRFHeaderValue)
		}
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	require.Equal(t, http.StatusForbidden, approve(false), "a session alone cannot approve without the CSRF header")
	require.Equal(t, "pending", env.quarantineStatus(t, created.QuarantineID))
	require.Equal(t, http.StatusOK, approve(true))

	env.worker.ProcessOnce(context.Background())
	require.Equal(t, "replayed", env.quarantineStatus(t, created.QuarantineID))

	var approvedBy, replayedBy string
	for _, entry := range env.ledgerEntries(t) {
		switch entry.Decision {
		case "approved":
			approvedBy = entry.Agent
		case "approved_replayed":
			replayedBy = entry.Agent
		}
	}
	require.Equal(t, "priya.raman@corp.test", approvedBy, "the approval names the signed-in person")
	require.Equal(t, "priya.raman@corp.test", replayedBy)
	require.True(t, env.ledgerValid(t))
}

func dbtestResetSessions(t *testing.T, sqlDB *sql.DB) {
	t.Helper()
	_, err := sqlDB.ExecContext(context.Background(), "DELETE FROM sessions")
	require.NoError(t, err)
}
