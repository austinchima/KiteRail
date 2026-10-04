package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/austinchima/kiterail/internal/quarantine"
	"github.com/austinchima/kiterail/internal/slackapp"
)

// TestE2E_SlackApprovalIsAuditedUnderTheReviewersEmail: a signed Slack button
// click approves a real held action through the same path as the console;
// the ledger names the Slack user's email and the worker replays it once.
func TestE2E_SlackApprovalIsAuditedUnderTheReviewersEmail(t *testing.T) {
	const secret = "slack-signing-secret-e2e-0123456789"
	slackAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "user": map[string]any{"profile": map[string]any{"email": "Priya.Raman@corp.test"}}})
	}))
	t.Cleanup(slackAPI.Close)

	env := newE2EEnvWith(t, func(d *httpDeps, _ *sql.DB) {
		d.slack = slackapp.New(slackapp.Config{
			BotToken: "xoxb-e2e", SigningSecret: secret, ChannelID: "C0REVIEW", TeamID: "T0ELODEA",
			Reviewers: []string{"priya.raman@corp.test"}, APIBase: slackAPI.URL,
		}, d.quarantine.(*quarantine.Handler), zap.NewNop())
	})

	status, respBody := env.post(t, "/", e2eAgentToken, toolsCallBody("11", "sensitive_tool"))
	require.Equal(t, http.StatusAccepted, status, respBody)
	var created struct {
		QuarantineID string `json:"quarantine_id"`
	}
	require.NoError(t, json.Unmarshal([]byte(respBody), &created))

	clickApprove := func(signWith string) int {
		payload, _ := json.Marshal(map[string]any{
			"type": "block_actions", "team": map[string]any{"id": "T0ELODEA"}, "user": map[string]any{"id": "U_PRIYA"},
			"actions": []map[string]any{{"action_id": "elodea_approve", "value": created.QuarantineID}},
		})
		body := "payload=" + url.QueryEscape(string(payload))
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		req, err := http.NewRequest(http.MethodPost, env.server.URL+"/integrations/slack/interactions", strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Slack-Request-Timestamp", ts)
		req.Header.Set("X-Slack-Signature", slackapp.Sign(signWith, ts, []byte(body)))
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	require.Equal(t, http.StatusUnauthorized, clickApprove("not-the-secret"), "a forged click is refused")
	require.Equal(t, "pending", env.quarantineStatus(t, created.QuarantineID))

	require.Equal(t, http.StatusOK, clickApprove(secret))
	require.Equal(t, "approved", env.quarantineStatus(t, created.QuarantineID))

	env.worker.ProcessOnce(context.Background())
	require.Equal(t, "replayed", env.quarantineStatus(t, created.QuarantineID))
	require.Equal(t, 1, env.upstreamCount(), "approved once, executed once")

	var approvedBy string
	for _, entry := range env.ledgerEntries(t) {
		if entry.Decision == "approved" {
			approvedBy = entry.Agent
		}
	}
	require.Equal(t, "priya.raman@corp.test", approvedBy)
	require.True(t, env.ledgerValid(t))
}
