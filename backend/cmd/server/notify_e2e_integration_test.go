package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/austinchima/elodea/internal/db"
	"github.com/austinchima/elodea/internal/notify"
)

// TestE2E_HeldActionNotifiesReviewersWithASignedWebhook: an agent call held
// by policy produces exactly one signed webhook event that names the action
// and links to review, without the tool arguments.
func TestE2E_HeldActionNotifiesReviewersWithASignedWebhook(t *testing.T) {
	const secret = "whsec_e2e_0123456789abcdef0123"
	var mu sync.Mutex
	var bodies [][]byte
	var signatures, timestamps []string
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, body)
		signatures = append(signatures, r.Header.Get("X-Elodea-Signature"))
		timestamps = append(timestamps, r.Header.Get("X-Elodea-Timestamp"))
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(receiver.Close)

	var sqlDB *sql.DB
	env := newE2EEnvWith(t, func(_ *httpDeps, conn *sql.DB) { sqlDB = conn })
	status, respBody := env.post(t, "/", e2eAgentToken, toolsCallBody("9", "sensitive_tool"))
	require.Equal(t, http.StatusAccepted, status, respBody)
	var created struct {
		QuarantineID string `json:"quarantine_id"`
	}
	require.NoError(t, json.Unmarshal([]byte(respBody), &created))

	worker := notify.NewWorker(db.New(sqlDB), []notify.Channel{notify.NewWebhook(receiver.URL, secret)}, "https://console.corp.test", zap.NewNop())
	worker.ProcessOnce(context.Background())
	worker.ProcessOnce(context.Background())

	require.Len(t, bodies, 1, "one held action, one event")
	require.Equal(t, notify.Sign([]byte(secret), timestamps[0], bodies[0]), signatures[0], "the receiver can verify the event came from Elodea")
	var event struct {
		Type   string            `json:"type"`
		Action notify.HeldAction `json:"action"`
	}
	require.NoError(t, json.Unmarshal(bodies[0], &event))
	require.Equal(t, notify.EventHeld, event.Type)
	require.Equal(t, created.QuarantineID, event.Action.ID)
	require.Equal(t, "agent-alpha", event.Action.Agent)
	require.Equal(t, "sensitive_tool", event.Action.Tool)
	require.Equal(t, "https://console.corp.test/#inbox", event.Action.ReviewURL)
	require.NotContains(t, string(bodies[0]), "arguments", "tool arguments never leave Elodea in a notification")
}
