package notify

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/austinchima/elodea/internal/db"
	"github.com/austinchima/elodea/internal/dbtest"
)

// TestOutbox_Postgres runs the worker against the real outbox SQL: each held
// action is sent once per channel even with two replicas racing, a failure
// is retried only after its backoff, and resolved actions are not announced.
func TestOutbox_Postgres(t *testing.T) {
	sqlDB := dbtest.Open(t)
	dbtest.Reset(t, sqlDB, "quarantine")
	ctx := context.Background()
	q := db.New(sqlDB)

	create := func(tool string) uuid.UUID {
		id, err := q.CreateQuarantineEntry(ctx, db.CreateQuarantineEntryParams{
			AgentID: "treasury-agent", ToolName: tool, Payload: []byte(`{}`), CreatedAt: time.Now(),
			RequestHeaders: []byte(`{}`), PolicyRule: "wire_high_value", Explanation: "over limit",
		})
		require.NoError(t, err)
		return uuid.MustParse(id)
	}
	held := create("swift.wire.initiate")

	slack := &recordingChannel{name: "slack"}
	replicaA := NewWorker(q, []Channel{slack}, "", zap.NewNop())
	replicaB := NewWorker(q, []Channel{slack}, "", zap.NewNop())
	var wg sync.WaitGroup
	for _, w := range []*Worker{replicaA, replicaB, replicaA, replicaB} {
		wg.Add(1)
		go func(w *Worker) { defer wg.Done(); w.ProcessOnce(ctx) }(w)
	}
	wg.Wait()
	require.Len(t, slack.actions, 1, "two replicas racing still send exactly one notification")
	assert.Equal(t, held.String(), slack.actions[0].ID)

	// A failing channel is retried only after its backoff.
	failing := &recordingChannel{name: "webhook", err: assert.AnError}
	w := NewWorker(q, []Channel{failing}, "", zap.NewNop())
	w.ProcessOnce(ctx)
	w.ProcessOnce(ctx)
	assert.Len(t, failing.actions, 1)
	var lastError string
	var attempts int
	require.NoError(t, sqlDB.QueryRowContext(ctx,
		"SELECT last_error, attempts FROM notification_outbox WHERE quarantine_id = $1 AND channel = 'webhook'", held,
	).Scan(&lastError, &attempts))
	assert.Equal(t, assert.AnError.Error(), lastError)
	assert.Equal(t, 1, attempts)

	// An action reviewed before its turn is closed without a message.
	resolved := create("refund.issue")
	_, err := sqlDB.ExecContext(ctx, "UPDATE quarantine SET status = 'approved' WHERE id = $1", resolved)
	require.NoError(t, err)
	quiet := &recordingChannel{name: "teams"}
	NewWorker(q, []Channel{quiet}, "", zap.NewNop()).ProcessOnce(ctx)
	for _, a := range quiet.actions {
		assert.NotEqual(t, resolved.String(), a.ID)
	}
}
