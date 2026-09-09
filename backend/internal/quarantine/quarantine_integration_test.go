package quarantine

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/austinchima/kiterail/internal/dbtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func openIntegrationDB(t *testing.T) *sql.DB {
	t.Helper()
	return dbtest.Open(t)
}

func resetQuarantineTable(t *testing.T, sqlDB *sql.DB) {
	t.Helper()
	dbtest.Reset(t, sqlDB, "quarantine")
}

// TestIntegration_CreateAndRetrieve creates a quarantine entry via real PostgreSQL
// and verifies it can be retrieved.
func TestIntegration_CreateAndRetrieve(t *testing.T) {
	sqlDB := openIntegrationDB(t)
	store, err := New(sqlDB)
	require.NoError(t, err)
	resetQuarantineTable(t, sqlDB)

	id, err := store.Create(context.Background(), "agent_1", "tool_x", []byte(`{"data": "test"}`), nil)
	require.NoError(t, err)
	assert.NotEmpty(t, id)

	entry, err := store.Get(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, "agent_1", entry.AgentID)
	assert.Equal(t, "tool_x", entry.ToolName)
	assert.Equal(t, "pending", entry.Status)
	assert.NotNil(t, entry.Payload)
	assert.NotEmpty(t, string(entry.Payload))
}

// TestIntegration_ListByStatus lists quarantine entries by status via real PostgreSQL.
func TestIntegration_ListByStatus(t *testing.T) {
	sqlDB := openIntegrationDB(t)
	store, err := New(sqlDB)
	require.NoError(t, err)
	resetQuarantineTable(t, sqlDB)

	_, err = store.Create(context.Background(), "agent_2", "tool_y", []byte(`{"data": "test2"}`), nil)
	require.NoError(t, err)
	_, err = store.Create(context.Background(), "agent_3", "tool_z", []byte(`{"data": "test3"}`), nil)
	require.NoError(t, err)

	entries, err := store.List(context.Background(), "pending")
	require.NoError(t, err)
	require.Len(t, entries, 2)
	for _, entry := range entries {
		assert.Equal(t, "pending", entry.Status)
	}
}

// TestIntegration_ApproveAndDeny tests the approve and deny operations via real PostgreSQL.
func TestIntegration_ApproveAndDeny(t *testing.T) {
	sqlDB := openIntegrationDB(t)
	store, err := New(sqlDB)
	require.NoError(t, err)
	resetQuarantineTable(t, sqlDB)

	id, err := store.Create(context.Background(), "agent_1", "tool_x", []byte(`{"data": "test"}`), nil)
	require.NoError(t, err)

	err = store.Approve(context.Background(), id, "admin")
	require.NoError(t, err)

	entry, err := store.Get(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, "approved", entry.Status)
	assert.Equal(t, "admin", entry.ResolvedBy)
	assert.True(t, entry.ResolvedAt.Valid)

	id2, err := store.Create(context.Background(), "agent_2", "tool_y", []byte(`{"data": "test2"}`), nil)
	require.NoError(t, err)

	err = store.Deny(context.Background(), id2, "admin", "violation")
	require.NoError(t, err)

	entry2, err := store.Get(context.Background(), id2)
	require.NoError(t, err)
	assert.Equal(t, "denied", entry2.Status)
	assert.Equal(t, "admin", entry2.ResolvedBy)

	var reason string
	err = sqlDB.QueryRowContext(context.Background(), "SELECT reason FROM quarantine WHERE id = $1", id2).Scan(&reason)
	require.NoError(t, err)
	assert.Equal(t, "violation", reason)
}

// TestIntegration_ReplayExhaustionSurfacesReplayFailed drives the replay
// state machine end-to-end against real PostgreSQL — create → approve →
// claim → upstream failure — until attempts exhaust, and asserts the row
// lands in 'replay_failed' where a reviewer can see it.
//
// This is the regression net for the live bug where MarkReplayFailed's SQL
// guard required status='approved' while the worker held the entry in
// 'replaying': the UPDATE silently matched zero rows (:exec swallowed the
// no-op), so exhausted entries stayed 'replaying' forever and startup
// recovery re-approved them into an infinite retry loop. Every unit test
// missed it because the mock store's semantics diverged from the real SQL —
// a state machine must be integration-tested against the database that owns
// it.
func TestIntegration_ReplayExhaustionSurfacesReplayFailed(t *testing.T) {
	sqlDB := openIntegrationDB(t)
	store, err := New(sqlDB)
	require.NoError(t, err)
	resetQuarantineTable(t, sqlDB)

	var upstreamCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusInternalServerError) // poisoned upstream: every replay fails
	}))
	defer target.Close()

	ctx := context.Background()
	id, err := store.Create(ctx, "agent_1", "tool_x", []byte(`{"data":"poison"}`), nil)
	require.NoError(t, err)
	require.NoError(t, store.Approve(ctx, id, "reviewer-jane"))

	// Each drainOnce is one production tick (claim approved entries, replay
	// them) minus the timer. The real SQL increments attempts on release
	// (ReturnToApproved), not at claim, so exhaustion takes
	// defaultMaxReplayAttempts+1 rounds: attempts 0,1,2 fail and release; the
	// round that reads attempts==3 parks the entry as replay_failed.
	wk := NewWorker(store, nil, zap.NewNop(), target.URL)
	const exhaustDrains = defaultMaxReplayAttempts + 1
	for drain := 0; drain < exhaustDrains; drain++ {
		wk.drainOnce(ctx)
	}

	entry, err := store.Get(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, StatusReplayFailed, entry.Status,
		"exhausted replays must surface as replay_failed, not wedge in 'replaying'")
	assert.Equal(t, int32(exhaustDrains), upstreamCalls.Load(),
		"the worker must stop calling the poisoned upstream once attempts exhaust")

	// A replay_failed entry must not be re-claimed by the worker.
	wk.drainOnce(ctx)
	assert.Equal(t, int32(exhaustDrains), upstreamCalls.Load(),
		"replay_failed entries must not be retried")
}
