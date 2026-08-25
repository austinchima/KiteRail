package quarantine

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/austinchima/kiterail/internal/db"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const integrationDBLockKey int64 = 4242420427

func quarantineTestDSN() string {
	if dsn := os.Getenv("KITERAIL_POSTGRES_DSN"); dsn != "" {
		return dsn
	}
	return os.Getenv("QUARANTINE_TEST_DSN")
}

func openIntegrationDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := quarantineTestDSN()
	if dsn == "" {
		t.Skip("KITERAIL_POSTGRES_DSN or QUARANTINE_TEST_DSN not set")
	}

	ctx := context.Background()
	lockDB, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	lockDB.SetMaxOpenConns(1)
	lockDB.SetMaxIdleConns(1)
	if err := lockDB.PingContext(ctx); err != nil {
		lockDB.Close()
		t.Fatalf("cannot connect to PostgreSQL: %v", err)
	}
	_, err = lockDB.ExecContext(ctx, "SELECT pg_advisory_lock($1)", integrationDBLockKey)
	require.NoError(t, err)

	sqlDB, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	if err := sqlDB.PingContext(ctx); err != nil {
		sqlDB.Close()
		_, _ = lockDB.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", integrationDBLockKey)
		lockDB.Close()
		t.Fatalf("cannot connect to PostgreSQL: %v", err)
	}
	if err := db.Migrate(ctx, sqlDB); err != nil {
		sqlDB.Close()
		_, _ = lockDB.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", integrationDBLockKey)
		lockDB.Close()
		t.Fatalf("cannot apply migrations: %v", err)
	}
	t.Cleanup(func() {
		sqlDB.Close()
		_, _ = lockDB.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", integrationDBLockKey)
		lockDB.Close()
	})

	return sqlDB
}

func resetQuarantineTable(t *testing.T, sqlDB *sql.DB) {
	t.Helper()
	_, err := sqlDB.ExecContext(context.Background(), "TRUNCATE quarantine")
	require.NoError(t, err)
}

// TestIntegration_CreateAndRetrieve creates a quarantine entry via real PostgreSQL
// and verifies it can be retrieved.
func TestIntegration_CreateAndRetrieve(t *testing.T) {
	sqlDB := openIntegrationDB(t)
	store, err := New(sqlDB)
	require.NoError(t, err)
	resetQuarantineTable(t, sqlDB)

	id, err := store.Create(context.Background(), "agent_1", "tool_x", []byte(`{"data": "test"}`))
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

	_, err = store.Create(context.Background(), "agent_2", "tool_y", []byte(`{"data": "test2"}`))
	require.NoError(t, err)
	_, err = store.Create(context.Background(), "agent_3", "tool_z", []byte(`{"data": "test3"}`))
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

	id, err := store.Create(context.Background(), "agent_1", "tool_x", []byte(`{"data": "test"}`))
	require.NoError(t, err)

	err = store.Approve(context.Background(), id, "admin")
	require.NoError(t, err)

	entry, err := store.Get(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, "approved", entry.Status)
	assert.Equal(t, "admin", entry.ResolvedBy)
	assert.True(t, entry.ResolvedAt.Valid)

	id2, err := store.Create(context.Background(), "agent_2", "tool_y", []byte(`{"data": "test2"}`))
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
