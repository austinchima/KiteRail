// Package dbtest provides a shared PostgreSQL harness for KiteRail's
// integration tests: one DSN reader, one advisory-lock owner, migration
// application, and per-test table resets.
//
// It was extracted because the same plumbing was triplicated across
// test files — and triplicated helpers drift exactly like lying mocks do
// (see docs/blog-posts/postmortem-mocks-that-lie.md). All integration tests
// must share this owner so concurrent package runs serialize instead of
// TRUNCATE-ing each other's tables.
package dbtest

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/austinchima/kiterail/internal/db"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

// lockKey serializes integration tests that share one database.
const lockKey int64 = 4242420427

// DSN returns the integration-test DSN, skipping the test when unset.
// QUARANTINE_TEST_DSN is accepted for backward compatibility with the
// pre-extraction quarantine tests.
func DSN(t *testing.T) string {
	t.Helper()
	if dsn := os.Getenv("KITERAIL_POSTGRES_DSN"); dsn != "" {
		return dsn
	}
	if dsn := os.Getenv("QUARANTINE_TEST_DSN"); dsn != "" {
		return dsn
	}
	t.Skip("KITERAIL_POSTGRES_DSN or QUARANTINE_TEST_DSN not set")
	return ""
}

// Open connects to the integration database, takes the shared advisory
// lock, applies migrations, and registers cleanup (lock release + close).
// Tests should call Reset for table isolation.
func Open(t *testing.T) *sql.DB {
	t.Helper()
	dsn := DSN(t)
	ctx := context.Background()

	lockDB, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	lockDB.SetMaxOpenConns(1)
	t.Cleanup(func() {
		_, _ = lockDB.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", lockKey)
		_ = lockDB.Close()
	})
	require.NoError(t, lockDB.PingContext(ctx))
	_, err = lockDB.ExecContext(ctx, "SELECT pg_advisory_lock($1)", lockKey)
	require.NoError(t, err)

	sqlDB, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	require.NoError(t, sqlDB.PingContext(ctx))
	require.NoError(t, db.Migrate(ctx, sqlDB))
	return sqlDB
}

// Reset truncates the given tables. Table names must be test-controlled
// constants, never derived from request data.
func Reset(t *testing.T, sqlDB *sql.DB, tables ...string) {
	t.Helper()
	for _, table := range tables {
		_, err := sqlDB.ExecContext(context.Background(), "TRUNCATE "+table)
		require.NoError(t, err)
	}
}
