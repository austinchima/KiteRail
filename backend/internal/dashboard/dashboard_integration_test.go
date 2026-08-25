package dashboard

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/austinchima/kiterail/internal/db"
	"github.com/austinchima/kiterail/internal/ledger"
	"github.com/austinchima/kiterail/internal/quarantine"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

const integrationDBLockKey int64 = 4242420427

func dashboardTestDSN() string {
	if dsn := os.Getenv("KITERAIL_POSTGRES_DSN"); dsn != "" {
		return dsn
	}
	return os.Getenv("DASHBOARDTEST_DSN")
}

func openIntegrationDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := dashboardTestDSN()
	if dsn == "" {
		t.Skip("KITERAIL_POSTGRES_DSN or DASHBOARDTEST_DSN not set")
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

func resetDashboardTables(t *testing.T, sqlDB *sql.DB) {
	t.Helper()
	_, err := sqlDB.ExecContext(context.Background(), "TRUNCATE ledger, quarantine RESTART IDENTITY")
	require.NoError(t, err)
}

// TestIntegration_ComplianceStatus tests the compliance status calculation
// with real database data.
func TestIntegration_ComplianceStatus(t *testing.T) {
	sqlDB := openIntegrationDB(t)
	ledgerStore, err := ledger.New(sqlDB)
	require.NoError(t, err)
	quarantineStore, err := quarantine.New(sqlDB)
	require.NoError(t, err)
	resetDashboardTables(t, sqlDB)

	err = ledgerStore.Append(context.Background(), db.LedgerEntry{
		Agent:       "agent_1",
		Tool:        "tool_a",
		Decision:    "allow",
		PolicyRule:  "policy_1",
		PayloadHash: "hash1",
	})
	require.NoError(t, err)
	err = ledgerStore.Append(context.Background(), db.LedgerEntry{
		Agent:       "agent_2",
		Tool:        "tool_b",
		Decision:    "deny",
		PolicyRule:  "policy_2",
		PayloadHash: "hash2",
	})
	require.NoError(t, err)

	_, err = quarantineStore.Create(context.Background(), "agent_3", "tool_c", []byte(`{"requires":"review"}`))
	require.NoError(t, err)

	handler := NewHandler(ledgerStore, quarantineStore, zap.NewNop())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/stats", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var response map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
	assert.Equal(t, float64(2), response["total_actions_today"])
	assert.Equal(t, float64(1), response["policy_violations"])
	assert.Equal(t, float64(50), response["compliance_status"])
	assert.Len(t, response["pending_approvals"], 1)
	assert.Len(t, response["recent_feed"], 2)
}
