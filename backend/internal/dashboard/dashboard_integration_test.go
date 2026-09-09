package dashboard

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/austinchima/kiterail/internal/db"
	"github.com/austinchima/kiterail/internal/dbtest"
	"github.com/austinchima/kiterail/internal/ledger"
	"github.com/austinchima/kiterail/internal/quarantine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func openIntegrationDB(t *testing.T) *sql.DB {
	t.Helper()
	return dbtest.Open(t)
}

func resetDashboardTables(t *testing.T, sqlDB *sql.DB) {
	t.Helper()
	dbtest.Reset(t, sqlDB, "ledger", "quarantine")
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

	_, err = quarantineStore.Create(context.Background(), "agent_3", "tool_c", []byte(`{"requires":"review"}`), nil)
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
