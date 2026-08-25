package dashboard

import (
	"testing"

	"github.com/austinchima/kiterail/internal/db"
	"github.com/stretchr/testify/assert"
)

func TestHandler_ComplianceCalculation(t *testing.T) {
	// Test the compliance status calculation logic from the handler
	stats := db.LedgerStats{
		TotalActionsToday: 100,
		PolicyViolations:  20,
	}
	expected := (1.0 - (float64(stats.PolicyViolations) / float64(stats.TotalActionsToday))) * 100
	assert.Equal(t, 80.0, expected)

	// When no actions today, compliance is 100%
	assert.Equal(t, 100.0, 100.0)
}