package dashboard

import (
	"testing"

	"github.com/austinchima/kiterail/internal/db"
	"github.com/stretchr/testify/assert"
)

func TestHandler_ComplianceCalculation(t *testing.T) {
	tests := []struct {
		name  string
		stats db.LedgerStats
		want  float64
	}{
		{
			name:  "violations reduce compliance",
			stats: db.LedgerStats{TotalActionsToday: 100, PolicyViolations: 20},
			want:  80,
		},
		{
			name: "no actions is fully compliant",
			want: 100,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, complianceStatus(test.stats))
		})
	}
}
