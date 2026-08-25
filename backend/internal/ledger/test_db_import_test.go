package ledger

import (
	"testing"

	"github.com/austinchima/kiterail/internal/db"
)

func TestDBImport(t *testing.T) {
	var e db.LedgerEntry
	if e.SeqNum != 0 {
		t.Errorf("unexpected SeqNum")
	}
}
