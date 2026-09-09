package db

import (
	"database/sql"
	"encoding/json"
	"time"
)

type LedgerEntry = Ledger

type LedgerStats struct {
	TotalActionsToday int64
	PolicyViolations  int64
}

// QuarantineEntry is the persisted request and its human-review state.
// RequestHeaders contains only protocol headers allowed for delayed replay.
type QuarantineEntry struct {
	ID             string
	AgentID        string
	ToolName       string
	Payload        []byte
	Status         string
	CreatedAt      time.Time
	ResolvedAt     sql.NullTime
	ResolvedBy     string
	Reason         string
	Attempts       int
	ReplayedAt     sql.NullTime
	RequestHeaders json.RawMessage
}

func ToQuarantineEntry(m Quarantine) QuarantineEntry {
	return QuarantineEntry{
		ID:             m.ID.String(),
		AgentID:        m.AgentID,
		ToolName:       m.ToolName,
		Payload:        m.Payload,
		Status:         m.Status,
		CreatedAt:      m.CreatedAt,
		ResolvedAt:     m.ResolvedAt,
		ResolvedBy:     m.ResolvedBy.String,
		Reason:         m.Reason.String,
		Attempts:       int(m.Attempts),
		ReplayedAt:     m.ReplayedAt,
		RequestHeaders: m.RequestHeaders,
	}
}

func (q *Queries) DB() *sql.DB {
	return q.db.(*sql.DB)
}
