package db

import (
	"database/sql"
	"time"
)

type LedgerEntry = Ledger

type LedgerStats struct {
	TotalActionsToday int64
	PolicyViolations  int64
}

type QuarantineEntry struct {
	ID         string
	AgentID    string
	ToolName   string
	Payload    []byte
	Status     string
	CreatedAt  time.Time
	ResolvedAt sql.NullTime
	ResolvedBy string
	Reason     string
	Attempts   int
	ReplayedAt sql.NullTime
}

func ToQuarantineEntry(m Quarantine) QuarantineEntry {
	return QuarantineEntry{
		ID:         m.ID.String(),
		AgentID:    m.AgentID,
		ToolName:   m.ToolName,
		Payload:    m.Payload,
		Status:     m.Status,
		CreatedAt:  m.CreatedAt,
		ResolvedAt: m.ResolvedAt,
		ResolvedBy: m.ResolvedBy.String,
		Reason:     m.Reason.String,
		Attempts:   int(m.Attempts),
		ReplayedAt: m.ReplayedAt,
	}
}

func (q *Queries) DB() *sql.DB {
	return q.db.(*sql.DB)
}
