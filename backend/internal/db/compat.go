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
	PolicyRule     string
	Explanation    string
}

// MarshalJSON keeps the documented v1 wire shape (PascalCase keys, base64
// Payload) but renders unset timestamps as null instead of sql.NullTime's
// {"Time": ..., "Valid": false} struct.
func (e QuarantineEntry) MarshalJSON() ([]byte, error) {
	nullableTime := func(t sql.NullTime) *time.Time {
		if !t.Valid {
			return nil
		}
		return &t.Time
	}
	headers := e.RequestHeaders
	if len(headers) == 0 {
		headers = json.RawMessage("{}")
	}
	return json.Marshal(struct {
		ID             string
		AgentID        string
		ToolName       string
		Payload        []byte
		Status         string
		CreatedAt      time.Time
		ResolvedAt     *time.Time
		ResolvedBy     string
		Reason         string
		Attempts       int
		ReplayedAt     *time.Time
		RequestHeaders json.RawMessage
		PolicyRule     string
		Explanation    string
	}{
		e.ID, e.AgentID, e.ToolName, e.Payload, e.Status, e.CreatedAt,
		nullableTime(e.ResolvedAt), e.ResolvedBy, e.Reason, e.Attempts,
		nullableTime(e.ReplayedAt), headers, e.PolicyRule, e.Explanation,
	})
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
		PolicyRule:     m.PolicyRule,
		Explanation:    m.Explanation,
	}
}

func (q *Queries) DB() *sql.DB {
	return q.db.(*sql.DB)
}
