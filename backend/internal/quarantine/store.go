package quarantine

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/austinchima/kiterail/internal/db"
	_ "github.com/lib/pq"
)

var ErrAlreadyResolved = errors.New("quarantine item already resolved")
var ErrNotFound = errors.New("quarantine item not found")

const Schema = `
CREATE TABLE IF NOT EXISTS quarantine (
    id SERIAL PRIMARY KEY,
    agent_id TEXT,
    tool_name TEXT,
    payload BYTEA,
    status TEXT,
    created_at TIMESTAMP,
    resolved_at TIMESTAMP,
    resolved_by TEXT,
	reason TEXT
);
`

type Store struct {
	q db.Querier
}

func New(sqlDB *sql.DB) (*Store, error) {
	if _, err := sqlDB.Exec(Schema); err != nil {
		return nil, fmt.Errorf("failed to create quarantine schema: %w", err)
	}
	return &Store{q: db.New(sqlDB)}, nil
}

func (s *Store) Create(ctx context.Context, agentID, toolName string, payload []byte) (string, error) {
	return s.q.CreateQuarantineEntry(ctx, db.CreateQuarantineEntryParams{
		AgentID:   agentID,
		ToolName:  toolName,
		Payload:   payload,
		CreatedAt: time.Now(),
	})
}

func (s *Store) Get(ctx context.Context, id string) (db.QuarantineEntry, error) {
	return s.q.GetQuarantineEntry(ctx, id)
}

func (s *Store) GetForReplay(ctx context.Context, id string) (db.QuarantineEntry, error) {
	return s.q.GetQuarantineEntryForReplay(ctx, id)
}

func (s *Store) List(ctx context.Context, status string) ([]db.QuarantineEntry, error) {
	return s.q.ListQuarantineByStatus(ctx, status)
}

func (s *Store) Approve(ctx context.Context, id, approvedBy string) error {
	res, err := s.q.ApproveQuarantineEntry(ctx, db.ApproveQuarantineEntryParams{
		Status:     "approved",
		ResolvedAt: time.Now(),
		ResolvedBy: approvedBy,
		ID:         id,
	})
	if err != nil {
		return fmt.Errorf("failed to approve quarantine entry: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}
	if n == 0 {
		return ErrAlreadyResolved
	}
	return nil
}

func (s *Store) MarkReplayFailed(ctx context.Context, id string) error {
	return s.q.MarkReplayFailed(ctx, id)
}

func (s *Store) Deny(ctx context.Context, id, deniedBy, reason string) error {
	res, err := s.q.DenyQuarantineEntry(ctx, db.DenyQuarantineEntryParams{
		Status:     "denied",
		ResolvedAt: time.Now(),
		ResolvedBy: deniedBy,
		Reason:     reason,
		ID:         id,
	})
	if err != nil {
		return fmt.Errorf("failed to deny quarantine entry: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}
	if n == 0 {
		return ErrAlreadyResolved
	}
	return nil
}