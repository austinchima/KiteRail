package quarantine

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/austinchima/kiterail/internal/db"
	"github.com/google/uuid"
)

func parseQuarantineID(id string) (uuid.UUID, error) {
	qid, err := uuid.Parse(id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid quarantine id %q: %w", id, err)
	}
	return qid, nil
}

var ErrAlreadyResolved = errors.New("quarantine item already resolved")
var ErrNotFound = errors.New("quarantine item not found")

// Status values for the durable replay state machine:
//
//	pending -> approved -> replaying -> replayed
//	                     |            \-> replay_failed -> approved (re-approve)
//	pending \-> denied
const (
	StatusPending      = "pending"
	StatusApproved     = "approved"
	StatusReplaying    = "replaying"
	StatusReplayed     = "replayed"
	StatusReplayFailed = "replay_failed"
	StatusDenied       = "denied"
)

type Store struct {
	q db.Querier
}

func New(sqlDB *sql.DB) (*Store, error) {
	// Schema is applied by internal/db.Migrate — no ad-hoc DDL here.
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
	qid, err := parseQuarantineID(id)
	if err != nil {
		return db.QuarantineEntry{}, ErrNotFound
	}
	m, err := s.q.GetQuarantineEntry(ctx, qid)
	if err != nil {
		return db.QuarantineEntry{}, err
	}
	return db.ToQuarantineEntry(m), nil
}

func (s *Store) GetForReplay(ctx context.Context, id string) (db.QuarantineEntry, error) {
	qid, err := parseQuarantineID(id)
	if err != nil {
		return db.QuarantineEntry{}, ErrNotFound
	}
	m, err := s.q.GetQuarantineEntryForReplay(ctx, qid)
	if err != nil {
		return db.QuarantineEntry{}, err
	}
	return db.ToQuarantineEntry(m), nil
}

func (s *Store) List(ctx context.Context, status string) ([]db.QuarantineEntry, error) {
	models, err := s.q.ListQuarantineByStatus(ctx, status)
	if err != nil {
		return nil, err
	}
	entries := make([]db.QuarantineEntry, 0, len(models))
	for _, m := range models {
		entries = append(entries, db.ToQuarantineEntry(m))
	}
	return entries, nil
}

func (s *Store) Approve(ctx context.Context, id, approvedBy string) error {
	qid, err := parseQuarantineID(id)
	if err != nil {
		return err
	}
	res, err := s.q.ApproveQuarantineEntry(ctx, db.ApproveQuarantineEntryParams{
		Status:     StatusApproved,
		ResolvedAt: sql.NullTime{Time: time.Now(), Valid: true},
		ResolvedBy: sql.NullString{String: approvedBy, Valid: approvedBy != ""},
		ID:         qid,
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
	qid, err := parseQuarantineID(id)
	if err != nil {
		return err
	}
	return s.q.MarkReplayFailed(ctx, qid)
}

// ClaimApproved atomically claims up to limit approved entries for replay,
// transitioning them to 'replaying'. Safe across concurrent workers.
func (s *Store) ClaimApproved(ctx context.Context, limit int) ([]db.QuarantineEntry, error) {
	models, err := s.q.ClaimApprovedForReplay(ctx, int32(limit))
	if err != nil {
		return nil, err
	}
	entries := make([]db.QuarantineEntry, 0, len(models))
	for _, m := range models {
		entries = append(entries, db.ToQuarantineEntry(m))
	}
	return entries, nil
}

// MarkReplayed transitions a claimed entry to 'replayed' after success.
func (s *Store) MarkReplayed(ctx context.Context, id string) error {
	qid, err := parseQuarantineID(id)
	if err != nil {
		return err
	}
	return s.q.MarkReplayed(ctx, qid)
}

// ReturnToApproved releases a claimed entry back to 'approved' so the worker
// retries it on the next tick (used when attempts remain).
func (s *Store) ReturnToApproved(ctx context.Context, id string) error {
	qid, err := parseQuarantineID(id)
	if err != nil {
		return err
	}
	return s.q.ReturnToApproved(ctx, qid)
}

// RecoverStuckReplays resets entries left in 'replaying' by a crash back to
// 'approved', and returns how many were recovered. Called once at startup.
func (s *Store) RecoverStuckReplays(ctx context.Context) (int64, error) {
	return s.q.RecoverStuckReplays(ctx)
}

func (s *Store) Deny(ctx context.Context, id, deniedBy, reason string) error {
	qid, err := parseQuarantineID(id)
	if err != nil {
		return err
	}
	res, err := s.q.DenyQuarantineEntry(ctx, db.DenyQuarantineEntryParams{
		Status:     StatusDenied,
		ResolvedAt: sql.NullTime{Time: time.Now(), Valid: true},
		ResolvedBy: sql.NullString{String: deniedBy, Valid: deniedBy != ""},
		Reason:     sql.NullString{String: reason, Valid: reason != ""},
		ID:         qid,
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
