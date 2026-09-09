package quarantine

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/austinchima/kiterail/internal/db"
	"github.com/austinchima/kiterail/internal/mcp"
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

// ErrStaleTransition indicates a state-transition UPDATE matched zero rows:
// the entry was not in the state the transition requires. State transitions
// must never silently no-op — a silent no-op is how the replay machine once
// wedged exhausted entries in 'replaying' forever — so the Store surfaces it
// as an error and the worker logs it.
var ErrStaleTransition = errors.New("quarantine entry not in expected state for transition")

// requireAffected wraps a state-transition exec and fails with
// ErrStaleTransition when the UPDATE matched no rows.
func requireAffected(res sql.Result, err error, op string) error {
	if err != nil {
		return fmt.Errorf("failed to %s: %w", op, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected for %s: %w", op, err)
	}
	if n == 0 {
		return fmt.Errorf("%s: %w", op, ErrStaleTransition)
	}
	return nil
}

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

// Store persists the quarantine state machine and coordinates replay ownership.
type Store struct {
	q     db.Querier
	sqlDB *sql.DB
}

// New binds a store to a database whose schema has already been migrated.
func New(sqlDB *sql.DB) (*Store, error) {
	// Schema is applied by internal/db.Migrate — no ad-hoc DDL here.
	return &Store{q: db.New(sqlDB), sqlDB: sqlDB}, nil
}

// Create retains the original body and replay-safe protocol metadata. Filtering
// at the persistence boundary prevents callers from accidentally storing tokens.
func (s *Store) Create(ctx context.Context, agentID, toolName string, payload []byte, headers http.Header) (string, error) {
	requestHeaders, err := json.Marshal(mcp.CaptureReplayHeaders(headers))
	if err != nil {
		return "", fmt.Errorf("encode replay headers: %w", err)
	}
	return s.q.CreateQuarantineEntry(ctx, db.CreateQuarantineEntryParams{
		AgentID:        agentID,
		ToolName:       toolName,
		Payload:        payload,
		CreatedAt:      time.Now(),
		RequestHeaders: requestHeaders,
	})
}

// WithReplayLock runs one replay pass exclusively across server instances.
// A transaction owns the advisory lock but does not contain the replay writes:
// each state transition must commit before the next upstream request is sent.
// The detached transaction survives request cancellation until the callback has
// returned and recovered its abandoned claims. Rollback then releases the lock
// on the same connection, including error and panic paths.
func (s *Store) WithReplayLock(ctx context.Context, replay func(context.Context) error) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	transaction, err := s.sqlDB.BeginTx(context.WithoutCancel(ctx), nil)
	if err != nil {
		return false, fmt.Errorf("begin replay lock transaction: %w", err)
	}
	defer transaction.Rollback()
	var acquired bool
	if err := transaction.QueryRowContext(ctx, "SELECT pg_try_advisory_xact_lock(918273646)").Scan(&acquired); err != nil {
		return false, fmt.Errorf("acquire replay lock: %w", err)
	}
	if !acquired {
		return false, nil
	}
	return true, replay(ctx)
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
	res, err := s.q.MarkReplayFailed(ctx, qid)
	return requireAffected(res, err, "mark replay failed")
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
	res, err := s.q.MarkReplayed(ctx, qid)
	return requireAffected(res, err, "mark replayed")
}

// ReturnToApproved releases a claimed entry back to 'approved' so the worker
// retries it on the next tick (used when attempts remain). This is where the
// attempts counter actually increments — not at claim time.
func (s *Store) ReturnToApproved(ctx context.Context, id string) error {
	qid, err := parseQuarantineID(id)
	if err != nil {
		return err
	}
	res, err := s.q.ReturnToApproved(ctx, qid)
	return requireAffected(res, err, "return to approved")
}

// RecoverStuckReplays resets entries left in 'replaying' by a crash back to
// 'approved', and returns how many were recovered. Callers must hold the replay
// lock so another live worker's requests cannot be mistaken for crashed work.
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
