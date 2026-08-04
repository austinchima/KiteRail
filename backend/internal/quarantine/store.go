package quarantine

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

// ErrAlreadyResolved is returned when attempting to approve or deny an entry
// that has already been resolved (approved or denied).
var ErrAlreadyResolved = errors.New("quarantine item already resolved")

// ErrNotFound is returned when a quarantine entry cannot be found by ID.
var ErrNotFound = errors.New("quarantine item not found")

// Schema represents the quarantine table.
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

// QuarantineEntry represents an entry in the quarantine queue.
type QuarantineEntry struct {
	ID         string
	AgentID    string
	ToolName   string
	Payload    []byte
	Status     string
	CreatedAt  time.Time
	ResolvedAt *time.Time
	ResolvedBy string
}

// Store represents a Postgres-backed quarantine queue.
type Store struct {
	db *sql.DB
}

// New creates a new Store.
func New(db *sql.DB) (*Store, error) {
	if _, err := db.Exec(Schema); err != nil {
		return nil, fmt.Errorf("failed to create quarantine schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Create inserts a quarantined payload.
func (s *Store) Create(ctx context.Context, agentID, toolName string, payload []byte) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx,
		"INSERT INTO quarantine (agent_id, tool_name, payload, status, created_at) VALUES ($1, $2, $3, $4, $5) RETURNING id::text",
		agentID, toolName, payload, "pending", time.Now(),
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("failed to insert quarantine entry: %w", err)
	}
	return id, nil
}

// Get retrieves a quarantine entry by ID.
func (s *Store) Get(ctx context.Context, id string) (QuarantineEntry, error) {
	var entry QuarantineEntry
	err := s.db.QueryRowContext(ctx,
		"SELECT id::text, COALESCE(agent_id, ''), COALESCE(tool_name, ''), payload, status, created_at, resolved_at, COALESCE(resolved_by, '') FROM quarantine WHERE id = $1",
		id,
	).Scan(&entry.ID, &entry.AgentID, &entry.ToolName, &entry.Payload, &entry.Status, &entry.CreatedAt, &entry.ResolvedAt, &entry.ResolvedBy)
	if err != nil {
		return QuarantineEntry{}, fmt.Errorf("failed to get quarantine entry: %w", err)
	}
	return entry, nil
}

// List lists quarantine entries by status.
func (s *Store) List(ctx context.Context, status string) ([]QuarantineEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id::text, COALESCE(agent_id, ''), COALESCE(tool_name, ''), payload, status, created_at, resolved_at, COALESCE(resolved_by, '') FROM quarantine WHERE status = $1",
		status,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list quarantine entries: %w", err)
	}
	defer rows.Close()

	var entries []QuarantineEntry
	for rows.Next() {
		var entry QuarantineEntry
		if err := rows.Scan(&entry.ID, &entry.AgentID, &entry.ToolName, &entry.Payload, &entry.Status, &entry.CreatedAt, &entry.ResolvedAt, &entry.ResolvedBy); err != nil {
			return nil, fmt.Errorf("failed to scan quarantine entry: %w", err)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// Approve marks a quarantine entry as approved. It accepts both 'pending' and
// 'replay_failed' rows so that a failed replay can be retried without creating
// a new quarantine item. Concurrent calls are still safe — exactly one caller
// will see rowsAffected == 1; all others get ErrAlreadyResolved.
func (s *Store) Approve(ctx context.Context, id, approvedBy string) error {
	res, err := s.db.ExecContext(ctx,
		"UPDATE quarantine SET status = $1, resolved_at = $2, resolved_by = $3 WHERE id = $4 AND status IN ('pending', 'replay_failed')",
		"approved", time.Now(), approvedBy, id,
	)
	if err != nil {
		return fmt.Errorf("failed to approve quarantine entry: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}
	if n == 0 {
		// Either the ID doesn't exist or it was already resolved (approved/denied).
		return ErrAlreadyResolved
	}
	return nil
}

// MarkReplayFailed transitions a quarantine entry from 'approved' back to
// 'replay_failed' when the downstream target call fails after the human
// approval step. This preserves the audit record of the approval decision
// while surfacing the item in the PENDING inbox for retry.
func (s *Store) MarkReplayFailed(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx,
		"UPDATE quarantine SET status = $1 WHERE id = $2 AND status = 'approved'",
		"replay_failed", id,
	)
	if err != nil {
		return fmt.Errorf("failed to mark quarantine entry as replay_failed: %w", err)
	}
	return nil
}

// Deny marks a quarantine entry as denied. Accepts both 'pending' and
// 'replay_failed' items so a reviewer can reject after a failed replay.
func (s *Store) Deny(ctx context.Context, id, deniedBy, reason string) error {
	res, err := s.db.ExecContext(ctx,
		"UPDATE quarantine SET status = $1, resolved_at = $2, resolved_by = $3, reason = $4 WHERE id = $5 AND status IN ('pending', 'replay_failed')",
		"denied", time.Now(), deniedBy, reason, id,
	)
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
