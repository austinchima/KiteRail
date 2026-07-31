package policy

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

// Schema represents the policies table.
const Schema = `
CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    title TEXT,
    trigger_rule TEXT,
    action_type TEXT,
    enabled BOOLEAN,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);
`

// Policy represents a security policy.
type Policy struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	TriggerRule string    `json:"trigger_rule"`
	ActionType  string    `json:"action_type"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Store represents a Postgres-backed policy store.
type Store struct {
	db *sql.DB
}

// New creates a new Store and seeds default policies.
func New(db *sql.DB) (*Store, error) {
	if _, err := db.Exec(Schema); err != nil {
		return nil, fmt.Errorf("failed to create policies schema: %w", err)
	}
	
	s := &Store{db: db}
	if err := s.SeedDefaults(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to seed default policies: %w", err)
	}
	
	return s, nil
}

// SeedDefaults populates the database with the initial policies if they do not exist.
func (s *Store) SeedDefaults(ctx context.Context) error {
	defaults := []Policy{
		{
			ID:          "POL-882-991",
			Title:       "Require Approval for Refunds > $1,000",
			TriggerRule: "Action == stripe.charge.refund",
			ActionType:  "Block execution. Route to Manager Approval Gate.",
			Enabled:     true,
		},
		{
			ID:          "POL-104-552",
			Title:       "DLP: Scrub PII/PCI (SSN, Cards) from LLM Prompts",
			TriggerRule: "Egress to OpenAI / Anthropic",
			ActionType:  "Apply regex masking for SSN, CC, and Phone Numbers.",
			Enabled:     true,
		},
		{
			ID:          "POL-404-001",
			Title:       "Block Unauthorized Wire Transfers (> $10K)",
			TriggerRule: "Action == swift.transfer AND amount > 10000 AND role != 'RiskOfficer'",
			ActionType:  "Deny instantly. Alert Risk Ops.",
			Enabled:     true,
		},
		{
			ID:          "POL-912-701",
			Title:       "Rate Limit: Plaid API Calls",
			TriggerRule: "Egress to Plaid API",
			ActionType:  "Throttle to 100 requests per minute.",
			Enabled:     false,
		},
	}

	for _, p := range defaults {
		var exists bool
		err := s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM policies WHERE id = $1)", p.ID).Scan(&exists)
		if err != nil {
			return err
		}
		if !exists {
			_, err = s.db.ExecContext(ctx,
				"INSERT INTO policies (id, title, trigger_rule, action_type, enabled, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
				p.ID, p.Title, p.TriggerRule, p.ActionType, p.Enabled, time.Now(), time.Now(),
			)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// List returns all policies.
func (s *Store) List(ctx context.Context) ([]Policy, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id, title, trigger_rule, action_type, enabled, created_at, updated_at FROM policies ORDER BY created_at ASC")
	if err != nil {
		return nil, fmt.Errorf("failed to query policies: %w", err)
	}
	defer rows.Close()

	var policies []Policy
	for rows.Next() {
		var p Policy
		if err := rows.Scan(&p.ID, &p.Title, &p.TriggerRule, &p.ActionType, &p.Enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan policy: %w", err)
		}
		policies = append(policies, p)
	}
	return policies, nil
}

// UpdateEnabled toggles the enabled state of a policy.
func (s *Store) UpdateEnabled(ctx context.Context, id string, enabled bool) error {
	res, err := s.db.ExecContext(ctx, "UPDATE policies SET enabled = $1, updated_at = $2 WHERE id = $3", enabled, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to update policy: %w", err)
	}
	
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return fmt.Errorf("policy not found")
	}
	
	return nil
}

// GetEnabledPolicies returns a map of enabled policy IDs.
func (s *Store) GetEnabledPolicies(ctx context.Context) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id FROM policies WHERE enabled = true")
	if err != nil {
		return nil, fmt.Errorf("failed to query enabled policies: %w", err)
	}
	defer rows.Close()

	enabled := make(map[string]bool)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan policy id: %w", err)
		}
		enabled[id] = true
	}
	return enabled, nil
}
