package policystore

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Policy represents a security policy.
type Policy struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	TriggerRule string    `json:"trigger_rule"`
	ActionType  string    `json:"action_type"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Code        string    `json:"code,omitempty"`
}

// Store represents a filesystem-backed policy store.
type Store struct {
	policyDir string
}

// New creates a new Store.
func New(policyDir string) (*Store, error) {
	if err := os.MkdirAll(policyDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create policy directory: %w", err)
	}
	return &Store{policyDir: policyDir}, nil
}

// List returns every Rego policy below the configured root in deterministic
// relative-path order. Recursive discovery matches OPA's loader, so the
// dashboard cannot omit a policy merely because a team grouped it in a
// subdirectory. Disabled files remain visible for reviewers but are marked
// disabled and are not loaded by OPA.
func (s *Store) List(ctx context.Context) ([]Policy, error) {
	policies := make([]Policy, 0)
	err := filepath.WalkDir(s.policyDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}

		name := entry.Name()
		if !strings.HasSuffix(name, ".rego") && !strings.HasSuffix(name, ".rego.disabled") {
			return nil
		}

		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("read policy metadata for %q: %w", path, err)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read policy %q: %w", path, err)
		}

		relativePath, err := filepath.Rel(s.policyDir, path)
		if err != nil {
			return fmt.Errorf("derive policy ID for %q: %w", path, err)
		}
		id := strings.TrimSuffix(strings.TrimSuffix(filepath.ToSlash(relativePath), ".rego.disabled"), ".rego")
		title, trigger, action := parseMetadata(string(content))
		if title == "" {
			title = id
		}

		policies = append(policies, Policy{
			ID:          id,
			Title:       title,
			TriggerRule: trigger,
			ActionType:  action,
			Enabled:     strings.HasSuffix(name, ".rego"),
			// The filesystem does not expose a portable creation time. ModTime is
			// therefore the honest source for both displayed lifecycle fields.
			CreatedAt: info.ModTime(),
			UpdatedAt: info.ModTime(),
			Code:      string(content),
		})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk policy directory: %w", err)
	}
	sort.Slice(policies, func(left, right int) bool { return policies[left].ID < policies[right].ID })
	return policies, nil
}

// Policies are immutable GitOps assets in v1.0: there is deliberately NO
// Save/UpdateEnabled here. Runtime policy mutation would let a single
// compromised admin credential rewrite the enforcement rulebook, and an
// unsanitized `id` would be a path-traversal footgun. If admin mutation ever
// returns, it must come with Engine.Reload wiring and strict id validation.

func parseMetadata(content string) (title, trigger, action string) {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "# Title:") {
			title = strings.TrimSpace(strings.TrimPrefix(line, "# Title:"))
		} else if strings.HasPrefix(line, "# Trigger:") {
			trigger = strings.TrimSpace(strings.TrimPrefix(line, "# Trigger:"))
		} else if strings.HasPrefix(line, "# Action:") {
			action = strings.TrimSpace(strings.TrimPrefix(line, "# Action:"))
		}
	}

	// Fallback if not specifically tagged, just grab first comment as title
	if title == "" {
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "# ") {
				title = strings.TrimPrefix(line, "# ")
				break
			}
		}
	}
	return
}
