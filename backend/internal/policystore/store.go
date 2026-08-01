package policystore

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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

// List returns all policies.
func (s *Store) List(ctx context.Context) ([]Policy, error) {
	entries, err := os.ReadDir(s.policyDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy directory: %w", err)
	}

	var policies []Policy
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		
		name := entry.Name()
		if !strings.HasSuffix(name, ".rego") && !strings.HasSuffix(name, ".rego.disabled") {
			continue
		}

		enabled := strings.HasSuffix(name, ".rego")
		id := strings.TrimSuffix(name, ".rego.disabled")
		id = strings.TrimSuffix(id, ".rego")

		path := filepath.Join(s.policyDir, name)
		info, err := entry.Info()
		if err != nil {
			continue
		}

		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		// Simple parsing to extract title, trigger, action from comments if possible
		title, trigger, action := parseMetadata(string(content))
		if title == "" {
			title = id
		}

		policies = append(policies, Policy{
			ID:          id,
			Title:       title,
			TriggerRule: trigger,
			ActionType:  action,
			Enabled:     enabled,
			CreatedAt:   info.ModTime(), // Fallback to modtime
			UpdatedAt:   info.ModTime(),
			Code:        string(content),
		})
	}
	return policies, nil
}

// UpdateEnabled toggles the enabled state of a policy by renaming the file.
func (s *Store) UpdateEnabled(ctx context.Context, id string, enabled bool) error {
	basePath := filepath.Join(s.policyDir, id)
	regoPath := basePath + ".rego"
	disabledPath := basePath + ".rego.disabled"

	if enabled {
		if _, err := os.Stat(disabledPath); err == nil {
			return os.Rename(disabledPath, regoPath)
		}
	} else {
		if _, err := os.Stat(regoPath); err == nil {
			return os.Rename(regoPath, disabledPath)
		}
	}
	return nil // Already in desired state or doesn't exist
}

// Save writes a policy to disk.
func (s *Store) Save(ctx context.Context, id string, content string, enabled bool) error {
	ext := ".rego"
	if !enabled {
		ext = ".rego.disabled"
	}
	path := filepath.Join(s.policyDir, id+ext)
	
	// If it already exists with the other extension, remove it
	otherExt := ".rego.disabled"
	if !enabled {
		otherExt = ".rego"
	}
	os.Remove(filepath.Join(s.policyDir, id+otherExt))
	
	return os.WriteFile(path, []byte(content), 0644)
}

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
