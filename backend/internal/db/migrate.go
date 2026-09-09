package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"

	_ "github.com/lib/pq"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Migrate applies all pending migrations in filename order. It uses a
// transaction-scoped Postgres advisory lock so concurrent instances cannot race.
// Keeping the lock and all schema work in one transaction also guarantees that
// cancellation releases the lock; pooled queries cannot unlock another session.
func Migrate(ctx context.Context, sqlDB *sql.DB) error {
	transaction, err := sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin migration transaction: %w", err)
	}
	defer transaction.Rollback()
	if _, err := transaction.ExecContext(ctx, "SELECT pg_advisory_xact_lock(918273645)"); err != nil {
		return fmt.Errorf("failed to acquire migration lock: %w", err)
	}

	if _, err := transaction.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`); err != nil {
		return fmt.Errorf("failed to create schema_migrations table: %w", err)
	}

	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("failed to read embedded migrations: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && path.Ext(e.Name()) == ".sql" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		var applied bool
		if err := transaction.QueryRowContext(ctx,
			"SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)", name,
		).Scan(&applied); err != nil {
			return fmt.Errorf("failed to check migration status for %s: %w", name, err)
		}
		if applied {
			continue
		}

		content, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("failed to read migration %s: %w", name, err)
		}
		if _, err := transaction.ExecContext(ctx, string(content)); err != nil {
			return fmt.Errorf("failed to apply migration %s: %w", name, err)
		}
		if _, err := transaction.ExecContext(ctx,
			"INSERT INTO schema_migrations (version) VALUES ($1)", name); err != nil {
			return fmt.Errorf("failed to record migration %s: %w", name, err)
		}
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("failed to commit migrations: %w", err)
	}
	return nil
}
