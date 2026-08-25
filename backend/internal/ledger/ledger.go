package ledger

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/austinchima/kiterail/internal/db"
	"github.com/lib/pq"
)

// normalizeTimestamp truncates to microseconds in UTC — the exact precision
// Postgres stores — so hashes computed before insert match hashes recomputed
// from rows read back during Verify().
func normalizeTimestamp(t time.Time) time.Time {
	return t.UTC().Truncate(time.Microsecond)
}

func calculateHash(entry db.LedgerEntry) string {
	// Length-prefixed canonical encoding: unambiguous even when fields
	// contain delimiter characters (unlike pipe-joined strings).
	fields := []string{
		fmt.Sprintf("%d", entry.SeqNum),
		normalizeTimestamp(entry.Timestamp).Format("2006-01-02T15:04:05.000000Z07:00"),
		entry.Agent,
		entry.Tool,
		entry.Decision,
		entry.PolicyRule,
		entry.PayloadHash,
		entry.RequestID,
		entry.PrevHash,
	}
	var data bytes.Buffer
	for _, f := range fields {
		fmt.Fprintf(&data, "%d:%s;", len(f), f)
	}
	hash := sha256.Sum256(data.Bytes())
	return hex.EncodeToString(hash[:])
}

type Store struct {
	q *db.Queries
}

func New(sqlDB *sql.DB) (*Store, error) {
	// Schema is applied by internal/db.Migrate — no ad-hoc DDL here.
	return &Store{q: db.New(sqlDB)}, nil
}

func (s *Store) Append(ctx context.Context, entry db.LedgerEntry) error {
	// SERIALIZABLE appends contend on the single chain-tip row, so Postgres
	// legitimately aborts losers (SQLSTATE 40001). Exponential backoff with
	// jitter prevents synchronized retry storms; the schedule is bounded
	// (~2s worst case) and cancellable via ctx.
	const maxRetries = 8
	for attempt := range maxRetries {
		err := s.appendOnce(ctx, entry)
		if err == nil {
			return nil
		}
		if isSerializationFailure(err) && attempt < maxRetries-1 {
			backoff := time.Duration(1<<uint(attempt)) * 10 * time.Millisecond
			backoff += time.Duration(rand.Int64N(int64(backoff/2) + 1))
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return fmt.Errorf("ledger append canceled while waiting to retry: %w", ctx.Err())
			}
			continue
		}
		return err
	}
	return fmt.Errorf("ledger append failed after %d attempts", maxRetries)
}

func isSerializationFailure(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "40001"
}

func (s *Store) appendOnce(ctx context.Context, entry db.LedgerEntry) error {
	sqlDB := s.q.DB()
	tx, err := sqlDB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("failed to begin tx: %w", err)
	}
	defer tx.Rollback()

	qtx := s.q.WithTx(tx)

	tip, err := qtx.GetLatestLedgerEntry(ctx)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("failed to get previous hash: %w", err)
	}

	entry.PrevHash = tip.Hash
	entry.SeqNum = tip.SeqNum + 1
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}
	entry.Timestamp = normalizeTimestamp(entry.Timestamp)
	entry.Hash = calculateHash(entry)

	err = qtx.InsertLedgerEntry(ctx, db.InsertLedgerEntryParams{
		SeqNum:      entry.SeqNum,
		Timestamp:   entry.Timestamp,
		Agent:       entry.Agent,
		Tool:        entry.Tool,
		Decision:    entry.Decision,
		PolicyRule:  entry.PolicyRule,
		PayloadHash: entry.PayloadHash,
		PrevHash:    entry.PrevHash,
		Hash:        entry.Hash,
		RequestID:   entry.RequestID,
	})
	if err != nil {
		return fmt.Errorf("failed to insert ledger entry: %w", err)
	}

	return tx.Commit()
}

func (s *Store) Verify(ctx context.Context) (bool, error) {
	sqlDB := s.q.DB()
	rows, err := sqlDB.QueryContext(ctx, "SELECT seq_num, timestamp, agent, tool, decision, policy_rule, payload_hash, prev_hash, hash, request_id FROM ledger ORDER BY seq_num ASC")
	if err != nil {
		return false, fmt.Errorf("failed to query ledger: %w", err)
	}
	defer rows.Close()

	var prevHash string
	for rows.Next() {
		var entry db.LedgerEntry
		if err := rows.Scan(&entry.SeqNum, &entry.Timestamp, &entry.Agent, &entry.Tool, &entry.Decision, &entry.PolicyRule, &entry.PayloadHash, &entry.PrevHash, &entry.Hash, &entry.RequestID); err != nil {
			return false, fmt.Errorf("failed to scan ledger entry: %w", err)
		}

		if entry.PrevHash != prevHash {
			return false, nil
		}

		expectedHash := calculateHash(entry)
		if entry.Hash != expectedHash {
			return false, nil
		}

		prevHash = entry.Hash
	}

	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("error iterating ledger rows: %w", err)
	}

	return true, nil
}

func (s *Store) Query(ctx context.Context) ([]db.LedgerEntry, error) {
	entries, err := s.q.ListRecentLedgerEntries(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query ledger: %w", err)
	}
	return entries, nil
}

func (s *Store) Stats(ctx context.Context) (db.LedgerStats, error) {
	var stats db.LedgerStats

	total, err := s.q.CountTodayActions(ctx)
	if err != nil {
		return stats, err
	}
	stats.TotalActionsToday = total

	violations, err := s.q.CountTodayViolations(ctx)
	if err != nil {
		return stats, err
	}
	stats.PolicyViolations = violations

	return stats, nil
}