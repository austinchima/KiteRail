package ledger

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/austinchima/kiterail/internal/db"
	_ "github.com/lib/pq"
)

const Schema = `
CREATE TABLE IF NOT EXISTS ledger (
    seq_num SERIAL PRIMARY KEY,
    timestamp TIMESTAMP,
    agent TEXT,
    tool TEXT,
    decision TEXT,
    policy_rule TEXT,
    payload_hash TEXT,
    prev_hash TEXT,
    hash TEXT
);
`

type Store struct {
	q db.Querier
}

func New(sqlDB *sql.DB) (*Store, error) {
	if _, err := sqlDB.Exec(Schema); err != nil {
		return nil, fmt.Errorf("failed to create ledger schema: %w", err)
	}
	return &Store{q: db.New(sqlDB)}, nil
}

func calculateHash(entry db.LedgerEntry) string {
	data := fmt.Sprintf("%d%s%s%s%s%s%s",
		entry.SeqNum,
		entry.Timestamp.UTC().Format(time.RFC3339Nano),
		entry.Agent,
		entry.Tool,
		entry.Decision,
		entry.PayloadHash,
		entry.PrevHash,
	)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (s *Store) Append(ctx context.Context, entry db.LedgerEntry) error {
	const maxRetries = 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		err := s.appendOnce(ctx, entry)
		if err == nil {
			return nil
		}
		if isSerializationFailure(err) && attempt < maxRetries-1 {
			time.Sleep(time.Duration(5*(attempt+1)) * time.Millisecond)
			continue
		}
		return err
	}
	return fmt.Errorf("ledger append failed after %d attempts", maxRetries)
}

func isSerializationFailure(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return len(errStr) >= 5 && errStr[:5] == "pq: E" &&
		(strings.Contains(errStr, "40001") || strings.Contains(errStr, "serialization"))
}

func (s *Store) appendOnce(ctx context.Context, entry db.LedgerEntry) error {
	sqlDB := s.q.DB()
	tx, err := sqlDB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("failed to begin tx: %w", err)
	}
	defer tx.Rollback()

	var prevHash string
	var seqNum int
	err = tx.QueryRowContext(ctx, "SELECT COALESCE(hash, ''), COALESCE(seq_num, 0) FROM ledger ORDER BY seq_num DESC LIMIT 1 FOR UPDATE").Scan(&prevHash, &seqNum)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("failed to get previous hash: %w", err)
	}

	entry.PrevHash = prevHash
	entry.SeqNum = seqNum + 1
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}
	entry.Hash = calculateHash(entry)

	_, err = tx.ExecContext(ctx,
		"INSERT INTO ledger (seq_num, timestamp, agent, tool, decision, policy_rule, payload_hash, prev_hash, hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
		entry.SeqNum, entry.Timestamp, entry.Agent, entry.Tool, entry.Decision, entry.PolicyRule, entry.PayloadHash, entry.PrevHash, entry.Hash,
	)
	if err != nil {
		return fmt.Errorf("failed to insert ledger entry: %w", err)
	}

	return tx.Commit()
}

func (s *Store) Verify(ctx context.Context) (bool, error) {
	sqlDB := s.q.DB()
	rows, err := sqlDB.QueryContext(ctx, "SELECT seq_num, timestamp, agent, tool, decision, policy_rule, payload_hash, prev_hash, hash FROM ledger ORDER BY seq_num ASC")
	if err != nil {
		return false, fmt.Errorf("failed to query ledger: %w", err)
	}
	defer rows.Close()

	var prevHash string
	for rows.Next() {
		var entry db.LedgerEntry
		if err := rows.Scan(&entry.SeqNum, &entry.Timestamp, &entry.Agent, &entry.Tool, &entry.Decision, &entry.PolicyRule, &entry.PayloadHash, &entry.PrevHash, &entry.Hash); err != nil {
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