package ledger

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"time"

	"github.com/austinchima/elodea/internal/db"
	"github.com/austinchima/elodea/internal/metrics"
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
	// Appended only when set, so entries written before policy versioning
	// keep their original hashes and existing chains still verify.
	if entry.PolicyVersion != "" {
		fields = append(fields, entry.PolicyVersion)
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

// appendLockKey is the transaction-scoped advisory lock that serializes chain
// appends across every replica.
const appendLockKey = 918273647

func (s *Store) Append(ctx context.Context, entry db.LedgerEntry) error {
	start := time.Now()
	err := s.appendWithRetry(ctx, entry)
	metrics.LedgerAppendDuration.Observe(time.Since(start).Seconds())
	if err != nil {
		metrics.LedgerAppendFailuresTotal.Inc()
	}
	return err
}

func (s *Store) appendWithRetry(ctx context.Context, entry db.LedgerEntry) error {
	// Appends queue on an advisory lock instead of racing under SERIALIZABLE,
	// so contention waits rather than aborting. The retry loop remains as a
	// bounded, cancellable fallback should Postgres still report SQLSTATE 40001.
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
	tx, err := sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin tx: %w", err)
	}
	defer tx.Rollback()

	// Held until commit, after which the next waiter's READ COMMITTED snapshot
	// sees this entry as the chain tip.
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", appendLockKey); err != nil {
		return fmt.Errorf("failed to lock ledger chain: %w", err)
	}

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

	err = qtx.InsertLedgerEntry(ctx, db.InsertLedgerEntryParams(entry))
	if err != nil {
		return fmt.Errorf("failed to insert ledger entry: %w", err)
	}

	return tx.Commit()
}

// Anchor is a chain head recorded outside the database (object-locked
// storage, a transparency log, a ticket). Verifying against an anchor detects
// truncation or wholesale rewrites that a self-consistent chain cannot.
type Anchor struct {
	SeqNum int64  `json:"seq_num"`
	Hash   string `json:"hash"`
}

// VerifyReport describes a full-chain verification.
type VerifyReport struct {
	Valid           bool   `json:"valid"`
	Entries         int64  `json:"entries"`
	HeadSeq         int64  `json:"head_seq"`
	HeadHash        string `json:"head_hash"`
	FirstInvalidSeq int64  `json:"first_invalid_seq,omitempty"`
	Reason          string `json:"reason,omitempty"`
}

var errStopStream = errors.New("stop ledger stream")

// Stream calls fn for every entry with seq_num > afterSeq in chain order,
// holding one connection and O(1) memory regardless of ledger size.
func (s *Store) Stream(ctx context.Context, afterSeq int64, fn func(db.LedgerEntry) error) error {
	const columns = "SELECT seq_num, timestamp, agent, tool, decision, policy_rule, payload_hash, prev_hash, hash, request_id, policy_version FROM ledger"
	var (
		rows *sql.Rows
		err  error
	)
	if afterSeq > 0 {
		rows, err = s.q.DB().QueryContext(ctx, columns+" WHERE seq_num > $1 ORDER BY seq_num ASC", afterSeq)
	} else {
		rows, err = s.q.DB().QueryContext(ctx, columns+" ORDER BY seq_num ASC")
	}
	if err != nil {
		return fmt.Errorf("failed to query ledger: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var entry db.LedgerEntry
		if err := rows.Scan(&entry.SeqNum, &entry.Timestamp, &entry.Agent, &entry.Tool, &entry.Decision, &entry.PolicyRule, &entry.PayloadHash, &entry.PrevHash, &entry.Hash, &entry.RequestID, &entry.PolicyVersion); err != nil {
			return fmt.Errorf("failed to scan ledger entry: %w", err)
		}
		if err := fn(entry); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating ledger rows: %w", err)
	}
	return nil
}

// VerifyChain recomputes every hash and link. With an anchor, the anchored
// entry must still exist with the anchored hash.
func (s *Store) VerifyChain(ctx context.Context, anchor *Anchor) (VerifyReport, error) {
	report := VerifyReport{Valid: true}
	anchorSeen := false
	fail := func(seq int64, reason string) error {
		report.Valid = false
		report.FirstInvalidSeq = seq
		report.Reason = reason
		return errStopStream
	}
	err := s.Stream(ctx, 0, func(entry db.LedgerEntry) error {
		report.Entries++
		if entry.PrevHash != report.HeadHash {
			return fail(entry.SeqNum, "prev_hash does not link to the previous entry")
		}
		if entry.Hash != calculateHash(entry) {
			return fail(entry.SeqNum, "hash does not match entry contents")
		}
		if anchor != nil && entry.SeqNum == anchor.SeqNum {
			anchorSeen = true
			if entry.Hash != anchor.Hash {
				return fail(entry.SeqNum, "entry differs from the external anchor")
			}
		}
		report.HeadSeq, report.HeadHash = entry.SeqNum, entry.Hash
		return nil
	})
	if err != nil && !errors.Is(err, errStopStream) {
		return VerifyReport{}, err
	}
	if report.Valid && anchor != nil && !anchorSeen {
		report.Valid = false
		report.FirstInvalidSeq = anchor.SeqNum
		report.Reason = "anchored entry is missing (ledger truncated or rewritten)"
	}
	return report, nil
}

func (s *Store) Verify(ctx context.Context) (bool, error) {
	report, err := s.VerifyChain(ctx, nil)
	return report.Valid, err
}

// Head returns the current chain head for external anchoring; ok is false for
// an empty ledger.
func (s *Store) Head(ctx context.Context) (db.GetLedgerHeadRow, bool, error) {
	head, err := s.q.GetLedgerHead(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return head, false, nil
	}
	if err != nil {
		return head, false, fmt.Errorf("failed to read ledger head: %w", err)
	}
	return head, true, nil
}

// PageQuery selects a newest-first page. BeforeSeq <= 0 starts at the head.
type PageQuery struct {
	BeforeSeq int64
	Limit     int
	Agent     string
	Decision  string
	Tool      string
}

func (s *Store) Page(ctx context.Context, p PageQuery) ([]db.LedgerEntry, error) {
	before := p.BeforeSeq
	if before <= 0 {
		before = math.MaxInt64
	}
	entries, err := s.q.ListLedgerPage(ctx, db.ListLedgerPageParams{
		BeforeSeq: before,
		Agent:     p.Agent,
		Decision:  p.Decision,
		Tool:      p.Tool,
		PageSize:  int32(p.Limit),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query ledger page: %w", err)
	}
	return entries, nil
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
