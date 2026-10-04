package ledger

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/austinchima/elodea/internal/db"
	"github.com/austinchima/elodea/internal/dbtest"
)

// Benchmarks for the audit ledger. The hashing benchmark needs nothing; the
// rest need Postgres (ELODEA_POSTGRES_DSN) and skip without it. They truncate
// the ledger table, so never point them at a database you care about.
//
//	go test ./internal/ledger -run '^$' -bench . -benchmem
//
// ELODEA_BENCH_CHAIN_SIZE sets the chain length for BenchmarkVerifyChain
// (default 10000).

func BenchmarkCalculateHash(b *testing.B) {
	entry := benchEntry(42)
	entry.PrevHash = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
	b.ReportAllocs()
	for b.Loop() {
		_ = calculateHash(entry)
	}
}

// BenchmarkAppend is one append at a time: the per-call cost the proxy pays
// before it forwards anything.
func BenchmarkAppend(b *testing.B) {
	store := openBenchStore(b)
	ctx := context.Background()
	for i := 0; b.Loop(); i++ {
		if err := store.Append(ctx, benchEntry(i)); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	verifyAfterBench(b, store)
}

// BenchmarkAppendParallel shows contention: appends serialize on one
// advisory lock, so this is the ceiling on ledgered decisions per second.
func BenchmarkAppendParallel(b *testing.B) {
	store := openBenchStore(b)
	ctx := context.Background()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if err := store.Append(ctx, benchEntry(i)); err != nil {
				b.Error(err)
				return
			}
			i++
		}
	})
	b.StopTimer()
	verifyAfterBench(b, store)
}

// BenchmarkVerifyChain times a full recompute of every hash and link.
func BenchmarkVerifyChain(b *testing.B) {
	size := 10000
	if v := os.Getenv("ELODEA_BENCH_CHAIN_SIZE"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			b.Fatalf("ELODEA_BENCH_CHAIN_SIZE must be a positive integer, got %q", v)
		}
		size = n
	}
	sqlDB := dbtest.Open(b)
	dbtest.Reset(b, sqlDB, "ledger")
	seedChain(b, sqlDB, size)
	store, err := New(sqlDB)
	if err != nil {
		b.Fatal(err)
	}

	ctx := context.Background()
	for b.Loop() {
		report, err := store.VerifyChain(ctx, nil)
		if err != nil {
			b.Fatal(err)
		}
		if !report.Valid || report.Entries != int64(size) {
			b.Fatalf("verify: valid=%v entries=%d, want %d (%s)", report.Valid, report.Entries, size, report.Reason)
		}
	}
	b.ReportMetric(float64(size), "entries")
}

func openBenchStore(b *testing.B) *Store {
	b.Helper()
	sqlDB := dbtest.Open(b)
	dbtest.Reset(b, sqlDB, "ledger")
	store, err := New(sqlDB)
	if err != nil {
		b.Fatal(err)
	}
	return store
}

// verifyAfterBench proves the appends under load still form a valid chain.
func verifyAfterBench(b *testing.B, store *Store) {
	b.Helper()
	report, err := store.VerifyChain(context.Background(), nil)
	if err != nil {
		b.Fatal(err)
	}
	if !report.Valid {
		b.Fatalf("chain invalid after benchmark at seq %d: %s", report.FirstInvalidSeq, report.Reason)
	}
}

// seedChain writes a valid chain in one transaction. Going through Append
// would take one round trip and lock per entry, which only slows the setup.
func seedChain(b *testing.B, sqlDB *sql.DB, size int) {
	b.Helper()
	ctx := context.Background()
	tx, err := sqlDB.BeginTx(ctx, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer tx.Rollback()
	q := db.New(sqlDB).WithTx(tx)

	prev := ""
	start := normalizeTimestamp(time.Now().Add(-time.Duration(size) * time.Millisecond))
	for i := range size {
		entry := benchEntry(i)
		entry.SeqNum = int64(i + 1)
		entry.Timestamp = start.Add(time.Duration(i) * time.Millisecond)
		entry.PrevHash = prev
		entry.Hash = calculateHash(entry)
		if err := q.InsertLedgerEntry(ctx, db.InsertLedgerEntryParams(entry)); err != nil {
			b.Fatal(err)
		}
		prev = entry.Hash
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
}

func benchEntry(i int) db.LedgerEntry {
	return db.LedgerEntry{
		Agent:         "agent_bench",
		Tool:          "stripe.charge.refund",
		Decision:      "allow",
		PolicyRule:    "refund_under_limit",
		PayloadHash:   fmt.Sprintf("%064x", i),
		RequestID:     strconv.Itoa(i),
		PolicyVersion: "sha256:benchbenchbench0",
	}
}
