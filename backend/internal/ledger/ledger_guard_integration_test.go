package ledger

import (
	"context"
	"testing"

	"github.com/austinchima/elodea/internal/db"
	"github.com/austinchima/elodea/internal/dbtest"
	"github.com/stretchr/testify/require"
)

func seedLedger(t *testing.T, store *Store, n int) {
	t.Helper()
	agents := []string{"agent_a", "agent_b"}
	decisions := []string{"allow", "deny", "quarantine"}
	for i := range n {
		require.NoError(t, store.Append(context.Background(), db.LedgerEntry{
			Agent: agents[i%len(agents)], Tool: "tool", Decision: decisions[i%len(decisions)],
			PolicyRule: "rule", PayloadHash: "hash",
		}))
	}
}

// Migration 005: the database itself refuses to rewrite history.
func TestLedger_AppendOnlyEnforcedByDatabase(t *testing.T) {
	sqlDB := openTestDB(t)
	store, err := New(sqlDB)
	require.NoError(t, err)
	dbtest.Reset(t, sqlDB, "ledger")
	seedLedger(t, store, 2)

	ctx := context.Background()
	_, err = sqlDB.ExecContext(ctx, "UPDATE ledger SET decision = 'allow' WHERE seq_num = 1")
	require.ErrorContains(t, err, "append-only")
	_, err = sqlDB.ExecContext(ctx, "DELETE FROM ledger WHERE seq_num = 2")
	require.ErrorContains(t, err, "append-only")
	_, err = sqlDB.ExecContext(ctx, "TRUNCATE ledger")
	require.ErrorContains(t, err, "append-only")

	valid, err := store.Verify(ctx)
	require.NoError(t, err)
	require.True(t, valid)
}

func TestLedger_PageHeadAndAnchoredVerify(t *testing.T) {
	sqlDB := openTestDB(t)
	store, err := New(sqlDB)
	require.NoError(t, err)
	dbtest.Reset(t, sqlDB, "ledger")
	seedLedger(t, store, 7)
	ctx := context.Background()

	page, err := store.Page(ctx, PageQuery{Limit: 3})
	require.NoError(t, err)
	require.Len(t, page, 3)
	require.Equal(t, int64(7), page[0].SeqNum)
	next, err := store.Page(ctx, PageQuery{Limit: 3, BeforeSeq: page[2].SeqNum})
	require.NoError(t, err)
	require.Equal(t, int64(4), next[0].SeqNum)

	denies, err := store.Page(ctx, PageQuery{Limit: 100, Decision: "deny", Agent: "agent_b"})
	require.NoError(t, err)
	for _, e := range denies {
		require.Equal(t, "deny", e.Decision)
		require.Equal(t, "agent_b", e.Agent)
	}

	head, ok, err := store.Head(ctx)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, int64(7), head.SeqNum)

	report, err := store.VerifyChain(ctx, &Anchor{SeqNum: head.SeqNum, Hash: head.Hash})
	require.NoError(t, err)
	require.True(t, report.Valid)
	require.Equal(t, int64(7), report.Entries)
	require.Equal(t, head.Hash, report.HeadHash)

	// A tail truncation (privileged maintenance) leaves a self-consistent
	// chain; only the external anchor catches it.
	tx, err := sqlDB.BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx, "SET LOCAL kiterail.ledger_maintenance = 'on'")
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx, "DELETE FROM ledger WHERE seq_num > 5")
	require.NoError(t, err)
	require.NoError(t, tx.Commit())

	plain, err := store.VerifyChain(ctx, nil)
	require.NoError(t, err)
	require.True(t, plain.Valid, "a truncated chain is still internally consistent")

	anchored, err := store.VerifyChain(ctx, &Anchor{SeqNum: head.SeqNum, Hash: head.Hash})
	require.NoError(t, err)
	require.False(t, anchored.Valid)
	require.Equal(t, int64(7), anchored.FirstInvalidSeq)

	var streamed []int64
	require.NoError(t, store.Stream(ctx, 2, func(e db.LedgerEntry) error {
		streamed = append(streamed, e.SeqNum)
		return nil
	}))
	require.Equal(t, []int64{3, 4, 5}, streamed)
}
