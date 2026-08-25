package quarantine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/austinchima/kiterail/internal/db"
	"github.com/austinchima/kiterail/internal/ledger"
)

// defaultMaxReplayAttempts is the production retry limit per approval.
const defaultMaxReplayAttempts = 3

// Worker drains approved quarantine entries and replays them against the
// upstream target. State lives entirely in Postgres, so a crash at any point
// loses nothing: startup recovery returns in-flight entries to 'approved'
// and the worker re-claims them. The Idempotency-Key header lets tolerant
// upstreams deduplicate replays that were interrupted mid-flight.
type Worker struct {
	store             StoreAPI
	lStore            LedgerAppender
	logger            *zap.Logger
	targetURL         string
	httpClient        *http.Client
	maxReplayAttempts int
	pollInterval      time.Duration
	batchSize         int
}

// LedgerAppender is the slice of the ledger store needed for HITL entries.
type LedgerAppender interface {
	Append(ctx context.Context, entry db.LedgerEntry) error
}

func NewWorker(store StoreAPI, lStore *ledger.Store, logger *zap.Logger, targetURL string) *Worker {
	var appender LedgerAppender
	if lStore != nil {
		appender = lStore
	}
	return &Worker{
		store:             store,
		lStore:            appender,
		logger:            logger,
		targetURL:         targetURL,
		httpClient:        &http.Client{Timeout: 30 * time.Second},
		maxReplayAttempts: defaultMaxReplayAttempts,
		pollInterval:      2 * time.Second,
		batchSize:         10,
	}
}

// Run starts recovery and the claim loop. It blocks until ctx is cancelled.
func (wk *Worker) Run(ctx context.Context) {
	recovered, err := wk.store.RecoverStuckReplays(ctx)
	if err != nil {
		wk.logger.Error("startup replay recovery failed", zap.Error(err))
	} else if recovered > 0 {
		wk.logger.Warn("recovered quarantined entries stuck in 'replaying' from a previous run",
			zap.Int64("count", recovered))
	}

	ticker := time.NewTicker(wk.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			wk.drainOnce(ctx)
		}
	}
}

func (wk *Worker) drainOnce(ctx context.Context) {
	entries, err := wk.store.ClaimApproved(ctx, wk.batchSize)
	if err != nil {
		if !errors.Is(err, context.Canceled) && ctx.Err() == nil {
			wk.logger.Error("failed to claim approved entries", zap.Error(err))
		}
		return
	}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return
		}
		wk.processClaimed(ctx, entry)
	}
}

// processClaimed attempts one replay of a claimed ('replaying') entry. The
// claim already incremented attempts; on failure we either retry later (back
// to 'approved' while attempts remain) or park it as 'replay_failed' so it
// reappears in the reviewer inbox.
func (wk *Worker) processClaimed(ctx context.Context, entry db.QuarantineEntry) {
	approvedBy := entry.ResolvedBy
	if approvedBy == "" {
		approvedBy = "unknown"
	}
	outcome, err := wk.doReplay(ctx, entry.ID, entry, approvedBy)
	if err == nil {
		if markErr := wk.store.MarkReplayed(ctx, entry.ID); markErr != nil {
			wk.logger.Error("replay succeeded but status update failed",
				zap.String("id", entry.ID), zap.Error(markErr))
			return
		}
		wk.recordLedger(ctx, entry.ID, entry, approvedBy, "approved_replayed")
		return
	}

	wk.recordLedger(ctx, entry.ID, entry, approvedBy, outcome)
	wk.logger.Warn("replay attempt failed",
		zap.String("id", entry.ID),
		zap.Int("attempt", entry.Attempts),
		zap.String("outcome", outcome),
		zap.Error(err),
	)

	if entry.Attempts >= wk.maxReplayAttempts {
		wk.logger.Error("all replay attempts exhausted, marking as replay_failed",
			zap.String("id", entry.ID),
			zap.Int("attempts", entry.Attempts),
		)
		if err := wk.store.MarkReplayFailed(ctx, entry.ID); err != nil {
			wk.logger.Error("failed to mark replay_failed", zap.String("id", entry.ID), zap.Error(err))
		}
		return
	}
	if err := wk.store.ReturnToApproved(ctx, entry.ID); err != nil {
		wk.logger.Error("failed to release entry for retry", zap.String("id", entry.ID), zap.Error(err))
	}
}

// doReplay performs a single upstream POST of the stored payload.
func (wk *Worker) doReplay(ctx context.Context, id string, entry db.QuarantineEntry, approvedBy string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, wk.targetURL, bytes.NewReader(entry.Payload))
	if err != nil {
		return "replay_error", fmt.Errorf("failed to build replay request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-KiteRail-Agent", entry.AgentID)
	req.Header.Set("X-KiteRail-Quarantine-ID", id)
	req.Header.Set("X-KiteRail-Approved-By", approvedBy)
	// Durable idempotency marker: stable across retries AND crash recoveries.
	req.Header.Set("Idempotency-Key", "kiterail-quarantine-"+id)

	resp, err := wk.httpClient.Do(req)
	if err != nil {
		return "replay_error", fmt.Errorf("upstream request failed: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Sprintf("replay_upstream_%d", resp.StatusCode), fmt.Errorf("upstream returned %d", resp.StatusCode)
	}
	return "approved_replayed", nil
}

// recordLedger appends the HITL approval + replay outcome entry. Errors are
// logged but do not propagate — the durable state machine remains the source
// of truth for retries.
func (wk *Worker) recordLedger(ctx context.Context, id string, entry db.QuarantineEntry, approvedBy, decision string) {
	if wk.lStore == nil {
		return
	}
	if err := wk.lStore.Append(ctx, db.LedgerEntry{
		Agent:       approvedBy,
		Tool:        entry.ToolName,
		Decision:    decision,
		PolicyRule:  "hitl_approval",
		PayloadHash: id,
		RequestID:   id,
	}); err != nil {
		wk.logger.Error("failed to write replay ledger entry", zap.String("id", id), zap.Error(err))
	}
}
