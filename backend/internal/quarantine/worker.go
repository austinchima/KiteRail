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
	"github.com/austinchima/kiterail/internal/mcp"
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
	targetAuthToken   string
	httpClient        *http.Client
	maxReplayAttempts int
	pollInterval      time.Duration
	batchSize         int
}

// WorkerOption customises a Worker after construction. Options keep the
// constructor stable when we add knobs — the same pattern proxy.NewHandler
// uses (see proxy.WithTargetAuthToken).
type WorkerOption func(*Worker)

// WithTargetAuthToken gives replays the same upstream credential as normal
// ALLOW requests (proxy.go applies it via its own Director). Without this an
// upstream that requires KITERAIL_TARGET_AUTH_TOKEN would reject every
// approved replay with 401/403. The token is used only for the outbound
// Authorization header — it is never persisted, logged, or copied into the
// audit ledger.
func WithTargetAuthToken(token string) WorkerOption {
	return func(wk *Worker) {
		wk.targetAuthToken = token
	}
}

// LedgerAppender is the slice of the ledger store needed for HITL entries.
type LedgerAppender interface {
	Append(ctx context.Context, entry db.LedgerEntry) error
}

func NewWorker(store StoreAPI, lStore *ledger.Store, logger *zap.Logger, targetURL string, opts ...WorkerOption) *Worker {
	var appender LedgerAppender
	if lStore != nil {
		appender = lStore
	}
	wk := &Worker{
		store:     store,
		lStore:    appender,
		logger:    logger,
		targetURL: targetURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			// A replay is one request, not a browser navigation. Returning a
			// redirect response makes it a retryable failure instead of silently
			// changing its destination or method on the worker's behalf.
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		maxReplayAttempts: defaultMaxReplayAttempts,
		pollInterval:      2 * time.Second,
		batchSize:         10,
	}
	for _, opt := range opts {
		opt(wk)
	}
	return wk
}

// Run starts the exclusive recovery-and-claim loop. It blocks until ctx is
// cancelled. Each pass holds a Postgres advisory lock, which prevents one
// replica from recovering another live replica's in-flight requests.
func (wk *Worker) Run(ctx context.Context) {
	wk.ProcessOnce(ctx)
	ticker := time.NewTicker(wk.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			wk.ProcessOnce(ctx)
		}
	}
}

// ProcessOnce runs a single claim-and-replay pass synchronously. Run calls
// it on every tick; tests and operators use it to drive the worker
// deterministically without sleeping for poll intervals.
func (wk *Worker) ProcessOnce(ctx context.Context) {
	acquired, err := wk.store.WithReplayLock(ctx, func(replayCtx context.Context) error {
		recovered, recoverErr := wk.store.RecoverStuckReplays(replayCtx)
		if recoverErr != nil {
			return fmt.Errorf("recover stuck replays: %w", recoverErr)
		}
		if recovered > 0 {
			wk.logger.Warn("recovered quarantined entries stuck in 'replaying' from a previous run",
				zap.Int64("count", recovered))
		}
		wk.drainOnce(replayCtx)
		return nil
	})
	if err != nil && !errors.Is(err, context.Canceled) && ctx.Err() == nil {
		wk.logger.Error("replay pass failed", zap.Error(err))
		return
	}
	if !acquired && ctx.Err() == nil {
		wk.logger.Debug("another server owns the replay pass")
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
// claim does NOT increment attempts — attempts increment when a failed replay
// is released (ReturnToApproved) and when a replay succeeds (MarkReplayed).
// On failure we either retry later (back to 'approved' while attempts remain)
// or park it as 'replay_failed' (once entry.Attempts reaches maxReplayAttempts)
// so it reappears in the reviewer inbox.
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
	replayHeaders, err := mcp.DecodeReplayHeaders(entry.RequestHeaders)
	if err != nil {
		return "replay_error", err
	}
	for name, values := range replayHeaders {
		req.Header[name] = append([]string(nil), values...)
	}

	// These headers are KiteRail-controlled execution metadata. Apply them
	// after stored MCP headers so a captured request cannot override them.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-KiteRail-Agent", entry.AgentID)
	req.Header.Set("X-KiteRail-Quarantine-ID", id)
	req.Header.Set("X-KiteRail-Approved-By", approvedBy)
	// Durable idempotency marker: stable across retries AND crash recoveries.
	req.Header.Set("Idempotency-Key", "kiterail-quarantine-"+id)
	// Authenticate to the upstream exactly like the ALLOW path does. The
	// token must never be persisted or logged — it stays in memory only.
	if wk.targetAuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+wk.targetAuthToken)
	}

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
