package quarantine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/austinchima/kiterail/internal/db"
	"github.com/austinchima/kiterail/internal/ledger"
)

// defaultMaxReplayAttempts is the production retry limit.
const defaultMaxReplayAttempts = 3

// defaultReplayBackoff is the production wait between retry attempts.
// Two entries cover the gap between attempt-0→1 and attempt-1→2.
var defaultReplayBackoff = []time.Duration{time.Second, 3 * time.Second}

// Handler exposes REST endpoints for the quarantine queue.
type Handler struct {
	store             *Store
	lStore            *ledger.Store
	logger            *zap.Logger
	targetURL         string
	httpClient        *http.Client
	maxReplayAttempts int
	replayBackoff     []time.Duration
}

// NewHandler creates a new quarantine HTTP handler.
// targetURL is the downstream API to replay approved requests against.
func NewHandler(store *Store, lStore *ledger.Store, logger *zap.Logger, targetURL string) *Handler {
	return &Handler{
		store:     store,
		lStore:    lStore,
		logger:    logger,
		targetURL: targetURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		maxReplayAttempts: defaultMaxReplayAttempts,
		replayBackoff:     defaultReplayBackoff,
	}
}

// ServeHTTP routes quarantine API requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/quarantine")
	path = strings.TrimPrefix(path, "/")

	switch {
	case r.Method == http.MethodGet && path == "":
		h.listPending(w, r)
	case r.Method == http.MethodGet && path != "":
		h.getEntry(w, r, path)
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/approve"):
		id := strings.TrimSuffix(path, "/approve")
		h.approveEntry(w, r, id)
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/deny"):
		id := strings.TrimSuffix(path, "/deny")
		h.denyEntry(w, r, id)
	default:
		http.Error(w, `{"error": "not found"}`, http.StatusNotFound)
	}
}

func (h *Handler) listPending(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	if status == "" {
		status = "pending"
	}
	entries, err := h.store.List(r.Context(), status)
	if err != nil {
		h.logger.Error("failed to list quarantine", zap.Error(err))
		http.Error(w, `{"error": "internal server error"}`, http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(entries)
}

func (h *Handler) getEntry(w http.ResponseWriter, r *http.Request, id string) {
	entry, err := h.store.Get(r.Context(), id)
	if err != nil {
		h.logger.Error("failed to get quarantine entry", zap.Error(err))
		http.Error(w, `{"error": "not found"}`, http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(entry)
}

func (h *Handler) approveEntry(w http.ResponseWriter, r *http.Request, id string) {
	var body struct {
		ApprovedBy string `json:"approved_by"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if body.ApprovedBy == "" {
		body.ApprovedBy = "api"
	}

	// Fetch the stored entry before marking it approved so we have the payload.
	entry, err := h.store.Get(r.Context(), id)
	if err != nil {
		h.logger.Error("quarantine entry not found", zap.String("id", id), zap.Error(err))
		http.Error(w, `{"error": "quarantine item not found"}`, http.StatusNotFound)
		return
	}

	// Mark as approved — conflict-safe; returns ErrAlreadyResolved if already done.
	if err := h.store.Approve(r.Context(), id, body.ApprovedBy); err != nil {
		if errors.Is(err, ErrAlreadyResolved) {
			http.Error(w, `{"error": "quarantine item already resolved"}`, http.StatusConflict)
			return
		}
		h.logger.Error("failed to approve", zap.String("id", id), zap.Error(err))
		http.Error(w, `{"error": "failed to approve"}`, http.StatusInternalServerError)
		return
	}

	// Respond immediately — the human's decision is recorded. Replay happens
	// asynchronously so the reviewer is never blocked on downstream latency or
	// transient failures.
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "approved", "id": id})

	// Fire replay in a goroutine. Use context.Background() so it outlives the
	// HTTP request context. entryCopy prevents a data race on the pointer.
	entryCopy := entry
	approvedBy := body.ApprovedBy
	go h.replayWithRetry(context.Background(), id, entryCopy, approvedBy)
}

// replayWithRetry attempts to replay the approved payload up to maxReplayAttempts
// times with exponential backoff between attempts. It is intended to be called
// in a goroutine — it blocks until the replay succeeds or all attempts are
// exhausted, then marks the item as replay_failed if needed.
func (h *Handler) replayWithRetry(ctx context.Context, id string, entry db.QuarantineEntry, approvedBy string) {
	for attempt := 0; attempt < h.maxReplayAttempts; attempt++ {
		if attempt > 0 {
			delay := h.replayBackoff[attempt-1]
			select {
			case <-ctx.Done():
				h.logger.Warn("replay context cancelled before retry",
					zap.String("id", id), zap.Int("attempt", attempt))
				h.markReplayFailed(ctx, id)
				return
			case <-time.After(delay):
			}
		}

		if err := h.doReplay(ctx, id, entry, approvedBy); err == nil {
			return // success — ledger entry already written inside doReplay
		} else {
			h.logger.Warn("replay attempt failed",
				zap.String("id", id),
				zap.Int("attempt", attempt+1),
				zap.Int("maxAttempts", h.maxReplayAttempts),
				zap.Error(err),
			)
		}
	}

	h.logger.Error("all replay attempts exhausted, marking as replay_failed",
		zap.String("id", id),
		zap.Int("attempts", h.maxReplayAttempts),
	)
	h.markReplayFailed(ctx, id)
}

// doReplay performs a single replay attempt — POSTs the stored payload to the
// target and records a ledger entry. It does NOT handle retries or status
// transitions; those are managed by replayWithRetry.
func (h *Handler) doReplay(ctx context.Context, id string, entry db.QuarantineEntry, approvedBy string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.targetURL, bytes.NewReader(entry.Payload))
	if err != nil {
		return fmt.Errorf("failed to build replay request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-KiteRail-Agent", entry.AgentID)
	req.Header.Set("X-KiteRail-Quarantine-ID", id)
	req.Header.Set("X-KiteRail-Approved-By", approvedBy)

	resp, err := h.httpClient.Do(req)
	if err != nil {
		h.recordReplayLedger(ctx, id, entry, approvedBy, "replay_error")
		return fmt.Errorf("upstream request failed: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		h.recordReplayLedger(ctx, id, entry, approvedBy, fmt.Sprintf("replay_upstream_%d", resp.StatusCode))
		return fmt.Errorf("upstream returned %d", resp.StatusCode)
	}

	h.recordReplayLedger(ctx, id, entry, approvedBy, "approved_replayed")
	return nil
}

// markReplayFailed transitions the quarantine row to 'replay_failed' so it
// reappears in the PENDING inbox. Errors are logged but do not propagate —
// this is best-effort cleanup after a failed replay.
func (h *Handler) markReplayFailed(ctx context.Context, id string) {
	if err := h.store.MarkReplayFailed(ctx, id); err != nil {
		h.logger.Error("failed to mark quarantine as replay_failed",
			zap.String("id", id),
			zap.Error(err),
		)
	}
}

// recordReplayLedger appends a HITL approval + replay outcome entry to the
// tamper-evident ledger. Errors are logged but do not propagate.
func (h *Handler) recordReplayLedger(ctx context.Context, id string, entry db.QuarantineEntry, approvedBy, decision string) {
	if h.lStore == nil {
		return
	}
	if err := h.lStore.Append(ctx, db.LedgerEntry{
		Agent:       approvedBy,
		Tool:        entry.ToolName,
		Decision:    decision,
		PolicyRule:  "hitl_approval",
		PayloadHash: id,
	}); err != nil {
		h.logger.Error("failed to write replay ledger entry", zap.String("id", id), zap.Error(err))
	}
}

func (h *Handler) denyEntry(w http.ResponseWriter, r *http.Request, id string) {
	var body struct {
		DeniedBy string `json:"denied_by"`
		Reason   string `json:"reason"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if body.DeniedBy == "" {
		body.DeniedBy = "api"
	}

	if err := h.store.Deny(r.Context(), id, body.DeniedBy, body.Reason); err != nil {
		if errors.Is(err, ErrAlreadyResolved) {
			http.Error(w, `{"error": "quarantine item already resolved"}`, http.StatusConflict)
			return
		}
		h.logger.Error("failed to deny", zap.String("id", id), zap.Error(err))
		http.Error(w, `{"error": "failed to deny"}`, http.StatusNotFound)
		return
	}

	// Record HITL denial in tamper-evident ledger.
	if h.lStore != nil {
		_ = h.lStore.Append(r.Context(), db.LedgerEntry{
			Agent:       body.DeniedBy,
			Tool:        "quarantine.deny",
			Decision:    "denied",
			PolicyRule:  "hitl_denial",
			PayloadHash: id,
		})
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "denied", "id": id})
}
