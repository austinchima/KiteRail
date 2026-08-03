package quarantine

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/austinchima/kiterail/internal/ledger"
)

// Handler exposes REST endpoints for the quarantine queue.
type Handler struct {
	store      *Store
	lStore     *ledger.Store
	logger     *zap.Logger
	targetURL  string
	httpClient *http.Client
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

	// Replay the original payload to the downstream target.
	replayErr := h.replayToTarget(r, id, entry, body.ApprovedBy)
	if replayErr != nil {
		h.logger.Error("target replay failed",
			zap.String("id", id),
			zap.String("target", h.targetURL),
			zap.Error(replayErr),
		)
		http.Error(w,
			fmt.Sprintf(`{"error": "target replay failed", "explanation": %q}`, replayErr.Error()),
			http.StatusBadGateway,
		)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "approved", "id": id})
}

// replayToTarget forwards the stored payload to the downstream API and records
// the outcome in the ledger. On failure it also marks the quarantine row as
// 'replay_failed' so the item resurfaces in the PENDING inbox for retry.
// It returns a non-nil error only if the target call itself fails.
func (h *Handler) replayToTarget(r *http.Request, id string, entry QuarantineEntry, approvedBy string) error {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, h.targetURL, bytes.NewReader(entry.Payload))
	if err != nil {
		h.markReplayFailed(r, id)
		return fmt.Errorf("failed to build replay request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-KiteRail-Agent", entry.AgentID)
	req.Header.Set("X-KiteRail-Quarantine-ID", id)
	req.Header.Set("X-KiteRail-Approved-By", approvedBy)

	resp, err := h.httpClient.Do(req)
	if err != nil {
		h.recordReplayLedger(r, id, entry, approvedBy, "replay_error")
		h.markReplayFailed(r, id)
		return fmt.Errorf("upstream request failed: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		h.recordReplayLedger(r, id, entry, approvedBy, fmt.Sprintf("replay_upstream_%d", resp.StatusCode))
		h.markReplayFailed(r, id)
		return fmt.Errorf("upstream returned %d", resp.StatusCode)
	}

	h.recordReplayLedger(r, id, entry, approvedBy, "approved_replayed")
	return nil
}

// markReplayFailed transitions the quarantine row to 'replay_failed' so it
// reappears in the PENDING inbox. Errors are logged but do not fail the
// request — the 502 response to the reviewer is already set at this point.
func (h *Handler) markReplayFailed(r *http.Request, id string) {
	if err := h.store.MarkReplayFailed(r.Context(), id); err != nil {
		h.logger.Error("failed to mark quarantine as replay_failed",
			zap.String("id", id),
			zap.Error(err),
		)
	}
}

// recordReplayLedger appends a HITL approval + replay outcome entry to the
// tamper-evident ledger. Errors here are logged but do not fail the request —
// the approval and replay already happened.
func (h *Handler) recordReplayLedger(r *http.Request, id string, entry QuarantineEntry, approvedBy, decision string) {
	if h.lStore == nil {
		return
	}
	if err := h.lStore.Append(r.Context(), ledger.LedgerEntry{
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
		_ = h.lStore.Append(r.Context(), ledger.LedgerEntry{
			Agent:       body.DeniedBy,
			Tool:        "quarantine.deny",
			Decision:    "denied",
			PolicyRule:  "hitl_denial",
			PayloadHash: id,
		})
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "denied", "id": id})
}
