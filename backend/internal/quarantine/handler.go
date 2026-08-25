package quarantine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"go.uber.org/zap"

	"github.com/austinchima/kiterail/internal/auth"
	"github.com/austinchima/kiterail/internal/db"
	"github.com/austinchima/kiterail/internal/ledger"
)

// StoreAPI is the persistence surface used by handler/worker (mockable).
type StoreAPI interface {
	Get(ctx context.Context, id string) (db.QuarantineEntry, error)
	List(ctx context.Context, status string) ([]db.QuarantineEntry, error)
	Approve(ctx context.Context, id, approvedBy string) error
	Deny(ctx context.Context, id, deniedBy, reason string) error
	ClaimApproved(ctx context.Context, limit int) ([]db.QuarantineEntry, error)
	MarkReplayed(ctx context.Context, id string) error
	MarkReplayFailed(ctx context.Context, id string) error
	ReturnToApproved(ctx context.Context, id string) error
	RecoverStuckReplays(ctx context.Context) (int64, error)
}

// Handler exposes REST endpoints for the quarantine queue.
//
// Approval/denial identity is ALWAYS derived from the authenticated
// reviewer/admin identity in the request context — never from the request
// body, which any agent could forge.
type Handler struct {
	store  StoreAPI
	lStore LedgerAppender
	logger *zap.Logger
}

// NewHandler creates a new quarantine HTTP handler.
func NewHandler(store StoreAPI, lStore *ledger.Store, logger *zap.Logger) *Handler {
	var appender LedgerAppender
	if lStore != nil {
		appender = lStore
	}
	return &Handler{
		store:  store,
		lStore: appender,
		logger: logger,
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
		status = StatusPending
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

// reviewerIdentity returns the authenticated human identity for HITL routes.
func reviewerIdentity(r *http.Request) (string, bool) {
	identity, ok := auth.FromContext(r.Context())
	if !ok || (identity.Role != auth.RoleReviewer && identity.Role != auth.RoleAdmin) {
		return "", false
	}
	return identity.ID, true
}

// approveEntry persists the human approval. Replay is NOT performed here —
// the durable Worker picks the 'approved' entry up from Postgres and owns all
// retry/state transitions, so a crash after this response loses nothing.
func (h *Handler) approveEntry(w http.ResponseWriter, r *http.Request, id string) {
	reviewerID, ok := reviewerIdentity(r)
	if !ok {
		http.Error(w, `{"error": "reviewer or admin role required"}`, http.StatusForbidden)
		return
	}

	// Fetch before marking so we can log tool context on failure paths.
	if _, err := h.store.Get(r.Context(), id); err != nil {
		h.logger.Error("quarantine entry not found", zap.String("id", id), zap.Error(err))
		http.Error(w, `{"error": "quarantine item not found"}`, http.StatusNotFound)
		return
	}

	if err := h.store.Approve(r.Context(), id, reviewerID); err != nil {
		if errors.Is(err, ErrAlreadyResolved) {
			http.Error(w, `{"error": "quarantine item already resolved"}`, http.StatusConflict)
			return
		}
		h.logger.Error("failed to approve", zap.String("id", id), zap.Error(err))
		http.Error(w, `{"error": "failed to approve"}`, http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "approved", "id": id})
}

func (h *Handler) denyEntry(w http.ResponseWriter, r *http.Request, id string) {
	reviewerID, ok := reviewerIdentity(r)
	if !ok {
		http.Error(w, `{"error": "reviewer or admin role required"}`, http.StatusForbidden)
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	json.NewDecoder(r.Body).Decode(&body)

	if err := h.store.Deny(r.Context(), id, reviewerID, body.Reason); err != nil {
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
		if err := h.lStore.Append(r.Context(), db.LedgerEntry{
			Agent:       reviewerID,
			Tool:        "quarantine.deny",
			Decision:    "denied",
			PolicyRule:  "hitl_denial",
			PayloadHash: id,
			RequestID:   id,
		}); err != nil {
			h.logger.Error("failed to write denial ledger entry", zap.String("id", id), zap.Error(err))
		}
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "denied", "id": id})
}
