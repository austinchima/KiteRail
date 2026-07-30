package quarantine

import (
	"encoding/json"
	"net/http"
	"strings"

	"go.uber.org/zap"

	"github.com/austinchima/kiterail/internal/events"
	"github.com/austinchima/kiterail/internal/ledger"
)

// Handler exposes REST endpoints for the quarantine queue.
type Handler struct {
	store   *Store
	pub     *events.Publisher
	lStore  *ledger.Store
	logger  *zap.Logger
}

// NewHandler creates a new quarantine HTTP handler.
func NewHandler(store *Store, pub *events.Publisher, lStore *ledger.Store, logger *zap.Logger) *Handler {
	return &Handler{
		store:  store,
		pub:    pub,
		lStore: lStore,
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

	if err := h.store.Approve(r.Context(), id, body.ApprovedBy); err != nil {
		h.logger.Error("failed to approve", zap.Error(err))
		http.Error(w, `{"error": "failed to approve"}`, http.StatusNotFound)
		return
	}

	// Publish audit event & record in tamper-evident ledger
	if h.pub != nil {
		_ = h.pub.PublishAudit(r.Context(), map[string]interface{}{
			"type":          "quarantine_approval",
			"quarantine_id": id,
			"approved_by":   body.ApprovedBy,
		})
	}
	if h.lStore != nil {
		_ = h.lStore.Append(r.Context(), ledger.LedgerEntry{
			Agent:       body.ApprovedBy,
			Tool:        "quarantine.approve",
			Decision:    "approved",
			PolicyRule:  "hitl_approval",
			PayloadHash: id,
		})
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "approved", "id": id})
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
		h.logger.Error("failed to deny", zap.Error(err))
		http.Error(w, `{"error": "failed to deny"}`, http.StatusNotFound)
		return
	}

	// Publish audit event & record in tamper-evident ledger
	if h.pub != nil {
		_ = h.pub.PublishAudit(r.Context(), map[string]interface{}{
			"type":          "quarantine_denial",
			"quarantine_id": id,
			"denied_by":     body.DeniedBy,
			"reason":        body.Reason,
		})
	}
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
