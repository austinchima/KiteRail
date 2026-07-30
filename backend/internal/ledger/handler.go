package ledger

import (
	"encoding/json"
	"net/http"

	"go.uber.org/zap"
)

// Handler handles ledger HTTP requests.
type Handler struct {
	store  *Store
	logger *zap.Logger
}

// NewHandler creates a new ledger HTTP handler.
func NewHandler(store *Store, logger *zap.Logger) *Handler {
	return &Handler{
		store:  store,
		logger: logger,
	}
}

// ServeHTTP routes the ledger requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/verify" || r.URL.Path == "/verify/" {
		h.handleVerify(w, r)
		return
	}

	h.handleQuery(w, r)
}

func (h *Handler) handleQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	entries, err := h.store.Query(r.Context())
	if err != nil {
		h.logger.Error("Failed to query ledger", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Make sure we return an empty array instead of null for zero entries
	if entries == nil {
		entries = []LedgerEntry{}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(entries); err != nil {
		h.logger.Error("Failed to encode ledger response", zap.Error(err))
	}
}

func (h *Handler) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	valid, err := h.store.Verify(r.Context())
	if err != nil {
		h.logger.Error("Failed to verify ledger", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"valid": valid,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("Failed to encode verify response", zap.Error(err))
	}
}
