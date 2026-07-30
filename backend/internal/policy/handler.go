package policy

import (
	"encoding/json"
	"net/http"
	"strings"

	"go.uber.org/zap"
)

// Handler represents the HTTP handler for policies.
type Handler struct {
	store  *Store
	logger *zap.Logger
}

// NewHandler creates a new policy handler.
func NewHandler(store *Store, logger *zap.Logger) *Handler {
	return &Handler{
		store:  store,
		logger: logger,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.handleList(w, r)
	case http.MethodPatch:
		h.handleUpdate(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) handleList(w http.ResponseWriter, r *http.Request) {
	policies, err := h.store.List(r.Context())
	if err != nil {
		h.logger.Error("Failed to list policies", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policies)
}

func (h *Handler) handleUpdate(w http.ResponseWriter, r *http.Request) {
	// Expected path: /api/v1/policies/{id}
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) == 0 {
		http.Error(w, "Missing policy ID", http.StatusBadRequest)
		return
	}
	id := parts[len(parts)-1]
	if id == "" || id == "policies" {
		http.Error(w, "Missing policy ID", http.StatusBadRequest)
		return
	}

	var req struct {
		Enabled      bool   `json:"enabled"`
		Confirmation string `json:"confirmation"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if !req.Enabled && req.Confirmation != "CONFIRM" {
		http.Error(w, "Missing or invalid confirmation to disable policy", http.StatusBadRequest)
		return
	}

	if err := h.store.UpdateEnabled(r.Context(), id, req.Enabled); err != nil {
		if err.Error() == "policy not found" {
			http.Error(w, "Policy not found", http.StatusNotFound)
			return
		}
		h.logger.Error("Failed to update policy", zap.String("id", id), zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}
