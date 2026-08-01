package policystore

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/austinchima/kiterail/internal/opaengine"
	"github.com/austinchima/kiterail/internal/proxy"
	"go.uber.org/zap"
)

// Handler represents the HTTP handler for policies.
type Handler struct {
	store  *Store
	engine *opaengine.Engine
	logger *zap.Logger
}

// NewHandler creates a new policy handler.
func NewHandler(store *Store, engine *opaengine.Engine, logger *zap.Logger) *Handler {
	return &Handler{
		store:  store,
		engine: engine,
		logger: logger,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/simulate") {
		h.handleSimulate(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.handleList(w, r)
	case http.MethodPatch:
		h.handleUpdate(w, r)
	case http.MethodPut, http.MethodPost:
		h.handleSave(w, r)
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
		h.logger.Error("Failed to update policy", zap.String("id", id), zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	h.engine.Reload(r.Context())

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func (h *Handler) handleSave(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	var id string
	if len(parts) > 0 {
		id = parts[len(parts)-1]
	}
	if id == "" || id == "policies" {
		http.Error(w, "Missing policy ID", http.StatusBadRequest)
		return
	}

	var req struct {
		Code    string `json:"code"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.store.Save(r.Context(), id, req.Code, req.Enabled); err != nil {
		h.logger.Error("Failed to save policy", zap.String("id", id), zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	h.engine.Reload(r.Context())

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func (h *Handler) handleSimulate(w http.ResponseWriter, r *http.Request) {
	var input proxy.EvalInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Default values for simulation if omitted
	if input.Timestamp.IsZero() {
		input.Timestamp = time.Now()
	}
	if input.Agent == "" {
		input.Agent = "simulator"
	}
	if input.RawMethod == "" {
		input.RawMethod = "tools/call"
	}

	start := time.Now()
	decision, err := h.engine.Evaluate(r.Context(), input)
	decision.LatencyMs = time.Since(start).Seconds() * 1000

	if err != nil {
		h.logger.Error("Simulation failed", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(decision)
}
