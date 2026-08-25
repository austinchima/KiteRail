package policystore

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/austinchima/kiterail/internal/opaengine"
	"github.com/austinchima/kiterail/internal/types"
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
	case http.MethodPatch, http.MethodPut, http.MethodPost:
		// Policies are immutable GitOps assets in v1.0: change them via git,
		// not the API. Runtime policy mutation would let a single compromised
		// admin credential rewrite the enforcement rulebook.
		http.Error(w, `{"error": "policies are immutable; modify via version control"}`, http.StatusMethodNotAllowed)
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

func (h *Handler) handleSimulate(w http.ResponseWriter, r *http.Request) {
	var input types.EvalInput
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
