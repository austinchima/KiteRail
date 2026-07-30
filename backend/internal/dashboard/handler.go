package dashboard

import (
	"encoding/json"
	"net/http"

	"go.uber.org/zap"

	"github.com/austinchima/kiterail/internal/ledger"
	"github.com/austinchima/kiterail/internal/quarantine"
)

// Handler represents the HTTP handler for the dashboard.
type Handler struct {
	ledgerStore     *ledger.Store
	quarantineStore *quarantine.Store
	logger          *zap.Logger
}

// NewHandler creates a new dashboard handler.
func NewHandler(lStore *ledger.Store, qStore *quarantine.Store, logger *zap.Logger) *Handler {
	return &Handler{
		ledgerStore:     lStore,
		quarantineStore: qStore,
		logger:          logger,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	// 1. Get Ledger Stats
	stats, err := h.ledgerStore.Stats(ctx)
	if err != nil {
		h.logger.Error("Failed to get ledger stats", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 2. Get Pending Approvals
	pending, err := h.quarantineStore.List(ctx, "pending")
	if err != nil {
		h.logger.Error("Failed to list pending approvals", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 3. Get Recent Feed
	recent, err := h.ledgerStore.Query(ctx)
	if err != nil {
		h.logger.Error("Failed to query ledger", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Limit feed to last 10 for dashboard
	feed := recent
	if len(feed) > 10 {
		feed = feed[:10]
	}

	complianceStatus := 100.0
	if stats.TotalActionsToday > 0 {
		complianceStatus = (1.0 - (float64(stats.PolicyViolations) / float64(stats.TotalActionsToday))) * 100
	}

	resp := map[string]interface{}{
		"total_actions_today": stats.TotalActionsToday,
		"policy_violations":   stats.PolicyViolations,
		"pending_approvals":   pending,
		"compliance_status":   complianceStatus,
		"recent_feed":         feed,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
