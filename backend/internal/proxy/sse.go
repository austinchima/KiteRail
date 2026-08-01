package proxy

import (
	"net/http"
)

// SSEHandler is a placeholder for the real-time topology stream.
// NATS-backed SSE streaming is deferred to v1.1. This endpoint returns 501
// so existing frontend code fails gracefully rather than hanging on a dead connection.
type SSEHandler struct{}

func NewSSEHandler() *SSEHandler {
	return &SSEHandler{}
}

func (h *SSEHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	http.Error(w, `{"error": "topology stream not available in v1.0 — planned for v1.1"}`, http.StatusNotImplemented)
}
