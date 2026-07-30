package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	
	"github.com/austinchima/kiterail/internal/events"
)

type SSEHandler struct {
	subscriber *events.Subscriber
}

func NewSSEHandler(sub *events.Subscriber) *SSEHandler {
	return &SSEHandler{subscriber: sub}
}

func (h *SSEHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Set headers for SSE
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// CORS is handled by the outer middleware, but just in case for older proxies
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	ch := h.subscriber.Subscribe()
	defer h.subscriber.Unsubscribe(ch)
	
	fmt.Fprintf(w, "event: connected\ndata: {}\n\n")
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-ch:
			data, err := json.Marshal(event)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", string(data))
			flusher.Flush()
		}
	}
}
