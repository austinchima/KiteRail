// Command mock-upstream is a minimal MCP tool server for load tests. It
// answers every JSON-RPC call immediately, so a benchmark measures Elodea
// rather than the tool behind it, and it counts the calls it received so the
// fail-closed test can compare what was forwarded against the ledger.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

var toolCalls atomic.Int64

func main() {
	addr := ":8082"
	if v := os.Getenv("MOCK_ADDR"); v != "" {
		addr = v
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /__stats", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int64{"tool_calls": toolCalls.Load()})
	})
	mux.HandleFunc("POST /__reset", func(w http.ResponseWriter, _ *http.Request) {
		toolCalls.Store(0)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/", handleRPC)

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("mock-upstream listening on %s", addr)
	log.Fatal(srv.ListenAndServe())
}

func handleRPC(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON-RPC body", http.StatusBadRequest)
		return
	}
	toolCalls.Add(1)
	if len(req.ID) == 0 {
		req.ID = json.RawMessage("null")
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"ok"}],"isError":false}}`, req.ID)
}
