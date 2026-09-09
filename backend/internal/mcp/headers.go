package mcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// CaptureReplayHeaders returns an independent copy of transport metadata needed
// to replay the same MCP request. Credentials, cookies, connection headers, and
// unrelated application headers are excluded; replay supplies its own service
// identity. Encoded values are preserved byte-for-byte, including custom MCP
// parameter headers whose schema is owned by the upstream server.
func CaptureReplayHeaders(header http.Header) http.Header {
	captured := make(http.Header)
	for name, values := range header {
		lowerName := strings.ToLower(name)
		switch lowerName {
		case "accept", "mcp-method", "mcp-name", "mcp-protocol-version":
		default:
			if !strings.HasPrefix(lowerName, "mcp-param-") || lowerName == "mcp-param-" {
				continue
			}
		}
		for _, value := range values {
			captured.Add(name, value)
		}
	}
	return captured
}

// DecodeReplayHeaders restores the allowlisted transport metadata stored with
// a quarantined request. It filters the decoded value a second time so old or
// manually edited rows cannot reintroduce credentials into an outbound replay.
func DecodeReplayHeaders(encoded []byte) (http.Header, error) {
	if len(encoded) == 0 {
		return make(http.Header), nil
	}

	var stored http.Header
	if err := json.Unmarshal(encoded, &stored); err != nil {
		return nil, fmt.Errorf("decode stored replay headers: %w", err)
	}
	return CaptureReplayHeaders(stored), nil
}
