package db

import (
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestQuarantineEntryJSON_NullTimesAndStableKeys(t *testing.T) {
	entry := QuarantineEntry{ID: "q1", AgentID: "a", ToolName: "t", Payload: []byte(`{"x":1}`), Status: "pending", CreatedAt: time.Unix(0, 0).UTC()}
	out, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{`"ResolvedAt":null`, `"ReplayedAt":null`, `"Payload":"eyJ4IjoxfQ=="`, `"RequestHeaders":{}`, `"AgentID":"a"`} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %s in %s", want, s)
		}
	}

	entry.ResolvedAt = sql.NullTime{Time: time.Unix(60, 0).UTC(), Valid: true}
	out, _ = json.Marshal(entry)
	if !strings.Contains(string(out), `"ResolvedAt":"1970-01-01T00:01:00Z"`) {
		t.Fatalf("resolved time not rendered: %s", out)
	}
}
