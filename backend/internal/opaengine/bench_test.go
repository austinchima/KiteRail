package opaengine

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/austinchima/elodea/internal/types"
)

// Benchmarks for one policy decision against the repository bundle. Run with:
//
//	go test ./internal/opaengine -run '^$' -bench . -benchmem -count 5
//
// Each case reaches a different rule so the numbers cover the cheap path
// (default deny) and the most expensive one (regex PII scan).
func BenchmarkEvaluate(b *testing.B) {
	engine := newRepositoryEngine(b)

	cases := []struct {
		name   string
		input  types.EvalInput
		action types.Action
	}{
		{"allow_small_refund", benchInput("stripe.charge.refund", map[string]any{"amount": 100}), types.ActionAllow},
		{"quarantine_large_refund", benchInput("stripe.charge.refund", map[string]any{"amount": 1500}), types.ActionQuarantine},
		{"deny_sanctioned_wire", benchInput("swift.wire.initiate", map[string]any{"amount": 500, "jurisdiction": "SANCTIONED"}), types.ActionDeny},
		{"deny_ssn_in_arguments", benchInput("crm.note.create", map[string]any{"ssn": "123-45-6789"}), types.ActionDeny},
		{"default_deny_unknown_tool", benchInput("unknown.tool", map[string]any{}), types.ActionDeny},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			ctx := context.Background()
			// Check the case once, outside the timer, so a policy change
			// can't silently turn the benchmark into a default-deny run.
			got, _ := engine.Evaluate(ctx, tc.input)
			if got.Action != tc.action {
				b.Fatalf("expected %s, got %s (%s)", tc.action, got.Action, got.Rule)
			}
			b.ReportAllocs()
			for b.Loop() {
				_, _ = engine.Evaluate(ctx, tc.input)
			}
		})
	}
}

// BenchmarkEvaluateParallel measures decisions per second across all cores,
// which is the shape the proxy sees under concurrent agents.
func BenchmarkEvaluateParallel(b *testing.B) {
	engine := newRepositoryEngine(b)
	input := benchInput("stripe.charge.refund", map[string]any{"amount": 100})
	ctx := context.Background()

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = engine.Evaluate(ctx, input)
		}
	})
}

func newRepositoryEngine(b *testing.B) *Engine {
	b.Helper()
	policyDir := filepath.Clean(filepath.Join("..", "..", "..", "policies"))
	if _, err := os.Stat(policyDir); err != nil {
		b.Skipf("repository policy directory not available: %v", err)
	}
	engine, err := New(context.Background(), policyDir, zap.NewNop())
	if err != nil {
		b.Fatal(err)
	}
	return engine
}

func benchInput(tool string, args map[string]any) types.EvalInput {
	return types.EvalInput{
		Protocol:  "mcp",
		Tool:      tool,
		Arguments: args,
		Agent:     "agent_bench",
		Timestamp: time.Now(),
		RawMethod: "tools/call",
	}
}
