#!/usr/bin/env bash
# KiteRail Phase 4 verification script (make-less, as the stabilization plan demands).
# Usage:  KITERAIL_POSTGRES_DSN=postgres://... ./scripts/verify.sh
# If the system temp volume is short on space, point the Go linker elsewhere:
#   GOTMPDIR=/path/with/space KITERAIL_POSTGRES_DSN=... ./scripts/verify.sh
# Each gate must pass; the script exits non-zero on the first failure.
set -euo pipefail

cd "$(dirname "$0")/.."
cd backend

# Resolve lint/vuln tools: PATH first, then the Go bin dir.
GOBIN="$(go env GOPATH)/bin"
resolve() { command -v "$1" 2>/dev/null || echo "$GOBIN/$1"; }
GOLANGCI_LINT="$(resolve golangci-lint)"
GOVULNCHECK="$(resolve govulncheck)"

echo "=== [1/8] gofmt (working tree must be clean) ==="
test -z "$(gofmt -l .)" || { gofmt -l .; exit 1; }
echo "ok"

echo "=== [2/8] go build ==="
go build ./...
echo "ok"

echo "=== [3/8] go vet ==="
go vet ./...
echo "ok"

echo "=== [4/8] golangci-lint ==="
"$GOLANGCI_LINT" run ./...
echo "ok"

echo "=== [5/8] govulncheck ==="
"$GOVULNCHECK" ./...
echo "ok"

echo "=== [6/8] go test -race (needs KITERAIL_POSTGRES_DSN for integration suites) ==="
if [ -z "${KITERAIL_POSTGRES_DSN:-}" ]; then
  echo "WARNING: KITERAIL_POSTGRES_DSN not set; integration suites will skip." >&2
fi
go test -race -count=1 ./...
echo "ok"

echo "=== [7/8] opa check --strict + opa test ==="
opa check --strict ../policies/ ../tests/policies/
opa test ../policies/ ../tests/policies/
echo "ok"

echo "=== [8/8] sqlc freshness (generated code must match sql/*.sql) ==="
if command -v sqlc >/dev/null 2>&1; then
  # sqlc diff compares generated bindings with the current SQL directly; it
  # remains useful in a dirty working tree where git diff also shows intended
  # source changes that have not been committed yet.
  sqlc diff
  echo "ok"
else
  echo "sqlc not installed locally; freshness gate enforced in CI. SKIPPED."
fi

echo
echo "ALL GATES GREEN"
