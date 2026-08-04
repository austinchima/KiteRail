# Changelog

All notable changes to KiteRail will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `POST /api/v1/policies/simulate` endpoint for dry-running policy evaluations without triggering audit or ledger side effects.
- `KITERAIL_ALLOWED_ORIGINS` configuration variable for CORS support.
- **Quarantine replay on approval**: `POST /api/v1/quarantine/:id/approve` now replays the original stored payload verbatim to `KITERAIL_TARGET_URL` after marking the item approved. The replay sets `X-KiteRail-Agent`, `X-KiteRail-Quarantine-ID`, and `X-KiteRail-Approved-By` headers on the upstream request so the target has full HITL context. A `502 Bad Gateway` is returned if the upstream call fails.
- `ErrAlreadyResolved` sentinel error in `internal/quarantine` — returned when attempting to approve or deny an item that has already been resolved.
- `ErrNotFound` sentinel error in `internal/quarantine` for missing quarantine items.
- Handler tests for the four approval replay paths: success, 409 conflict, 404 not found, and 502 target error (`internal/quarantine/handler_test.go`).

### Changed
- Refactored `internal/policy` to `internal/policystore` and `internal/opa` to `internal/opaengine` for better package boundary clarity.
- `KITERAIL_TARGET_URL` is now strictly required with no default value. Server fails fast if unset.
- Updated README with a "Why KiteRail vs X" table and refined positioning.
- `quarantine.NewHandler` now accepts `targetURL string` to enable direct HTTP replay on approval. `main.go` passes `cfg.TargetURL`.
- `quarantine.Store.Approve()` and `quarantine.Store.Deny()` now use `WHERE status = 'pending'` and check `RowsAffected` — concurrent resolution attempts are conflict-safe, with exactly one caller succeeding and all others receiving `ErrAlreadyResolved` (HTTP `409 Conflict`).

### Fixed
- **Data race in quarantine replay config** (`internal/quarantine`): `maxReplayAttempts` and `replayBackoff` were package-level mutable variables. A goroutine spawned by `TestApprove_Returns200Immediately` held a reference to them while subsequent tests wrote to them concurrently, causing the race detector to fail CI. Both variables are now instance fields on `Handler`, initialised in `NewHandler` to production defaults. Tests create per-handler instances with zero-delay backoff instead of mutating shared globals. `go test -race` passes cleanly on both `feature/quarantine-replay-failure-handling` and `main`.
- **Goroutine leak in `TestApprove_Returns200Immediately`**: The test previously returned before its background replay goroutine finished (the goroutine was gated on a slow test-server). It now calls `close(ready)` then `<-done` to drain the goroutine before the test exits, preventing it from racing against writes in later tests.
- **Quarantine approve did not replay**: Approving a quarantined request marked it in the ledger but never forwarded the payload to the target API. The approving human reviewer had no way to complete the intended action. Now fully implemented end-to-end.
- **Double-approve vulnerability**: Concurrent `approve` calls on the same quarantine item could previously both succeed, potentially triggering duplicate actions on the target. Now safe.

### Changed
- Added inline comments to `corsMiddleware` in `cmd/server/main.go` clarifying the origin-check and header-set logic.
- Reformatted `examples/test_payload.json` to pretty-printed JSON for readability.

## [1.1.0-alpha] - 2026-08-01

### Added
- Prometheus `/metrics` endpoint exposing core counters and histograms (`kiterail_http_requests_total`, `kiterail_http_request_duration_seconds`, `kiterail_decisions_total`).
- `echo-target` mock service in `docker-compose.yml` to ensure `ALLOW` paths succeed out-of-the-box.
- Policy examples cookbook (`policies/examples/`) with 4 templates: `allow_list.rego`, `threshold.rego`, `time_window.rego`, and `jurisdiction.rego`.
- Dedicated "Using KiteRail from the CLI" section in README.md with practical cURL recipes.

### Removed
- `nats` service and unused NATS variables stripped from `docker-compose.yml` (v1 is strictly Postgres).

## [1.0.0] - 2026-08-01

### Added

- Retry logic for serializable transaction failures in `ledger.Append()`: up to 3 attempts
  with 5ms/10ms linear backoff. Prevents silent hash-chain corruption under concurrent load.
- Version constant `1.0.0` in server binary, reflected in `/api/v1/health` response.

### Changed

- **NATS JetStream removed from v1.0 runtime.** All audit events now write directly to the
  Postgres ledger. NATS JetStream will return in v1.1 for real-time streaming and SIEM export.
- `quarantine.NewHandler` signature simplified — publisher parameter removed. HITL approve/deny
  actions write only to the Postgres ledger in this release.
- `proxy.NewSSEHandler` accepts no arguments and returns HTTP 501 for the topology stream
  endpoint. The Topology dashboard view uses its built-in static simulation.
- Server startup no longer requires a reachable NATS server — reducing local dev and Docker
  Compose dependencies to Postgres only.

### Fixed

- `ledger.Append()` previously had no retry on serialization failure. Any concurrent write
  would return an error silently discarded by the proxy, breaking the hash chain without
  any signal. Now retried up to 3 times and surfaced correctly if all attempts fail.

### Removed

- NATS JetStream publisher and subscriber startup from `main.go` (deferred to v1.1)
- NATS health check from `/api/v1/health` response body (deferred to v1.1)
- `events.Publisher` dependency from `quarantine/handler.go`
- `events.Subscriber` dependency from `proxy/sse.go`

## [0.2.0] - 2026-07-30

### Added

- REST API for ledger queries and verification: `GET /api/v1/ledger` and `POST /api/v1/ledger/verify`
- Full audit event publishing to NATS JetStream and tamper-evident ledger logging for all human quarantine approvals and denials
- Default Rego policy (`backend/policies/default.rego`) returning structured decision objects (`action`, `rule`, `explanation`)
- Sample configuration reference (`backend/kiterail.example.yaml`)
- REST API for quarantine HITL: `GET /api/v1/quarantine`, `POST /api/v1/quarantine/:id/approve`, `POST /api/v1/quarantine/:id/deny`
- Frontend dynamic integration for Dashboard, MCPServers, Sidebar, and Inbox without mock data
- Security Policy disable confirmation workflow requiring exact phrase verification

### Fixed

- **MCP Spec Compliance**: Proxy now correctly parses `tools/call` JSON-RPC requests, extracting `params.name` and `params.arguments` per the MCP specification
- **Authentication**: Added bearer token middleware (`KITERAIL_API_KEYS`) — proxy no longer accepts unauthenticated requests
- **OPA Engine Data Race**: Added `sync.RWMutex` to guard concurrent `Evaluate()` and `Reload()` calls
- **Ledger Concurrency**: Added `FOR UPDATE` lock and `SERIALIZABLE` transaction isolation to prevent hash-chain race conditions
- **NATS Deduplication**: Added `Nats-Msg-Id` headers and 2-minute dedup window to prevent duplicate events on retries

### Changed

- Updated README.md architecture diagram to represent end-to-end logging of all decision outcomes (ALLOW, DENY, QUARANTINE, HITL actions) to NATS JetStream & Audit Ledger
- Clarified domain-agnostic positioning (DevOps/Cloud, Healthcare, HR/ERP) across documentation
- All Rego policies now use `input.tool` and `input.arguments` instead of `input.method` and `input.params`
- Audit ledger description updated from "tamper-evident" to "tamper-detectable" for accuracy
- Removed unimplemented PII/PCI redaction claim from README

## [0.1.0] - 2026-07-25

### Added

- Go inline proxy server with MCP JSON-RPC request interception (`internal/proxy`)
- OPA Rego policy evaluation engine with hot-reload support (`internal/opa`)
- NATS JetStream durable event publisher for quarantine, audit, and telemetry streams (`internal/events`)
- Postgres-backed quarantine queue with approve/deny workflow (`internal/quarantine`)
- SHA-256 hash-chained tamper-evident audit ledger (`internal/ledger`)
- YAML + environment variable configuration loader (`internal/config`)
- Graceful shutdown with signal handling and dependency draining
- Example FinTech Rego policies:
  - `refund_limit.rego` — quarantine refunds exceeding $1,000
  - `pii_redaction.rego` — block SSN patterns in outbound payloads
  - `wire_transfer.rego` — AML jurisdiction blocking and high-value transfer holds
  - `default_deny.rego` — deny-all base policy
- Docker Compose for one-command local development (proxy + NATS + Postgres)
- Multi-stage Dockerfile producing <20MB production image
- Apache 2.0 license
- Production README with architecture diagram, quickstart, and policy authoring guide

[Unreleased]: https://github.com/austinchima/KiteRail/compare/v1.1.0-alpha...HEAD
[1.1.0-alpha]: https://github.com/austinchima/KiteRail/compare/v1.0.0...v1.1.0-alpha
[1.0.0]: https://github.com/austinchima/KiteRail/compare/v0.2.0...v1.0.0
[0.2.0]: https://github.com/austinchima/KiteRail/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/austinchima/KiteRail/releases/tag/v0.1.0
