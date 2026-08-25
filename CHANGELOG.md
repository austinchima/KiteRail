# Changelog

All notable changes to KiteRail will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0-beta.1] - 2026-08-03

### Added
- **sqlc migration**: Replaced manual SQL + `Scan()` in `internal/ledger` and `internal/quarantine` with sqlc-generated type-safe querier (`internal/db`). All queries now compile-time verified; zero reflection at runtime.
- **Generated querier** (`internal/db/querier.go`): `LedgerEntry`, `QuarantineEntry`, `LedgerStats` types + `Querier` interface with full CRUD + `DB() *sql.DB` for transaction access.
- **sqlc config** (`backend/sqlc.yaml`) + query files (`sql/ledger.sql`, `sql/quarantine.sql`, `sql/schema.sql`) with annotations for all CRUD operations.
- **Hash-chain ledger** and **quarantine stores** refactored to use generated querier; custom logic (hash-chain, SERIALIZABLE retries) kept on top.
- **Full test coverage**: `internal/ledger/ledger_test.go` and `internal/quarantine/store_test.go` migrated to sqlc types; all tests pass with `go test -race ./...`.
- **All dependent code updated**: `internal/proxy/proxy.go`, `internal/quarantine/handler.go`, `internal/ledger/handler.go`, `internal/dashboard/handler.go`, `internal/proxy/proxy_test.go`, `internal/quarantine/handler_test.go` — all use `db.LedgerEntry`, `db.QuarantineEntry`, `db.LedgerStats`.
- `policies/main.rego` — Decision aggregator with severity-based selection (deny=3, quarantine=2, allow=1).
- `tests/policies/authz_test.rego` — Unit tests for the aggregator logic (small refund allowed, large refund quarantined, deny beats quarantine, unknown tool defaults to deny).
- GitHub Actions policy job (`.github/workflows/ci.yml`) — runs `opa check --strict`, `opa test`, and smoke-evals the quickstart payload.
- `docs/policy-cookbook/` — Policy pattern library (Threshold, Time Window, Jurisdiction, Allow List) demonstrating the new authoring pattern.
- Ledger request-ID round-trip integration test (`TestLedger_RequestID_SurvivesRoundTrip`) asserting persistence across raw row read, `GetLedgerEntry`, `ListLedgerEntriesAsc`, `ListRecentLedgerEntries`, and `Verify()`.

### Changed
- Replaced manual `database/sql` + `Scan()` with sqlc-generated type-safe methods in `internal/ledger` and `internal/quarantine`.
- Stores now wrap `db.Querier` interface; `DB() *sql.DB` method exposed for SERIALIZABLE transactions.
- Removed manual `Scan()` loops and raw SQL from store code — generated methods handle type-safe row mapping.
- Test files updated: variable renamed from `db` to `sqlDB` to avoid shadowing `db` package; mocks updated for schema expectations.
- `POST /api/v1/policies/simulate` endpoint for dry-running policy evaluations without triggering audit or ledger side effects.
- `KITERAIL_ALLOWED_ORIGINS` configuration variable for CORS support.
- **Quarantine replay on approval**: `POST /api/v1/quarantine/:id/approve` now replays the original stored payload verbatim to `KITERAIL_TARGET_URL` after marking the item approved. The replay sets `X-KiteRail-Agent`, `X-KiteRail-Quarantine-ID`, and `X-KiteRail-Approved-By` headers on the upstream request so the target has full HITL context. A `502 Bad Gateway` is returned if the upstream call fails.
- `ErrAlreadyResolved` sentinel error in `internal/quarantine` — returned when attempting to approve or deny an item that has already been resolved.
- `ErrNotFound` sentinel error in `internal/quarantine` for missing quarantine items.
- Handler tests for the four approval replay paths: success, 409 conflict, 404 not found, and 502 target error (`internal/quarantine/handler_test.go`).
- Refactored `internal/policy` to `internal/policystore` and `internal/opa` to `internal/opaengine` for better package boundary clarity.
- `KITERAIL_TARGET_URL` is now strictly required with no default value. Server fails fast if unset.
- Updated README with a "Why KiteRail vs X" table and refined positioning.
- `quarantine.NewHandler` now accepts `targetURL string` to enable direct HTTP replay on approval. `main.go` passes `cfg.TargetURL`.
- `quarantine.Store.Approve()` and `quarantine.Store.Deny()` now use `WHERE status = 'pending'` and check `RowsAffected` — concurrent resolution attempts are conflict-safe, with exactly one caller succeeding and all others receiving `ErrAlreadyResolved` (HTTP `409 Conflict`).
- **Policy authoring pattern**: Policies must now contribute to the `decisions` set using `decisions contains {...} if {...}` instead of defining the complete `decision` rule. Old-style policies will conflict with the aggregator and fail closed (returning `policy_eval_error` with action `deny`).
- **Default deny moved to aggregator**: The default-deny behavior moved from `policies/default_deny.rego` (deleted) into `policies/main.rego`.
- **Example policies relocated**: `policies/examples/` moved to `docs/policy-cookbook/` and converted to the new `decisions contains` pattern.
- **Engine fail-closed behavior**: `internal/opaengine/engine.go` now fails closed on evaluation errors — returns `deny` with `rule: "policy_eval_error"` and logs the error internally instead of propagating a 500. Engine constructor now requires a `*zap.Logger`.
- **Ledger hash algorithm changed (BREAKING)**: The `calculateHash()` function now uses a different algorithm (fixed-width timestamp format, pipe separators, includes `PolicyRule`). Existing ledger entries hashed with the old algorithm will fail `Verify()`. Dev/test ledgers must be wiped (`TRUNCATE ledger`) or re-hashed. Production users must run `backend/sql/migrations/001_timestamptz.sql` to convert `TIMESTAMP` columns to `TIMESTAMPTZ` for timezone-safe storage.
- **sqlc output regenerated (v1.31.1) and now canonical**: all ledger & quarantine SQL lives in `sql/*.sql`, including the replay state machine (`ClaimApprovedForReplay`, `MarkReplayed`, `ReturnToApproved`, `RecoverStuckReplays`) that was previously hand-written in Go; generated package renamed to `db` to match its import path; app-facing type names preserved via a thin compatibility layer (`internal/db/compat.go`).
- Quarantine queries use native UUID equality again (primary-key index preserved); string IDs remain the HTTP/store boundary contract and are converted once inside the store.

### Fixed
- **Policy evaluation conflict bug**: Multiple policies defining the complete `decision` rule in the same package caused OPA `eval_conflict_error` (e.g., `refund_limit.rego` at $1,000 and `threshold.rego` at $500 for `stripe.charge.refund`). Fixed by introducing a decision aggregator in `policies/main.rego` that collects `decisions` set contributions and selects the most restrictive action (deny > quarantine > allow) with deterministic tie-breaking.
- **Time window policy bug**: `time_window.rego` declared unused variables `ns` and `date`; fixed to use only `weekday := time.weekday(time.now_ns())`.
- **Bug A — Ledger hash chain false positive on Verify()**: `calculateHash()` used `time.RFC3339Nano` which produces variable-width output and includes nanoseconds. Postgres `TIMESTAMP` stores only microseconds, so timestamps read back during `Verify()` were truncated, causing recomputed hashes to differ from stored hashes. Fixed by introducing `normalizeTimestamp()` (truncates to microseconds UTC) and using fixed-width format `2006-01-02T15:04:05.000000Z07:00` in `calculateHash()`. Added `TestCalculateHash_StableAfterMicrosecondTruncation` unit test and real-Postgres integration test `TestLedger_RoundtripWithVerify` that would fail on the old code.
- **Bug B — PolicyRule excluded from hash and ambiguous field concatenation**: The `policy_rule` column was not included in the hash, so it could be tampered with undetectably. Adjacent fields were concatenated without separators (e.g., `agent="a",tool="bc"` identical to `agent="ab",tool="c"`). Fixed by adding `PolicyRule` to the hash input and using pipe (`|`) separators between all fields. Added `TestCalculateHash_CoversPolicyRule` unit test.
- **Bug C — Serialization failure retry dead code**: `isSerializationFailure()` checked for prefix `"pq: E"` which never matches lib/pq's actual error format (`"pq: could not serialize..."`). The documented "retry x3 on SQLSTATE 40001" never fired. Fixed by using `errors.As(err, &pqErr)` with `pqErr.Code == "40001"`. Moved lib/pq from blank import to named import.
- **SECURITY: Proxy credential leak** — The reverse proxy forwarded the agent's KiteRail bearer token (`Authorization` header) to the downstream target on all allow and passthrough paths. The `Authorization` header is now stripped in the reverse-proxy `Director` before any request leaves the proxy. Added `TestServeHTTP_Allow_StripsAuthorizationHeader` and `TestServeHTTP_NonJSONPassthrough_StripsAuthorizationHeader` to verify the fix.
- **request_id was never persisted**: `appendOnce()` INSERT omitted `request_id` while `calculateHash()` hashed it, so every entry with a non-empty request ID failed `Verify()`. It is now written via generated `InsertLedgerEntry` bound to the same SERIALIZABLE transaction through `WithTx`.
- **Serialization retry storms**: fixed-width 5/10 ms backoff let concurrent appends exhaust 3 attempts under contention; retries are now exponential with jitter (bounded <2 s worst case) and context-cancellable.
- Integration test helpers now apply schema migrations — suites previously failed against any fresh database.
- CI now fails when checked-in `internal/db` code is stale relative to canonical SQL (`sqlc generate && git diff --exit-code -- internal/db`).

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

[Unreleased]: https://github.com/austinchima/KiteRail/compare/v1.1.0-beta.1...HEAD
[1.1.0-beta.1]: https://github.com/austinchima/KiteRail/compare/v1.1.0-alpha...v1.1.0-beta.1
[1.1.0-alpha]: https://github.com/austinchima/KiteRail/compare/v1.0.0...v1.1.0-alpha
[1.0.0]: https://github.com/austinchima/KiteRail/compare/v0.2.0...v1.0.0
[0.2.0]: https://github.com/austinchima/KiteRail/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/austinchima/KiteRail/releases/tag/v0.1.0