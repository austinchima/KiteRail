# Changelog

All notable changes to Elodea (formerly KiteRail) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Ships as **2.0.0**: the rename changes header, metric, and policy-package names (see *Changed*). It also carries the 1.2.0 work below, which was never tagged as a separate release.

### Added
- **Single sign-on for reviewers and admins (OIDC).** Works with Okta, Entra ID, Auth0, Keycloak and any OIDC provider. The server runs the Authorization Code flow with PKCE and gives the browser only an opaque `HttpOnly` session cookie. Roles come from IdP groups (`oidc.reviewer_groups`, `oidc.admin_groups`), and approvals and denials are recorded under the verified identity. Sessions are server-side (migration `008_sso.sql`), expire after 8h or 1h idle by default, and are revoked on sign-out. Session-authenticated changes require `X-Requested-With: elodea` and an allowed `Origin`. Agents still authenticate with bearer tokens only. Static reviewer/admin tokens become optional break-glass access. Configure with `ELODEA_OIDC_*` or the Helm `oidc` values; see `docs/DEPLOYMENT.md`.
- **Held-action notifications** to Slack and to a generic webhook signed with HMAC-SHA256 (`X-Elodea-Signature`), so reviewers hear about a held action immediately. Delivered through a Postgres outbox (migration `009_notifications.sql`): survives restarts, retries with backoff, never sent concurrently by two replicas, and skipped if the action was reviewed first. Messages never include tool arguments. Configure with `ELODEA_NOTIFY_SLACK_WEBHOOK_URL`, `ELODEA_NOTIFY_WEBHOOK_URL`, `ELODEA_NOTIFY_WEBHOOK_SECRET` (each with a `_FILE` variant where secret) and `ELODEA_CONSOLE_URL`; new metric `elodea_notifications_total`.
- **Approve and deny from Slack.** A Slack app posts held actions with Approve and Deny buttons. Clicks are verified with Slack's request signature and workspace, accepted only from users whose Slack email is on `ELODEA_SLACK_REVIEWERS`, applied through the same conflict-safe path as the console, recorded in the ledger under that email, and the message is updated with the outcome. Create the app from `deploy/slack/manifest.yaml`; configure with `ELODEA_SLACK_BOT_TOKEN`, `_SIGNING_SECRET`, `_CHANNEL_ID`, `_TEAM_ID` (required in production), `_REVIEWERS`, and `_API_BASE` for GovSlack. New endpoint `POST /integrations/slack/interactions`.
- Console: `#inbox` (and other view names) in the URL open that view directly, so notification links land on the approvals queue.
- Console: **Continue with SSO** sign-in, with the token form kept as a fallback, and clear messages when the provider refuses or the user has no Elodea group.
- Docs: SSO and notification guides in `docs/DEPLOYMENT.md`, webhook event format and signature check in `docs/API.md`, an updated architecture (package map, replay sequence, notification outbox) and a current roadmap in `docs/ARCHITECTURE.md`.

### Fixed
- `SECURITY.md` pointed vulnerability reports at a repository that doesn't exist, and the README and supported-versions table called 1.2.0 a release although it was never tagged.
- CI tested policies with OPA 1.18.2 while the server embeds OPA 1.21.1; both now use 1.21.1.

### Dependencies
- OPA 1.21.1, go-jose 4.1.5, testify 1.12.1 and two more Go modules; GitHub Actions moved to their Node 24 releases (`checkout` v7, `setup-go` v7, `setup-helm` v5, `setup-qemu-action` v4, `attest-build-provenance` v4, `action-gh-release` v3); `trivy-action` pinned to v0.36.0 by commit.
- Dependabot now targets `dev`, and holds the Go builder image on Go 1.26 (patch and digest updates only) until `go.mod`, CI and golangci-lint move together.
- Slack notifications escape agent-supplied text in the message preview as well as the body, so a tool name cannot trigger `@channel`.

### Changed
- **Renamed from KiteRail to Elodea.** Product name, binary (`/usr/local/bin/elodea`), container image (`ghcr.io/<owner>/elodea`), Helm chart (`deploy/helm/elodea`), example config (`backend/elodea.example.yaml`), console, and docs.
- **Environment variables are now `ELODEA_*`.** `KITERAIL_*` names still work: each is applied when its `ELODEA_*` counterpart is unset, and startup logs a deprecation warning listing them.
- **Headers are now `X-Elodea-*`** (`Agent`, `Quarantine-ID`, `Approved-By`, `Decision`, `Policy-Version`). Upstreams that read `X-KiteRail-*` must switch. Inbound `X-KiteRail-*` headers are still stripped from agent requests, so they cannot be spoofed.
- **Policy package is now `elodea.authz`** and the input schema is `elodea.eval/v1`. A bundle that still declares `package kiterail.authz` is rejected with an error naming the fix, rather than silently denying every call.
- **Prometheus metrics are now `elodea_*`.** Update dashboards and alerts.
- **MCP decision metadata is now `result._meta["elodea/decision"]`** (was `kiterail/decision`). Clients that read it must switch.
- **Docker Compose defaults** use the `elodea` database, user, and password. Existing local volumes created as `kiterail` need recreating or an explicit DSN.

### Unchanged on purpose
- The replay `Idempotency-Key` prefix stays `kiterail-quarantine-<id>`, because upstreams deduplicate on it and a replay that straddles the upgrade must not execute twice.
- Applied database migrations, the `kiterail.ledger_maintenance` setting, and the ledger trigger names are unchanged.
- The Go module path and repository URL stay `github.com/austinchima/kiterail` until the repository itself is renamed.

## [1.2.0] - not released separately (ships in 2.0.0)

Production-readiness release: closes two policy-bypass paths, makes the audit
trail complete and externally verifiable, and makes the enforcement core
protocol-neutral so new agent protocols plug in without touching policy,
ledger, or review.

### Security
- **Upstream URL pinned.** Allowed requests are forwarded to exactly `target_url`; previously the agent-controlled request path and query were appended, letting a policy-allowed body reach any upstream endpoint with the server's credential.
- **Agent-controlled headers stripped.** `Proxy-Authorization`, `Cookie`, `Idempotency-Key`, and all `X-KiteRail-*` headers are removed before forwarding (previously only `Authorization`), so an agent cannot impersonate a human-approved replay. The proxy now asserts `X-KiteRail-Agent` itself.
- **Separation of duties enforced at startup.** One identity can no longer be configured as both an agent and a reviewer/admin.
- Production rejects tokens shorter than 24 bytes and non-`http(s)` target URLs.

### Audit integrity
- Ledger is **append-only at the database level** (migration `005`): `UPDATE`/`DELETE`/`TRUNCATE` are rejected unless an operator opts in per transaction.
- Every decision records the **policy bundle version** that made it (`policy_version`, migration `006`); old entries keep verifying.
- Human approvals are ledgered (`approved`); approve/deny return `503` if their audit entry cannot be written.
- Replays write a **write-ahead** `replay_started` entry and do not execute if the ledger is down.
- HITL entries carry the real payload hash, joining them to the original `quarantine` decision; a failed quarantine insert is ledgered as `quarantine_store_failed`.
- New endpoints: `GET /api/v1/ledger/head` (external anchoring), `GET /api/v1/ledger/export` (streaming NDJSON), keyset-paginated and filterable `GET /api/v1/ledger`, and anchored `verify` with a detailed report.

### Protocol-neutral core
- New ingress **adapter** boundary (`proxy.Adapter`); MCP is the first adapter. Policy input gains `schema_version`, `protocol`, and `protocol_version`.
- **MCP-native outcomes**: MCP clients receive denials and quarantines as `isError` tool results (or JSON-RPC errors `-32010`/`-32011`) the model can read, instead of HTTP errors.
- Baseline `policies/mcp/protocol.rego` allows read-only MCP discovery (`initialize`, `ping`, `*/list`) keyed on the protocol method.

### Policy fixes found while building the landing-page simulator
- `refund_limit.rego` auto-allowed refunds whose `amount` was `null` or a boolean (Rego orders those below numbers). Amounts must now be numbers; anything else is held as `refund_amount_invalid`. Regression tests added.
- Policy explanations are plain sentences (no dash punctuation), and every policy file declares a `# Title:` for the console.
- Held actions now store the `policy_rule` and `explanation` that held them (migration `007`), returned as `PolicyRule` / `Explanation` on quarantine items, so reviewers see why without consulting the ledger.

### Policy lifecycle
- **Hot reload** via `SIGHUP`, `POST /api/v1/policies/reload` (admin), and directory polling (`policy_reload_interval`, default 30 s). A bundle that fails to compile is rejected and the previous one keeps enforcing.
- **Replay-time policy re-check**: an approved action that current policy now denies is blocked (`replay_blocked_by_policy`) and returned to reviewers.
- Fixed `wire_transfer.rego` allowing transfers with a missing jurisdiction, and `pii_redaction.rego` erroring on non-string values.

### Reliability
- Allowed tool calls that stream their result (SSE or chunked output) are no longer cut off by the server-wide `write_timeout`. The upstream must start responding within the timeout (`ResponseHeaderTimeout`); after that a live stream may run as long as it needs. Regression test included.
- Ledger appends serialize on a transaction-scoped advisory lock instead of SERIALIZABLE retries, removing abort/backoff storms under load.
- Crash-interrupted replays now count as attempts, so a poison payload cannot loop forever; exhausted entries park without another upstream call.
- Quarantine list is ordered and capped (500), unknown `status` values return `400`, and database errors return `500` instead of `404`.
- One ledger verification/export runs at a time (`429` otherwise).
- Postgres connection retries reuse one pool and honour shutdown.
- Migrations run in numeric order regardless of zero padding.
- Quarantine JSON renders unset `ResolvedAt`/`ReplayedAt` as `null`, as documented.

### Operations & packaging
- Distroless, non-root image from digest-pinned bases with a built-in `-healthcheck` probe, version injected at build time, and LICENSE included.
- Helm chart (`deploy/helm/kiterail`): hardened pod security, probes, secrets mounted as files, ConfigMap policies with hot reload, PDB, HPA, NetworkPolicy, ServiceMonitor.
- `*_FILE` variants for every secret, `tls_terminated_upstream`, `metrics_listen_addr` (internal metrics port), and a `log_level` that is now honoured.
- New metrics: ledger append latency and failures, replay outcomes, policy reloads, active policy version, build info.
- Release workflow: multi-arch images on GHCR, cosign keyless signing, SPDX SBOM, SLSA provenance, packaged Helm chart. CI adds image build plus Trivy scan, Helm lint, pinned OPA, and Dependabot.
- `SECURITY.md`, `docs/DEPLOYMENT.md`.

## [1.1.0] - 2026-09-09

### Added
- **Stabilization correctness pass**: strict duplicate-key/precision-preserving MCP JSON decoding; exact, Base64-aware mirrored MCP header validation; replay-safe protocol-header persistence; advisory-locked replay recovery; redirect-safe replays; recursive policy listing; and bounded strict simulation input. These paths now have regression tests for the previously unobservable failure modes.
- **Production HTTP hardening** (`cmd/server`): `ReadHeaderTimeout` on the server (Slowloris defense; yaml `read_header_timeout`, default 5 s), exact CORS origins, and readiness-first graceful shutdown — SIGTERM flips `/readyz` to `503` (`{"ready": false, "draining": true}`), rejects protected new work during `shutdown_drain_delay`, then calls `srv.Shutdown`. Liveness (`/api/v1/health`, no DB) vs readiness (`/readyz`, Postgres ping plus OPA decision entry point) are split and documented.
- **OPA engine Windows absolute-path fix** (`internal/opaengine`): `rego.Load` URL-parses its path arguments, so a Windows absolute policy dir (`D:\...`) had its drive letter eaten as a URL scheme and failed to load. New `loaderPath` helper converts absolute dirs to `file://` URLs (leading slash before the drive letter is load-bearing); relative dirs pass through unchanged. Three test workarounds reverted to plain `t.TempDir()`; `TestLoaderPath` pins the mapping.
- **Linting as a permanent reviewer**: `.golangci.yml` (v2 config; errcheck + staticcheck with exclusions only for idiomatic unchecked returns — deferred `Close`/`Rollback`, `os.RemoveAll`/`Setenv`) and matching CI gates: `gofmt -l`, `golangci-lint-action@v7`, `govulncheck`, coverage artifact upload. Repo-wide lint is clean at 0 issues.
- `.gitattributes` (`*.go text eol=lf`) fixing a pre-existing CRLF drift that made `gofmt -l` report 31 files dirty on a fresh checkout.
- **MCP ingress per the 2026-07-28 stateless profile** (`internal/proxy`): the proxy now enforces the normative intermediary subset — (1) the body must be a **single** JSON-RPC 2.0 message: batch arrays, client-sent responses (`result`/`error` without `method`), and missing/`!= "2.0"` `jsonrpc` are rejected with HTTP 400 + JSON-RPC `-32600`; (2) mirrored-header validation **before OPA evaluation**: `Mcp-Method` / `Mcp-Name` headers, when present, MUST equal the body's `method` / `params.name` — contradiction → HTTP 400 + `-32020`, so policy input is never attacker-spoofable (absent headers are tolerated for legacy clients); (3) `MCP-Protocol-Version` is accepted and forwarded verbatim, not enforced (version pinning is a deliberate post-MVP decision — see `docs/ARCHITECTURE.md`); on allow, headers are mirrored, never rewritten. Documented in `docs/API.md` with a full proxy error-mapping table (`-32600` envelope, `-32020` contradiction, custom codes reserved to `-32000..-32019`).
- **One documented meaning for `EvalInput.RawMethod`**: the JSON-RPC protocol method from the validated body (`"tools/call"`, or the actual method for other calls) — never the HTTP method, which is transport metadata. Typed doc comment in `internal/types`; simulator passes it through verbatim so simulated and enforced evaluations stay semantically identical.
- **Ingress + E2E tests**: `proxy_test.go` gains the Phase 3 sweep — RawMethod == protocol method for `tools/call` and other methods, contradictory `Mcp-Method`/`Mcp-Name` rejected before OPA (upstream untouched, no ledger row, engine never sees the input), matching mirrored headers allowed and forwarded verbatim, protocol-version pass-through, batch rejection; the fail-closed ingress table grows jsonrpc-version, batch, and client-response rows. E2E Invariants 8a/8b (`cmd/server/e2e_integration_test.go`) pin header/body contradiction → 400/-32020 with zero upstream/ledger side effects, and mirror-don't-rewrite for all three MCP headers against the real stack.
- **Typed policy actions** (`internal/types`): new `Action` string type with `ActionAllow` / `ActionDeny` / `ActionQuarantine` constants and a `Valid()` method; `ProxyDecision.Action` is now typed. The compiler — not convention — separates the three outcomes; all Go consumers (engine, proxy, tests) swept off string literals (SQL literals unchanged as the single source of truth).
- **Decision validation at the trust boundary** (`internal/opaengine.Evaluate`): a policy decision with an empty/unknown action, an empty rule, or a non-decision value is rewritten to `{action: deny, rule: "invalid_policy_decision", explanation: "Policy engine returned an invalid decision"}` — fail closed on malformed policy output (garbage in, deny out). An empty result is a separate named deny, `no_policy_decision`, so the ledger distinguishes a missing entry point from malformed policy output.
- **`rego.StrictBuiltinErrors(true)`** on the OPA engine: builtin runtime errors (bad JSON, division by zero, …) now surface as `policy_eval_error` instead of being silently swallowed into the fallback deny.
- **Quarantine replay credential parity**: `quarantine.WithTargetAuthToken` WorkerOption — the replay worker injects the configured target service credential on HITL-approved replays; the agent's token is never presented upstream.
- **Per-identity rate limiting** on the agent trust domain: token-bucket limiter keyed by authenticated identity (`rate_limit_rps` / `rate_limit_burst` config). Authentication always precedes the limiter so buckets key off verified identities only.
- **Auth/trust-domain unit tests** (`cmd/server/main_test.go`): identity fixtures across agent/reviewer/admin roles exercising the three trust domains.
- **Shared integration-test harness** (`internal/dbtest`): DSN resolution (`KITERAIL_POSTGRES_DSN` / `QUARANTINE_TEST_DSN`), advisory-locked DB open with migrations and per-test truncate — extracted from triplicated per-package plumbing.
- **Quarantine schema compatibility migration** (`004_quarantine_uuid.sql`): fresh databases use UUID quarantine IDs, while existing integer IDs are preserved in `legacy_id` as rows are upgraded; replay-safe request headers are added without dropping quarantine data.
- **End-to-end invariant suite** (`cmd/server/e2e_integration_test.go`): 6 invariants against real Postgres + real OPA + `httptest` upstream — allow-parity with credential stripping, quarantine→approve→replay parity, ledger hash-chain integrity, trust separation, ledger-outage fail-closed, replay exhaustion. Requires a DSN env var; skips otherwise.
- `Worker.ProcessOnce(ctx)` seam enabling deterministic single-pass replay drains in tests (`Run` drives it per tick).
- **Replay exhaustion integration test** (`TestIntegration_ReplayExhaustionSurfacesReplayFailed`) driving create→approve→claim→fail through a real `Worker` against real Postgres.
- **Rego rule-presence pin** (`tests/policies/authz_test.rego`): `test_every_decision_carries_a_rule` asserts every `decisions`-set contribution across probe inputs carries a non-empty rule; existing aggregator tests now also pin their rule names (the Go engine fails closed on empty rules, so a forgotten rule would silently deny everything it touched — this catches the authoring mistake at CI time).
- **Simulator parity test** (`internal/policystore/handler_test.go`): `TestSimulateParity` asserts `POST /simulate` returns byte-for-byte the enforcement outcome (action/rule/explanation) for well-formed and malformed decisions; a `raw_probe` rule fires only when `raw_method` is empty, so any re-introduced simulator default flips it to `default_deny` — the divergence is caught, not silent.
- **Engine validation tests** (`internal/opaengine/engine_test.go`): `TestEngine_InvalidDecisions` (well-formed pass-through + missing-rule / empty-action / unknown-action / non-decision cases) and `TestEngine_EvalError` (builtin runtime error → `policy_eval_error`).
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
- **Toolchain/dependency security bump**: Go 1.26.0 → 1.26.6 (stdlib fixes for `crypto/tls`, `crypto/x509`, `net/http`, `net/url`, `net/textproto`, `mime`, `os`, `encoding/asn1`) and `golang.org/x/crypto` v0.54.0 → v0.56.0, `golang.org/x/net` v0.57.0 → v0.58.0. `govulncheck` reports zero reachable vulnerabilities.
- **Typed dashboard response** (`internal/dashboard`): `map[string]interface{}` replaced with a typed `statsResponse` struct — the JSON wire format is unchanged, but the API boundary is now compile-time checked.
- **Metric initialisms** (`internal/metrics`): `HttpRequestsTotal` → `HTTPRequestsTotal`, `HttpRequestDuration` → `HTTPRequestDuration` (staticcheck ST1003); call sites updated. Label values unchanged.
- **`denyEntry` body hardening** (`internal/quarantine`): request body now capped at 1 MB via `http.MaxBytesReader` and decode errors checked — a malformed body returns `400` (`{"error": "invalid request body"}`) instead of silently denying with an empty reason; an empty body remains valid.
- `internal/db/migrate.go` uses `path.Ext` instead of a hand-rolled `fileExt` helper.
- **Simulator parity**: `POST /api/v1/policies/simulate` no longer defaults `raw_method` to `"tools/call"` — simulation runs the identical input through the identical engine and returns the enforcement outcome, not a simulator-specific approximation.
- **Replay state-machine guards**: `MarkReplayFailed` now transitions only from `replaying` (previously guarded on `approved`, which would wedge a replay the moment any attempt failed); all replay transitions use `:execresult` and return `ErrStaleTransition` on zero affected rows instead of silently succeeding.
- `mockStore` realigned to real SQL semantics (no claim-time attempt increment; transitions error on wrong state; `Approve` resets attempts) with a warning header comment — mocks must be tested against reality, not the other way around.
- Token validation in `internal/auth` is now constant-time (`subtle.ConstantTimeCompare`, deliberately no early return) closing the timing side-channel on which configured token matched.
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
- **Public CI no longer builds the dashboard**: `web/` is excluded from this repository by design and ships through its own separate CI/CD pipeline. The public workflow now covers exactly what the repo contains — backend (vet, race tests, build) and OPA policy checks. Architecture diagrams are unchanged; the dashboard remains part of the documented application flow.
- Interactive architecture diagram regenerated from the corrected spec: adds the `worker → ledger` replay-audit edge, updates the ledger sublabel to the current retry policy (×8, jittered backoff), and re-pins repository evidence to the latest revision.
- **Shared decision types extracted** into `internal/types` (`EvalInput`, `ProxyDecision`): `internal/opaengine` no longer imports `internal/proxy`; type aliases in the proxy package keep every existing `proxy.EvalInput` / `proxy.ProxyDecision` reference compiling unchanged.

### Fixed
- **Unchecked-error hygiene (errcheck)**: deferred `Close`/`RemoveAll`/advisory-unlock sites across tests, `migrate.go`, and `main.go` now either check the error or explicitly discard it (`_, _ =`), including a stale `require.NoError(t, err)` after an unchecked `os.WriteFile` in `opaengine` tests that failed to compile once the write was checked.
- **OPA builtin runtime errors silently swallowed**: without strict builtin errors, a policy hitting a builtin error at runtime evaluated as undefined and fell into the fallback deny, masking broken policies as "no match". Now surfaced distinctly as `policy_eval_error`.
- **Replay worker credential parity**: HITL-approved replays now carry the configured target service credential (`WithTargetAuthToken`); previously the replay path had no upstream credential story of its own.
- **False `MarkReplayFailed` state guard**: guard targeted `approved` instead of `replaying`, so a failed replay could never be marked `replay_failed` and was retried forever (exhaustion wedge). Guard corrected; regression covered by an integration test with a proven negative control.
- **Claim-time attempt accounting discrepancy**: the mock store incremented attempts at claim while the real store increments at resolution; mock realigned to real SQL semantics and unit tests updated to real call counts.
- **Worker comment dishonesty**: false "claim incremented attempts" comment corrected to match actual behavior.
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
- Migration execution now holds schema creation and version recording under one transaction-scoped advisory lock, so cancellation rolls back cleanly and cannot leave another pooled connection holding the lock.

### Removed
- **Dead NATS code** (`internal/events/`): the publisher/subscriber package carried `nats-server/v2` as a direct dependency for zero production value (main always wired `NoOpPublisher`). The `proxy.EventPublisher` interface and `NoOpPublisher` stay as the v1.1 streaming seam; the NATS implementation returns with the real feature.
- Config `nats_url` / `KITERAIL_NATS_URL` (no consumer; config, tests, and `kiterail.example.yaml` swept).
- Unreachable `policystore.Store.Save` / `Store.UpdateEnabled` and their tests (policy mutation is deliberately not exposed over HTTP; nothing calls `Engine.Reload`). The store integration test is rewritten List-only.
- Hygiene deletions: `backend/test_db_import.go`, `backend/internal/ledger/test_db_import_test.go`, and `backend/sql/migrations/001_timestamptz.sql` (superseded by `sql/schema.sql` as the sqlc codegen source, applied by the integration harness; the changelog entry referencing the migration file predates this cleanup).

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

[Unreleased]: https://github.com/austinchima/KiteRail/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/austinchima/KiteRail/compare/v1.0.0...v1.1.0
[1.1.0-beta.1]: https://github.com/austinchima/KiteRail/compare/v1.1.0-alpha...v1.1.0-beta.1
[1.1.0-alpha]: https://github.com/austinchima/KiteRail/compare/v1.0.0...v1.1.0-alpha
[1.0.0]: https://github.com/austinchima/KiteRail/compare/v0.2.0...v1.0.0
[0.2.0]: https://github.com/austinchima/KiteRail/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/austinchima/KiteRail/releases/tag/v0.1.0
