# KiteRail MVP Stabilisation & Improvement Plan

> **Prepared:** 2026-09-07 · Principal-engineer review of the codebase and the
> `MVP Stabilisation Prompts.md` task list, informed by four research passes:
> (1) full backend code read with a learner-oriented quality lens, (2) the
> 2025–2026 MCP gateway/security market landscape, (3) the current MCP
> specification (2026-07-28 stateless profile) and authorization spec, and
> (4) idiomatic Go 1.26 + production MVP primitives. All external claims are
> dated and sourced in the appendix.

---

## 1. Where the project stands

| Prompt task | Status | Notes |
|---|---|---|
| 1. Ledger `request_id` + sqlc reproducibility | ✅ Done | Verified in repo; CI freshness gate present |
| 2. Auth, trust-domain routing, rate-limiter ordering | ✅ Done | Three explicit chains; 11 tests |
| 3. Quarantine replay auth parity | ✅ Done (this week) | `WithTargetAuthToken` worker option + wiring + 3 tests |
| 4A. E2E invariant harness | ✅ Done | Real PG + OPA + full wiring; `dbtest` extracted |
| 4B. E2E invariant scenarios | ✅ Done | Invariants 1–7 green; 8 landed with Phase 3 |
| 5. OPA decision metadata + simulator parity | ✅ Done | Typed `Action`, `invalid_policy_decision`, `TestSimulateParity` |
| 6. MCP ingress compatibility | ✅ Done | 2026-07-28 stateless profile: -32600 envelope, -32020 contradiction, mirror-don't-rewrite |
| 7. Release gate | 🔲 Not started | Moved after hardening — see Phase 5 |
| 8. Perf / coverage metrics | 🔲 Not started | See Phase 5 |

**New finding (blocking):** the full-code review uncovered a *second live bug*
in the quarantine replay state machine — exhausted replays never reach
`replay_failed`. Details and fix in Phase 0. It survived because every worker
test runs against a mock store whose semantics diverge from the real SQL —
the single most instructive lesson in this codebase for a Go learner.

---

## 2. What the research found (condensed)

### 2.1 Market position — you are differentiated, and the ledger is the moat

"MCP gateway" became a funded product category between March 2025 and
September 2026. Four camps: gateway incumbents (Kong, Envoy AI Gateway,
Portkey — now open source, LiteLLM, Traefik, Azure APIM), cloud/SASE platforms
(Cloudflare, Microsoft), pure-play MCP security startups (Lasso, Runlayer,
MintMCP, Zenity), and AI-runtime security vendors (HiddenLayer's $100M Series
B, 2026-09-03). Consolidation is real: SentinelOne/Prompt Security ~$250M,
Cato/Aim, Check Point/Lakera, F5/CalypsoAI, Zscaler/SplxAI — all 2025.

Benchmarking KiteRail primitive-by-primitive:

| Primitive | KiteRail | Field | Verdict |
|---|---|---|---|
| Inline JSON-RPC proxy | ✅ | Table stakes (Kong, Portkey, `soth-ai/mcp-proxy`) | No moat; correctness + docs are the edge |
| General policy engine (OPA) | ✅ | Parity — `soth-ai/mcp-proxy` ships OPA + audit/enforce modes | No moat |
| Quarantine / HITL | ✅ | Rare among OSS gateways (Lasso, Zenity have it; GateKeeper only on roadmap) | **Real differentiator** |
| Hash-chained tamper-evident ledger | ✅ | **No competitor found claims hash chaining** — all have "immutable logs" only | **The unique claim — protect and compound it** |
| Agent identity at tool-call boundary | ❌ | Nobody does it well; NIST CAISI / OpenID Foundation / NCCoE all publishing 2026 | **Biggest open lane — watch, don't build yet** |
| Spec-compliant auth (OAuth 2.1, RFC 8707/9728) | ❌ | Portkey, GateKeeper, Cloudflare, mcpo | Post-MVP positioning |
| Shadow/audit rollout mode | ❌ (implied) | soth-ai, Zenity; OPA industry practice | **Cheap, high enterprise value — v1.1** |
| Credential injection / vaulting | ❌ | Portkey, Traefik, MintMCP | Post-MVP |
| Rate limiting / budgets | partial (per-agent only) | LiteLLM, Envoy, APISIX | v1.1 |
| Registry integration, OpenAPI↔MCP, multi-server multiplexing | ❌ | Everyone | **Do not build — consume, don't construct** |

The market thesis in one sentence (Portkey's CEO): *"Enterprises don't want to
block MCP, they want a way to trust it."* A solo Go project cannot out-breadth
Kong or Portkey. It can out-focus them on the three primitives they treat as
afterthoughts: **quarantine/HITL, tamper-evident audit, and (later) agent
identity.** Every recommendation below either protects one of those three or
removes something that dilutes them.

### 2.2 Spec reality — the 2026-07-28 stateless profile changes Task 6

The current MCP spec (2026-07-28, governed by the Agentic AI Foundation since
2025-12) removed the `initialize` handshake and sessions entirely. Every
Streamable HTTP POST **MUST** carry `MCP-Protocol-Version`, `Mcp-Method`, and
(for `tools/call`) `Mcp-Name`; header/body disagreement **MUST** be rejected
with HTTP 400 + JSON-RPC `-32020` — precisely because an intermediary that
authorizes on headers while the server executes the body is a named attack
class. Bodies must be a **single** JSON-RPC message (batching is out).
`-32020..-32099` is now reserved for the spec. The authorization spec mandates
OAuth 2.1, RFC 8728 Protected Resource Metadata, RFC 8707 resource indicators,
and explicitly **forbids token passthrough** (confused deputy).

KiteRail is an *intermediary*, so the normative subset for Task 6 is: body is
always the source of truth for policy; mirrored headers are validated when
present and contradictions fail closed; headers are mirrored, never rewritten,
when forwarding. The full 30-item MUST/SHOULD/OPTIONAL checklist is in the
research appendix and phases into the roadmap below.

### 2.3 The second live bug — and the lesson it teaches

**Bug (verified against `sql/quarantine.sql` and generated code):**
`MarkReplayFailed` is `UPDATE ... WHERE id=$1 AND status='approved'`, but the
worker calls it while the entry is in **`replaying`** (claimed at
`ClaimApproved`, failed at `processClaimed`). The `:exec` query never checks
`RowsAffected`, so the no-op is silent. Consequences:

- After `maxReplayAttempts`, a poisoned entry **stays `replaying` forever** —
  reviewers never see `replay_failed`, and `RecoverStuckReplays` flips it back
  to `approved` on restart, so it retries the doomed call again: an infinite
  retry loop across restarts.
- Mock/real divergence: the in-memory `mockStore` increments `Attempts` at
  claim time (real SQL increments in `ReturnToApproved`/`MarkReplayed`) and its
  `MarkReplayFailed` *accepts* `replaying`. So the mock exhausts in 3 calls and
  "passes" while the real store takes 4 calls and wedges. Every worker test is
  green; production is broken.
- The worker comment "the claim already incremented attempts" (worker.go:120)
  is false and would mislead the next maintainer.

**The lesson for a Go learner:** a mock that diverges from reality doesn't
just fail to protect you — it *actively conceals* bugs while giving the
feeling of coverage. The remedy is not "write more unit tests"; it is (a) make
mocks faithfully mirror real semantics, and (b) integration-test state
machines against the real database, because state machines live in SQL, not in
Go. This is why Task 4A/4B (real-component E2E) is not optional polish — it is
the regression net that would have caught both this bug and the Task 3 auth
bug.

### 2.4 Code health — the rest of the review, ranked

Full per-package review (what's exemplary, what's not) is in the appendix.
Highest-leverage findings beyond the Phase 0 bug:

- **Typed strings are the cheapest bug-killer available.** Status constants
  (`"approved"`, `"replaying"`, …) and decision actions (`"allow"`, …) are
  untyped strings compared across packages and SQL. The Phase 0 bug *was* a
  string mismatch that compiled. `type Status string` and `type Action string`
  move that entire class to compile time. (§4, Phase 2.)
- **Dead and half-built code** *(Phase 4 resolution: the `internal/events` package, `nats-server/v2` direct dependency, and unreachable `policystore.Save`/`UpdateEnabled` have been deleted; the rest of this bullet documents what the review found at the time)*: `backend/test_db_import.go` + `internal/ledger/test_db_import_test.go` (scratch), orphaned
  `backend/sql/migrations/` contradicting the embedded migrations, the entire
  `internal/events` package + `nats-server/v2` as a **direct dependency** for
  zero production value (main wires `NoOpPublisher`), `proxy/sse.go` 501 stub
  unmounted, and `policystore.Store.Save`/`UpdateEnabled` — unreachable via
  HTTP (mutation is deliberately rejected), a latent path-traversal footgun,
  and even if wired, nothing calls `Engine.Reload`. Half-built features are
  worse than absent ones: finish them or delete them.
- **Ledger semantic abuse:** the worker and deny handler write the quarantine
  UUID into both `payload_hash` and `request_id`, while the proxy path writes
  a real SHA-256 and the real JSON-RPC id. `Verify()` passes either way, but a
  ledger whose columns change meaning per writer undermines its whole forensic
  value — and the forensic value *is* the moat.
- **Test smells:** a tautological dashboard test (asserts a recomputed formula
  against itself, never calls the handler); sqlmock tests that pattern-match
  SQL strings (they test generated code, not your logic); advisory-lock key
  `4242420427` and `openIntegrationDB` duplicated across three test files.
- **Dependency health:** `lib/pq` is officially in maintenance mode (its own
  README recommends pgx); the ledger's serialization-retry check is coupled to
  `*pq.Error`. Not urgent, but plan the pgx move deliberately.
- **Hardening gaps vs. 2026 practice:** `http.Server` has zero timeouts
  (Slowloris — a real CVE class, CVE-2025-53634); graceful shutdown exists but
  lacks the readiness-first drain; CI lacks gofmt/staticcheck-or-golangci-lint/
  gosec/govulncheck/coverage; `/api/v1/health` and `/readyz` are not split by
  liveness semantics.
- **What's genuinely exemplary (keep doing this):** length-prefixed canonical
  hash encoding with a comment explaining why; microsecond-truncation
  normalization pinned by a test; fail-closed defaults everywhere; approver
  identity from context with a `{"approved_by":"forge-me"}` forgery test; env-
  only secret config (`yaml:"-"`); the Task 3 leak test using zap's observer
  core. Several of these are better than production code I've audited.

---

## 3. Guiding principles (drawn from the research, applied throughout)

1. **Body is source of truth; headers are validated mirrors.** Never let an
   attacker-spoofable header feed policy.
2. **Fail closed, and say so in a comment at the decision site.** KiteRail
   already does this well — it's a brand asset.
3. **Typed over stringly.** Every status/action/enum becomes a typed string
   with constants. Compilers are the cheapest reviewers.
4. **Tests must be as honest as the threat model.** Mocks mirror real
   semantics or get deleted; state machines get real-database integration
   tests.
5. **One source of truth, enforced.** One migrations dir, one schema mirror,
   one advisory-lock helper, CI gates that detect drift.
6. **Finish features or delete them.** Dead code and stubs are where the next
   maintainer (human or AI) burns a day.
7. **Out-focus, don't out-breadth.** Every new primitive must strengthen
   quarantine/HITL, tamper-evident audit, or (later) agent identity — or it
   waits.

---

## 4. The roadmap

Phases 0–5 ship the stable MVP (the prompt's tasks, re-sequenced around the new
bug and the hardening the release gate will demand). Phase 6 is the v1.1
candidate list, market-prioritized. Every phase ends with
`go test -race -count=1 ./...` green plus its own acceptance checks. When the
repository's Compose Postgres service is used from the host, its published
address is `localhost:55432` (container port `5432`); CI's service container
continues to use `localhost:5432`.

### Phase 0 — Hotfix: replay-exhaustion wedge (blocking, ~half a day)

The second live bug ships in v1.0.0 today; fix before anything else.

1. `sql/quarantine.sql`: change the `MarkReplayFailed` guard to
   `status = 'replaying'`; allowing `approved` would hide an invalid state
   transition because the worker claims an entry before it can fail. Regenerate with the CI-pinned sqlc
   (`sqlc generate`; the CI freshness gate then protects it).
2. Change `:exec` → `:execresult` and make `Store.MarkReplayFailed` return an
   error when `RowsAffected == 0` — state transitions must never silently
   no-op. (This is the general fix: audit every `:exec` used as a state
   transition the same way.)
3. Fix the false comment at `worker.go:120` ("claim already incremented
   attempts") to describe reality: attempts increment on `ReturnToApproved` /
   `MarkReplayed`.
4. Align `mockStore` with real semantics (no claim-time increment;
   `MarkReplayFailed` accepts only `replaying`) so unit tests stop lying — then
   adjust the existing exhaustion test's call counts (real path takes one more
   upstream call than the mock did).
5. **Acceptance:** a new env-gated integration test drives
   create → approve → claim → fail ×4 against real Postgres and asserts the
   row lands in `replay_failed`; `go test -race ./...` green.
6. Hygiene in the same commit: delete `backend/test_db_import.go`,
   `internal/ledger/test_db_import_test.go`, and orphaned `backend/sql/migrations/`;
   correct the `sql/schema.sql` header to name the real embedded dir.

*Learning focus:* `:exec` swallows zero-row updates; `RowsAffected` is how
state machines defend themselves; mocks must be derived from the real SQL, not
invented.

### Phase 1 — Task 4A/4B: the E2E invariant suite (the regression net)

Scope adjustments from the review: the harness must exercise the **real
quarantine store's state machine** (the thing that hid both live bugs), and the
duplicated integration-test plumbing gets extracted first.

1. Extract `internal/dbtest`: one `Open(t)` helper owning the advisory lock
   (single lock key), DSN handling, `db.Migrate`, per-test `TRUNCATE`, and
   `t.Cleanup` teardown. Migrate the three existing integration test files to
   it — deleting ~100 lines of triplicated helpers.
2. Build `backend/cmd/server/e2e_integration_test.go` per the prompt: real PG
   (via `dbtest`), real OPA engine on a temp policy dir, real ledger +
   quarantine stores, real `buildHTTPHandler` wiring, `httptest` upstream
   requiring the service Bearer token, and a synchronous worker trigger (export
   a minimal `ProcessOnce`-style seam — honest, production `Run` unchanged; no
   `time.Sleep`).
3. Implement invariants 1–5 from the prompt (allow path end-to-end; quarantine
   → approve → replay with auth; `ledger.Verify()` true with non-empty
   JSON-RPC ids; trust separation; fail-closed when the ledger is unavailable)
   **plus three new ones:**
   - **Invariant 6 — exhaustion surfaces:** failing upstream ×N lands the entry
     in `replay_failed` where a reviewer can see it (Phase 0, permanently
     pinned).
   - **Invariant 7 — ledger schema honesty:** a replayed entry's ledger row
     carries a real SHA-256 payload hash and the original JSON-RPC request id
     (see Phase 6 item 4 — until then, assert and document current behavior).
   - **Invariant 8 — header/body contradiction** (added with Phase 3; harness
     lands now).
4. **Acceptance (prompt's criteria):** real wiring, real PG + OPA, ledger
   verification passes, no unbounded sleeps, `-race` green, teardown leaves no
   zombie connections.

*Learning focus:* testcontainers vs. env-gated CI Postgres (we keep the CI
service — simpler and already working); `httptest.NewServer` as a fake
upstream; why state machines belong in integration tests.

### Phase 2 — Task 5: OPA decision validation + simulator parity

1. `internal/types`: introduce `type Action string` with `ActionAllow /
   ActionDeny / ActionQuarantine` constants; sweep the codebase (proxy switch,
   engine, handlers, metrics labels, tests) off string literals. Keep SQL
   literals as-is (they live in `.sql`, one source of truth).
2. In `opaengine.Evaluate`: validate the parsed decision — empty/unknown
   action or empty rule → deterministic fail-closed result
   `{action: deny, rule: "invalid_policy_decision", explanation: "Policy engine
   returned an invalid decision"}` (exactly the prompt's shape). Eval errors
   already fail closed; keep that.
3. `policystore.handleSimulate`: run the identical validation path so
   simulation output is byte-for-byte the enforcement outcome; stop defaulting
   `RawMethod` to `"tools/call"` here (Phase 3 defines the one true meaning).
4. Tests: valid allow-with-rule; missing rule; empty action; eval error;
   simulator == runtime for all four. Plus one aggregator-level Rego test in
   `tests/policies/` pinning that every policy contribution carries a rule
   (the fintech policies already do).
5. **Acceptance (prompt's):** rule populated on success; fail-closed on
   malformed decisions; simulator parity; switch statement untouched.

*Learning focus:* fail-closed at trust boundaries; why "garbage in, deny out"
is a one-line property worth a test each.

### Phase 3 — Task 6: MCP ingress per the 2026-07-28 profile (narrow, as the prompt demands)

Not the whole spec — no Tasks/Apps/elicitation/multiple transports. The
normative intermediary subset:

1. **One documented meaning for `RawMethod`: the JSON-RPC protocol method.**
   `proxy.go` sets it from the validated body (`tools/call`, or the actual
   method for others); never `r.Method`. HTTP method is transport metadata,
   already available to policy as such if ever needed.
2. **Single-message rule:** reject JSON-RPC arrays (batching is not in MCP)
   and client-sent responses; require `jsonrpc:"2.0"`. Fail closed as today,
   with `-32600` semantics documented.
3. **Mirrored-header validation (stateless profile):** when `Mcp-Method` /
   `Mcp-Name` are present they MUST be singleton, non-empty headers and equal
   the body's `method` / `params.name` (`tools/call` and `prompts/get`) or
   `params.uri` (`resources/read`). Decode the case-sensitive Base64 sentinel
   before comparing `Mcp-Name`. Contradiction → HTTP 400 + JSON-RPC `-32020`
   **before OPA evaluation**, so policy input is never attacker-spoofable.
   Absent headers are tolerated (legacy clients) — policy still reads the
   body. When forwarding, mirror headers; never rewrite one side only.
4. **`MCP-Protocol-Version`:** for the MVP, accept-and-forward without
   enforcing (enforcement = version pinning, a v1.1 decision once upstream
   ecosystems settle; API7/LiteLLM show the ops cost of premature pinning).
   Document the stance in `docs/ARCHITECTURE.md`.
5. Error mapping table (proxy-generated errors use spec codes; custom codes
   stay in `-32000..-32019`): document in API.md.
6. Tests: the prompt's three (tools/call RawMethod/Tool; other method;
   contradictory metadata rejected) plus version-header pass-through and
   batch-rejection.
7. **Acceptance (prompt's):** one documented RawMethod meaning; real and
   simulated EvalInput semantically identical; contradictory metadata fails
   closed.

*Learning focus:* why the spec forces header/body agreement (the
load-balancer-authorizes-header/executes-body attack); intermediaries mirror,
never edit.

### Phase 4 — Production hardening ✅ Done

*(Completed; the plan items below are kept for the record.)*

Small, idiomatic, high-value — do these *before* Task 7 so the gate evaluates
the hardened artifact:

1. `http.Server` timeouts: `ReadHeaderTimeout` (Slowloris defense),
   `Read/WriteTimeout`, `IdleTimeout` — explicit in `cmd/server`.
2. Graceful shutdown: flip readiness to 503 on SIGTERM *before*
   `srv.Shutdown` (drain window), check `Shutdown`'s return.
3. Health split: `/api/v1/health` stays shallow (liveness), `/readyz` checks
   DB ping + policy engine loaded (readiness). Never DB in liveness.
4. CI: add `gofmt -l`, `golangci-lint v2` (catches `HttpRequestsTotal`
   initialisms, unchecked errors, unused code), `govulncheck`, and a coverage
   upload; keep the sqlc freshness gate.
5. Cheap code fixes surfaced by the new linters: unchecked decode error +
   body cap in `denyEntry`; typed response structs replacing
   `map[string]interface{}` at the API boundary (start with dashboard);
   `path.Ext` instead of hand-rolled `fileExt`.
6. Dependency hygiene: remove `nats-server/v2` from direct deps (test-only
   build tag for the events test, or gate/delete the package until v1.1);
   `finish-or-delete` on `policystore.Save`/`UpdateEnabled` (recommend: delete
   until admin mutation + `Engine.Reload` is a real feature, with `id`
   sanitization when it returns).
7. **Acceptance:** `make`-less verification script runs green (commands listed
   in Phase 5); no behavior change beyond the listed items; `-race` green.

*Outcome (Phase 4 as executed):* `ReadHeaderTimeout` (yaml `read_header_timeout`,
default 5 s); readiness-first drain (SIGTERM flips `/readyz` to 503 before
`srv.Shutdown`, then rejects protected new work during a bounded drain delay);
health split kept (`/api/v1/health` liveness, `/readyz` readiness with DB ping
and a compiled OPA decision entry point). CI gained `gofmt -l`, golangci-lint v2, govulncheck,
and a coverage artifact; the sqlc freshness gate stays. Linter-surfaced fixes:
`denyEntry` body cap (1 KiB) + checked decode → 400 on bad body; typed
`statsResponse` replacing the dashboard's `map[string]interface{}`;
`path.Ext` replacing hand-rolled `fileExt`; `HTTP*` metric initialism renames.
Dependency hygiene: `internal/events` deleted (NATS dead code),
`nats-server/v2` off direct deps, unreachable `policystore.Save`/
`UpdateEnabled` deleted. Toolchain bumped to Go 1.26.6 with `x/crypto` v0.56.0
/ `x/net` v0.58.0 — `govulncheck` reports zero reachable vulnerabilities.
New lint config `.golangci.yml` (v2; errcheck + staticcheck with idiomatic
exclusions for deferred `Close`/`Rollback`/`RemoveAll`/`Setenv`). Also fixed:
OPA engine on Windows absolute policy dirs (`loaderPath` → `file://` URLs;
relative dirs unchanged), and a pre-existing CRLF/gofmt drift fixed repo-wide
via `.gitattributes` (`*.go text eol=lf`).

*Learning focus:* zero-value `http.Server` is a hazard; readiness-as-drain;
every direct dependency is a liability you must justify.

### Phase 5 — Task 7 release gate + Task 8 performance metrics

1. Run the gate exactly as the prompt specifies: emit the verification command
   list, wait for real output, evaluate against the six audit areas, produce
   the 8-section report, conclude `READY` / `NOT READY FOR STABLE MVP TAG`.
   The prior phases' acceptance criteria *are* the blocking-defect list.
2. Task 8 metrics (resume-grade numbers): `vegeta` load test vs. a 10 ms
   httptest upstream at 1,000+ rps (P99 proxy overhead target <5 ms);
   `go test -bench` for `ledger.Append` including 1 MB payloads; 500-goroutine
   concurrency stress under `-race` asserting chain integrity + contiguous
   seq_nums; `go test -coverprofile` for proxy + ledger (target ≥90% on the
   critical path — the E2E suite should get most of the way there).
3. Also fix the two broken tests the review found before citing coverage
   numbers: the tautological dashboard test (extract the compliance calc into
   a function and test that) and the stale-error assert in
   `opaengine/engine_test.go:71`.
4. **Acceptance:** raw numeric outputs recorded in the release report;
   commands reproducible from a fresh clone.

*Learning focus:* metrics you can't reproduce are vanity; benchmarks as
ordinary tests; the race detector as a mindset.

### Phase 6 — v1.1 candidates (market-prioritized; not part of the stable-MVP gate)

Ordered by leverage ÷ effort, each tied to a differentiator or a dependency
health need:

| # | Item | Effort | Rationale |
|---|---|---|---|
| 1 | **Shadow/audit mode for policies** (evaluate new bundle, log divergence, don't enforce; atomic swap via the engine's existing mutex pattern; `policy_shadow_mismatches_total`) | M | How enterprises actually adopt policy engines; `soth-ai/mcp-proxy` already ships audit/enforce — this closes the parity gap |
| 2 | **Ledger honesty + rug-pull detection** (worker/deny rows store real payload SHA-256 + original JSON-RPC id; add tool-name + tool-description hash captured at quarantine time so approval binds the exact tool definition; re-validate on replay — the spec's replay-binding checklist item) | M | Compounds the *unique* moat; turns the ledger into tamper-evident rug-pull evidence no competitor ships |
| 3 | **pgx migration** (`pgx/v5/stdlib` drop-in first; native later; adapter for the serialization-error check) | S→M | `lib/pq` is maintenance-mode; sqlc already supports pgx codegen |
| 4 | **Approval-bound tuple** (method, tool, arguments-hash, protocol version, authenticated principal) recorded at approve-time and re-checked at replay | S | Extends #2; spec-backed MUST for replay integrity |
| 5 | **RED metrics + OTel traces** (`http_requests_total{route,status}`, duration histograms, `policy_decisions_total{rule,decision}`, quarantine depth gauge; `otelhttp` wrapper; traceparent propagation in `_meta`) | M | Task 8 proves speed; this proves operability; the field's observability bar |
| 6 | **Typed statuses** (`type Status string` in quarantine) and typed API responses everywhere | S | Bug-class elimination started in Phase 2, finished here |
| 7 | **External anchoring of the ledger head** (signed daily root to object-lock storage) | S | Internal-only chains are beatable by tail-rewrite; anchoring makes the moat real — defer deliberately, record the chain from day one (already done) |
| 8 | **OAuth 2.1 resource-server conformance** (RFC 9728 PRM endpoint, RFC 8707 audience validation, step-up challenge pass-through) | L | The field's auth bar; positions KiteRail for pilots with real IdPs; biggest item — schedule only after 1–5 |
| 9 | **Agent identity watch** (track OIDC-A / NIST CAISI / SPIFFE convergence; design the EvalInput extension so `agent` can become an attested identity later without schema breakage) | S (design) | The biggest open lane in the field — be ready to move when the standard firms up; do not build early |

**Explicitly not building** (guardrails for a solo maintainer): multi-server
multiplexing, OpenAPI↔MCP conversion, MCP registry construction (consume Docker
Catalog / official registry later), behavioral/intent analytics (integrate
mcp-scan-style tooling instead of competing with Invariant), distributed rate
limiting (Redis) until multi-instance is real, Envoy-style hot restart
(in-process atomic swap suffices).

---

## 5. How to work through this (for the Go learner)

Each phase is also a curriculum. In order, you will practice:

- **Phase 0:** reading generated SQL as the source of truth; `RowsAffected`;
  mock fidelity; regenerating sqlc code and letting CI enforce freshness.
- **Phase 1:** integration testing against real Postgres; harness design
  (setup/teardown discipline, `t.Cleanup`, no sleeps); invariants as
  executable specifications.
- **Phase 2:** fail-closed design; typed strings; property-style tests (one
  test per malformed input, not one mega-test).
- **Phase 3:** protocol semantics; why intermediaries validate then mirror;
  reading a spec for normative language (MUST/SHOULD).
- **Phase 4:** the production HTTP server (timeouts, shutdown, probes);
  linting as a permanent reviewer; dependency budgeting.
- **Phase 5:** benchmarking, load testing, and honest reporting.
- **Phase 6:** architectural judgment — what to build, what to integrate, what
  to refuse.

Two habits worth adopting permanently, both evidenced in your own codebase:
write the comment that explains *why* at every fail-closed decision site
(already a strength), and treat every green test as a claim that must survive
contact with the real database (the lesson of Phase 0).

---

## Appendix A — Research sources (condensed)

**Market:** Kong AI MCP Proxy plugin (developer.konghq.com); Envoy AI Gateway
v1.0 (aigateway.envoyproxy.io, 2026-06-23); Portkey MCP Gateway open-sourcing
(thenewstack.io, 2026-03-31); LiteLLM MCP docs; Traefik triple-gate
(traefik.io, 2025-10-14); Cloudflare MCP Server Portals (2025-08-26); Azure
APIM MCP GA (2025-11-18); Lasso, Zenity, Runlayer ($30M Series A, 2026-06),
MintMCP, HiddenLayer $100M (2026-09-03); `soth-ai/mcp-proxy` and
`siyad01/gatekeeper` (closest OSS rivals); Invariant Labs mcp-scan; Docker MCP
Catalog; Agentic AI Foundation (Linux Foundation, 2025-12-09); OpenID
Foundation agent-identity whitepaper (2025-10); NIST CAISI + NCCoE concept
paper (2026-02-05).

**Spec:** MCP 2026-07-28 Streamable HTTP, versioning, authorization, and schema
pages (modelcontextprotocol.io, fetched 2026-09-07); OWASP MCP Security Cheat
Sheet; OWASP MCP Top 10 v0.1 (2026-05-07); FastMCP confused-deputy CVE-2026-27124.

**Go & MVP primitives:** go.dev/doc/modules/layout (project layout verdict:
keep `cmd/` + `internal/`); Dave Cheney, functional options (2014, still
canonical); lib/pq README (maintenance mode → pgx); go.dev Go 1.24 `t.Context`
/ Go 1.25 synctest / Go 1.26 goroutine-leak profile; testcontainers-go docs
(2026-07); golangci-lint v2 (2025-03); govulncheck; CVE-2025-53634 (Slowloris
via zero-value `http.Server`); Kubernetes probe semantics
(kubernetes.io, 2026-06); RED method (last9.io) / USE (Brendan Gregg); hash-chain
tamper-evidence best practices (finqub.io, 2026-06; ISO 27001 A.8.15);
golang-migrate/goose/Atlas comparison (2026); OPA shadow-mode lifecycle
(cloudmatos.ai, 2025-12).
