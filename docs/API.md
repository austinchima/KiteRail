# KiteRail REST API Reference

Base URL for a local development instance: `http://localhost:8080`

Every endpoint under `/api/v1/` returns JSON. The `/` root is not a REST endpoint — it is the transparent MCP / JSON-RPC proxy documented [in its own section](#the-proxy-endpoint).

---

## Authentication

All endpoints except `/api/v1/health`, `/readyz`, and `/metrics` require a bearer token.

```http
Authorization: Bearer <token>
```

Tokens are accepted **only** via the `Authorization` header — never query parameters, which leak into access logs and referrer headers.

### Trust domains

KiteRail enforces three separate trust domains. Tokens must never be shared across domains; startup fails if a duplicate token is detected.

| Domain | Config key | Env var | Can do |
|---|---|---|---|
| **Agent** | `api_keys` | `KITERAIL_API_KEYS` | Call the proxy (`POST /`) |
| **Reviewer** | `reviewer_api_keys` | `KITERAIL_REVIEWER_API_KEYS` | Approve/deny quarantine, read ledger & dashboard, list/simulate policies |
| **Admin** | `admin_api_keys` | `KITERAIL_ADMIN_API_KEYS` | Everything a reviewer can |

The mapped identity (`agent_id`, reviewer ID, admin ID) is what gets recorded in the audit ledger for every decision.

**Failure modes:**

| Condition | Status | Body |
|---|---|---|
| No/malformed `Authorization` header | `401 Unauthorized` | `{"error": "missing or malformed Authorization header, expected Bearer token"}` |
| Token not recognised | `403 Forbidden` | `{"error": "invalid API key"}` |
| Agent hitting a reviewer/admin route | `403 Forbidden` | `{"error": "insufficient role"}` |

---

## Conventions

- All request bodies are `Content-Type: application/json`.
- All response bodies are JSON unless otherwise noted.
- Timestamps are RFC 3339 in UTC (e.g. `2026-08-01T14:32:11Z`).
- IDs are opaque strings — don't parse them. New quarantine IDs are UUIDs; integer IDs from pre-UUID databases are retained internally as `legacy_id` during migration.
- Errors use the shape `{"error": "<human message>"}` and where applicable `{"error": "...", "explanation": "..."}`.

---

## Endpoint Summary

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/api/v1/health` | none | Liveness (process up; never touches the DB) |
| `GET` | `/readyz` | none | Readiness — `503` unless Postgres answers |
| `GET` | `/metrics` | none | Prometheus metrics |
| `POST` | `/` | agent | The proxy — governs MCP / JSON-RPC tool calls |
| `GET` | `/api/v1/quarantine` | reviewer/admin | List HITL items by status |
| `POST` | `/api/v1/quarantine/:id/approve` | reviewer/admin | Approve (durable worker replays) |
| `POST` | `/api/v1/quarantine/:id/deny` | reviewer/admin | Reject a quarantined item |
| `GET` | `/api/v1/ledger` | reviewer/admin | Read audit entries |
| `GET\|POST` | `/api/v1/ledger/verify` | reviewer/admin | Verify hash-chain integrity |
| `GET` | `/api/v1/policies` | reviewer/admin | List loaded policies |
| `POST` | `/api/v1/policies/simulate` | reviewer/admin | Dry-run any tool call against current policies |
| `PATCH\|PUT\|POST` | `/api/v1/policies/:id` | — | **Disabled** (`405`) — policies are GitOps-immutable in the stable release |
| `GET` | `/api/v1/dashboard/stats` | reviewer/admin | Aggregate counts for the local UI |
| `GET` | `/api/v1/topology/stream` | required | SSE — reserved for a future release (currently `501 Not Implemented`) |

Per-agent rate limiting is enforced with a token bucket (`rate_limit_rps` / `rate_limit_burst`, defaults 10 rps / burst 20). Exceeding it returns `429 Too Many Requests`.

---

## End-to-End Request Sequence

To understand how KiteRail's endpoints work together, here is a complete lifecycle of an intercepted agent request that gets flagged for human review:

1. **Agent:** Sends a tool call `POST /` (e.g., refund $5000).
2. **Proxy:** Checks the OPA policy. The policy returns `quarantine`.
3. **Proxy:** Returns `202 Accepted` to the agent with a `quarantine_id`. The request pauses here.
4. **Human Reviewer:** Calls `GET /api/v1/quarantine` and sees the pending refund.
5. **Human Reviewer:** Calls `POST /api/v1/quarantine/<id>/approve`.
6. **Proxy:** Immediately responds `200 OK` with `{"status": "approved", "id": "..."}`. The durable replay worker claims the approved entry from Postgres (state: `replaying`) and POSTs the original payload to the target with a stable `Idempotency-Key`. One advisory-locked replay pass runs across replicas, so crash recovery cannot reset another live worker's claim. A failed entry is retried three times and the fourth failed call parks it as `replay_failed` for re-approval. If the server crashes mid-replay, the next locked pass returns the abandoned entry to `approved`.
7. **Proxy:** Each replay outcome is recorded in the ledger with decisions `approved_replayed`, `replay_error`, or `replay_upstream_<code>`.

---

## `GET /api/v1/health` and `GET /readyz`

`/api/v1/health` is the **liveness** probe: it reports process uptime only and never touches Postgres, so it stays green even during a database outage.

**Response — `200 OK`**
```json
{
  "status": "ok",
  "version": "1.1.0",
  "uptime_seconds": 1234.56
}
```

`/readyz` is the **readiness** probe: it returns `503 Service Unavailable` unless Postgres answers within 2 seconds **and** the active OPA query contains KiteRail's authorization decision entry point. Orchestrators/load balancers should gate traffic on `/readyz`, not on health.

During graceful shutdown the server flips readiness to `503` **before** beginning connection drain: the instant SIGTERM is received, `/readyz` starts returning `503` with body `{"ready": false, "draining": true}` while `/api/v1/health` stays `200` until the process exits. Protected routes reject new work with `503` during the configured `shutdown_drain_delay` (default 5 s); existing requests then receive the server's 10-second shutdown window. The HTTP server also enforces `ReadHeaderTimeout` (Slowloris defense; default 5 s, configurable via `read_header_timeout` in the YAML config).

---

## The Proxy Endpoint

### `POST /`

This is the whole point of KiteRail. The ingress is **strict and fail closed** — only bounded JSON-RPC/MCP invocations are processed:

1. Authenticated via agent bearer token.
2. Method must be `POST`; anything else is rejected with `405`.
3. Body is size-capped (`max_request_body_bytes`, default 1 MiB); oversized bodies get `413`.
4. Parsed as JSON and validated as a **single** JSON-RPC 2.0 invocation per the 2026-07-28 MCP stateless profile: the body must be one JSON object with `jsonrpc: "2.0"`. Batches, client-sent responses (`result`/`error`), duplicate member names at any depth, non-UTF-8/non-JSON input, missing `method`/`params`, empty/non-string `method`, `tools/call` without a `params.name`, and non-object `params.arguments` are all rejected with `400` + JSON-RPC `-32600`. JSON numbers, including large JSON-RPC IDs, are retained without float64 rounding. **Nothing malformed is ever forwarded to the target or bypasses policy evaluation.**
5. Mirrored MCP metadata is validated (see below): a contradiction between the `Mcp-Method` / `Mcp-Name` headers and the body is rejected with `400` + JSON-RPC `-32020` **before** policy evaluation — policy input is never attacker-spoofable via headers.
6. If `method == "tools/call"`, `params.name` becomes the tool name and `params.arguments` becomes the arguments object (per the MCP specification). For any other `method`, the method string itself is used as the tool name.
7. Evaluated against the OPA policy engine. Policies contribute to a shared `decisions` set; the aggregator selects the most restrictive action (deny > quarantine > allow). The engine input's `raw_method` is the JSON-RPC protocol method from the validated body (`"tools/call"`, or the actual method for other calls) — never the HTTP method, which is transport metadata.
8. Written to the audit ledger with a SHA-256 hash of the request body. **If the ledger write fails, the request is refused with `503` — allowed requests never execute unaudited.**
9. Routed based on the decision.

**Request**
```bash
curl -X POST http://localhost:8080/ \
  -H 'Authorization: Bearer sk_agent_...' \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "stripe.charge.refund",
      "arguments": { "amount": 1500, "charge": "ch_xxx" }
    }
  }'
```

**Response — depends on the OPA decision**

| Decision | Status | Body |
|---|---|---|
| `allow` | Whatever the target API returns | Whatever the target API returns |
| `deny` | `403 Forbidden` | `{"error": "Denied by policy", "explanation": "<rule text>"}` |
| `quarantine` | `202 Accepted` | `{"quarantine_id": "<opaque-id>", "status": "quarantined"}` |

**Mirrored MCP headers (2026-07-28 stateless profile)**

KiteRail is a validating intermediary: the body is always the source of truth for policy, and mirrored headers are checked, never trusted blindly.

| Header | Rule |
|---|---|
| `Mcp-Method` | When present, exactly one non-empty value MUST equal the body's `method`. Contradiction or duplication → `400` + `-32020`. Absent → tolerated for legacy clients; policy reads the body. |
| `Mcp-Name` | When present, exactly one non-empty value is decoded from the case-sensitive `=?base64?<base64>?=` sentinel when used. It MUST equal `params.name` for `tools/call` and `prompts/get`, or `params.uri` for `resources/read`; it is rejected for other methods. |
| `MCP-Protocol-Version` | Exactly one non-empty value is accepted and forwarded without enforcement. Version pinning is a deliberate post-MVP decision (see `docs/ARCHITECTURE.md`). |

On allow, headers are **mirrored, never rewritten**: `Mcp-Method` / `Mcp-Name` / `MCP-Protocol-Version` arrive at the target exactly as the client sent them. On quarantine, only replay-safe protocol metadata (`Accept`, those MCP headers, and `Mcp-Param-*`) is retained; credentials, cookies, and connection headers are never persisted.

**Error mapping (proxy-generated errors)**

| Condition | HTTP | JSON-RPC code | Body shape |
|---|---|---|---|
| Non-POST, oversized body | `405` / `413` | `-32600` | spec error object (below) |
| Envelope violation (non-JSON, batch array, client-sent response, missing/`!= "2.0"` `jsonrpc`, missing/invalid `method`/`params`) | `400` | `-32600` | `{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"..."}}` |
| Header/body contradiction (`Mcp-Method` / `Mcp-Name`) | `400` | `-32020` | same shape, `code: -32020` |
| Policy `deny` | `403` | — | `{"error": "Denied by policy", "explanation": "<rule text>"}` |

`-32600` is the JSON-RPC 2.0 standard *invalid request* code; `-32020` is reserved by the 2026-07-28 MCP spec for header/body disagreement. KiteRail's own codes, if any are ever added, stay inside the spec-reserved custom range `-32000..-32019`.

**Notes**
- The proxy transparently forwards the original request path, headers (minus the agent's Authorization header, which is stripped), and body when the decision is `allow`. Target URL is `KITERAIL_TARGET_URL`.
- If your target API requires service authentication, set `KITERAIL_TARGET_AUTH_TOKEN` (environment only, never YAML). It is presented to the target as `Authorization: Bearer <token>` on forwarded and replayed requests.
- The audit ledger entry is written *before* the routing decision is executed, so a crash between "decide" and "route" still leaves an auditable record — and a ledger outage blocks execution rather than allowing unaudited traffic.

---

## Quarantine (Human-in-the-Loop)

### `GET /api/v1/quarantine`

List quarantined items awaiting human review. **Reviewer/admin only.**
Filter by status with `?status=pending|approved|replaying|replayed|denied|replay_failed` (default: `pending`).
Note: The `Payload` field contains base64 encoded bytes of the original request body.

**Request**
```bash
curl -H "Authorization: Bearer sk_reviewer_..." \
  http://localhost:8080/api/v1/quarantine?status=pending
```

**Response — `200 OK`**
```json
[
  {
    "ID": "1042",
    "AgentID": "agent_alpha",
    "ToolName": "stripe.charge.refund",
    "Payload": "eyAiYW1vdW50IjogNTAwMCwgImNoYXJnZSI6ICJjaF94eHgiIH0=",
    "Status": "pending",
    "CreatedAt": "2026-08-01T14:32:11Z",
    "ResolvedAt": null,
    "ResolvedBy": ""
  }
]
```

### `POST /api/v1/quarantine/:id/approve`

Approve a quarantined item. **Reviewer/admin only.** KiteRail will:

1. Mark the item `approved` in the database (conflict-safe — concurrent calls return `409`). The approver identity is taken from the **authenticated reviewer/admin token** — any `approved_by` value in the request body is ignored. The response is returned **immediately**.
2. The durable replay worker claims the entry (`approved` → `replaying`) and POSTs the original payload verbatim to `KITERAIL_TARGET_URL` with a stable `Idempotency-Key: kiterail-quarantine-<id>` header, so tolerant upstreams can deduplicate retries and crash-recovery replays. One Postgres advisory lock owns each recovery-and-replay pass across replicas. Failed attempts return the entry to `approved` for another pass; after three retry releases, the fourth failed call transitions to `replay_failed`, reappearing in the reviewer inbox for manual re-approval. Redirect responses are failures and are never followed.
3. Each replay outcome is recorded in the ledger with decisions: `approved_replayed` (success), `replay_error` (network/timeout failure), or `replay_upstream_<code>` (upstream HTTP error code).

The replay sets the following headers on the upstream request so the target can identify the context:

| Header | Value |
|---|---|
| `X-KiteRail-Agent` | Original agent identity from the quarantined entry |
| `X-KiteRail-Quarantine-ID` | The quarantine item ID |
| `X-KiteRail-Approved-By` | Authenticated reviewer/admin ID from the approval token |
| `Idempotency-Key` | `kiterail-quarantine-<id>` — stable across retries and crash recoveries |

**Request**
```bash
curl -X POST -H "Authorization: Bearer sk_reviewer_..." \
  -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/quarantine/1042/approve
```

A request body is not required; any supplied `approved_by` is ignored in favour of the authenticated identity.

**Response — `200 OK`**
```json
{ "id": "1042", "status": "approved" }
```

**Failure modes:**

| Condition | Status | Body |
|---|---|---|
| Caller is an agent or unauthenticated | `403 Forbidden` | `{"error": "reviewer or admin role required"}` |
| ID not found | `404 Not Found` | `{"error": "quarantine item not found"}` |
| Item already resolved | `409 Conflict` | `{"error": "quarantine item already resolved"}` |

### `POST /api/v1/quarantine/:id/deny`

Reject a quarantined item. **Reviewer/admin only.** The original request is *not* replayed. The denial is written to the audit ledger with the authenticated reviewer identity.

Accepts an optional JSON body (capped at 1 KiB):
```json
{
  "reason": "Amount exceeds policy limit"
}
```
A malformed or over-limit body is rejected with `400 Bad Request` (`{"error": "invalid request body"}`) before anything is persisted. An empty body is valid and simply records no reason.

The denying reviewer's identity always comes from their bearer token. `reason` is persisted to the quarantine row.

**Request**
```bash
curl -X POST -H "Authorization: Bearer sk_reviewer_..." \
  -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/quarantine/1042/deny \
  -d '{"reason": "Amount exceeds policy limit"}'
```

**Response — `200 OK`**
```json
{ "id": "1042", "status": "denied" }
```

---

## Audit Ledger

### `GET /api/v1/ledger`

Read audit entries in reverse chronological order (newest first).
Currently, this endpoint does not accept filtering query parameters; it returns the 100 most recent entries (fixed limit; pagination is planned).

**Request**
```bash
curl -H "Authorization: Bearer sk_reviewer_..." \
  http://localhost:8080/api/v1/ledger
```

**Response — `200 OK`**
```json
[
  {
    "SeqNum": 4212,
    "Timestamp": "2026-08-01T14:32:11Z",
    "Agent": "agent_alpha",
    "Tool": "stripe.charge.refund",
    "Decision": "quarantine",
    "PolicyRule": "refund_over_limit",
    "PayloadHash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "PrevHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "Hash": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
  }
]
```

Every entry stores `Hash = SHA256(PrevHash || entry_data)`. Any tampering breaks the chain from that point onward and is detected by `POST /api/v1/ledger/verify`.

### `GET|POST /api/v1/ledger/verify`

Walk the entire chain and verify integrity. Returns whether the chain is valid. Both `GET` and `POST` are accepted.

**Request**
```bash
curl -X POST -H "Authorization: Bearer sk_reviewer_..." \
  http://localhost:8080/api/v1/ledger/verify
```

**Response — `200 OK` (chain intact)**
```json
{
  "valid": true
}
```

Note that a `valid: false` response is *still* HTTP 200 — the endpoint reports the state of the chain; it does not error on tampering. This is intentional: monitoring systems should alert on `valid == false` rather than on HTTP status.

---

## Policies

### `GET /api/v1/policies`

List all Rego policies currently loaded by the OPA engine.

**Request**
```bash
curl -H "Authorization: Bearer sk_reviewer_..." \
  http://localhost:8080/api/v1/policies
```

**Response — `200 OK`**
```json
[
  {
    "id": "refund_limit",
    "title": "Refund Limit",
    "trigger_rule": "refund_over_limit",
    "action_type": "quarantine",
    "enabled": true,
    "created_at": "2026-08-01T14:00:00Z",
    "updated_at": "2026-08-01T14:00:00Z"
  }
]
```

Policies are **immutable GitOps assets** in v1.0: mutation endpoints (`PATCH/PUT/POST /api/v1/policies/:id`) return `405 Method Not Allowed`. Change policies through version control and redeploy/restart — this prevents a single compromised admin credential from rewriting the enforcement rulebook at runtime.

### `POST /api/v1/policies/simulate`

Dry-run any tool call against the current policy set *without* executing it. This is the safest way to test policy changes before deploying them.

**Request body**
```json
{
  "tool": "stripe.charge.refund",
  "arguments": { "amount": 2500 },
  "agent": "agent_alpha"
}
```

`tool` and `agent` are required so the simulated policy input is not silently different from production. The body is limited to 1 MiB, rejects duplicate JSON keys, and preserves numeric values. Simulations never touch the real agent identity or ledger.

**Request**
```bash
curl -X POST -H "Authorization: Bearer sk_reviewer_..." \
  -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/policies/simulate \
  -d '{
    "tool": "stripe.charge.refund",
    "arguments": { "amount": 2500 },
    "agent": "agent_alpha"
  }'
```

**Response — `200 OK`**
```json
{
  "action": "quarantine",
  "rule": "refund_over_limit",
  "latency_ms": 1.4,
  "explanation": "Refund exceeds $1,000 threshold — routed to human approval"
}
```

Simulations do **not** touch the ledger, do not create quarantine records, and do not call the target API. Their sole purpose is to answer *"if I sent this request right now, what would happen?"*

**Policy Authoring Note:** KiteRail policies now use the `decisions contains` pattern instead of defining the complete `decision` rule. The aggregator in `policies/main.rego` collects all `decisions` contributions and selects the most restrictive action: **deny > quarantine > allow**. Ties are broken deterministically. See [Writing Policies in the README](../README.md#writing-policies) and [docs/policy-cookbook/](policy-cookbook/) for patterns and examples.

Use this endpoint in CI to prevent policy regressions:

```bash
#!/usr/bin/env bash
# ci/check-policy.sh — fails if a known-safe tool call is not allowed
result=$(curl -s -X POST -H "Authorization: Bearer $KITERAIL_TOKEN" \
  -H "Content-Type: application/json" \
  "$KITERAIL_URL/api/v1/policies/simulate" \
  -d '{"tool": "stripe.charge.refund", "arguments": {"amount": 100}}')

action=$(echo "$result" | jq -r .action)
[[ "$action" == "allow" ]] || {
  echo "regression: small refund would be blocked"
  echo "$result" | jq .
  exit 1
}
```

---

## Dashboard Stats

### `GET /api/v1/dashboard/stats`

Aggregate counts and recent activity for the local React dashboard. Also usable directly if you're wiring your own UI.

**Request**
```bash
curl -H "Authorization: Bearer sk_reviewer_..." \
  http://localhost:8080/api/v1/dashboard/stats
```

**Response — `200 OK`**
```json
{
  "total_actions_today": 8421,
  "policy_violations": 143,
  "pending_approvals": [
    {
      "ID": "1042",
      "AgentID": "agent_alpha",
      "ToolName": "stripe.charge.refund",
      "Payload": "eyAiYW1vdW50IjogNTAwMCwgImNoYXJnZSI6ICJjaF94eHgiIH0=",
      "Status": "pending",
      "CreatedAt": "2026-08-01T14:32:11Z",
      "ResolvedAt": null,
      "ResolvedBy": ""
    }
  ],
  "compliance_status": 98.3,
  "recent_feed": [
    {
      "SeqNum": 4212,
      "Timestamp": "2026-08-01T14:32:11Z",
      "Agent": "agent_alpha",
      "Tool": "stripe.charge.refund",
      "Decision": "quarantine",
      "PolicyRule": "refund_over_limit",
      "PayloadHash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      "PrevHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "Hash": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
    }
  ]
}
```

---

## CLI Usage Examples

Everything the dashboard does is a thin wrapper over the REST API. You never need the UI. You can use standard `curl` commands to manage the proxy.

```bash
# List all quarantined requests (reviewer token)
curl -H "Authorization: Bearer sk_reviewer_..." \
  http://localhost:8080/api/v1/quarantine

# Approve a quarantined request — the durable worker replays it to the target
curl -X POST -H "Authorization: Bearer sk_reviewer_..." \
  http://localhost:8080/api/v1/quarantine/1042/approve

# Deny a quarantined request
curl -X POST -H "Authorization: Bearer sk_reviewer_..." \
  -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/quarantine/1042/deny \
  -d '{"reason": "Amount exceeds policy limit"}'

# Read the audit ledger (100 most recent entries, newest first)
curl -H "Authorization: Bearer sk_reviewer_..." \
  http://localhost:8080/api/v1/ledger

# Verify the ledger's hash chain is intact (GET or POST)
curl -X POST -H "Authorization: Bearer sk_reviewer_..." \
  http://localhost:8080/api/v1/ledger/verify

# Dry-run a policy without executing
curl -X POST -H "Authorization: Bearer sk_reviewer_..." \
  -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/policies/simulate \
  -d '{"tool": "stripe.charge.refund", "arguments": {"amount": 2500}}'
```

---

## Reserved for a future release

### `GET /api/v1/topology/stream`

Server-Sent Events stream of live proxy events for the dashboard's topology view. In the stable release this endpoint returns `501 Not Implemented` — the dashboard falls back to a static simulation. Full streaming returns in a future release alongside the NATS JetStream re-integration.

---

## Rate limiting

Per-agent token-bucket rate limiting is enforced at the ingress: `rate_limit_rps` (default 10) with `rate_limit_burst` (default 20). Agents exceeding their budget receive `429 Too Many Requests`. Reviewer/admin traffic is not currently rate-limited.

---

## Versioning

The API is versioned under `/api/v1/`. Breaking changes bump the version segment; additive changes (new fields, new endpoints) do not.

---

## Feedback

Missing an endpoint or a field you need? Open a [GitHub Discussion](https://github.com/austinchima/KiteRail/discussions) — API surface is exactly the kind of thing worth shaping around real usage.
