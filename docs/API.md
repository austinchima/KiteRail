# Elodea REST API Reference

Base URL for a local development instance: `http://localhost:8080`

Every endpoint under `/api/v1/` returns JSON. The `/` root is not a REST endpoint — it is the transparent MCP / JSON-RPC proxy documented [in its own section](#the-proxy-endpoint).

---

## Authentication

All endpoints except `/api/v1/health`, `/readyz`, `/metrics`, `/api/v1/auth/config` and the `/auth/*` sign-in routes require authentication. Agents always use a bearer token. Reviewers and admins use a bearer token or, when single sign-on is configured, a session cookie (see [Single sign-on](#single-sign-on)).

```http
Authorization: Bearer <token>
```

Tokens are accepted **only** via the `Authorization` header — never query parameters, which leak into access logs and referrer headers.

### Trust domains

Elodea enforces three separate trust domains. Tokens must never be shared across domains; startup fails if a duplicate token is detected.

| Domain | Config key | Env var | Can do |
|---|---|---|---|
| **Agent** | `api_keys` | `ELODEA_API_KEYS` | Call the proxy (`POST /`) |
| **Reviewer** | `reviewer_api_keys` or SSO group in `oidc.reviewer_groups` | `ELODEA_REVIEWER_API_KEYS` / `ELODEA_OIDC_REVIEWER_GROUPS` | Approve/deny quarantine, read ledger & dashboard, list/simulate policies |
| **Admin** | `admin_api_keys` or SSO group in `oidc.admin_groups` | `ELODEA_ADMIN_API_KEYS` / `ELODEA_OIDC_ADMIN_GROUPS` | Everything a reviewer can, plus policy reload |

The mapped identity (`agent_id`, reviewer ID, admin ID, or the SSO user's verified email) is what gets recorded in the audit ledger for every decision.

**Failure modes:**

| Condition | Status | Body |
|---|---|---|
| No/malformed `Authorization` header | `401 Unauthorized` | `{"error": "missing or malformed Authorization header, expected Bearer token"}` |
| Token not recognised | `403 Forbidden` | `{"error": "invalid API key"}` |
| Agent hitting a reviewer/admin route | `403 Forbidden` | `{"error": "insufficient role"}` |

### Single sign-on

With `oidc` configured, reviewers and admins sign in through the organisation's identity provider. The server runs the OIDC Authorization Code flow with PKCE and gives the browser only an opaque `HttpOnly` session cookie (`__Host-elodea_session` over HTTPS). Provider tokens never reach the browser, and the database stores only a SHA-256 of the session token.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/auth/config` | `{"sso": true, "provider": "Okta"}`, or `{"sso": false}`. Tells the console which sign-in to show. |
| `GET` | `/auth/login?return_to=<console URL>` | Redirects to the identity provider. `return_to` must be an exact `allowed_origins` entry plus an optional path. |
| `GET` | `/auth/callback` | The provider redirects here. On success, sets the session cookie and redirects to `return_to`; on refusal, redirects to `return_to?sso_error=<code>`. |
| `POST` | `/auth/logout` | Revokes the session and clears the cookie. Requires `X-Requested-With: elodea`. Returns `204`. |

- **Identity and role.** The identity recorded in the ledger is the `identity_claim` (default `email`, which must have `email_verified: true`). The role comes from `groups_claim`: membership in an `admin_groups` entry makes an admin, otherwise a `reviewer_groups` entry makes a reviewer, otherwise sign-in is refused.
- **Sessions** last `session_ttl` (default 8h) and end after `session_idle_ttl` (default 1h) of inactivity. Removing someone from the IdP group takes effect when their session ends; lower these to make that sooner.
- **CSRF.** Requests authenticated by the session cookie that change state (`POST`) must send `X-Requested-With: elodea`, and any `Origin` header must be an allowed origin; otherwise `403 {"error": "cross-site request rejected"}`. Bearer-token requests are unaffected.
- **Agents** can never authenticate with a cookie: the proxy route accepts bearer tokens only.

`sso_error` codes: `denied` (cancelled or refused at the provider), `no_role` (in no mapped group), `unverified_email`, `no_identity` (identity claim missing), `unavailable` (provider unreachable), `failed` (token exchange or verification failed), `session_failed`.

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
| `GET` | `/readyz` | none | Readiness — `503` unless Postgres answers and a policy bundle is loaded; reports `policy_version` |
| `GET` | `/metrics` | none | Prometheus metrics (served on `metrics_listen_addr` instead, when set) |
| `GET` | `/api/v1/auth/config` | none | Which sign-in options the console should show |
| `GET` | `/auth/login`, `/auth/callback` | none | Single sign-on round trip (browser redirects) |
| `POST` | `/auth/logout` | session | End the SSO session |
| `POST` | `/integrations/slack/interactions` | Slack signature | Approve or deny from a Slack message |
| `POST` | `/` | agent | The proxy — governs MCP / JSON-RPC tool calls |
| `GET` | `/api/v1/quarantine` | reviewer/admin | List HITL items by status |
| `POST` | `/api/v1/quarantine/:id/approve` | reviewer/admin | Approve (durable worker replays) |
| `POST` | `/api/v1/quarantine/:id/deny` | reviewer/admin | Reject a quarantined item |
| `GET` | `/api/v1/ledger` | reviewer/admin | Page through audit entries (filters, keyset pagination) |
| `GET` | `/api/v1/ledger/head` | reviewer/admin | Current chain head, for external anchoring |
| `GET` | `/api/v1/ledger/export` | reviewer/admin | Stream the full chain as NDJSON (SIEM / offline verification) |
| `GET\|POST` | `/api/v1/ledger/verify` | reviewer/admin | Verify hash-chain integrity, optionally against an external anchor |
| `GET` | `/api/v1/policies` | reviewer/admin | List loaded policies |
| `POST` | `/api/v1/policies/simulate` | reviewer/admin | Dry-run any tool call against current policies |
| `POST` | `/api/v1/policies/reload` | admin | Recompile the deployed policy bundle (rejected bundles keep the previous policy) |
| `PATCH\|PUT\|POST` | `/api/v1/policies/:id` | — | **Disabled** (`405`) — policies are GitOps-immutable in the stable release |
| `GET` | `/api/v1/dashboard/stats` | reviewer/admin | Aggregate counts for the local UI |

Per-agent rate limiting is enforced with a token bucket (`rate_limit_rps` / `rate_limit_burst`, defaults 10 rps / burst 20). Exceeding it returns `429 Too Many Requests`.

---

## End-to-End Request Sequence

To understand how Elodea's endpoints work together, here is a complete lifecycle of an intercepted agent request that gets flagged for human review:

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

`/readyz` is the **readiness** probe: it returns `503 Service Unavailable` unless Postgres answers within 2 seconds **and** the active OPA query contains Elodea's authorization decision entry point. Orchestrators/load balancers should gate traffic on `/readyz`, not on health.

During graceful shutdown the server flips readiness to `503` **before** beginning connection drain: the instant SIGTERM is received, `/readyz` starts returning `503` with body `{"ready": false, "draining": true}` while `/api/v1/health` stays `200` until the process exits. Protected routes reject new work with `503` during the configured `shutdown_drain_delay` (default 5 s); existing requests then receive the server's 10-second shutdown window. The HTTP server also enforces `ReadHeaderTimeout` (Slowloris defense; default 5 s, configurable via `read_header_timeout` in the YAML config).

---

## The Proxy Endpoint

### `POST /`

This is the whole point of Elodea. The ingress is **strict and fail closed** — only bounded JSON-RPC/MCP invocations are processed:

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

Every deny/quarantine response carries `X-Elodea-Decision` and `X-Elodea-Policy-Version`; quarantine also carries `X-Elodea-Quarantine-ID`.

**MCP-native outcomes.** Clients that send `MCP-Protocol-Version` (every conforming MCP client does) receive protocol-native responses instead of the REST shapes above, so the *model* learns why an action did not run rather than seeing a transport error:

- `tools/call` → HTTP `200` with a normal tool result marked `isError: true`. The text tells the model the action was blocked (deny) or is awaiting human approval and must not be retried (quarantine). Structured detail is in `result._meta["elodea/decision"]` (`decision`, `rule`, `explanation`, `policy_version`, and `quarantine_id` when quarantined).
- Any other method → HTTP `200` with a JSON-RPC error: `-32010` (denied by policy) or `-32011` (pending human approval), detail in `error.data`.

```json
{"jsonrpc":"2.0","id":3,"result":{
  "content":[{"type":"text","text":"Blocked by Elodea policy \"aml_jurisdiction_block\": Transfer to OFAC-flagged jurisdiction blocked by AML policy. The action was not executed."}],
  "isError":true,
  "_meta":{"elodea/decision":{"decision":"deny","rule":"aml_jurisdiction_block","explanation":"...","policy_version":"sha256:30d5052758c83ac5"}}}}
```

**Mirrored MCP headers (2026-07-28 stateless profile)**

Elodea is a validating intermediary: the body is always the source of truth for policy, and mirrored headers are checked, never trusted blindly.

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
| Policy `deny` | `403` (`200` for MCP-native clients) | `-32010` (non-`tools/call`, MCP-native) | see above |
| Policy `quarantine` | `202` (`200` for MCP-native clients) | `-32011` (non-`tools/call`, MCP-native) | see above |
| Audit ledger unavailable | `503` | — | `audit unavailable` — the action is never executed unaudited |

`-32600` is the JSON-RPC 2.0 standard *invalid request* code; `-32020` is reserved by the 2026-07-28 MCP spec for header/body disagreement. Elodea's own codes stay inside the spec-reserved custom range `-32000..-32019`.

**Notes**
- On `allow` the body is forwarded to **exactly** `ELODEA_TARGET_URL`: the agent cannot choose the upstream path or query string (policy only sees the body, so letting the agent steer the URL would be a policy bypass). Approved replays go to the same URL.
- Agent-controlled headers that must never reach the upstream are stripped: `Authorization`, `Proxy-Authorization`, `Cookie`, `Idempotency-Key`, and every `X-Elodea-*` header. The proxy then sets `X-Elodea-Agent` to the authenticated agent ID, so the upstream can trust it.
- If your target API requires service authentication, set `ELODEA_TARGET_AUTH_TOKEN` (environment only, never YAML). It is presented to the target as `Authorization: Bearer <token>` on forwarded and replayed requests.
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
    "ResolvedBy": "",
    "Reason": "",
    "Attempts": 0,
    "ReplayedAt": null,
    "RequestHeaders": {},
    "PolicyRule": "refund_over_limit",
    "Explanation": "Refund exceeds the $1,000 autonomous limit. Routed to human approval."
  }
]
```

### `POST /api/v1/quarantine/:id/approve`

Approve a quarantined item. **Reviewer/admin only.** Elodea will:

1. Mark the item `approved` in the database (conflict-safe — concurrent calls return `409`). The approver identity is taken from the **authenticated reviewer/admin token** — any `approved_by` value in the request body is ignored. The response is returned **immediately**.
2. The durable replay worker claims the entry (`approved` → `replaying`) and POSTs the original payload verbatim to `ELODEA_TARGET_URL` with a stable `Idempotency-Key: kiterail-quarantine-<id>` header, so tolerant upstreams can deduplicate retries and crash-recovery replays. One Postgres advisory lock owns each recovery-and-replay pass across replicas. Failed attempts return the entry to `approved` for another pass; after three retry releases, the fourth failed call transitions to `replay_failed`, reappearing in the reviewer inbox for manual re-approval. Redirect responses are failures and are never followed.
3. **Policy re-check.** Immediately before replaying, the worker re-evaluates the stored request against the policy in force *now*. If it is now denied (a newly sanctioned jurisdiction, a revoked agent), the replay is blocked, recorded as `replay_blocked_by_policy` with the current rule and policy version, and the item returns to the inbox as `replay_failed`.
4. **Write-ahead audit.** A `replay_started` ledger entry is written before the upstream call; if the ledger is unavailable the replay is deferred, so nothing executes unaudited. Outcomes follow as `approved_replayed` (success), `replay_error` (network/timeout failure), `replay_upstream_<code>` (upstream HTTP error code), or `replay_exhausted` (attempts used up by crash-interrupted replays).

The approval itself is ledgered as `approved` (and a denial as `denied`) under the reviewer's identity. All human-in-the-loop entries carry the **same `payload_hash` as the original `quarantine` decision**, so one query reconstructs the whole story of an action; `request_id` holds the quarantine ID.

The replay sets the following headers on the upstream request so the target can identify the context:

| Header | Value |
|---|---|
| `X-Elodea-Agent` | Original agent identity from the quarantined entry |
| `X-Elodea-Quarantine-ID` | The quarantine item ID |
| `X-Elodea-Approved-By` | Authenticated reviewer/admin ID from the approval token |
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
| Decision stored but the audit entry could not be written | `503 Service Unavailable` | `{"error": "decision recorded but audit unavailable"}` |
| Database error | `500 Internal Server Error` | `{"error": "internal server error"}` |

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

Read audit entries newest first, one page at a time.

| Query | Meaning |
|---|---|
| `limit` | Page size, 1–1000 (default 100) |
| `before` | Return entries with `seq_num` below this value. Pass back the `X-Next-Before` response header to get the next page; the header is absent on the last page. |
| `agent`, `decision`, `tool` | Exact-match filters (combine freely) |

**Request**
```bash
curl -H "Authorization: Bearer sk_reviewer_..." \
  "http://localhost:8080/api/v1/ledger?limit=50&decision=quarantine"
```

**Response — `200 OK`**
```json
[
  {
    "seq_num": 4212,
    "timestamp": "2026-08-01T14:32:11Z",
    "agent": "agent_alpha",
    "tool": "stripe.charge.refund",
    "decision": "quarantine",
    "policy_rule": "refund_over_limit",
    "payload_hash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "prev_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "hash": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
    "request_id": "1",
    "policy_version": "sha256:30d5052758c83ac5"
  }
]
```

Every entry stores `hash = SHA256(length-prefixed fields || prev_hash)`; `policy_version` joins the hash for entries that have one (older entries keep their original hashes). The table is **append-only at the database level**: `UPDATE`, `DELETE`, and `TRUNCATE` on `ledger` are rejected by triggers. A deliberate operator purge must opt in for one transaction with `SET LOCAL kiterail.ledger_maintenance = 'on'`.

### `GET /api/v1/ledger/head`

The current chain head: `{"seq_num": 8, "hash": "6bbf…", "timestamp": "…"}` (`{"seq_num": 0, "hash": ""}` when empty). Record it on a schedule somewhere the database owner cannot rewrite (object-locked storage, a transparency log, your SIEM). A hash chain on its own proves internal consistency; an external anchor also proves nothing was truncated or rewritten wholesale.

### `GET /api/v1/ledger/export`

Streams the chain in sequence order as NDJSON (`application/x-ndjson`), one entry per line, using constant memory. Resume an interrupted export with `?after_seq=<last seq_num received>`. Only one export or verification runs at a time; a concurrent request gets `429`.

### `GET|POST /api/v1/ledger/verify`

Recomputes every hash and link. Optionally verifies against an external anchor: `GET ?anchor_seq=<n>&anchor_hash=<hash>` or `POST {"seq_num": n, "hash": "..."}`.

**Response — `200 OK`**
```json
{
  "valid": true,
  "entries": 8,
  "head_seq": 8,
  "head_hash": "6bbf894b867bed88fc146c568699b3cd3c5701d9b7e0af039b7cfcb8f903ec6d"
}
```

On failure, `valid` is `false` and `first_invalid_seq` plus `reason` say where and why (for example `"anchored entry is missing (ledger truncated or rewritten)"`). A `valid: false` response is *still* HTTP 200 — alert on the field, not the status. Only one verification or export runs at a time; a concurrent request gets `429`.

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

### `POST /api/v1/policies/reload`

**Admin only.** Recompiles the policy directory that is already deployed (policies still change only through version control and your deploy pipeline). Elodea also reloads on `SIGHUP` and, by default, polls the directory every `policy_reload_interval` (30 s), so a ConfigMap or GitOps sync takes effect without a restart.

**Response — `200 OK`**
```json
{"policy_version": "sha256:4f2a…", "previous_version": "sha256:30d5…", "ready": true}
```

A bundle that fails to compile returns `422` with the compiler error in `detail`, and **the previous policy keeps enforcing**. `GET /api/v1/policies` reports the active version in `X-Elodea-Policy-Version`.

### Policy input document

Policies receive this input (`input.*`). The shape is versioned and additive-only: new fields may appear, existing ones never change meaning.

| Field | Meaning |
|---|---|
| `schema_version` | `"elodea.eval/v1"` |
| `protocol` | Ingress adapter that produced the input (`"mcp"`) |
| `protocol_version` | Client-declared protocol revision (e.g. MCP `2026-07-28`), when sent |
| `raw_method` | Protocol operation (`"tools/call"`, `"resources/read"`, …) |
| `tool` | Policy subject: the tool name for `tools/call`, otherwise the method |
| `arguments` | Tool arguments (`tools/call`) or the request params |
| `agent` | Authenticated agent identity (never client-asserted) |
| `timestamp` | Evaluation time (RFC 3339) |

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
  "explanation": "Refund exceeds the $1,000 autonomous limit. Routed to human approval."
}
```

Simulations do **not** touch the ledger, do not create quarantine records, and do not call the target API. Their sole purpose is to answer *"if I sent this request right now, what would happen?"*

**Policy Authoring Note:** Elodea policies now use the `decisions contains` pattern instead of defining the complete `decision` rule. The aggregator in `policies/main.rego` collects all `decisions` contributions and selects the most restrictive action: **deny > quarantine > allow**. Ties are broken deterministically. See [Writing Policies in the README](../README.md#writing-policies) and [docs/policy-cookbook/](policy-cookbook/) for patterns and examples.

Use this endpoint in CI to prevent policy regressions:

```bash
#!/usr/bin/env bash
# ci/check-policy.sh — fails if a known-safe tool call is not allowed
result=$(curl -s -X POST -H "Authorization: Bearer $ELODEA_TOKEN" \
  -H "Content-Type: application/json" \
  "$ELODEA_URL/api/v1/policies/simulate" \
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

## Held-action notifications

When a policy holds an action, Elodea notifies reviewers so the agent isn't left waiting until someone opens the console. Configure Slack (`ELODEA_NOTIFY_SLACK_WEBHOOK_URL`), a generic webhook (`ELODEA_NOTIFY_WEBHOOK_URL` plus `ELODEA_NOTIFY_WEBHOOK_SECRET`), or both. Set `ELODEA_CONSOLE_URL` so each notification links to the approvals queue (`<console>/#inbox`).

Notifications say which agent, which tool, which rule held it and why. They never include the tool arguments, which can contain payment or personal data.

**Delivery** goes through a Postgres outbox: it survives restarts, retries failures with backoff (15s doubling to 1h, 8 attempts), and replicas never send the same notification concurrently. It is at-least-once, so deduplicate on `X-Elodea-Delivery`. An action reviewed before its notification goes out is not announced. Redirects are treated as failures and never followed.

### Webhook event

```http
POST <ELODEA_NOTIFY_WEBHOOK_URL>
Content-Type: application/json
X-Elodea-Event: action.held
X-Elodea-Delivery: 7ab69ae4-dc75-4cd4-bff9-430f88b14c35
X-Elodea-Timestamp: 1791030000
X-Elodea-Signature: sha256=5d2f...

{
  "type": "action.held",
  "action": {
    "id": "7ab69ae4-dc75-4cd4-bff9-430f88b14c35",
    "agent": "treasury-agent",
    "tool": "swift.wire.initiate",
    "rule": "wire_high_value",
    "explanation": "Wire transfer exceeds $10,000. Routed to compliance review.",
    "held_at": "2026-10-03T09:30:00Z",
    "review_url": "https://elodea-console.example.com/#inbox"
  }
}
```

Any `2xx` response counts as delivered. To verify a request, compute `HMAC-SHA256(secret, "<X-Elodea-Timestamp>.<raw body>")`, compare it with the hex after `sha256=` in constant time, and reject timestamps more than five minutes old:

```python
import hashlib, hmac, time

def verify(secret: bytes, headers, body: bytes) -> bool:
    ts = headers["X-Elodea-Timestamp"]
    if abs(time.time() - int(ts)) > 300:
        return False
    expected = "sha256=" + hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, headers["X-Elodea-Signature"])
```

---

## Slack interactivity

### `POST /integrations/slack/interactions`

Receives Slack's button clicks when the Slack app is configured (`ELODEA_SLACK_*`). It is authenticated by Slack's request signature, not a bearer token:

- `X-Slack-Signature` must equal `v0=` + hex `HMAC-SHA256(signing_secret, "v0:<X-Slack-Request-Timestamp>:<raw body>")`, and the timestamp must be within five minutes. Otherwise `401`.
- The payload's workspace must match `ELODEA_SLACK_TEAM_ID` when set. Otherwise `403`.
- The clicking user's email (from Slack's `users.info`; bots and deactivated accounts refused) must be in `ELODEA_SLACK_REVIEWERS`, or nothing changes.

Valid clicks always get `200` within Slack's three-second limit. The decision is applied through the same path as `POST /api/v1/quarantine/:id/approve|deny` (conflict-safe, ledgered as `approved` / `denied` with the reviewer's email), and the message is then updated through Slack's `response_url`, which must be on `slack.com` or `slack-gov.com`.

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

Planned Server-Sent Events stream of live decisions for reviewer consoles. It is **not routed** in this release (the path falls through to the agent proxy and is rejected). Until it ships, poll `GET /api/v1/ledger?limit=…` or tail `GET /api/v1/ledger/export?after_seq=…`.

---

## Rate limiting

Per-agent token-bucket rate limiting is enforced at the ingress: `rate_limit_rps` (default 10) with `rate_limit_burst` (default 20). Agents exceeding their budget receive `429 Too Many Requests`. Reviewer/admin traffic is not currently rate-limited.

---

## Versioning

The API is versioned under `/api/v1/`. Breaking changes bump the version segment; additive changes (new fields, new endpoints) do not.

---

## Feedback

Missing an endpoint or a field you need? Open a [GitHub Discussion](https://github.com/austinchima/elodea/discussions) — API surface is exactly the kind of thing worth shaping around real usage.
