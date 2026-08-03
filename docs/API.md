# KiteRail REST API Reference

Base URL for a local development instance: `http://localhost:8080`

Every endpoint under `/api/v1/` returns JSON. The `/` root is not a REST endpoint — it is the transparent MCP / JSON-RPC proxy documented [in its own section](#the-proxy-endpoint).

---

## Authentication

All endpoints except `/api/v1/health` require a bearer token.

```http
Authorization: Bearer <token>
```

Tokens are configured via `KITERAIL_API_KEYS` as a comma-separated list of `token:agent_id` pairs (e.g. `sk_dev_123:agent_alpha,sk_prod_abc:agent_beta`). The mapped `agent_id` is what gets recorded in the audit ledger for every decision.

**Failure modes:**

| Condition | Status | Body |
|---|---|---|
| No `Authorization` header and no `?token=` query param | `401 Unauthorized` | `{"error": "missing authentication token"}` |
| Malformed header (not `Bearer <token>`) | `401 Unauthorized` | `{"error": "invalid Authorization format, expected Bearer token"}` |
| Token not in `KITERAIL_API_KEYS` | `403 Forbidden` | `{"error": "invalid API key"}` |

Server-Sent Events endpoints accept the token as a query parameter (`?token=<token>`) since browsers cannot set custom headers on `EventSource` connections.

---

## Conventions

- All request bodies are `Content-Type: application/json`.
- All response bodies are JSON unless otherwise noted.
- Timestamps are RFC 3339 in UTC (e.g. `2026-08-01T14:32:11Z`).
- IDs are opaque strings — don't parse them.
- Errors use the shape `{"error": "<human message>"}` and where applicable `{"error": "...", "explanation": "..."}`.

---

## Endpoint Summary

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/api/v1/health` | none | Liveness + version |
| `POST` | `/` | required | The proxy — governs MCP / JSON-RPC tool calls |
| `GET` | `/api/v1/quarantine` | required | List pending HITL items |
| `POST` | `/api/v1/quarantine/:id/approve` | required | Approve + replay to target |
| `POST` | `/api/v1/quarantine/:id/deny` | required | Reject a quarantined item |
| `GET` | `/api/v1/ledger` | required | Read audit entries |
| `POST` | `/api/v1/ledger/verify` | required | Verify hash-chain integrity |
| `GET` | `/api/v1/policies` | required | List loaded policies |
| `POST` | `/api/v1/policies/simulate` | required | Dry-run any tool call against current policies |
| `GET` | `/api/v1/dashboard/stats` | required | Aggregate counts for the local UI |
| `GET` | `/api/v1/topology/stream` | required | SSE — reserved for v1.1 (currently `501 Not Implemented`) |

---

## End-to-End Request Sequence

To understand how KiteRail's endpoints work together, here is a complete lifecycle of an intercepted agent request that gets flagged for human review:

1. **Agent:** Sends a tool call `POST /` (e.g., refund $5000).
2. **Proxy:** Checks the OPA policy. The policy returns `quarantine`.
3. **Proxy:** Returns `202 Accepted` to the agent with a `quarantine_id`. The request pauses here.
4. **Human Reviewer:** Calls `GET /api/v1/quarantine` and sees the pending refund.
5. **Human Reviewer:** Calls `POST /api/v1/quarantine/<id>/approve`.
6. **Proxy:** Replays the exact original payload to the downstream API.
7. **Proxy:** Writes an `approved` entry to the cryptographic ledger.

---

## `GET /api/v1/health`

Public endpoint. Use for liveness probes and CI smoke tests.

**Request**
```bash
curl http://localhost:8080/api/v1/health
```

**Response — `200 OK`**
```json
{
  "status": "ok",
  "version": "1.0.0",
  "uptime_seconds": 1234.56,
  "services": {
    "postgres": true
  }
}
```

The `services` map reports the reachability of each backing dependency. Any `false` value means the proxy is up but degraded — investigate before serving traffic.

---

## The Proxy Endpoint

### `POST /`

This is the whole point of KiteRail. Any request the proxy receives is:

1. Authenticated via bearer token.
2. Parsed as JSON. Non-JSON requests are forwarded unmodified to the target.
3. Inspected for a JSON-RPC `method` + `params` shape. Requests without both are forwarded unmodified.
4. If `method == "tools/call"`, `params.name` becomes the tool name and `params.arguments` becomes the arguments object (per the MCP specification). For any other `method`, the method string itself is used as the tool name.
5. Evaluated against the OPA policy engine.
6. Written to the audit ledger with a SHA-256 hash of the request body.
7. Routed based on the decision.

**Request**
```bash
curl -X POST http://localhost:8080/ \
  -H 'Authorization: Bearer sk_dev_123' \
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

**Notes**
- The proxy transparently forwards the original request path, headers (minus the Authorization header, which is stripped), and body when the decision is `allow`. Target URL is `KITERAIL_TARGET_URL`.
- The audit ledger entry is written *before* the routing decision is executed, so a crash between "decide" and "route" still leaves an auditable record.
- Non-JSON or non-JSON-RPC requests bypass policy evaluation entirely and are forwarded as-is. This is intentional — KiteRail is opinionated about MCP tool calls, not opinionated about every byte a downstream service might handle.

---

## Quarantine (Human-in-the-Loop)

### `GET /api/v1/quarantine`

List quarantined items awaiting human review. 
Note: The `Payload` field contains base64 encoded bytes of the original request body.

**Request**
```bash
curl -H "Authorization: Bearer sk_dev_123" \
  http://localhost:8080/api/v1/quarantine
```

**Response — `200 OK`**
```json
[
  {
    "ID": "q_01H8XYZ...",
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

Approve a quarantined item. Note: In v1.0, this marks the action approved in the ledger but does NOT automatically replay it to the target yet. Replay routing is planned for v1.1.

**Request**
```bash
curl -X POST -H "Authorization: Bearer sk_dev_123" \
  http://localhost:8080/api/v1/quarantine/q_01H8XYZ.../approve
```

**Response — `200 OK`**
```json
{ "id": "q_01H8XYZ...", "status": "approved" }
```

**Failure modes:**

| Condition | Status | Body |
|---|---|---|
| ID not found | `404 Not Found` | `{"error": "quarantine item not found"}` |
| Item already resolved | `409 Conflict` | `{"error": "quarantine item already resolved"}` |
| Target API replay failed | `502 Bad Gateway` | `{"error": "target replay failed", "explanation": "<upstream error>"}` |

### `POST /api/v1/quarantine/:id/deny`

Reject a quarantined item. The original request is *not* replayed. The denial is written to the audit ledger.

**Request**
```bash
curl -X POST -H "Authorization: Bearer sk_dev_123" \
  http://localhost:8080/api/v1/quarantine/q_01H8XYZ.../deny
```

**Response — `200 OK`**
```json
{ "id": "q_01H8XYZ...", "status": "denied" }
```

---

## Audit Ledger

### `GET /api/v1/ledger`

Read audit entries in reverse chronological order.
Currently, this endpoint does not accept filtering query parameters; it returns all entries.

**Request**
```bash
curl -H "Authorization: Bearer sk_dev_123" \
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

### `POST /api/v1/ledger/verify`

Walk the entire chain and verify integrity. Returns whether the chain is valid.

**Request**
```bash
curl -X POST -H "Authorization: Bearer sk_dev_123" \
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
curl -H "Authorization: Bearer sk_dev_123" \
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

Policies are hot-reloaded when files under `KITERAIL_POLICY_DIR` change. There is no need to restart the proxy after editing a `.rego` file.

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

`agent` is optional — defaults to the caller's agent identity from the bearer token.

**Request**
```bash
curl -X POST -H "Authorization: Bearer sk_dev_123" \
  -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/policies/simulate \
  -d '{
    "tool": "stripe.charge.refund",
    "arguments": { "amount": 2500 }
  }'
```

**Response — `200 OK`**
```json
{
  "action": "quarantine",
  "rule": "refund_over_limit",
  "latency_ms": 1.4,
  "explanation": "Refund exceeds $1,000 threshold — routed to human approval",
  "would_forward_to": null,
  "would_write_ledger": false
}
```

Simulations do **not** touch the ledger, do not create quarantine records, and do not call the target API. Their sole purpose is to answer *"if I sent this request right now, what would happen?"*

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
curl -H "Authorization: Bearer sk_dev_123" \
  http://localhost:8080/api/v1/dashboard/stats
```

**Response — `200 OK`**
```json
{
  "total_actions_today": 8421,
  "policy_violations": 143,
  "pending_approvals": [
    {
      "ID": "q_01H8XYZ...",
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
# List all quarantined requests
curl -H "Authorization: Bearer sk_dev_123" \
  http://localhost:8080/api/v1/quarantine

# Approve a quarantined request 
# Note: In v1.0, this marks the action approved in the ledger but does NOT automatically replay it to the target yet. Replay routing is planned for v1.1.
curl -X POST -H "Authorization: Bearer sk_dev_123" \
  http://localhost:8080/api/v1/quarantine/<id>/approve

# Deny a quarantined request
curl -X POST -H "Authorization: Bearer sk_dev_123" \
  http://localhost:8080/api/v1/quarantine/<id>/deny

# Read the audit ledger
curl -H "Authorization: Bearer sk_dev_123" \
  http://localhost:8080/api/v1/ledger?limit=50

# Verify the ledger's hash chain is intact
curl -X POST -H "Authorization: Bearer sk_dev_123" \
  http://localhost:8080/api/v1/ledger/verify

# Dry-run a policy without executing
curl -X POST -H "Authorization: Bearer sk_dev_123" \
  -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/policies/simulate \
  -d '{"tool": "stripe.charge.refund", "arguments": {"amount": 2500}}'
```

---

## Reserved for v1.1

### `GET /api/v1/topology/stream`

Server-Sent Events stream of live proxy events for the dashboard's topology view. In v1.0 this endpoint returns `501 Not Implemented` — the dashboard falls back to a static simulation. Full streaming returns in v1.1 alongside the NATS JetStream re-integration.

---

## Rate limiting

None in v1.0. The proxy trusts the caller (authenticated by bearer token) and the target API to enforce their own rate limits. This will change once the multi-tenant Cloud deployment ships.

---

## Versioning

The API is versioned under `/api/v1/`. Breaking changes bump the version segment; additive changes (new fields, new endpoints) do not.

---

## Feedback

Missing an endpoint or a field you need? Open a [GitHub Discussion](https://github.com/austinchima/KiteRail/discussions) — API surface is exactly the kind of thing worth shaping around real usage.
