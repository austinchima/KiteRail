# Elodea

**Elodea is an inline policy enforcement proxy for autonomous AI agents.**

> *Elodea treats AI agent safety as a systems problem, not a prompt problem. The LLM does one bounded step — deciding what tool to call. Everything safety-critical (policy, routing, audit, human review) is deterministic Go code you can read, diff, and test. If your agent can spend money, that shouldn't depend on how a model was fine-tuned.*

![Go](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go) ![License](https://img.shields.io/badge/License-Apache_2.0-blue) ![OPA](https://img.shields.io/badge/Policy-OPA_Rego-7d9fc3)

## Status
**v1.1.0** is the latest tagged release. **`main` is the upcoming 2.0.0:** the production-readiness work (signed images, Helm chart, hot-reloadable policy, externally anchorable audit ledger), single sign-on for reviewers, Slack and webhook notifications for held actions, approve/deny from Slack, and the rename from KiteRail to Elodea. It is a major version because the rename changes header, metric and policy-package names (see [CHANGELOG.md](CHANGELOG.md)). Looking for design partners running agentic workflows in fintech or DevOps.

## The Problem

Autonomous AI agents calling real-world APIs introduce uncontrolled risk. Regulated industries require strict authorization, human-in-the-loop controls for high-risk decisions, and an audit trail proving exactly what happened. Building these controls natively into every agent is error-prone.

Elodea targets fintech tool-call governance (like refunds and wire transfers) out of the box. The architecture is domain-agnostic: Rego policies work just as well for `kubectl` or HR APIs, but we focus on one vertical first to get the primitives right.

## How It Works

```mermaid
flowchart TB
    subgraph Client["🤖 Agent Plane"]
        A[Autonomous AI Agent<br/>JSON-RPC / MCP caller]
    end

    subgraph Ingress["🔐 Ingress Middleware"]
        M[HTTP Middleware<br/>metrics · CORS · bearer token / SSO session]
    end

    subgraph Control["⚙️ Control Plane · Request + Review"]
        direction TB
        P[MCP Interceptor<br/>validate · evaluate · route]
        E[[OPA Policy Engine<br/>compiled Rego · RWMutex]]
        API[Reviewer/Admin REST API<br/>HITL · audit · policy simulation]
        PS[(Policy Store<br/>versioned Rego bundle)]

        P -- EvalInput --> E
        E -- Decision · allow / deny / quarantine --> P
        API -- dry-run EvalInput --> E
        PS -. compile + hot reload .-> E
        API -. list policies .-> PS
    end

    subgraph Replay["♻️ Control Plane · Replay"]
        W[Durable Replay Worker<br/>replay · retry · audit]
    end

    subgraph Data["📒 Data Plane · PostgreSQL"]
        direction LR
        L[(Audit Ledger<br/>hash-chain · serial retry ×3)]
        Q[(Quarantine Store<br/>payload + replay state)]
    end

    subgraph Human["👤 Human Plane"]
        direction TB
        N[Notifier<br/>Slack · signed webhook]
        UI[Reviewer console<br/>HITL inbox · ledger · SSO]
        REV[Human Reviewer<br/>approve · deny]
        N -- held action --> REV
        REV -- review interaction --> UI
    end

    subgraph Upstream["🎯 Target Plane"]
        T[Downstream API<br/>downstream service]
    end

    A -- JSON-RPC / MCP --> M
    UI -- reviewer/admin REST request --> M
    M -- POST / · agent route --> P
    M -- /api/v1/* · human route + role guard --> API

    P -- append decision before routing · fail closed --> L
    P -- ALLOW · forward --> T
    P -- QUARANTINE · create pending item --> Q

    API -- list + approve / deny --> Q
    W -- claim / status --> Q
    W -- replay approved payload · Idempotency-Key --> T
    Q -. outbox .-> N

    classDef control fill:#1e293b,stroke:#38bdf8,color:#e2e8f0,stroke-width:2px
    classDef data fill:#0f172a,stroke:#a78bfa,color:#e2e8f0,stroke-width:2px
    classDef human fill:#78350f,stroke:#fbbf24,color:#fef3c7,stroke-width:2px
    classDef ingress fill:#052e16,stroke:#4ade80,color:#dcfce7,stroke-width:2px
    classDef upstream fill:#1e1b4b,stroke:#a5b4fc,color:#e0e7ff,stroke-width:2px
    classDef agent fill:#450a0a,stroke:#f87171,color:#fee2e2,stroke-width:2px

    class P,E,API,PS,W control
    class L,Q data
    class UI,REV,N human
    class M ingress
    class T upstream
    class A agent
```

## Features

- **Inline enforcement, zero agent changes:** point an MCP client at Elodea instead of the tool server. Every call is validated, decided by policy, ledgered, and only then executed. Anything ambiguous fails closed.
- **Agents learn from "no":** MCP clients get denials and quarantines as readable tool results (`isError`), so the model adapts instead of crashing on an HTTP error.
- **Human-in-the-loop that holds up:** high-risk calls wait in a durable queue. Approvals are ledgered, replays are idempotent, and every replay is **re-checked against current policy** before it executes.
- **Reviewers find out immediately, and can decide on the spot:** held actions are announced in Slack or to a signed webhook (PagerDuty, Opsgenie, your own service) with a link straight to the approval queue. With the Slack app, listed reviewers approve or deny right from the message, recorded under their email. Tool arguments never leave Elodea in a notification.
- **Approvals tied to real people:** reviewers sign in with your identity provider (Okta, Entra ID, Auth0, Keycloak, any OIDC provider). Roles come from IdP groups, and every approval is recorded under the verified identity.
- **Audit an auditor will accept:** a SHA-256 hash chain that is append-only in the database. Each entry names the exact policy version that decided it, and the chain head can be anchored externally to prove nothing was truncated. Paginated queries and streaming NDJSON export (for SIEMs) are built in.
- **Policy as code, live:** OPA/Rego bundles with a dry-run simulator, hot reload (SIGHUP, admin API, or GitOps polling), and automatic rejection of bundles that don't compile.
- **Ships like infrastructure:** distroless signed images with SBOM and provenance, a hardened Helm chart, file-mounted secrets, Prometheus metrics, and liveness/readiness split for zero-downtime rollouts.

## Built to outlast protocol churn

Agent protocols are moving fast: MCP revisions, agent-to-agent protocols, vendor function-calling APIs. Elodea's job doesn't change when they do. It still decides what an autonomous system is allowed to *do*, records who decided, and makes high-risk actions wait for a human. So the design keeps the protocol at the edge:

- **Adapters normalize, the core decides.** An ingress adapter (`proxy.Adapter`; MCP today) turns wire traffic into one protocol-neutral action. Policy, ledger, quarantine, and replay never see the wire format, so a new protocol is a new adapter, not a rewrite.
- **A versioned, additive policy input** (`input.schema_version = "elodea.eval/v1"`, plus `protocol` and `protocol_version`). Policies written today keep working, and new protocols or versions can be targeted explicitly when needed.
- **Smarter agents make it more valuable, not less.** More autonomy means more consequential actions, which means more need for deterministic limits, a human checkpoint, and evidence. Elodea assumes the model can be wrong or compromised and constrains outcomes, not prompts, so its guarantees don't depend on any model's behaviour.
- **Standards over lock-in:** OPA/Rego for policy, Postgres for state, Prometheus for metrics, OCI and Helm for delivery, and a ledger you can export and verify offline.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/austinchima/KiteRail.git elodea
cd elodea

# Start all services (proxy + Postgres)
docker compose up -d

# Test the health endpoint
curl http://localhost:8080/api/v1/health

# Send a test MCP request through the proxy (agent token)
curl -X POST http://localhost:8080/ \
  -H 'Authorization: Bearer sk_agent_local_000000000000' \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "stripe.charge.refund", "arguments": {"amount": 1500}}, "id": 1}'
# → Returns 202 Quarantined (exceeds $1,000 threshold)

# Approve it as a human reviewer (reviewer token)
curl -X POST http://localhost:8080/api/v1/quarantine/<id>/approve \
  -H 'Authorization: Bearer sk_reviewer_local_00000000'
# → The durable worker re-checks policy and replays the payload to the target

# Verify the audit chain
curl -H 'Authorization: Bearer sk_reviewer_local_00000000' http://localhost:8080/api/v1/ledger/verify
```

Compose exposes Postgres on host port `55432`. To run the integration tests from the host, set `ELODEA_POSTGRES_DSN=postgres://elodea:elodea@localhost:55432/elodea?sslmode=disable`.

## Deploying to production

```bash
helm install elodea deploy/helm/elodea \
  --set config.targetURL=https://payments.internal/mcp \
  --set secret.name=elodea-secrets \
  --set config.allowedOrigins='{https://elodea.example.com}'
```

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for secrets, policy delivery, ledger anchoring, monitoring, and the production checklist. Release images are signed; verify them with the steps in [SECURITY.md](SECURITY.md).

## Dashboard

![Elodea Dashboard](./assets/dashboard.png)

The reviewer dashboard (HITL inbox and audit ledger) is part of Elodea Cloud and is developed separately. It doesn't ship in this repository. Everything it does goes through the documented reviewer API ([docs/API.md](docs/API.md)), so you can build your own console, or drive reviews from Slack or a ticketing system, with the same guarantees.

Interested in piloting Elodea on real agent workflows? I am looking for design partners in fintech or agent-DevOps. Open a [GitHub Discussion](https://github.com/austinchima/KiteRail/discussions).

## Writing Policies

Elodea uses Open Policy Agent (OPA) for policy evaluation. Policies contribute decisions to a shared `decisions` set. The aggregator in `policies/main.rego` selects the most restrictive action: **deny > quarantine > allow**. Ties at equal severity are broken deterministically (sorted JSON encoding) so evaluation can never produce a conflict.

Example policy (`policies/fintech/refund_limit.rego`):

```rego
package elodea.authz

import rego.v1

# Allow refunds under $1,000
decisions contains {"action": "allow", "rule": "refund_under_limit", "explanation": "Refund amount within autonomous limit"} if {
    input.tool == "stripe.charge.refund"
    input.arguments.amount <= 1000
}

# Quarantine refunds over $1,000 for human review
decisions contains {"action": "quarantine", "rule": "refund_over_limit", "explanation": "Refund exceeds the $1,000 autonomous limit. Routed to human approval."} if {
    input.tool == "stripe.charge.refund"
    input.arguments.amount > 1000
}
```

The default-deny behavior is built into the aggregator (`policies/main.rego`). Individual policies must **not** define the complete rule `decision` directly — they contribute to the `decisions` set using `decisions contains`.

👉 See [docs/policy-cookbook/](docs/policy-cookbook/) for more patterns (Threshold, Time Window, Jurisdiction, Allow List).  
👉 See [docs/API.md](docs/API.md) for the full REST reference and CLI usage examples.

## Configuration

Elodea is configured via environment variables or a `elodea.yaml` file.

| Variable | Description | Default |
|----------|-------------|---------|
| `ELODEA_LISTEN_ADDR` | Address the proxy listens on | `:8080` |
| `ELODEA_TARGET_URL` | Upstream target server URL | **required — no default** |
| `ELODEA_ALLOWED_ORIGINS` | Comma-separated list of allowed CORS origins | `*` (all origins — set explicit origins in production) |
| `ELODEA_POLICY_DIR` | Directory containing `.rego` policies | `./policies` |
| `ELODEA_POSTGRES_DSN` | PostgreSQL connection DSN string | `postgres://elodea:elodea@localhost:5432/elodea?sslmode=disable` |
| `ELODEA_API_KEYS` | Comma-separated `token:agent_id` pairs for agent (machine) auth | (none — proxy rejects requests if unset) |
| `ELODEA_REVIEWER_API_KEYS` | Comma-separated `token:reviewer_id` pairs — humans who approve quarantined actions. With SSO these are break-glass access only | (none — the server refuses to start without a reviewer/admin key **or** SSO) |
| `ELODEA_ADMIN_API_KEYS` | Comma-separated `token:admin_id` pairs | (none) |
| `ELODEA_TARGET_AUTH_TOKEN` | Service credential presented to the upstream target on forwarded/replayed requests | (none) |
| `ELODEA_ENVIRONMENT` | `development` or `production`. Production enforces strict startup validation: no dev credentials, tokens ≥ 24 bytes, TLS required, no local no-TLS DSN | `development` |
| `ELODEA_TLS_TERMINATED_UPSTREAM` | `true` when an ingress/mesh terminates TLS in front of Elodea (satisfies the production TLS check) | `false` |
| `ELODEA_LOG_LEVEL` | `debug`, `info`, `warn`, `error` | `info` |
| `ELODEA_POLICY_RELOAD_INTERVAL` | Poll the policy directory and hot-reload changes (`0` disables; SIGHUP and the admin API still work) | `30s` |
| `ELODEA_METRICS_LISTEN_ADDR` | Serve `/metrics` on a separate internal listener (e.g. `:9090`) | (served on the main port) |
| `ELODEA_OIDC_ISSUER`, `_CLIENT_ID`, `_CLIENT_SECRET`, `_REDIRECT_URL` | Single sign-on for reviewers and admins. Also `ELODEA_OIDC_REVIEWER_GROUPS`, `_ADMIN_GROUPS`, `_SCOPES`, `_IDENTITY_CLAIM`, `_PROVIDER_NAME`, and `ELODEA_SESSION_TTL` / `_IDLE_TTL`. See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#single-sign-on-for-reviewers) | (SSO off) |
| `ELODEA_NOTIFY_SLACK_WEBHOOK_URL` | Slack incoming webhook for held-action notifications | (off) |
| `ELODEA_NOTIFY_WEBHOOK_URL` / `_SECRET` | Generic webhook for held actions, signed with HMAC-SHA256 (secret required in production) | (off) |
| `ELODEA_CONSOLE_URL` | Where reviewers open the console; notifications link to its approvals queue | (none) |
| `ELODEA_SLACK_BOT_TOKEN`, `_SIGNING_SECRET`, `_CHANNEL_ID`, `_TEAM_ID`, `_REVIEWERS` | Approve or deny held actions from Slack. Create the app from [deploy/slack/manifest.yaml](deploy/slack/manifest.yaml); see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#approve-and-deny-from-slack) | (off) |
| `ELODEA_*_FILE` | File-based variants of `POSTGRES_DSN`, `TARGET_AUTH_TOKEN`, `API_KEYS`, `REVIEWER_API_KEYS`, `ADMIN_API_KEYS`, `OIDC_CLIENT_SECRET`, `NOTIFY_SLACK_WEBHOOK_URL`, `NOTIFY_WEBHOOK_SECRET`, `SLACK_BOT_TOKEN`, `SLACK_SIGNING_SECRET` (key files: one `token:id` per line) | — |

> **Trust domains are separate.** Agent tokens can only call the proxy. Approving quarantined actions, reading the ledger, and the dashboard require a reviewer/admin token or an SSO session; agents can never authenticate with a session cookie. Sharing a token across domains, or giving one identity both an agent and a reviewer role, is rejected at startup.

*When both are set, environment variables override values in `elodea.yaml`. Pre-rename `KITERAIL_*` variables still work and log a deprecation warning.*

## Architecture

Elodea organizes into six planes (agent, ingress, control, data, human, target) with interface-driven boundaries between packages. New decision engines, storage backends, or verticals can drop in without touching the core proxy.

👉 **See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** for the full design, request lifecycle, extension points, and correctness discussion.

## Roadmap

Next, in priority order:

- **More adapters** on the new adapter boundary: agent-to-agent (A2A) task traffic and function-calling gateways.
- **Agent identity federation:** OAuth 2.1 / RFC 9728 protected-resource metadata for agents, so Elodea evaluates both the agent and the human it acts for. (Reviewer single sign-on with OIDC has shipped.)
- **Payment controls as policy features:** amount, velocity, and aggregate limits; maker-checker; dual approval above a threshold; beneficiary allowlists.
- **Shadow mode** for policy rollouts: record what a new bundle *would* decide without enforcing it.
- **Pre-built policy packs** for common governance regimes (payments, cloud operations, data egress).
- **Managed ledger anchoring** to a transparency log on a schedule.

👉 **See [docs/ARCHITECTURE.md#roadmap](docs/ARCHITECTURE.md#roadmap)** for the full engineering and product roadmap.

## Why not just use...?

| Tool | What it governs | Where Elodea is different |
|---|---|---|
| Cloudflare AI Gateway / Portkey | LLM prompts and responses | Elodea governs the *tool calls that leave the LLM*. Prompts are safe; refunds are not. |
| Docker / Microsoft / Lasso MCP gateways | Routing, isolation, and who may call which MCP server | Elodea adds what they leave out: a separate human approves high-risk calls, the exact approved request runs only after re-checking current policy, and a hash-chained ledger an examiner can verify. Run it behind your gateway. |
| Auth0 async authorization / Permit consent | A user approving their *own* agent's action | Elodea is four-eyes review: a different, authorized person approves, bound to the exact payload, with tamper-evident evidence. |
| Lakera Guard / NeMo Guardrails | Prompt injection and unsafe outputs | Elodea assumes the LLM is compromised and firewalls what it can *do*. |
| OPA + a custom proxy | Same primitives | Elodea packages the proxy, hash-chained ledger, HITL queue, and wire-format parsing—the parts that are hard to get right under concurrency. |

## Contributing

PRs are welcome. Please open an issue first for major architectural changes so we can agree on the approach before you write code.

## License

This project is licensed under the Apache 2.0 License. See the [LICENSE](LICENSE) file for details.

See [CHANGELOG.md](CHANGELOG.md) for release notes.
