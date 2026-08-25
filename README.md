# KiteRail

**KiteRail is an inline policy enforcement proxy for autonomous AI agents.**

> *KiteRail treats AI agent safety as a systems problem, not a prompt problem. The LLM does one bounded step — deciding what tool to call. Everything safety-critical (policy, routing, audit, human review) is deterministic Go code you can read, diff, and test. If your agent can spend money, that shouldn't depend on how a model was fine-tuned.*

![Go](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go) ![License](https://img.shields.io/badge/License-Apache_2.0-blue) ![OPA](https://img.shields.io/badge/Policy-OPA_Rego-7d9fc3)

## Status
v1.0.0. Looking for design partners running agentic workflows in fintech or DevOps.

## The Problem

Autonomous AI agents calling real-world APIs introduce uncontrolled risk. Regulated industries require strict authorization, human-in-the-loop controls for high-risk decisions, and an audit trail proving exactly what happened. Building these controls natively into every agent is error-prone.

KiteRail targets fintech tool-call governance (like refunds and wire transfers) out of the box. The architecture is domain-agnostic: Rego policies work just as well for `kubectl` or HR APIs, but we focus on one vertical first to get the primitives right.

## How It Works

```mermaid
flowchart TB
    subgraph Client["🤖 Agent Plane"]
        A[Autonomous AI Agent<br/>JSON-RPC / MCP caller]
    end

    subgraph Ingress["🔐 Ingress Middleware"]
        M[HTTP Middleware<br/>metrics · CORS · bearer auth]
    end

    subgraph Control["⚙️ Control Plane · Request + Review"]
        direction TB
        P[MCP Interceptor<br/>validate · evaluate · route]
        E[[OPA Policy Engine<br/>compiled Rego · RWMutex]]
        API[Reviewer/Admin REST API<br/>HITL · audit · policy simulation]
        PS[(Policy Store<br/>immutable Rego files)]

        P -- EvalInput --> E
        E -- Decision · allow / deny / quarantine --> P
        API -- dry-run EvalInput --> E
        PS -. load + compile at startup .-> E
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
        UI[React Dashboard<br/>HITL inbox · ledger]
        REV[Human Reviewer<br/>approve · deny]
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

    classDef control fill:#1e293b,stroke:#38bdf8,color:#e2e8f0,stroke-width:2px
    classDef data fill:#0f172a,stroke:#a78bfa,color:#e2e8f0,stroke-width:2px
    classDef human fill:#78350f,stroke:#fbbf24,color:#fef3c7,stroke-width:2px
    classDef ingress fill:#052e16,stroke:#4ade80,color:#dcfce7,stroke-width:2px
    classDef upstream fill:#1e1b4b,stroke:#a5b4fc,color:#e0e7ff,stroke-width:2px
    classDef agent fill:#450a0a,stroke:#f87171,color:#fee2e2,stroke-width:2px

    class P,E,API,PS,W control
    class L,Q data
    class UI,REV human
    class M ingress
    class T upstream
    class A agent
```

## Features

- **Policy Simulator:** Dry-run the `/api/v1/policies/simulate` endpoint to validate agent payload changes before they hit production.
- **Human-in-the-Loop:** High-risk payloads route to a quarantine queue for human review.
- **Audit Ledger:** Hash-chained, tamper-detectable Postgres audit log with serial isolation.
- **OPA Policy Engine:** Declarative Rego rules compiled from immutable policy files at startup, with a dry-run simulation API.
- **Inline Proxy:** Designed for low-latency JSON-RPC / MCP interception. Requires zero agent code modifications.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/austinchima/KiteRail.git
cd KiteRail

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
# → The durable worker replays the payload to the target
```

## Local Dashboard

![KiteRail Dashboard](./assets/dashboard.png)

The included React dashboard provides a real-time human-in-the-loop inbox and an audit ledger view. 

> **Note:** The real-time SSE streaming endpoint for live dashboard updates returns `501 Not Implemented` in v1.0. The React frontend will gracefully fallback without live data until the NATS re-integration lands in v1.1.

Interested in piloting KiteRail on real agent workflows? I am looking for design partners in fintech or agent-DevOps. Open a [GitHub Discussion](https://github.com/austinchima/KiteRail/discussions).

## Writing Policies

KiteRail uses Open Policy Agent (OPA) for policy evaluation. Policies contribute decisions to a shared `decisions` set. The aggregator in `policies/main.rego` selects the most restrictive action: **deny > quarantine > allow**. Ties at equal severity are broken deterministically (sorted JSON encoding) so evaluation can never produce a conflict.

Example policy (`policies/fintech/refund_limit.rego`):

```rego
package kiterail.authz

import rego.v1

# Allow refunds under $1,000
decisions contains {"action": "allow", "rule": "refund_under_limit", "explanation": "Refund amount within autonomous limit"} if {
    input.tool == "stripe.charge.refund"
    input.arguments.amount <= 1000
}

# Quarantine refunds over $1,000 for human review
decisions contains {"action": "quarantine", "rule": "refund_over_limit", "explanation": "Refund exceeds $1,000 threshold — routed to human approval"} if {
    input.tool == "stripe.charge.refund"
    input.arguments.amount > 1000
}
```

The default-deny behavior is built into the aggregator (`policies/main.rego`). Individual policies must **not** define the complete rule `decision` directly — they contribute to the `decisions` set using `decisions contains`.

👉 See [docs/policy-cookbook/](docs/policy-cookbook/) for more patterns (Threshold, Time Window, Jurisdiction, Allow List).  
👉 See [docs/API.md](docs/API.md) for the full REST reference and CLI usage examples.

## Configuration

KiteRail is configured via environment variables or a `kiterail.yaml` file.

| Variable | Description | Default |
|----------|-------------|---------|
| `KITERAIL_LISTEN_ADDR` | Address the proxy listens on | `:8080` |
| `KITERAIL_TARGET_URL` | Upstream target server URL | **required — no default** |
| `KITERAIL_ALLOWED_ORIGINS` | Comma-separated list of allowed CORS origins | `*` (all origins — set explicit origins in production) |
| `KITERAIL_POLICY_DIR` | Directory containing `.rego` policies | `./policies` |
| `KITERAIL_POSTGRES_DSN` | PostgreSQL connection DSN string | `postgres://kiterail:kiterail@localhost:5432/kiterail?sslmode=disable` |
| `KITERAIL_API_KEYS` | Comma-separated `token:agent_id` pairs for agent (machine) auth | (none — proxy rejects requests if unset) |
| `KITERAIL_REVIEWER_API_KEYS` | Comma-separated `token:reviewer_id` pairs — humans who approve quarantined actions | (none — server refuses to start without at least one reviewer/admin key) |
| `KITERAIL_ADMIN_API_KEYS` | Comma-separated `token:admin_id` pairs | (none) |
| `KITERAIL_TARGET_AUTH_TOKEN` | Service credential presented to the upstream target on forwarded/replayed requests | (none) |
| `KITERAIL_ENVIRONMENT` | `development` or `production`. Production enforces strict startup validation: no dev credentials, TLS required, no local no-TLS DSN | `development` |

> **Trust domains are separate.** Agent tokens can only call the proxy. Approving quarantined actions, reading the ledger, and the dashboard require a reviewer/admin token. Sharing a token across domains is rejected at startup.

*When both are set, environment variables override values in `kiterail.yaml`.*

## Architecture

KiteRail organizes into six planes (agent, ingress, control, data, human, target) with interface-driven boundaries between packages. New decision engines, storage backends, or verticals can drop in without touching the core proxy.

👉 **See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** for the full design, request lifecycle, extension points, and correctness discussion.

## Roadmap

Two tracks toward v1.1 — the version of KiteRail designed for production pilots:

- **Protocol abstraction:** Moving beyond MCP to enforce policies on standard REST and gRPC traffic.
- **Pre-built policy packs:** Ready-to-use OPA rules for common governance requirements.
- **Two-identity authorization:** Checking both the autonomous agent's identity and the human user's identity (via OAuth/SAML) to enforce strict segregation of duties.
- **CLI & Metrics:** A dedicated `kiterail` CLI and Prometheus `/metrics` endpoints.

👉 **See [docs/ARCHITECTURE.md#roadmap](docs/ARCHITECTURE.md#roadmap)** for the full engineering and product roadmap.

## Why not just use...?

| Tool | What it governs | Where KiteRail is different |
|---|---|---|
| Cloudflare AI Gateway / Portkey | LLM prompts and responses | KiteRail governs the *tool calls that leave the LLM*. Prompts are safe; refunds are not. |
| Lakera Guard / NeMo Guardrails | Prompt injection and unsafe outputs | KiteRail assumes the LLM is compromised and firewalls what it can *do*. |
| OPA + a custom proxy | Same primitives | KiteRail packages the proxy, hash-chained ledger, HITL queue, and wire-format parsing—the parts that are hard to get right under concurrency. |

## Contributing

PRs are welcome. Please open an issue first for major architectural changes so we can agree on the approach before you write code.

## License

This project is licensed under the Apache 2.0 License. See the [LICENSE](LICENSE) file for details.

See [CHANGELOG.md](CHANGELOG.md) for release notes.
