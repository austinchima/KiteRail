# KiteRail

> *KiteRail treats AI agent safety as a systems problem, not a prompt problem. The LLM does one bounded step — deciding what tool to call. Everything safety-critical (policy, routing, audit, human review) is deterministic Go code you can read, diff, and test. If your agent can spend money, that shouldn't depend on how a model was fine-tuned.*

![Go](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go) ![License](https://img.shields.io/badge/License-Apache_2.0-blue) ![OPA](https://img.shields.io/badge/Policy-OPA_Rego-7d9fc3)

## Status
v1.0.0. Built solo by a 2026 new grad.
Looking for design partners running agentic workflows in fintech or DevOps.

## The Problem

Autonomous AI agents calling real-world APIs introduce uncontrolled risk. Regulations like the EU AI Act, SOX, and PCI-DSS mandate human oversight for high-risk AI decisions. 

KiteRail v1 targets fintech tool-call governance (like refunds and wire transfers). The architecture is domain-agnostic: Rego policies work just as well for `kubectl` or HR APIs, but we are focusing on one vertical first.

## How It Works

```mermaid
flowchart TB
    subgraph Client["🤖 Agent Plane"]
        A[Autonomous AI Agent]
    end

    subgraph Ingress["🔐 Ingress Middleware"]
        direction LR
        M1[CORS Middleware] --> M2[Bearer Auth<br/>KITERAIL_API_KEYS]
    end

    subgraph Control["⚙️ Control Plane · KiteRail Proxy"]
        direction TB
        P[MCP Interceptor<br/>parses tools/call<br/>extracts name + arguments]
        E[[OPA Policy Engine<br/>Rego evaluator<br/>hot-reload, RWMutex]]
        SIM[/Policy Simulator<br/>dry-run endpoint/]
        PS[(Policy Store<br/>./policies/*.rego)]
        P --> E
        SIM --> E
        E -.reads.-> PS
    end

    subgraph Data["📒 Data Plane · Postgres"]
        direction LR
        L[(Audit Ledger<br/>SHA-256 hash-chain<br/>SERIALIZABLE + FOR UPDATE<br/>retry x3)]
        Q[(Quarantine Store<br/>pending payloads)]
    end

    subgraph Human["👤 Human Plane"]
        direction TB
        UI[React Dashboard<br/>HITL Inbox · Ledger Viewer]
        REV[Human Reviewer]
        UI <--> REV
    end

    subgraph Upstream["🎯 Target Plane"]
        T[Downstream API<br/>Stripe · kubectl · EHR · ...]
    end

    A -- JSON-RPC / MCP --> M1
    M2 --> P

    E -- ALLOW --> T
    E -- DENY --> DENIED[403 Forbidden]
    E -- QUARANTINE --> Q

    Q --> UI
    UI -- approve --> T
    UI -- deny --> DENIED

    P -- append entry --> L
    UI -- approve/deny --> L

    UI <-. REST API<br/>/api/v1/{ledger,quarantine,policies,dashboard} .-> Control
    UI <-. reads .-> L

    classDef control fill:#1e293b,stroke:#38bdf8,color:#e2e8f0,stroke-width:2px
    classDef data fill:#0f172a,stroke:#a78bfa,color:#e2e8f0,stroke-width:2px
    classDef human fill:#78350f,stroke:#fbbf24,color:#fef3c7,stroke-width:2px
    classDef ingress fill:#052e16,stroke:#4ade80,color:#dcfce7,stroke-width:2px
    classDef upstream fill:#1e1b4b,stroke:#a5b4fc,color:#e0e7ff,stroke-width:2px
    classDef agent fill:#450a0a,stroke:#f87171,color:#fee2e2,stroke-width:2px

    class P,E,SIM,PS control
    class L,Q data
    class UI,REV human
    class M1,M2 ingress
    class T,DENIED upstream
    class A agent
```

## Features

- **Inline MCP Proxy:** Low-overhead interception (typical p95 <10ms in local benchmarks). Requires zero agent code modifications.
- **OPA Policy Engine:** Declarative Rego rules, hot-reload support, and GitOps friendly.
- **Policy Simulator:** Dry-run `/api/v1/policies/simulate` endpoint to validate agent payload changes before they hit production.
- **Human-in-the-Loop:** Quarantine queue for high-risk payloads, which wait for human review.
- **Audit Ledger:** Hash-chained, tamper-detectable Postgres audit log with serial isolation.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/austinchima/KiteRail.git
cd KiteRail

# Start all services (proxy + Postgres)
docker compose up -d

# Test the health endpoint
curl http://localhost:8080/api/v1/health

# Send a test MCP request through the proxy
curl -X POST http://localhost:8080/ \
  -H 'Authorization: Bearer sk_dev_123' \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "stripe.charge.refund", "arguments": {"amount": 1500}}, "id": 1}'
# → Returns 202 Quarantined (exceeds $1,000 threshold)
```

## Writing Policies

KiteRail uses Open Policy Agent (OPA) for policy evaluation. Rules return a structured `decision` object containing `action` (`allow`, `deny`, or `quarantine`), `rule`, and `explanation`.

Example policy (`policies/fintech/refund_limit.rego`):

```rego
package kiterail.authz

import rego.v1

# Allow refunds under $1,000
decision := {"action": "allow", "rule": "refund_under_limit", "explanation": "Refund amount within autonomous limit"} if {
    input.tool == "stripe.charge.refund"
    input.arguments.amount <= 1000
}

# Quarantine refunds over $1,000 for human review
decision := {"action": "quarantine", "rule": "refund_over_limit", "explanation": "Refund exceeds $1,000 threshold — routed to human approval"} if {
    input.tool == "stripe.charge.refund"
    input.arguments.amount > 1000
}
```

> **Note:** A `policies/default_deny.rego` file ensures all unrecognized actions are blocked by default.

## Using KiteRail from the CLI

Everything the dashboard does is a thin wrapper over the REST API. You never need the UI.

> 🚀 **Roadmap:** We are currently building a dedicated `kiterail` CLI tool to make these commands even easier (e.g. `kiterail quarantine approve <id>`). Stay tuned!

```bash
# List all quarantined requests
curl -H "Authorization: Bearer sk_dev_123" \
  http://localhost:8080/api/v1/quarantine

# Approve a quarantined request (replays it to the target)
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

# Dry-run a policy without executing (killer feature)
curl -X POST -H "Authorization: Bearer sk_dev_123" \
  -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/policies/simulate \
  -d '{"tool": "stripe.charge.refund", "arguments": {"amount": 2500}}'
```

## Configuration

KiteRail is configured via environment variables or a `kiterail.yaml` file.

| Variable | Description | Default |
|----------|-------------|---------|
| `KITERAIL_LISTEN_ADDR` | Address the proxy listens on | `:8080` |
| `KITERAIL_TARGET_URL` | Upstream target server URL | **required — no default** |
| `KITERAIL_ALLOWED_ORIGINS` | Comma-separated list of allowed CORS origins | (none — CORS disabled if unset) |
| `KITERAIL_POLICY_DIR` | Directory containing `.rego` policies | `./policies` |
| `KITERAIL_POSTGRES_DSN` | PostgreSQL connection DSN string | `postgres://kiterail:kiterail@localhost:5432/kiterail?sslmode=disable` |
| `KITERAIL_API_KEYS` | Comma-separated `token:agent_id` pairs for proxy auth | (none — proxy rejects requests if unset) |

## Architecture

KiteRail is organized into six planes (agent, ingress, control, data, human, target) with interface-driven boundaries between packages, so new decision engines, storage backends, or verticals can be added without touching the core proxy.

👉 **See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** for the full design, request lifecycle, extension points, and correctness discussion.

## Roadmap

We are currently building towards R2, the version of KiteRail designed for production pilots with our first design partners. Here is what is coming next:

- **Protocol agnosticism:** Moving beyond MCP. We are abstracting the interception layer so KiteRail can enforce policies on standard REST and gRPC traffic.
- **The compliance stack:** Pre-built, auditor-tested OPA policy packs for specific regulatory frameworks. We will ship out-of-the-box rules for the EU AI Act (Article 14), SOX, HIPAA, and PCI-DSS.
- **Two-identity authorization:** Right now, KiteRail checks if an agent is allowed to take an action. Next, we will check if the human user who triggered the agent is allowed to take that action. This stops privilege escalation.

## Why not just use...?

| Tool | What it governs | Where KiteRail is different |
|---|---|---|
| Cloudflare AI Gateway / Portkey | LLM prompts and responses | KiteRail governs the *tool calls that leave the LLM*. Prompts are safe; refunds are not. |
| Lakera Guard / NeMo Guardrails | Prompt injection and unsafe outputs | KiteRail assumes the LLM is compromised and firewalls what it can *do*. |
| OPA + a homegrown proxy | Same primitives | KiteRail packages the proxy, hash-chained ledger, HITL queue, and MCP wire-format parsing—the parts that are hard to get right under concurrency. |

## Local Dashboard

![KiteRail Dashboard](./assets/dashboard.png)

The included React dashboard gives you a real-time Human-in-the-Loop inbox and an audit ledger view. 

Interested in piloting KiteRail on real agent workflows? I am looking for design partners in fintech or agent-DevOps. Open a [GitHub Discussion](https://github.com/austinchima/KiteRail/discussions).

## Contributing

PRs are welcome. Please open an issue first for major architectural changes so we can agree on the approach before you write code.

## License

This project is licensed under the Apache 2.0 License. See the [LICENSE](LICENSE) file for details.

See [CHANGELOG.md](CHANGELOG.md) for release notes.
