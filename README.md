# ⚡ KiteRail

Inline compliance proxy for autonomous AI agents

![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go) ![License](https://img.shields.io/badge/License-Apache_2.0-blue) ![OPA](https://img.shields.io/badge/Policy-OPA_Rego-7d9fc3) ![NATS](https://img.shields.io/badge/Events-NATS_JetStream-27aae1)

## The Problem

Autonomous AI agents calling real-world APIs (payments, banking, databases) introduce significant uncontrolled risk. Regulations such as the EU AI Act, SOX, and PCI-DSS increasingly mandate human oversight for high-risk AI decisions. KiteRail provides a safety layer between your AI agents and your internal systems, ensuring compliance without sacrificing automation speed.

## How It Works

```mermaid
flowchart LR
    A[AI Agent] --> B[KiteRail Proxy]
    B --> C{OPA Policy Eval}
    C -->|ALLOW| D[Target MCP Server]
    C -->|DENY| E[Block + Log]
    C -->|QUARANTINE| F[NATS JetStream]
    F --> G[HITL Inbox + Audit Ledger]
```

## Features

- **Inline MCP Proxy** — Sub-5ms interception, requires no agent code changes.
- **OPA Policy Engine** — Declarative Rego rules, hot-reload support, completely GitOps friendly.
- **Human-in-the-Loop** — Quarantine queue for payloads flagged as high-risk, pending human approval.
- **NATS JetStream** — Durable event streaming providing at-least-once delivery for audit logs and quarantine events.
- **Audit Ledger** — Hash-chained, tamper-detectable audit log backed by PostgreSQL with serial isolation for ordered compliance records.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/austinchima/kiterail.git
cd kiterail

# Start all services (proxy, NATS, Postgres)
docker compose up -d

# Test the health endpoint
curl http://localhost:8080/api/v1/health

# Send a test MCP request through the proxy
curl -X POST http://localhost:8080/ \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "stripe.charge.refund", "arguments": {"amount": 1500}}, "id": 1}'
# → Returns 202 Quarantined (exceeds $1,000 threshold)
```

## Writing Policies

KiteRail uses Open Policy Agent (OPA) for policy evaluation. You define rules in Rego. By default, rules are loaded from the `policies/` directory.

Example policy (`policies/stripe.rego`):

```rego
package kiterail.mcp

default allow := false
default quarantine := false

# Allow all read-only methods
allow {
    input.tool == "stripe.charge.retrieve"
}

# Quarantine large refunds for human review
quarantine {
    input.tool == "stripe.charge.refund"
    input.arguments.amount > 1000
}
```

## Configuration

KiteRail is configured entirely via environment variables.

| Variable | Description | Default |
|----------|-------------|---------|
| `KITERAIL_LISTEN_ADDR` | The address the proxy listens on | `:8080` |
| `KITERAIL_TARGET_URL` | The upstream MCP server URL | `http://localhost:3000` |
| `KITERAIL_POLICY_DIR` | Directory containing `.rego` policies | `./policies` |
| `KITERAIL_NATS_URL` | URL for the NATS JetStream server | `nats://localhost:4222` |
| `KITERAIL_DB_DSN` | PostgreSQL connection string | `postgres://user:pass@localhost:5432/kiterail?sslmode=disable` |
| `KITERAIL_API_KEYS` | Comma-separated `token:agent_id` pairs for proxy auth | (none — proxy rejects all if unset) |

## Architecture

KiteRail's codebase is structured around distinct internal packages:

- `internal/proxy`: The core HTTP/WebSocket proxy that intercepts MCP traffic.
- `internal/opa`: Integration with the Open Policy Agent engine for evaluating requests against Rego policies.
- `internal/events`: NATS JetStream publisher for asynchronous event handling.
- `internal/quarantine`: Manages the lifecycle of requests held for Human-in-the-Loop review.
- `internal/quarantine/handler`: REST API for listing, approving, and denying quarantined requests.
- `internal/ledger`: Handles the hash-chained, Postgres-backed tamper-evident audit log.

## Cloud Dashboard

KiteRail Cloud provides a managed React dashboard featuring a Human-in-the-Loop inbox, topology visualization, and SIEM export capabilities. Learn more at [kiterail.dev](https://kiterail.dev).

## Contributing

We welcome contributions from the community. PRs are always welcome, but please open an issue first for major changes or architectural discussions to ensure alignment.

## License

This project is licensed under the Apache 2.0 License. See the [LICENSE](LICENSE) file for details.
