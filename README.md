# ⚡ KiteRail

Inline compliance proxy for autonomous AI agents

![Go](https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go) ![License](https://img.shields.io/badge/License-Apache_2.0-blue) ![OPA](https://img.shields.io/badge/Policy-OPA_Rego-7d9fc3) ![NATS](https://img.shields.io/badge/Events-NATS_JetStream-27aae1)

## The Problem

Autonomous AI agents calling real-world APIs (payments, infrastructure, healthcare, databases) introduce significant uncontrolled risk. Regulations such as the EU AI Act, SOX, HIPAA, and PCI-DSS increasingly mandate human oversight for high-risk AI decisions. 

KiteRail provides a domain-agnostic safety layer between your AI agents and internal systems. While Fintech is the primary reference implementation, KiteRail's policy model extends seamlessly to DevOps/Cloud infrastructure (`kubectl`, `terraform`), Healthcare EHRs, and Enterprise HR/ERP operations.

## How It Works

```mermaid
flowchart LR
    A[AI Agent] --> B[KiteRail Proxy]
    B --> C{OPA Policy Engine}
    
    C -->|ALLOW| D[Target API Server]
    C -->|DENY| E[Block Request]
    C -->|QUARANTINE| F[Quarantine Store]
    
    F --> I[HITL Approval Inbox]
    I -->|APPROVE| D
    I -->|REJECT| E
    
    D & E & F & I --> G[NATS JetStream]
    G --> H[(Immutable Audit Ledger)]
```

## Features

- **Inline MCP Proxy** — Designed for sub-5ms low-latency interception; requires zero agent code modifications.
- **OPA Policy Engine** — Declarative Rego rules, hot-reload support, completely GitOps friendly.
- **Human-in-the-Loop** — Quarantine queue for payloads flagged as high-risk, pending human review & token injection.
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
  -H 'Authorization: Bearer sk_dev_123' \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "stripe.charge.refund", "arguments": {"amount": 1500}}, "id": 1}'
# → Returns 202 Quarantined (exceeds $1,000 threshold)
```

## Writing Policies

KiteRail uses Open Policy Agent (OPA) for policy evaluation. Rules return a structured `decision` object containing `action` (`allow`, `deny`, or `quarantine`), `rule`, and `explanation`.

Example policy (`policies/stripe.rego`):

```rego
package kiterail.authz

default decision = {
    "action": "deny",
    "rule": "default_deny",
    "explanation": "Action strictly blocked by default policy"
}

# Allow read-only operations
decision = {
    "action": "allow",
    "rule": "allow_read_only",
    "explanation": "Read-only operation allowed"
} {
    input.tool == "stripe.charge.retrieve"
}

# Quarantine large refunds for human review
decision = {
    "action": "quarantine",
    "rule": "quarantine_high_value_refund",
    "explanation": "Stripe refunds over $1,000 require human review"
} {
    input.tool == "stripe.charge.refund"
    input.arguments.amount > 1000
}
```

## Configuration

KiteRail is configured via environment variables or a `kiterail.yaml` file.

| Variable | Description | Default |
|----------|-------------|---------|
| `KITERAIL_LISTEN_ADDR` | Address the proxy listens on | `:8080` |
| `KITERAIL_TARGET_URL` | Upstream target server URL | `http://localhost:8081` |
| `KITERAIL_POLICY_DIR` | Directory containing `.rego` policies | `./policies` |
| `KITERAIL_NATS_URL` | URL for NATS JetStream server | `nats://localhost:4222` |
| `KITERAIL_POSTGRES_DSN` | PostgreSQL connection DSN string | `postgres://kiterail:kiterail@localhost:5432/kiterail?sslmode=disable` |
| `KITERAIL_API_KEYS` | Comma-separated `token:agent_id` pairs for proxy auth | (none — proxy rejects requests if unset) |

## Architecture

KiteRail's codebase is structured around distinct internal Go packages:

- `internal/proxy`: The core HTTP proxy intercepting MCP & API traffic with bearer auth middleware.
- `internal/opa`: Integration with the Open Policy Agent engine evaluating requests against Rego decision rules.
- `internal/events`: NATS JetStream publisher for durable asynchronous event delivery.
- `internal/quarantine`: Manages the lifecycle of requests held for Human-in-the-Loop review.
- `internal/quarantine/handler`: REST API for listing, approving, and denying quarantined items.
- `internal/ledger`: Hash-chained, Postgres-backed tamper-evident audit log handler.

## Cloud Dashboard (Planned Managed Service)

KiteRail Cloud (planned enterprise service) will provide a managed multi-tenant dashboard featuring a real-time Human-in-the-Loop inbox, topology visualization, RBAC, and SIEM export capabilities (Splunk / Datadog). 

For enterprise inquiries, custom deployments, or early access interest, please open a GitHub Discussion or reach out via repository issues.

## Contributing

We welcome contributions from the community. PRs are always welcome, but please open an issue first for major changes or architectural discussions to ensure alignment.

## License

This project is licensed under the Apache 2.0 License. See the [LICENSE](LICENSE) file for details.
