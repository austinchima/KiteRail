# Changelog

All notable changes to KiteRail will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/austinchima/KiteRail/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/austinchima/KiteRail/releases/tag/v0.1.0
