# KiteRail Architecture

This document covers the request lifecycle and the internal package structure of KiteRail.

## Request Lifecycle (Sequence View)

Shows exactly what happens on a single `tools/call` request. This highlights the asynchronous Human-in-the-Loop (HITL) review loop.

```mermaid
sequenceDiagram
    autonumber
    participant A as AI Agent
    participant M as CORS + Auth<br/>Middleware
    participant P as Proxy Handler
    participant O as OPA Engine
    participant Q as Quarantine Store
    participant L as Audit Ledger
    participant T as Target API
    participant U as HITL Dashboard

    A->>M: POST / (JSON-RPC tools/call)
    M->>M: Validate Bearer token<br/>→ inject agent_id into ctx
    M->>P: forward request
    P->>P: Read body, hash SHA-256
    P->>P: Parse method + params.name<br/>+ params.arguments
    P->>O: Evaluate(EvalInput)
    O-->>P: Decision{action, rule, latency_ms, explanation}
    P->>L: Append entry (hash-chained)

    alt Decision = allow
        P->>T: Forward request
        T-->>A: Response
    else Decision = deny
        P-->>A: 403 Forbidden<br/>{ error, explanation }
    else Decision = quarantine
        P->>Q: Create(agent, tool, payload)
        Q-->>P: quarantine_id
        P-->>A: 202 Accepted<br/>{ quarantine_id, status }

        Note over U,Q: Async — human review
        U->>Q: GET /api/v1/quarantine
        U->>Q: POST /:id/approve or /:id/deny
        alt Approved
            Q->>T: Replay request
            Q->>L: Append approval entry
        else Denied
            Q->>L: Append denial entry
        end
    end
```

## Package Dependency Graph

Shows how the Go packages compose to separate concerns, allowing for easy expansion of backends (e.g., swapping PostgreSQL or OPA).

```mermaid
flowchart LR
    subgraph cmd["cmd/server"]
        MAIN[main.go<br/>wires everything]
    end

    subgraph internal["internal/"]
        CFG[config<br/>env + yaml loader]
        PROXY[proxy<br/>handler · auth · sse]
        OPA[opaengine<br/>Rego evaluator]
        PS[policystore<br/>Rego CRUD]
        Q[quarantine<br/>store · handler]
        LED[ledger<br/>store · handler]
        DASH[dashboard<br/>stats aggregator]
    end

    subgraph external["External"]
        PG[(PostgreSQL)]
        REGO[Rego policy files]
    end

    MAIN --> CFG
    MAIN --> PROXY
    MAIN --> OPA
    MAIN --> PS
    MAIN --> Q
    MAIN --> LED
    MAIN --> DASH

    PROXY -->|OPAEngine iface| OPA
    PROXY -->|QuarantineStore iface| Q
    PROXY -->|LedgerStore iface| LED

    Q --> LED
    DASH --> LED
    DASH --> Q

    OPA --> REGO
    PS --> REGO
    Q --> PG
    LED --> PG

    classDef entry fill:#1e293b,stroke:#38bdf8,color:#e2e8f0
    classDef pkg fill:#0f172a,stroke:#a78bfa,color:#e2e8f0
    classDef ext fill:#450a0a,stroke:#f87171,color:#fee2e2

    class MAIN entry
    class CFG,PROXY,OPA,PS,Q,LED,DASH pkg
    class PG,REGO ext
```
