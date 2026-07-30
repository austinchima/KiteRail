package kiterail.authz

# Default to denying everything
default decision = {
    "action": "deny",
    "rule": "default_deny",
    "explanation": "No policy allowed this action"
}

# Allow read-only operations by default (Base system rule)
decision = {
    "action": "allow",
    "rule": "allow_read_only",
    "explanation": "Tool is recognized as a read-only operation"
} {
    is_read_only(input.tool)
}

# Rule: POL-882-991 - Quarantine high-value Stripe refunds
decision = {
    "action": "quarantine",
    "rule": "POL-882-991",
    "explanation": "Stripe refunds over $1000 require human review"
} {
    input.enabled_policies["POL-882-991"] == true
    input.tool == "stripe.charge.refund"
    input.arguments.amount > 1000
}

# Rule: POL-104-552 - DLP: Scrub PII/PCI (Placeholder action)
decision = {
    "action": "quarantine",
    "rule": "POL-104-552",
    "explanation": "DLP Scrubbing required for OpenAI/Anthropic (Quarantined for manual review)"
} {
    input.enabled_policies["POL-104-552"] == true
    is_llm_tool(input.tool)
}

# Rule: POL-404-001 - Block Unauthorized Wire Transfers (> $10K)
decision = {
    "action": "deny",
    "rule": "POL-404-001",
    "explanation": "Unauthorized wire transfer > $10K blocked"
} {
    input.enabled_policies["POL-404-001"] == true
    input.tool == "swift.transfer"
    input.arguments.amount > 10000
}

# Rule: POL-912-701 - Rate Limit Plaid
decision = {
    "action": "deny",
    "rule": "POL-912-701",
    "explanation": "Rate Limit exceeded for Plaid API"
} {
    input.enabled_policies["POL-912-701"] == true
    input.tool == "plaid.accounts.get"
    # Placeholder logic for rate limiting
}


# Helper to determine read-only operations
is_read_only(tool) {
    read_only_tools := {
        "github.repo.get",
        "github.issue.list",
        "stripe.charge.retrieve",
        "stripe.customer.list"
    }
    read_only_tools[tool]
}

is_llm_tool(tool) {
    llm_tools := {
        "openai.chat.completions",
        "anthropic.messages.create"
    }
    llm_tools[tool]
}
