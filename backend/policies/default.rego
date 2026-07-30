package kiterail

# Default to denying everything
default action = "deny"
default rule = "default_deny"
default explanation = "No policy allowed this action"

# Rule: Allow read-only operations
action = "allow" {
    is_read_only(input.request.tool)
    rule := "allow_read_only"
    explanation := "Tool is recognized as a read-only operation"
}

# Rule: Quarantine high-value Stripe refunds
action = "quarantine" {
    input.request.tool == "stripe.charge.refund"
    input.request.payload.amount > 1000
    rule := "quarantine_high_value_refund"
    explanation := "Stripe refunds over $1000 require human review"
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
