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