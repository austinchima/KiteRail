package kiterail.authz

import rego.v1

# Pattern: Threshold
# Quarantine or deny a tool call if a numeric argument exceeds a safe threshold.

# Quarantine refunds over $500
decisions contains {"action": "quarantine", "rule": "refund_threshold_exceeded", "explanation": "Refunds over $500 require human review"} if {
	input.tool == "stripe.charge.refund"
	input.arguments.amount > 500
}

# Allow refunds under $500
decisions contains {"action": "allow", "rule": "refund_under_threshold", "explanation": "Refund amount is within autonomous limits"} if {
	input.tool == "stripe.charge.refund"
	input.arguments.amount <= 500
}