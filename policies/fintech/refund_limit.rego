# Title: Refund limits for stripe.charge.refund
package elodea.authz

import rego.v1

# Rego orders values across types (null < boolean < number < string), so an
# amount must be checked as a number before it is compared to a limit.
refund_amount_valid if is_number(input.arguments.amount)

# Allow refunds under $1,000
decisions contains {"action": "allow", "rule": "refund_under_limit", "explanation": "Refund amount within autonomous limit"} if {
    input.tool == "stripe.charge.refund"
    refund_amount_valid
    input.arguments.amount <= 1000
}

# Quarantine refunds over $1,000 for human review
decisions contains {"action": "quarantine", "rule": "refund_over_limit", "explanation": "Refund exceeds the $1,000 autonomous limit. Routed to human approval."} if {
    input.tool == "stripe.charge.refund"
    refund_amount_valid
    input.arguments.amount > 1000
}

# Missing or non-numeric amounts are never auto-approved
decisions contains {"action": "quarantine", "rule": "refund_amount_invalid", "explanation": "Refund amount is missing or not a number. Routed to human approval."} if {
    input.tool == "stripe.charge.refund"
    not refund_amount_valid
}
