# Title: Wire transfer controls (AML, high value)
package elodea.authz

import rego.v1

high_risk_jurisdictions := {"HIGH_RISK", "SANCTIONED", "OFAC_FLAGGED"}

# A wire must name its destination jurisdiction as a string; anything else is
# routed to a human instead of being treated as "not high risk".
wire_jurisdiction_known if {
    is_string(input.arguments.jurisdiction)
    input.arguments.jurisdiction != ""
}

wire_amount_known if is_number(input.arguments.amount)

# Block transfers to sanctioned jurisdictions
decisions contains {"action": "deny", "rule": "aml_jurisdiction_block", "explanation": "Transfer to OFAC-flagged jurisdiction blocked by AML policy"} if {
    input.tool == "swift.wire.initiate"
    input.arguments.jurisdiction in high_risk_jurisdictions
}

# Missing or malformed jurisdiction/amount: never auto-approve
decisions contains {"action": "quarantine", "rule": "wire_incomplete", "explanation": "Wire transfer is missing a valid jurisdiction or amount. Routed to compliance review."} if {
    input.tool == "swift.wire.initiate"
    not wire_jurisdiction_known
}

decisions contains {"action": "quarantine", "rule": "wire_incomplete", "explanation": "Wire transfer is missing a valid jurisdiction or amount. Routed to compliance review."} if {
    input.tool == "swift.wire.initiate"
    not wire_amount_known
}

# Quarantine high-value transfers for review
decisions contains {"action": "quarantine", "rule": "wire_high_value", "explanation": "Wire transfer exceeds $10,000. Routed to compliance review."} if {
    input.tool == "swift.wire.initiate"
    wire_jurisdiction_known
    not input.arguments.jurisdiction in high_risk_jurisdictions
    wire_amount_known
    input.arguments.amount > 10000
}

# Allow normal transfers
decisions contains {"action": "allow", "rule": "wire_allowed", "explanation": "Wire transfer within limits and to approved jurisdiction"} if {
    input.tool == "swift.wire.initiate"
    wire_jurisdiction_known
    not input.arguments.jurisdiction in high_risk_jurisdictions
    wire_amount_known
    input.arguments.amount <= 10000
}
