package kiterail.authz

import rego.v1

high_risk_jurisdictions := {"HIGH_RISK", "SANCTIONED", "OFAC_FLAGGED"}

# Block transfers to sanctioned jurisdictions
decisions contains {"action": "deny", "rule": "aml_jurisdiction_block", "explanation": "Transfer to OFAC-flagged jurisdiction blocked by AML policy"} if {
    input.tool == "swift.wire.initiate"
    input.arguments.jurisdiction in high_risk_jurisdictions
}

# Quarantine high-value transfers for review
decisions contains {"action": "quarantine", "rule": "wire_high_value", "explanation": "Wire transfer exceeds $10,000 — routed to compliance review"} if {
    input.tool == "swift.wire.initiate"
    not input.arguments.jurisdiction in high_risk_jurisdictions
    input.arguments.amount > 10000
}

# Allow normal transfers
decisions contains {"action": "allow", "rule": "wire_allowed", "explanation": "Wire transfer within limits and to approved jurisdiction"} if {
    input.tool == "swift.wire.initiate"
    not input.arguments.jurisdiction in high_risk_jurisdictions
    input.arguments.amount <= 10000
}