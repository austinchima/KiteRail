package kiterail.authz

import rego.v1

# Block payloads containing SSN patterns being sent to external LLMs
decisions contains {"action": "deny", "rule": "pii_ssn_detected", "explanation": "SSN pattern detected in payload destined for external model"} if {
    some field in ["ssn", "social_security", "tax_id"]
    input.arguments[field]
    contains_ssn_pattern(input.arguments[field])
}

contains_ssn_pattern(value) if {
    regex.match(`\d{3}-\d{2}-\d{4}`, value)
}