# Title: Block SSNs in tool arguments
package elodea.authz

import rego.v1

# Block payloads containing SSN patterns being sent to external LLMs
decisions contains {"action": "deny", "rule": "pii_ssn_detected", "explanation": "SSN pattern detected in payload destined for external model"} if {
    some field in ["ssn", "social_security", "tax_id"]
    contains_ssn_pattern(input.arguments[field])
}

# Only strings can carry the pattern; other types are simply not a match
# (rather than a builtin error that fails closed by accident).
contains_ssn_pattern(value) if {
    is_string(value)
    regex.match(`\d{3}-\d{2}-\d{4}`, value)
}
