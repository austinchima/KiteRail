package kiterail.authz

import rego.v1

# Pattern: Jurisdiction
# Deny actions if they involve a region/country that the system is not authorized to operate in.

embargoed_countries := {"CU", "IR", "KP", "SY"}

decision := {"action": "deny", "rule": "embargoed_jurisdiction", "explanation": "Transactions to this jurisdiction are prohibited"} if {
	input.tool == "banking.wire.transfer"
	input.arguments.destination_country in embargoed_countries
}
