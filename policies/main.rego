package kiterail.authz

import rego.v1

# ============================================================
# Decision Aggregator.
# Individual policies MUST NOT define `decision` directly.
# They contribute candidates to the `decisions` SET:
#   decisions contains {"action": ..., "rule": ..., "explanation": ...} if { ... }
# The most restrictive action wins: deny > quarantine > allow.
# Ties at equal severity are broken deterministically (sorted
# JSON encoding) so evaluation can never produce a conflict.
# ============================================================

severity := {"deny": 3, "quarantine": 2, "allow": 1}

default decision := {"action": "deny", "rule": "default_deny", "explanation": "No matching allow rule found"}

decision := result if {
    count(decisions) > 0
    max_sev := max({severity[d.action] | some d in decisions})
    winners := sort([json.marshal(d) | some d in decisions; severity[d.action] == max_sev])
    result := json.unmarshal(winners[0])
}