package kiterail.authz_test

import rego.v1
import data.kiterail.authz

test_small_refund_allowed if {
	d := authz.decision with input as {"tool": "stripe.charge.refund", "arguments": {"amount": 100}, "agent": "a"}
	d.action == "allow"
	d.rule == "refund_under_limit"
}

test_large_refund_quarantined if {
	d := authz.decision with input as {"tool": "stripe.charge.refund", "arguments": {"amount": 1500}, "agent": "a"}
	d.action == "quarantine"
	d.rule == "refund_over_limit"
}

test_deny_beats_quarantine if {
	d := authz.decision with input as {"tool": "swift.wire.initiate", "arguments": {"amount": 50000, "jurisdiction": "OFAC_FLAGGED"}, "agent": "a"}
	d.action == "deny"
	d.rule == "aml_jurisdiction_block"
}

test_unknown_tool_default_deny if {
	d := authz.decision with input as {"tool": "unknown.tool", "arguments": {}, "agent": "a"}
	d.action == "deny"
	d.rule == "default_deny"
}

# Every policy contribution to the decisions set must carry a non-empty rule.
# The Go engine fails closed (invalid_policy_decision) on any decision with an
# empty rule, so a policy that forgot one would silently deny everything it
# touched — this catches that authoring mistake at CI time.
test_every_decision_carries_a_rule if {
	every inp in decision_probe_inputs {
		ds := {d | some d in authz.decisions with input as inp}
		every d in ds {
			d.rule != ""
		}
	}
}

decision_probe_inputs := [
	{"tool": "stripe.charge.refund", "arguments": {"amount": 100}, "agent": "a"},
	{"tool": "stripe.charge.refund", "arguments": {"amount": 1500}, "agent": "a"},
	{"tool": "swift.wire.initiate", "arguments": {"amount": 50000, "jurisdiction": "OFAC_FLAGGED"}, "agent": "a"},
]
