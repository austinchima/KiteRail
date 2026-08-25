package kiterail.authz_test

import rego.v1
import data.kiterail.authz

test_small_refund_allowed if {
	d := authz.decision with input as {"tool": "stripe.charge.refund", "arguments": {"amount": 100}, "agent": "a"}
	d.action == "allow"
}

test_large_refund_quarantined if {
	d := authz.decision with input as {"tool": "stripe.charge.refund", "arguments": {"amount": 1500}, "agent": "a"}
	d.action == "quarantine"
}

test_deny_beats_quarantine if {
	d := authz.decision with input as {"tool": "swift.wire.initiate", "arguments": {"amount": 50000, "jurisdiction": "OFAC_FLAGGED"}, "agent": "a"}
	d.action == "deny"
}

test_unknown_tool_default_deny if {
	d := authz.decision with input as {"tool": "unknown.tool", "arguments": {}, "agent": "a"}
	d.action == "deny"
	d.rule == "default_deny"
}