package elodea.authz_test

import rego.v1
import data.elodea.authz

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

test_wire_missing_jurisdiction_quarantined if {
	d := authz.decision with input as {"tool": "swift.wire.initiate", "arguments": {"amount": 500}, "agent": "a"}
	d.action == "quarantine"
	d.rule == "wire_incomplete"
}

test_wire_non_numeric_amount_quarantined if {
	d := authz.decision with input as {"tool": "swift.wire.initiate", "arguments": {"amount": "500", "jurisdiction": "US"}, "agent": "a"}
	d.action == "quarantine"
	d.rule == "wire_incomplete"
}

test_small_wire_allowed if {
	d := authz.decision with input as {"tool": "swift.wire.initiate", "arguments": {"amount": 500, "jurisdiction": "US"}, "agent": "a"}
	d.action == "allow"
	d.rule == "wire_allowed"
}

test_pii_non_string_is_not_an_eval_error if {
	d := authz.decision with input as {"tool": "stripe.charge.refund", "arguments": {"amount": 100, "ssn": 123456789}, "agent": "a"}
	d.action == "allow"
}

test_pii_ssn_denied if {
	d := authz.decision with input as {"tool": "stripe.charge.refund", "arguments": {"amount": 100, "ssn": "123-45-6789"}, "agent": "a"}
	d.action == "deny"
	d.rule == "pii_ssn_detected"
}

test_mcp_discovery_allowed if {
	d := authz.decision with input as {"tool": "tools/list", "raw_method": "tools/list", "arguments": {}, "agent": "a"}
	d.action == "allow"
	d.rule == "mcp_protocol_discovery"
}

test_tool_named_like_protocol_method_not_allowed if {
	d := authz.decision with input as {"tool": "tools/list", "raw_method": "tools/call", "arguments": {}, "agent": "a"}
	d.action == "deny"
	d.rule == "default_deny"
}

test_refund_null_amount_not_auto_allowed if {
	d := authz.decision with input as {"tool": "stripe.charge.refund", "arguments": {"amount": null}, "agent": "a"}
	d.action == "quarantine"
	d.rule == "refund_amount_invalid"
}

test_refund_boolean_amount_not_auto_allowed if {
	d := authz.decision with input as {"tool": "stripe.charge.refund", "arguments": {"amount": true}, "agent": "a"}
	d.action == "quarantine"
	d.rule == "refund_amount_invalid"
}

test_refund_string_amount_held if {
	d := authz.decision with input as {"tool": "stripe.charge.refund", "arguments": {"amount": "50"}, "agent": "a"}
	d.action == "quarantine"
	d.rule == "refund_amount_invalid"
}

decision_probe_inputs := [
	{"tool": "stripe.charge.refund", "arguments": {"amount": 100}, "agent": "a"},
	{"tool": "stripe.charge.refund", "arguments": {"amount": 1500}, "agent": "a"},
	{"tool": "swift.wire.initiate", "arguments": {"amount": 50000, "jurisdiction": "OFAC_FLAGGED"}, "agent": "a"},
	{"tool": "swift.wire.initiate", "arguments": {"amount": 500}, "agent": "a"},
	{"tool": "tools/list", "raw_method": "tools/list", "arguments": {}, "agent": "a"},
]
