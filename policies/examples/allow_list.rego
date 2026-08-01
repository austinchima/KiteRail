package kiterail.authz

import rego.v1

# Pattern: Allow List
# Only allow tools that are explicitly defined in the list.
# Everything else will fall through to default deny.

allowed_tools := {
	"github.issue.create",
	"github.pr.review",
	"linear.ticket.update"
}

decision := {"action": "allow", "rule": "allowed_tool", "explanation": "Tool is on the approved allow-list"} if {
	input.tool in allowed_tools
}
