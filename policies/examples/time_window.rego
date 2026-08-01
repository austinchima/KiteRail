package kiterail.authz

import rego.v1

# Pattern: Time Window
# Restrict agent actions to specific time windows, such as business hours.

# Deny deployments on weekends (Saturday=6, Sunday=0)
decision := {"action": "deny", "rule": "no_weekend_deploys", "explanation": "Production deployments are not allowed on weekends"} if {
	input.tool == "kubernetes.deployment.update"
	
	# Extract the day of the week from the current time in UTC
	# Note: In a real system you may pass the timestamp in the input or use time.now_ns()
	ns := time.now_ns()
	date := time.date(ns)
	weekday := time.weekday(ns)
	
	weekday in ["Saturday", "Sunday"]
}
