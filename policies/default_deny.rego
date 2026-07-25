package kiterail.authz

import rego.v1

default decision := {"action": "deny", "rule": "default_deny", "explanation": "No matching allow rule found"}
