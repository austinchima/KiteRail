# Title: Allow read-only MCP discovery
package elodea.authz

import rego.v1

# Read-only MCP protocol operations that clients need to connect and discover
# capabilities. Matched on raw_method (the JSON-RPC method), never on the
# policy subject, so a tools/call for a tool *named* "tools/list" is not
# covered here. Tool execution (tools/call) always needs an explicit policy.
mcp_discovery_methods := {
    "initialize",
    "ping",
    "tools/list",
    "resources/list",
    "resources/templates/list",
    "prompts/list",
}

decisions contains {"action": "allow", "rule": "mcp_protocol_discovery", "explanation": "Read-only MCP protocol operation"} if {
    input.raw_method in mcp_discovery_methods
}
