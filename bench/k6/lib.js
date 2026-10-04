// Shared request builders for the Elodea k6 scripts.
import http from 'k6/http';

export const PROXY_URL = __ENV.PROXY_URL || 'http://localhost:8080';
export const UPSTREAM_URL = __ENV.UPSTREAM_URL || 'http://localhost:8082';
export const AGENT_TOKEN = __ENV.AGENT_TOKEN || 'sk_agent_local_000000000000';
export const OUT_DIR = __ENV.OUT_DIR || 'bench/results';

// One call per policy outcome, matching the repository policy bundle.
// Without an MCP-Protocol-Version header the proxy answers deny with 403 and
// quarantine with 202, so the status code identifies the outcome.
export const CALLS = {
  allow: { tool: 'stripe.charge.refund', args: { amount: 100 }, status: 200 },
  quarantine: { tool: 'stripe.charge.refund', args: { amount: 1500 }, status: 202 },
  deny: { tool: 'swift.wire.initiate', args: { amount: 500, jurisdiction: 'SANCTIONED' }, status: 403 },
};

export function rpcBody(call) {
  return JSON.stringify({
    jsonrpc: '2.0',
    method: 'tools/call',
    params: { name: call.tool, arguments: call.args },
    id: `${__VU}-${__ITER}`,
  });
}

export function postProxy(call, tags) {
  return http.post(`${PROXY_URL}/`, rpcBody(call), {
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${AGENT_TOKEN}` },
    tags,
  });
}

export function postUpstream(call, tags) {
  return http.post(`${UPSTREAM_URL}/`, rpcBody(call), {
    headers: { 'Content-Type': 'application/json' },
    tags,
  });
}

export function stamp() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

export function ms(value) {
  return value === undefined ? 'n/a' : `${value.toFixed(2)} ms`;
}
