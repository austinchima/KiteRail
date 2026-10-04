// Added latency: the same allowed tool call sent straight to the mock
// upstream, then through Elodea, at the same fixed request rate. The
// difference is what Elodea costs per call (auth, policy, ledger write, proxy hop).
//
//   k6 run bench/k6/latency.js
//   k6 run -e RATE=100 -e DURATION=120s bench/k6/latency.js
import { check } from 'k6';
import { CALLS, OUT_DIR, ms, postProxy, postUpstream, stamp } from './lib.js';

const RATE = Number(__ENV.RATE || 50);
const DURATION = __ENV.DURATION || '60s';
const durationSeconds = parseInt(DURATION, 10) * (DURATION.endsWith('m') ? 60 : 1);

const phase = (exec, startTime) => ({
  executor: 'constant-arrival-rate',
  exec,
  rate: RATE,
  timeUnit: '1s',
  duration: DURATION,
  preAllocatedVUs: Math.max(10, Math.ceil(RATE / 5)),
  maxVUs: Math.max(50, RATE * 2),
  startTime,
});

// Warm-up traffic (connection pools, OPA caches, Postgres buffers) is tagged
// separately so it never counts toward either phase.
const WARMUP_SECONDS = 10;

export const options = {
  scenarios: {
    warmup: { ...phase('warmup', '0s'), duration: `${WARMUP_SECONDS}s` },
    direct: phase('direct', `${WARMUP_SECONDS + 2}s`),
    proxied: phase('proxied', `${WARMUP_SECONDS + 2 + durationSeconds + 5}s`),
  },
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  // Thresholds on tagged submetrics make k6 report each phase separately.
  thresholds: {
    'http_req_duration{target:direct}': ['p(99)<1000'],
    'http_req_duration{target:proxy}': ['p(99)<1000'],
    'http_req_failed{target:direct}': ['rate<0.01'],
    'http_req_failed{target:proxy}': ['rate<0.01'],
  },
};

export function warmup() {
  postUpstream(CALLS.allow, { target: 'warmup' });
  postProxy(CALLS.allow, { target: 'warmup' });
}

export function direct() {
  const res = postUpstream(CALLS.allow, { target: 'direct' });
  check(res, { 'direct 200': (r) => r.status === 200 });
}

export function proxied() {
  const res = postProxy(CALLS.allow, { target: 'proxy' });
  check(res, { 'proxy allowed 200': (r) => r.status === 200 });
}

export function handleSummary(data) {
  const d = data.metrics['http_req_duration{target:direct}'].values;
  const p = data.metrics['http_req_duration{target:proxy}'].values;
  const stats = ['med', 'p(95)', 'p(99)'];
  const result = {
    test: 'latency',
    rate_per_second: RATE,
    duration: DURATION,
    direct_ms: Object.fromEntries(stats.map((s) => [s, d[s]])),
    proxy_ms: Object.fromEntries(stats.map((s) => [s, p[s]])),
    added_ms: Object.fromEntries(stats.map((s) => [s, p[s] - d[s]])),
    proxy_error_rate: data.metrics['http_req_failed{target:proxy}'].values.rate,
  };

  const lines = [
    '',
    `Elodea added latency at ${RATE} req/s (${DURATION} per phase)`,
    '              direct        via Elodea    added',
    ...stats.map((s) => `  ${s.padEnd(10)}  ${ms(d[s]).padEnd(12)}  ${ms(p[s]).padEnd(12)}  ${ms(p[s] - d[s])}`),
    `  proxy error rate: ${(result.proxy_error_rate * 100).toFixed(3)}%`,
    '',
  ];
  return {
    stdout: lines.join('\n'),
    [`${OUT_DIR}/latency-${stamp()}.json`]: JSON.stringify(result, null, 2),
  };
}
