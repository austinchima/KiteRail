// Throughput at a fixed offered load. Run it at increasing RATE values
// (bench/step.sh does this) and take the highest rate that holds the target:
// p99 under 100 ms, under 0.1% errors, and no dropped iterations.
//
//   k6 run -e RATE=400 bench/k6/throughput.js
//   k6 run -e RATE=400 -e MIX=mixed bench/k6/throughput.js
//
// MIX=allow (default) sends only allowed calls, the path that writes the
// ledger and forwards upstream. MIX=mixed sends 80% allow, 10% quarantine and
// 10% deny; quarantined calls also write a held-action row.
import http from 'k6/http';
import { check } from 'k6';
import { CALLS, OUT_DIR, ms, postProxy, stamp } from './lib.js';

const RATE = Number(__ENV.RATE || 200);
const DURATION = __ENV.DURATION || '60s';
const MIX = __ENV.MIX || 'allow';

// 403 (deny) and 202 (quarantine) are correct answers, not failures.
http.setResponseCallback(http.expectedStatuses(200, 202, 403));

export const options = {
  scenarios: {
    load: {
      executor: 'constant-arrival-rate',
      rate: RATE,
      timeUnit: '1s',
      duration: DURATION,
      preAllocatedVUs: Math.max(20, Math.ceil(RATE / 4)),
      maxVUs: Math.max(100, RATE * 2),
    },
  },
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  thresholds: {
    http_req_duration: ['p(99)<100'],
    http_req_failed: ['rate<0.001'],
  },
};

function pick() {
  if (MIX !== 'mixed') return 'allow';
  const r = Math.random();
  if (r < 0.8) return 'allow';
  return r < 0.9 ? 'quarantine' : 'deny';
}

export default function () {
  const kind = pick();
  const call = CALLS[kind];
  const res = postProxy(call, { decision: kind });
  check(res, { [`${kind} -> ${call.status}`]: (r) => r.status === call.status });
}

export function handleSummary(data) {
  const m = data.metrics;
  const dur = m.http_req_duration.values;
  const reqs = m.http_reqs.values;
  const dropped = m.dropped_iterations ? m.dropped_iterations.values.count : 0;
  const result = {
    test: 'throughput',
    mix: MIX,
    offered_rate_per_second: RATE,
    achieved_rate_per_second: reqs.rate,
    requests: reqs.count,
    dropped_iterations: dropped,
    error_rate: m.http_req_failed.values.rate,
    latency_ms: { med: dur.med, 'p(95)': dur['p(95)'], 'p(99)': dur['p(99)'], max: dur.max },
    checks_passed_rate: m.checks.values.rate,
  };
  const held = dur['p(99)'] < 100 && result.error_rate < 0.001 && dropped === 0;

  const lines = [
    '',
    `Elodea throughput, ${MIX} mix: offered ${RATE} req/s, achieved ${reqs.rate.toFixed(1)} req/s`,
    `  p50 ${ms(dur.med)}   p95 ${ms(dur['p(95)'])}   p99 ${ms(dur['p(99)'])}   max ${ms(dur.max)}`,
    `  errors ${(result.error_rate * 100).toFixed(3)}%   dropped iterations ${dropped}   correct outcomes ${(result.checks_passed_rate * 100).toFixed(2)}%`,
    `  ${held ? 'HELD' : 'DID NOT HOLD'} the target (p99 < 100 ms, errors < 0.1%, nothing dropped)`,
    '',
  ];
  return {
    stdout: lines.join('\n'),
    [`${OUT_DIR}/throughput-${MIX}-${RATE}-${stamp()}.json`]: JSON.stringify({ ...result, held }, null, 2),
  };
}
