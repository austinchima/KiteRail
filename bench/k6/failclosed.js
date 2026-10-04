// Steady stream of allowed calls for bench/failclosed.sh, which stops
// Postgres partway through. This script only generates load and counts
// outcomes; the shell script checks the invariant against the ledger.
//
// Expected while the database is down: 503 "audit unavailable", never 200.
import http from 'k6/http';
import { Counter } from 'k6/metrics';
import { CALLS, postProxy } from './lib.js';

const RATE = Number(__ENV.RATE || 50);
const DURATION = __ENV.DURATION || '60s';

const allowed = new Counter('outcome_allowed_200');
const refused = new Counter('outcome_refused_503');
const other = new Counter('outcome_other');

// Every status is an expected observation here; the counters tell them apart.
http.setResponseCallback(http.expectedStatuses({ min: 100, max: 599 }));

export const options = {
  scenarios: {
    load: {
      executor: 'constant-arrival-rate',
      rate: RATE,
      timeUnit: '1s',
      duration: DURATION,
      preAllocatedVUs: 20,
      maxVUs: 200,
    },
  },
};

export default function () {
  const res = postProxy(CALLS.allow, { decision: 'allow' });
  if (res.status === 200) allowed.add(1);
  else if (res.status === 503) refused.add(1);
  else other.add(1, { status: String(res.status) });
}

export function handleSummary(data) {
  const count = (name) => (data.metrics[name] ? data.metrics[name].values.count : 0);
  const summary = {
    allowed_200: count('outcome_allowed_200'),
    refused_503: count('outcome_refused_503'),
    other: count('outcome_other'),
  };
  return {
    stdout: `\nk6 outcomes: ${JSON.stringify(summary)}\n`,
    [__ENV.SUMMARY_FILE || 'bench/results/failclosed-k6.json']: JSON.stringify(summary, null, 2),
  };
}
