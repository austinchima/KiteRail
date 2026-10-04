#!/usr/bin/env bash
# Fail-closed check: send a steady stream of allowed calls, stop Postgres in
# the middle, start it again, then compare the calls the mock upstream
# received with the 'allow' entries the ledger gained.
#
# Elodea writes the ledger before it forwards, so the test passes only if
#   calls forwarded upstream <= allow entries added to the ledger
# i.e. no tool call ever executed without an audit record.
#
# Needs the bench stack running (see bench/README.md) and k6 on PATH.
set -euo pipefail
cd "$(dirname "$0")/.."

COMPOSE=(docker compose -f docker-compose.yml -f bench/docker-compose.bench.yml)
K6=${K6:-k6}
UPSTREAM_URL=${UPSTREAM_URL:-http://localhost:8082}
RATE=${RATE:-50}
OUTAGE_START=${OUTAGE_START:-20}
OUTAGE_SECONDS=${OUTAGE_SECONDS:-20}
DURATION=${DURATION:-60}
OUT=bench/results/failclosed-$(date -u +%Y-%m-%dT%H-%M-%SZ)

ledger_allows() {
  "${COMPOSE[@]}" exec -T postgres psql -U elodea -d elodea -tAc \
    "SELECT count(*) FROM ledger WHERE decision = 'allow'" | tr -d '[:space:]'
}

upstream_calls() {
  curl -fsS "$UPSTREAM_URL/__stats" | sed -E 's/.*"tool_calls":([0-9]+).*/\1/'
}

wait_for_postgres() {
  for _ in $(seq 1 60); do
    if "${COMPOSE[@]}" exec -T postgres pg_isready -U elodea >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "postgres did not come back within 60s" >&2
  return 1
}

mkdir -p bench/results
before=$(ledger_allows)
curl -fsS -X POST "$UPSTREAM_URL/__reset" >/dev/null

echo "Sending $RATE allowed calls/s for ${DURATION}s; Postgres goes down at ${OUTAGE_START}s for ${OUTAGE_SECONDS}s."
"$K6" run -q -e RATE="$RATE" -e DURATION="${DURATION}s" -e SUMMARY_FILE="$OUT-k6.json" \
  bench/k6/failclosed.js &
k6_pid=$!

sleep "$OUTAGE_START"
echo ">>> stopping postgres"
"${COMPOSE[@]}" stop postgres >/dev/null
sleep "$OUTAGE_SECONDS"
echo ">>> starting postgres"
"${COMPOSE[@]}" start postgres >/dev/null

wait "$k6_pid"
wait_for_postgres

after=$(ledger_allows)
forwarded=$(upstream_calls)
ledgered=$((after - before))
unaudited=$((forwarded > ledgered ? forwarded - ledgered : 0))

if [ "$unaudited" -eq 0 ]; then verdict=PASS; else verdict=FAIL; fi

cat >"$OUT.json" <<EOF
{
  "test": "failclosed",
  "rate_per_second": $RATE,
  "duration_seconds": $DURATION,
  "outage_seconds": $OUTAGE_SECONDS,
  "forwarded_upstream": $forwarded,
  "ledger_allow_entries_added": $ledgered,
  "forwarded_without_ledger_entry": $unaudited,
  "verdict": "$verdict"
}
EOF

echo
echo "Forwarded to upstream:        $forwarded"
echo "Allow entries added to ledger: $ledgered"
echo "Forwarded without an entry:    $unaudited"
echo "$verdict (details in $OUT.json and $OUT-k6.json)"
[ "$verdict" = PASS ]
