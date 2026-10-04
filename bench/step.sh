#!/usr/bin/env bash
# Runs bench/k6/throughput.js at increasing request rates. The highest rate
# that prints HELD is the sustained throughput for this machine.
#
#   bench/step.sh
#   RATES="200 300 400 500" MIX=mixed DURATION=60s bench/step.sh
set -euo pipefail
cd "$(dirname "$0")/.."

K6=${K6:-k6}
RATES=${RATES:-"100 200 400 800 1600"}
MIX=${MIX:-allow}
DURATION=${DURATION:-30s}

mkdir -p bench/results
for rate in $RATES; do
  # k6 exits non-zero when a threshold fails; that is a result, not an error.
  "$K6" run -q -e RATE="$rate" -e MIX="$MIX" -e DURATION="$DURATION" bench/k6/throughput.js || true
  sleep 5
done
