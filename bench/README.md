# Benchmarks

Reproducible performance and correctness measurements for Elodea. Every number
quoted anywhere about Elodea should come from these scripts, with the machine
and settings written next to it.

| What | Tool | Answers |
|---|---|---|
| Policy decision time | Go benchmark (`internal/opaengine`) | How long one OPA decision takes, per rule path |
| Ledger cost | Go benchmark (`internal/ledger`) | Hash time, append time, append ceiling under contention, full-chain verify time |
| Added latency | k6 `latency.js` | How much slower a tool call is through Elodea than straight to the tool |
| Throughput | k6 `throughput.js` + `step.sh` | The highest request rate Elodea sustains within the latency target |
| Fail-closed | `failclosed.sh` | Whether any tool call ran without an audit record while the database was down |

## Prerequisites

- Docker with Compose v2.23 or newer (the overlay uses inline `configs`)
- Go (the version in `backend/go.mod`) for the Go benchmarks
- [k6](https://grafana.com/docs/k6/latest/set-up/install-k6/) on `PATH`
  (`winget install k6 --source winget`, `brew install k6`, or your package manager)
- Bash for the `.sh` scripts (Git Bash works on Windows)

## 1. Go benchmarks (no stack needed for the policy engine)

```bash
cd backend
go test ./internal/opaengine -run '^$' -bench . -benchmem -count 5
```

The ledger benchmarks need Postgres and **truncate the `ledger` table**. Point
them only at the bench stack (step 2) or another throwaway database:

```bash
ELODEA_POSTGRES_DSN='postgres://elodea:elodea@localhost:55432/elodea?sslmode=disable' \
ELODEA_BENCH_CHAIN_SIZE=100000 \
  go test ./internal/ledger -run '^$' -bench . -benchmem -count 5
```

`BenchmarkVerifyChain` reports ns/op for the whole chain; divide by `entries`
for the per-entry cost. `BenchmarkAppendParallel`'s ns/op is the effective
time per append when every core is appending at once, so `1e9 / ns/op` is the
ceiling on ledgered decisions per second for that database.

Use [benchstat](https://pkg.go.dev/golang.org/x/perf/cmd/benchstat) on the
`-count 5` output to get a median with a confidence interval.

## 2. Start the bench stack

From the repo root:

```bash
docker compose -f docker-compose.yml -f bench/docker-compose.bench.yml up -d --build
```

This is the normal dev stack with three changes (see the comments in
`docker-compose.bench.yml`): the proxy forwards to `mock-upstream`, a Go tool
server that answers instantly and counts calls; the per-agent rate limit is
raised; and logging drops to `warn`.

Stop it afterwards with the same `-f` flags and `down` (add `-v` to wipe the
database).

## 3. Added latency

```bash
k6 run bench/k6/latency.js                     # 50 req/s, 60 s per phase
k6 run -e RATE=100 -e DURATION=120s bench/k6/latency.js
```

Runs a 10 s warm-up, then the same allowed call straight to the mock and then
through Elodea, at the same fixed rate. It prints the median, p95 and p99 for
each and the difference. Without the warm-up the first requests (cold
connection pools and caches) dominate p99.

## 4. Throughput

```bash
bench/step.sh                                   # allow-only, 100 → 1600 req/s
RATES="200 300 400 500" MIX=mixed DURATION=60s bench/step.sh
```

Each step is a fixed offered load. A step **HELD** if p99 < 100 ms, errors
< 0.1% and k6 dropped nothing. The highest rate that held is the sustained
throughput. `MIX=mixed` sends 80% allow, 10% quarantine, 10% deny.

Every decision is written to the ledger first, and appends serialize on one
advisory lock, so expect throughput to track `BenchmarkAppendParallel`.

## 5. Fail-closed under database outage

```bash
bench/failclosed.sh
RATE=100 DURATION=90 OUTAGE_START=30 OUTAGE_SECONDS=30 bench/failclosed.sh
```

Sends allowed calls, stops Postgres partway through, starts it again, then
compares the calls the mock upstream received with the `allow` entries the
ledger gained. It **PASS**es only if no call was forwarded without a ledger
entry. It prints how many calls were refused with `503 audit unavailable`.

## Recording results

Every k6 run writes a JSON summary to `bench/results/`. Commit the ones you
quote, and fill in this block alongside them:

```
Date:
Machine:     CPU, cores, RAM, OS
Runtime:     Docker Desktop / native Linux, Docker version
Elodea:      git commit
Postgres:    16-alpine, default config, Docker volume
k6:          version, run on the same machine (it competes for CPU)
```

Two habits keep the numbers honest: report the median of several runs, not the
best one, and quote p99 alongside the median.
