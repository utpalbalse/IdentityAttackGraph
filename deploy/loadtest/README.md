# Load test (k6)

`api_smoke.js` ramps to 20 VUs against the NHIID read API and asserts latency + error SLOs
(p95 < 300ms, p99 < 500ms, < 1% errors) across the hot read paths: inventory, findings, triage,
and the graph.

## Run

Seed a stack first (`make dev && make seed`), then:

```bash
# install k6: https://grafana.com/docs/k6/latest/set-up/install-k6/
BASE_URL=http://localhost:8080 k6 run deploy/loadtest/api_smoke.js

# with auth enabled:
BASE_URL=https://nhiid.example.com TOKEN=<bearer> k6 run deploy/loadtest/api_smoke.js
```

The thresholds make the run **fail** (non-zero exit) if SLOs are breached, so it can gate a release
in CI or a pre-prod check. Pair it with the Prometheus `nhiid_http_request_duration_seconds`
histogram and OTLP traces to find the slow endpoints.
