// k6 load test for the NHIID read API. Exercises the hot read paths (inventory, findings, triage,
// graph) under a ramped load and asserts latency/error SLOs. Run against a seeded stack:
//
//   BASE_URL=http://localhost:8080 TOKEN=... k6 run deploy/loadtest/api_smoke.js
//
// TOKEN is only needed when the API runs with auth.mode != off.
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

const BASE = __ENV.BASE_URL || 'http://localhost:8080';
const TOKEN = __ENV.TOKEN || '';
const errors = new Rate('app_errors');

export const options = {
  scenarios: {
    reads: {
      executor: 'ramping-vus',
      startVUs: 1,
      stages: [
        { duration: '20s', target: 20 }, // ramp up
        { duration: '40s', target: 20 }, // hold
        { duration: '10s', target: 0 },  // ramp down
      ],
    },
  },
  thresholds: {
    // 99% of reads under 500ms; <1% application errors.
    http_req_duration: ['p(95)<300', 'p(99)<500'],
    app_errors: ['rate<0.01'],
    checks: ['rate>0.99'],
  },
};

const params = TOKEN ? { headers: { Authorization: `Bearer ${TOKEN}` } } : {};

// Weighted hot read paths.
const endpoints = [
  '/api/v1/identities?limit=50',
  '/api/v1/identities?provider=k8s',
  '/api/v1/findings?severity=high',
  '/api/v1/triage',
  '/api/v1/graph',
];

export default function () {
  // Liveness is cheap and unauthenticated.
  const h = http.get(`${BASE}/healthz`);
  check(h, { 'healthz 200': (r) => r.status === 200 });

  const path = endpoints[Math.floor(Math.random() * endpoints.length)];
  const res = http.get(`${BASE}${path}`, params);
  const ok = check(res, {
    'status 2xx': (r) => r.status >= 200 && r.status < 300,
    'body is json': (r) => (r.headers['Content-Type'] || '').includes('application/json'),
  });
  errors.add(!ok);

  sleep(0.5);
}
