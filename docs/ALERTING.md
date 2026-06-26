# Alerting

NHIID closes the **detect → notify** loop: after each detection pass the worker dispatches **new**
findings at or above a severity threshold to a Slack incoming webhook or a generic JSON webhook.
Disabled by default; enable per environment.

## How it works

1. The detection pass upserts findings (deduped by fingerprint).
2. The **alert sweep** (`runAlerts`, after detection) claims open findings where `alerted_at IS NULL`
   and `severity >= min_severity`, joined with their identity.
3. It sends them as one batch to the notifier.
4. **Only on a successful (2xx) send** does it stamp `alerted_at`, so each finding alerts **once**.
   If the sink is down, `alerted_at` stays NULL and the next sweep retries — **at-least-once**, no
   findings silently dropped.

Re-running detection does not re-alert existing findings. A finding that is resolved and later
re-opens is a fresh row and alerts again.

## Configuration

`configs/config.yaml` (or env overrides):

```yaml
notify:
  enabled: false
  kind: "slack"            # slack (incoming webhook) | webhook (generic JSON POST)
  webhook_url: ""          # set via NHIID_NOTIFY_WEBHOOK_URL (a secret)
  min_severity: "high"     # info|low|medium|high|critical
```

| Env | Purpose |
|-----|---------|
| `NHIID_NOTIFY_ENABLED` | `true` to enable |
| `NHIID_NOTIFY_KIND` | `slack` or `webhook` |
| `NHIID_NOTIFY_WEBHOOK_URL` | the webhook URL (keep it secret) |
| `NHIID_NOTIFY_MIN_SEVERITY` | severity floor (default `high`) |

### Slack

Create a Slack [incoming webhook](https://api.slack.com/messaging/webhooks) and set its URL. Messages
use Block Kit (header + one section per finding, capped at 20, with a "…and N more" summary) and a
plain-text fallback. Each finding shows severity, detector, identity, account, and narrative.

### Generic webhook

`kind: webhook` POSTs a stable JSON envelope — route it into PagerDuty Events, a SIEM/SOAR intake,
or your own handler:

```json
{ "source": "nhiid", "sent_at": "2026-06-26T12:00:00Z", "count": 2,
  "alerts": [ { "finding_id": "…", "detector": "over_privileged_sa", "severity": "high",
                "title": "…", "narrative": "…", "identity_name": "prod/deployer",
                "account": "k8s:demo", "first_seen": "…", "evidence": { } } ] }
```

## Kubernetes (Helm)

```yaml
config:
  notify:
    enabled: true
    kind: slack
    minSeverity: high
secrets:
  notifyWebhookURL: "https://hooks.slack.com/services/…"   # or supply via existingSecret key notify-webhook-url
```

The webhook URL is injected into the worker as `NHIID_NOTIFY_WEBHOOK_URL` from the chart Secret.

## Observability

| Metric | Meaning |
|--------|---------|
| `nhiid_alerts_sent_total{severity}` | findings dispatched |
| `nhiid_alerts_failed_total` | dispatch failures (left pending for retry) |
| `nhiid_jobs_total{job="alert"}` / `nhiid_jobs_failed_total{job="alert"}` | sweep runs / failures |

A rising `nhiid_alerts_failed_total` with flat `..._sent_total` means the sink is unreachable —
findings are accumulating un-alerted and will flush when it recovers.

## Notes

- Alerting runs in the **worker** (where detection runs), not the API.
- Suppressed findings never reach the queue (they aren't upserted as open), so they don't alert.
- There is no per-detector routing yet — `min_severity` is the only filter.
