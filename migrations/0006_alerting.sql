-- 0006: alerting. `alerted_at` records when a finding was dispatched to the notifier so each
-- finding alerts at most once. NULL means "pending alert" — the worker's alert sweep claims these
-- and only stamps alerted_at after the notifier succeeds, so a transient notifier outage is retried
-- (at-least-once delivery) rather than dropped.

ALTER TABLE findings ADD COLUMN IF NOT EXISTS alerted_at timestamptz;

CREATE INDEX IF NOT EXISTS idx_findings_unalerted
    ON findings(severity) WHERE status = 'open' AND alerted_at IS NULL;
