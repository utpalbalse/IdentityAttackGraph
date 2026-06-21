-- 0005: dedupe exposures by fingerprint so re-running a repo secret scan is idempotent
-- (the collector's ON CONFLICT DO NOTHING upsert needs a unique target). See internal/collectors/repo.

CREATE UNIQUE INDEX IF NOT EXISTS uq_exposures_fingerprint ON exposures(fingerprint);
