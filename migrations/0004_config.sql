-- 0004: key/value settings store for hot-reloadable, audited configuration (risk weights).
-- The suppressions, audit_log, and snapshots tables already exist (0001); this only adds the
-- settings table the /config endpoints and worker weight-reload use.

CREATE TABLE IF NOT EXISTS config_settings (
    key        text PRIMARY KEY,
    value      jsonb NOT NULL,
    updated_by text,
    updated_at timestamptz NOT NULL DEFAULT now()
);
