-- 0003: dedupe remediation recommendations per (finding, action) so the worker can regenerate
-- them idempotently without piling up duplicates. See internal/remediate + docs/RISK_MODEL.md.

CREATE UNIQUE INDEX IF NOT EXISTS uq_remediation_finding_action
    ON remediation_actions(finding_id, action);
