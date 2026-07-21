-- 0007: remediation urgency. The risk engine already computed an urgency score (composite blended
-- with exploitability: verified-live exposure, crown-jewel reach, public exposure, and a discount
-- for trust guarded by ExternalId/MFA/IP) but had nowhere to put it, so the triage queue fell back
-- to ordering by risk_score alone. Persisting it lets the queue rank by "fix this first" rather than
-- "this scored highest", which is what docs/RISK_MODEL.md describes.

ALTER TABLE identities ADD COLUMN IF NOT EXISTS urgency int NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_identities_urgency ON identities(urgency DESC, risk_score DESC);
