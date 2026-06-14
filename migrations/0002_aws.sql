-- 0002: support real cloud collectors.
-- owner_identity_id links a permission set (roles row) directly to the principal that holds it,
-- so the risk engine can count an identity's directly-held privileges in addition to roles it can
-- reach via assume-role trust edges. See docs/AWS_COLLECTOR.md.

ALTER TABLE roles ADD COLUMN IF NOT EXISTS owner_identity_id uuid REFERENCES identities(id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS idx_roles_owner_identity ON roles(owner_identity_id);
