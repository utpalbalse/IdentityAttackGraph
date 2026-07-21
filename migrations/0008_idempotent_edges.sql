-- 0008: make trust_edges and resource_bindings genuinely idempotent.
--
-- Both repos upserted with a bare `ON CONFLICT DO NOTHING`. Without a conflict target that clause
-- only fires on an actual constraint violation, and the only constraint on either table was the
-- primary key -- which is a fresh uuid_generate_v4() on every insert. So no conflict ever occurred
-- and each collector run appended a duplicate set of rows.
--
-- This is not cosmetic. The risk engine scores the trust factor per edge, so N duplicate
-- can_assume edges added N * conditionless_assume points until the factor clamped at 100: an
-- identity's score climbed on every collection cycle without anything changing in the cloud.
-- It also duplicated the conditionless_assume_role and wildcard_trust findings.
--
-- Migration 0005 already applied this same fix to exposures; these two tables were missed.
--
-- NULLS NOT DISTINCT (Postgres 15+) is required: these keys are half-nullable (an edge is
-- identity->role or role->role, never both), and under default NULLS DISTINCT semantics every row
-- with a NULL component would still be considered unique.

-- Collapse existing duplicates, keeping the physically-first row of each natural key.
DELETE FROM trust_edges a USING trust_edges b
 WHERE a.ctid > b.ctid
   AND a.src_identity_id IS NOT DISTINCT FROM b.src_identity_id
   AND a.src_role_id     IS NOT DISTINCT FROM b.src_role_id
   AND a.dst_identity_id IS NOT DISTINCT FROM b.dst_identity_id
   AND a.dst_role_id     IS NOT DISTINCT FROM b.dst_role_id
   AND a.edge_type       =  b.edge_type;

DELETE FROM resource_bindings a USING resource_bindings b
 WHERE a.ctid > b.ctid
   AND a.identity_id  IS NOT DISTINCT FROM b.identity_id
   AND a.role_id      IS NOT DISTINCT FROM b.role_id
   AND a.resource_urn =  b.resource_urn
   AND a.effect       =  b.effect;

ALTER TABLE trust_edges
    ADD CONSTRAINT uq_trust_edges_natural_key
    UNIQUE NULLS NOT DISTINCT (src_identity_id, src_role_id, dst_identity_id, dst_role_id, edge_type);

ALTER TABLE resource_bindings
    ADD CONSTRAINT uq_resource_bindings_natural_key
    UNIQUE NULLS NOT DISTINCT (identity_id, role_id, resource_urn, effect);
