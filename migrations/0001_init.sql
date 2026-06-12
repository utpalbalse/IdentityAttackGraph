-- NHIID core schema. See docs/DATA_MODEL.md for the narrative.
-- Idempotent-friendly: uses IF NOT EXISTS where practical.

CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ---------- provenance / runs ----------
CREATE TABLE IF NOT EXISTS snapshots (
    id           uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    started_at   timestamptz NOT NULL DEFAULT now(),
    finished_at  timestamptz,
    scope        jsonb NOT NULL DEFAULT '{}',
    entity_counts jsonb NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS collector_runs (
    id              uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    collector       text NOT NULL,
    account_ref     text NOT NULL,
    cursor_before   jsonb,
    cursor_after    jsonb,
    records_in      int NOT NULL DEFAULT 0,
    records_upserted int NOT NULL DEFAULT 0,
    errors          int NOT NULL DEFAULT 0,
    status          text NOT NULL DEFAULT 'running',
    started_at      timestamptz NOT NULL DEFAULT now(),
    finished_at     timestamptz
);

CREATE TABLE IF NOT EXISTS collector_state (
    collector   text NOT NULL,
    account_ref text NOT NULL,
    cursor      jsonb NOT NULL DEFAULT '{}',
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (collector, account_ref)
);

-- ---------- owners ----------
CREATE TABLE IF NOT EXISTS owners (
    id           uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    kind         text NOT NULL,           -- user|team|service
    email        text,
    display_name text,
    source       text,                    -- tag|csv|iac
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

-- ---------- identities ----------
CREATE TABLE IF NOT EXISTS identities (
    id               uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    kind             text NOT NULL,
    name             text NOT NULL,
    arn_or_email     text,
    provider         text NOT NULL,
    account_ref      text NOT NULL,
    state            text NOT NULL DEFAULT 'active',
    owner_id         uuid REFERENCES owners(id),
    created_at_source timestamptz,
    last_seen_at     timestamptz,
    last_rotated_at  timestamptz,
    is_ai_agent      boolean NOT NULL DEFAULT false,
    ai_agent_meta    jsonb NOT NULL DEFAULT '{}',
    risk_score       int NOT NULL DEFAULT 0,
    risk_breakdown   jsonb NOT NULL DEFAULT '{}',
    -- provenance
    source           text NOT NULL,
    external_id      text NOT NULL,
    collector_run_id uuid,
    collected_at     timestamptz,
    raw_hash         text,
    attributes       jsonb NOT NULL DEFAULT '{}',
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider, external_id)
);
CREATE INDEX IF NOT EXISTS idx_identities_account_kind ON identities(account_ref, kind);
CREATE INDEX IF NOT EXISTS idx_identities_risk ON identities(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_identities_name_trgm ON identities USING gin (name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_identities_arn_trgm ON identities USING gin (arn_or_email gin_trgm_ops);

-- ---------- credentials ----------
CREATE TABLE IF NOT EXISTS credentials (
    id               uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    identity_id      uuid NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    cred_type        text NOT NULL,
    external_id      text NOT NULL,        -- AccessKeyId / key fingerprint, NEVER the secret
    status           text NOT NULL DEFAULT 'active',
    created_at_source timestamptz,
    last_used_at     timestamptz,
    last_used_region text,
    last_used_service text,
    expires_at       timestamptz,
    source           text NOT NULL,
    account_ref      text NOT NULL,
    collected_at     timestamptz,
    attributes       jsonb NOT NULL DEFAULT '{}',
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (cred_type, external_id)
);
CREATE INDEX IF NOT EXISTS idx_credentials_identity ON credentials(identity_id);

-- ---------- secrets ----------
CREATE TABLE IF NOT EXISTS secrets (
    id                  uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    store               text NOT NULL,
    external_id         text NOT NULL,
    account_ref         text NOT NULL,
    name                text,
    last_rotated_at     timestamptz,
    rotation_enabled    boolean NOT NULL DEFAULT false,
    version_count       int NOT NULL DEFAULT 0,
    material_fingerprint text,             -- sha256 only if ever observed; usually NULL
    referenced_by_count int NOT NULL DEFAULT 0,
    last_accessed_at    timestamptz,
    source              text NOT NULL,
    collected_at        timestamptz,
    attributes          jsonb NOT NULL DEFAULT '{}',
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (store, external_id)
);

-- ---------- roles ----------
CREATE TABLE IF NOT EXISTS roles (
    id                  uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    provider            text NOT NULL,
    external_id         text NOT NULL,
    account_ref         text NOT NULL,
    name                text NOT NULL,
    policy_document     jsonb NOT NULL DEFAULT '{}',
    trust_policy        jsonb NOT NULL DEFAULT '{}',
    privilege_level     text NOT NULL DEFAULT 'read',
    is_assumable        boolean NOT NULL DEFAULT false,
    permission_count    int NOT NULL DEFAULT 0,
    wildcard_action_count int NOT NULL DEFAULT 0,
    wildcard_resource_count int NOT NULL DEFAULT 0,
    source              text NOT NULL,
    collected_at        timestamptz,
    attributes          jsonb NOT NULL DEFAULT '{}',
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider, external_id)
);

-- ---------- trust edges ----------
CREATE TABLE IF NOT EXISTS trust_edges (
    id              uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    src_identity_id uuid REFERENCES identities(id) ON DELETE CASCADE,
    src_role_id     uuid REFERENCES roles(id) ON DELETE CASCADE,
    dst_identity_id uuid REFERENCES identities(id) ON DELETE CASCADE,
    dst_role_id     uuid REFERENCES roles(id) ON DELETE CASCADE,
    edge_type       text NOT NULL,         -- can_assume|can_impersonate|can_mint_token|federated_from
    condition       jsonb NOT NULL DEFAULT '{}',
    observed        boolean NOT NULL DEFAULT false,
    source          text NOT NULL,
    account_ref     text NOT NULL,
    collected_at    timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_trust_src ON trust_edges(src_identity_id, src_role_id);
CREATE INDEX IF NOT EXISTS idx_trust_dst ON trust_edges(dst_identity_id, dst_role_id);

-- ---------- resource bindings ----------
CREATE TABLE IF NOT EXISTS resource_bindings (
    id                   uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    identity_id          uuid REFERENCES identities(id) ON DELETE CASCADE,
    role_id              uuid REFERENCES roles(id) ON DELETE CASCADE,
    resource_urn         text NOT NULL,
    resource_kind        text,
    resource_criticality text NOT NULL DEFAULT 'low',  -- low|medium|high|crown_jewel
    actions              text[] NOT NULL DEFAULT '{}',
    effect               text NOT NULL DEFAULT 'allow',
    source               text NOT NULL,
    account_ref          text NOT NULL,
    collected_at         timestamptz,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_binding_identity ON resource_bindings(identity_id);
CREATE INDEX IF NOT EXISTS idx_binding_role ON resource_bindings(role_id);

-- ---------- workloads ----------
CREATE TABLE IF NOT EXISTS workloads (
    id           uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    kind         text NOT NULL,
    external_id  text NOT NULL,
    account_ref  text NOT NULL,
    name         text NOT NULL,
    environment  text,
    identity_id  uuid REFERENCES identities(id) ON DELETE SET NULL,
    source       text NOT NULL,
    collected_at timestamptz,
    attributes   jsonb NOT NULL DEFAULT '{}',
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (kind, external_id)
);
CREATE INDEX IF NOT EXISTS idx_workloads_identity ON workloads(identity_id);

-- ---------- repositories ----------
CREATE TABLE IF NOT EXISTS repositories (
    id             uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    provider       text NOT NULL,
    external_id    text NOT NULL,
    org            text NOT NULL,
    name           text NOT NULL,
    visibility     text NOT NULL DEFAULT 'private',
    default_branch text,
    last_scanned_at timestamptz,
    source         text NOT NULL,
    collected_at   timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider, external_id)
);

-- credential/secret exposure found in a repo (location + fingerprint only, NEVER value)
CREATE TABLE IF NOT EXISTS exposures (
    id            uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    repository_id uuid REFERENCES repositories(id) ON DELETE CASCADE,
    identity_id   uuid REFERENCES identities(id) ON DELETE CASCADE,
    secret_id     uuid REFERENCES secrets(id) ON DELETE CASCADE,
    path          text NOT NULL,
    commit_sha    text,
    line          int,
    pattern       text NOT NULL,          -- e.g. aws_akia, gcp_sa_json, pem_private_key
    fingerprint   text NOT NULL,          -- sha256 of matched material, not the material
    verified      boolean NOT NULL DEFAULT false,
    source        text NOT NULL,
    collected_at  timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_exposures_identity ON exposures(identity_id);

-- ---------- usage events (partitioned by month) ----------
CREATE TABLE IF NOT EXISTS usage_events (
    id            uuid NOT NULL DEFAULT uuid_generate_v4(),
    identity_id   uuid NOT NULL,
    event_time    timestamptz NOT NULL,
    event_name    text NOT NULL,
    event_source  text,
    src_ip        inet,
    src_asn       int,
    src_region    text,
    src_country   text,
    user_agent    text,
    runtime       text,
    mfa_used      boolean,
    error_code    text,
    request_params_hash text,
    raw_hash      text,
    source        text NOT NULL,
    account_ref   text NOT NULL,
    PRIMARY KEY (identity_id, event_time, id)
) PARTITION BY RANGE (event_time);

-- bootstrap partitions (worker creates future ones; these cover demo + current)
CREATE TABLE IF NOT EXISTS usage_events_default PARTITION OF usage_events DEFAULT;
CREATE INDEX IF NOT EXISTS idx_usage_identity_time ON usage_events(identity_id, event_time DESC);

-- ---------- findings ----------
CREATE TABLE IF NOT EXISTS findings (
    id                uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    detector          text NOT NULL,
    category          text NOT NULL,
    severity          text NOT NULL,
    confidence        int NOT NULL DEFAULT 50,
    identity_id       uuid REFERENCES identities(id) ON DELETE CASCADE,
    title             text NOT NULL,
    narrative         text NOT NULL,
    evidence          jsonb NOT NULL DEFAULT '{}',
    fingerprint       text NOT NULL,
    status            text NOT NULL DEFAULT 'open',
    risk_contribution int NOT NULL DEFAULT 0,
    assignee          text,
    notes             text,
    snapshot_id       uuid REFERENCES snapshots(id),
    first_seen_at     timestamptz NOT NULL DEFAULT now(),
    last_seen_at      timestamptz NOT NULL DEFAULT now(),
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_findings_open_fp ON findings(fingerprint) WHERE status = 'open';
CREATE INDEX IF NOT EXISTS idx_findings_triage ON findings(status, severity, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_identity ON findings(identity_id);

-- ---------- remediation ----------
CREATE TABLE IF NOT EXISTS remediation_actions (
    id          uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    finding_id  uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    action      text NOT NULL,
    status      text NOT NULL DEFAULT 'recommended',
    risk_before int NOT NULL DEFAULT 0,
    risk_after  int NOT NULL DEFAULT 0,
    risk_delta  int NOT NULL DEFAULT 0,
    assignee    text,
    notes       text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_remediation_finding ON remediation_actions(finding_id);

-- ---------- suppressions ----------
CREATE TABLE IF NOT EXISTS suppressions (
    id          uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    detector    text,
    identity_id uuid REFERENCES identities(id) ON DELETE CASCADE,
    reason      text NOT NULL,
    created_by  text NOT NULL,
    expires_at  timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- ---------- graph projection ----------
CREATE TABLE IF NOT EXISTS graph_nodes (
    id          uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    node_type   text NOT NULL,            -- identity|credential|secret|role|resource|workload|repo|account|idp
    entity_id   uuid,                     -- fk into the source table (logical)
    account_ref text,
    label       text NOT NULL,
    criticality text NOT NULL DEFAULT 'low',
    attributes  jsonb NOT NULL DEFAULT '{}',
    updated_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (node_type, entity_id)
);
CREATE INDEX IF NOT EXISTS idx_nodes_type ON graph_nodes(node_type);

CREATE TABLE IF NOT EXISTS graph_edges (
    id          uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    src_node_id uuid NOT NULL REFERENCES graph_nodes(id) ON DELETE CASCADE,
    dst_node_id uuid NOT NULL REFERENCES graph_nodes(id) ON DELETE CASCADE,
    edge_type   text NOT NULL,            -- owns|uses|assumes|impersonates|references|exposes|binds_to|runs_in|federated_from
    weight      double precision NOT NULL DEFAULT 1.0,
    observed    boolean NOT NULL DEFAULT false,
    attributes  jsonb NOT NULL DEFAULT '{}',
    updated_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (src_node_id, dst_node_id, edge_type)
);
CREATE INDEX IF NOT EXISTS idx_edges_src ON graph_edges(src_node_id);
CREATE INDEX IF NOT EXISTS idx_edges_dst ON graph_edges(dst_node_id);

-- ---------- audit ----------
CREATE TABLE IF NOT EXISTS audit_log (
    id          uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    actor       text NOT NULL,
    action      text NOT NULL,
    target_type text,
    target_id   text,
    before      jsonb,
    after       jsonb,
    at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log(at DESC);
