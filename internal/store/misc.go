package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nhiid/nhiid/internal/models"
)

// ---------- CredentialRepo --------------------------------------------------

type CredentialRepo struct{ pool *pgxpool.Pool }

func (r *CredentialRepo) Upsert(ctx context.Context, c models.Credential) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.pool.QueryRow(ctx, `
		INSERT INTO credentials
			(identity_id,cred_type,external_id,status,created_at_source,
			 last_used_at,last_used_region,last_used_service,expires_at,source,account_ref,collected_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (cred_type, external_id) DO UPDATE SET
			status=EXCLUDED.status, last_used_at=EXCLUDED.last_used_at,
			last_used_region=EXCLUDED.last_used_region, last_used_service=EXCLUDED.last_used_service,
			expires_at=EXCLUDED.expires_at, collected_at=EXCLUDED.collected_at, updated_at=now()
		RETURNING id`,
		c.IdentityID, c.CredType, c.ExternalID, c.Status, c.CreatedAtSource,
		c.LastUsedAt, c.LastUsedRegion, c.LastUsedService, c.ExpiresAt,
		c.Source, c.AccountRef, nil,
	).Scan(&id)
	return id, err
}

func (r *CredentialRepo) ForIdentity(ctx context.Context, identityID uuid.UUID) ([]models.Credential, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id,identity_id,cred_type,external_id,status,created_at_source,
		        last_used_at,last_used_region,last_used_service,expires_at,source,account_ref
		 FROM credentials WHERE identity_id=$1`, identityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Credential
	for rows.Next() {
		var c models.Credential
		if err := rows.Scan(&c.ID, &c.IdentityID, &c.CredType, &c.ExternalID, &c.Status,
			&c.CreatedAtSource, &c.LastUsedAt, &c.LastUsedRegion, &c.LastUsedService,
			&c.ExpiresAt, &c.Source, &c.AccountRef); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ---------- SecretRepo ------------------------------------------------------

type SecretRepo struct{ pool *pgxpool.Pool }

func (r *SecretRepo) Upsert(ctx context.Context, s models.Secret) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.pool.QueryRow(ctx, `
		INSERT INTO secrets
			(store,external_id,account_ref,name,last_rotated_at,rotation_enabled,
			 version_count,material_fingerprint,last_accessed_at,source,collected_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,now())
		ON CONFLICT (store, external_id) DO UPDATE SET
			last_rotated_at=EXCLUDED.last_rotated_at, rotation_enabled=EXCLUDED.rotation_enabled,
			version_count=EXCLUDED.version_count, last_accessed_at=EXCLUDED.last_accessed_at,
			updated_at=now()
		RETURNING id`,
		s.Store, s.ExternalID, s.AccountRef, s.Name, s.LastRotatedAt, s.RotationEnabled,
		s.VersionCount, s.MaterialFingerprint, s.LastAccessedAt, s.Source,
	).Scan(&id)
	return id, err
}

// ---------- RoleRepo --------------------------------------------------------

type RoleRepo struct{ pool *pgxpool.Pool }

func (r *RoleRepo) Upsert(ctx context.Context, role models.Role) (uuid.UUID, error) {
	pol, _ := json.Marshal(role.PolicyDocument)
	trust, _ := json.Marshal(role.TrustPolicy)
	if role.ID == uuid.Nil {
		role.ID = models.DeterministicID("role", role.ExternalID)
	}
	var id uuid.UUID
	err := r.pool.QueryRow(ctx, `
		INSERT INTO roles
			(id,provider,external_id,account_ref,name,policy_document,trust_policy,
			 privilege_level,is_assumable,permission_count,
			 wildcard_action_count,wildcard_resource_count,owner_identity_id,source,collected_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,now())
		ON CONFLICT (provider, external_id) DO UPDATE SET
			name=EXCLUDED.name, policy_document=EXCLUDED.policy_document,
			trust_policy=EXCLUDED.trust_policy, privilege_level=EXCLUDED.privilege_level,
			is_assumable=EXCLUDED.is_assumable, permission_count=EXCLUDED.permission_count,
			wildcard_action_count=EXCLUDED.wildcard_action_count,
			wildcard_resource_count=EXCLUDED.wildcard_resource_count,
			owner_identity_id=EXCLUDED.owner_identity_id, updated_at=now()
		RETURNING id`,
		role.ID, role.Provider, role.ExternalID, role.AccountRef, role.Name, pol, trust,
		role.PrivilegeLevel, role.IsAssumable, role.PermissionCount,
		role.WildcardActionCount, role.WildcardResourceCount, role.OwnerIdentityID, role.Source,
	).Scan(&id)
	return id, err
}

// ForIdentity returns the permission sets an identity holds: roles it owns directly
// (owner_identity_id) plus roles it can reach via assume-role trust edges.
func (r *RoleRepo) ForIdentity(ctx context.Context, identityID uuid.UUID) ([]models.Role, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT DISTINCT r.id,r.provider,r.external_id,r.account_ref,r.name,r.policy_document,
		       r.trust_policy,r.privilege_level,r.is_assumable,
		       r.permission_count,r.wildcard_action_count,r.wildcard_resource_count,r.source
		FROM roles r
		LEFT JOIN trust_edges te ON te.dst_role_id=r.id AND te.src_identity_id=$1
		WHERE r.owner_identity_id=$1 OR te.src_identity_id=$1`, identityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Role
	for rows.Next() {
		var ro models.Role
		var polRaw, trustRaw []byte
		if err := rows.Scan(&ro.ID, &ro.Provider, &ro.ExternalID, &ro.AccountRef, &ro.Name,
			&polRaw, &trustRaw, &ro.PrivilegeLevel, &ro.IsAssumable,
			&ro.PermissionCount, &ro.WildcardActionCount, &ro.WildcardResourceCount, &ro.Source); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(polRaw, &ro.PolicyDocument)
		_ = json.Unmarshal(trustRaw, &ro.TrustPolicy)
		out = append(out, ro)
	}
	return out, rows.Err()
}

// ---------- TrustEdgeRepo ---------------------------------------------------

type TrustEdgeRepo struct{ pool *pgxpool.Pool }

func (r *TrustEdgeRepo) Upsert(ctx context.Context, e models.TrustEdge) error {
	cond, _ := json.Marshal(e.Condition)
	_, err := r.pool.Exec(ctx, `
		INSERT INTO trust_edges
			(src_identity_id,src_role_id,dst_identity_id,dst_role_id,
			 edge_type,condition,observed,source,account_ref,collected_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,now())
		ON CONFLICT DO NOTHING`,
		e.SrcIdentityID, e.SrcRoleID, e.DstIdentityID, e.DstRoleID,
		e.EdgeType, cond, e.Observed, e.Source, e.AccountRef)
	return err
}

func (r *TrustEdgeRepo) ForIdentity(ctx context.Context, id uuid.UUID) ([]models.TrustEdge, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id,src_identity_id,src_role_id,dst_identity_id,dst_role_id,
		       edge_type,condition,observed,source,account_ref
		FROM trust_edges WHERE src_identity_id=$1 OR dst_identity_id=$1`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.TrustEdge
	for rows.Next() {
		var e models.TrustEdge
		var condRaw []byte
		if err := rows.Scan(&e.ID, &e.SrcIdentityID, &e.SrcRoleID, &e.DstIdentityID, &e.DstRoleID,
			&e.EdgeType, &condRaw, &e.Observed, &e.Source, &e.AccountRef); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(condRaw, &e.Condition)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---------- BindingRepo -----------------------------------------------------

type BindingRepo struct{ pool *pgxpool.Pool }

func (r *BindingRepo) Upsert(ctx context.Context, b models.ResourceBinding) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO resource_bindings
			(identity_id,role_id,resource_urn,resource_kind,resource_criticality,actions,effect,source,account_ref,collected_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,now())
		ON CONFLICT DO NOTHING`,
		b.IdentityID, b.RoleID, b.ResourceURN, b.ResourceKind, b.ResourceCriticality,
		b.Actions, b.Effect, b.Source, b.AccountRef)
	return err
}

func (r *BindingRepo) ForIdentity(ctx context.Context, id uuid.UUID) ([]models.ResourceBinding, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id,identity_id,role_id,resource_urn,resource_kind,resource_criticality,actions,effect,source,account_ref
		FROM resource_bindings WHERE identity_id=$1 OR role_id IN (
			SELECT dst_role_id FROM trust_edges WHERE src_identity_id=$1 AND dst_role_id IS NOT NULL)`,
		id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.ResourceBinding
	for rows.Next() {
		var b models.ResourceBinding
		if err := rows.Scan(&b.ID, &b.IdentityID, &b.RoleID, &b.ResourceURN, &b.ResourceKind,
			&b.ResourceCriticality, &b.Actions, &b.Effect, &b.Source, &b.AccountRef); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// ---------- WorkloadRepo ----------------------------------------------------

type WorkloadRepo struct{ pool *pgxpool.Pool }

func (r *WorkloadRepo) Upsert(ctx context.Context, w models.Workload) (uuid.UUID, error) {
	attrs, _ := json.Marshal(w.Attributes)
	var id uuid.UUID
	err := r.pool.QueryRow(ctx, `
		INSERT INTO workloads (kind,external_id,account_ref,name,environment,identity_id,attributes,source,collected_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now())
		ON CONFLICT (kind, external_id) DO UPDATE SET
			name=EXCLUDED.name, environment=EXCLUDED.environment,
			identity_id=EXCLUDED.identity_id, attributes=EXCLUDED.attributes, updated_at=now()
		RETURNING id`,
		w.Kind, w.ExternalID, w.AccountRef, w.Name, w.Environment,
		w.IdentityID, attrs, w.Source,
	).Scan(&id)
	return id, err
}

func (r *WorkloadRepo) ForIdentity(ctx context.Context, id uuid.UUID) ([]models.Workload, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id,kind,external_id,account_ref,name,environment,identity_id,source FROM workloads WHERE identity_id=$1`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Workload
	for rows.Next() {
		var w models.Workload
		if err := rows.Scan(&w.ID, &w.Kind, &w.ExternalID, &w.AccountRef, &w.Name, &w.Environment, &w.IdentityID, &w.Source); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// ---------- RepoRepo --------------------------------------------------------

type RepoRepo struct{ pool *pgxpool.Pool }

func (r *RepoRepo) Upsert(ctx context.Context, repo models.Repository) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.pool.QueryRow(ctx, `
		INSERT INTO repositories (provider,external_id,org,name,visibility,default_branch,source,collected_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,now())
		ON CONFLICT (provider, external_id) DO UPDATE SET
			visibility=EXCLUDED.visibility, default_branch=EXCLUDED.default_branch, updated_at=now()
		RETURNING id`,
		repo.Provider, repo.ExternalID, repo.Org, repo.Name,
		repo.Visibility, repo.DefaultBranch, repo.Source,
	).Scan(&id)
	return id, err
}

// ---------- ExposureRepo ----------------------------------------------------

type ExposureRepo struct{ pool *pgxpool.Pool }

func (r *ExposureRepo) Upsert(ctx context.Context, e models.Exposure) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO exposures
			(repository_id,identity_id,secret_id,path,commit_sha,line,pattern,fingerprint,verified,source,collected_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,now())
		ON CONFLICT DO NOTHING`,
		e.RepositoryID, e.IdentityID, e.SecretID,
		e.Path, e.CommitSHA, e.Line, e.Pattern, e.Fingerprint, e.Verified, e.Source)
	return err
}

func (r *ExposureRepo) ForIdentity(ctx context.Context, id uuid.UUID) ([]models.Exposure, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id,repository_id,identity_id,secret_id,path,commit_sha,line,pattern,fingerprint,verified,source
		FROM exposures WHERE identity_id=$1`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Exposure
	for rows.Next() {
		var ex models.Exposure
		if err := rows.Scan(&ex.ID, &ex.RepositoryID, &ex.IdentityID, &ex.SecretID,
			&ex.Path, &ex.CommitSHA, &ex.Line, &ex.Pattern, &ex.Fingerprint, &ex.Verified, &ex.Source); err != nil {
			return nil, err
		}
		out = append(out, ex)
	}
	return out, rows.Err()
}

// ---------- UsageRepo -------------------------------------------------------

type UsageRepo struct{ pool *pgxpool.Pool }

func (r *UsageRepo) Insert(ctx context.Context, e models.UsageEvent) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO usage_events
			(id,identity_id,event_time,event_name,event_source,src_ip,src_asn,
			 src_region,src_country,user_agent,runtime,mfa_used,error_code,source,account_ref)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		ON CONFLICT DO NOTHING`,
		e.ID, e.IdentityID, e.EventTime, e.EventName, e.EventSource,
		e.SrcIP, e.SrcASN, e.SrcRegion, e.SrcCountry, e.UserAgent,
		e.Runtime, e.MFAUsed, e.ErrorCode, e.Source, e.AccountRef)
	return err
}

func (r *UsageRepo) RecentForIdentity(ctx context.Context, id uuid.UUID, since time.Time) ([]models.UsageEvent, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id,identity_id,event_time,event_name,event_source,
		       COALESCE(src_ip::text,''),src_asn,src_region,src_country,
		       user_agent,runtime,mfa_used,error_code,source,account_ref
		FROM usage_events
		WHERE identity_id=$1 AND event_time >= $2
		ORDER BY event_time ASC`, id, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.UsageEvent
	for rows.Next() {
		var e models.UsageEvent
		if err := rows.Scan(&e.ID, &e.IdentityID, &e.EventTime, &e.EventName, &e.EventSource,
			&e.SrcIP, &e.SrcASN, &e.SrcRegion, &e.SrcCountry,
			&e.UserAgent, &e.Runtime, &e.MFAUsed, &e.ErrorCode, &e.Source, &e.AccountRef); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---------- RemediationRepo -------------------------------------------------

type RemediationRepo struct{ pool *pgxpool.Pool }

func (r *RemediationRepo) Insert(ctx context.Context, a models.RemediationAction) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.pool.QueryRow(ctx, `
		INSERT INTO remediation_actions (finding_id,action,status,risk_before,risk_after,risk_delta,assignee,notes)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
		a.FindingID, a.Action, a.Status, a.RiskBefore, a.RiskAfter, a.RiskDelta, a.Assignee, a.Notes,
	).Scan(&id)
	return id, err
}

// Upsert is idempotent per (finding_id, action): re-running detection refreshes the projected
// risk delta but never overwrites an operator's status/notes.
func (r *RemediationRepo) Upsert(ctx context.Context, a models.RemediationAction) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO remediation_actions (finding_id,action,status,risk_before,risk_after,risk_delta,notes)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (finding_id, action) DO UPDATE SET
			risk_before=EXCLUDED.risk_before, risk_after=EXCLUDED.risk_after,
			risk_delta=EXCLUDED.risk_delta, updated_at=now()`,
		a.FindingID, a.Action, a.Status, a.RiskBefore, a.RiskAfter, a.RiskDelta, a.Notes)
	return err
}

// ForIdentity returns all remediation actions across an identity's findings.
func (r *RemediationRepo) ForIdentity(ctx context.Context, identityID uuid.UUID) ([]models.RemediationAction, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT ra.id,ra.finding_id,ra.action,ra.status,ra.risk_before,ra.risk_after,ra.risk_delta,COALESCE(ra.assignee,''),COALESCE(ra.notes,'')
		FROM remediation_actions ra
		JOIN findings f ON f.id = ra.finding_id
		WHERE f.identity_id=$1
		ORDER BY ra.risk_delta DESC`, identityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.RemediationAction
	for rows.Next() {
		var a models.RemediationAction
		if err := rows.Scan(&a.ID, &a.FindingID, &a.Action, &a.Status,
			&a.RiskBefore, &a.RiskAfter, &a.RiskDelta, &a.Assignee, &a.Notes); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// RiskReductionDone sums the projected risk delta of completed remediations — the program's
// measurable risk reduction over time.
func (r *RemediationRepo) RiskReductionDone(ctx context.Context) (int, int, error) {
	var total, done int
	err := r.pool.QueryRow(ctx, `
		SELECT COALESCE(SUM(risk_delta) FILTER (WHERE status='done'),0),
		       COUNT(*) FILTER (WHERE status='done')
		FROM remediation_actions`).Scan(&total, &done)
	return total, done, err
}

// UpdateStatus changes an action's workflow status (and optional notes), preserving the
// projected risk fields that were computed when the recommendation was generated.
func (r *RemediationRepo) UpdateStatus(ctx context.Context, id uuid.UUID, status, notes string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE remediation_actions
		SET status=$1, notes=COALESCE(NULLIF($2,''), notes), updated_at=now()
		WHERE id=$3`, status, notes, id)
	return err
}

func (r *RemediationRepo) ForFinding(ctx context.Context, findingID uuid.UUID) ([]models.RemediationAction, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id,finding_id,action,status,risk_before,risk_after,risk_delta,COALESCE(assignee,''),COALESCE(notes,'')
		FROM remediation_actions WHERE finding_id=$1`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.RemediationAction
	for rows.Next() {
		var a models.RemediationAction
		if err := rows.Scan(&a.ID, &a.FindingID, &a.Action, &a.Status,
			&a.RiskBefore, &a.RiskAfter, &a.RiskDelta, &a.Assignee, &a.Notes); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ---------- GraphRepo -------------------------------------------------------

type GraphRepo struct{ pool *pgxpool.Pool }

func (r *GraphRepo) UpsertNode(ctx context.Context, n models.GraphNode) (uuid.UUID, error) {
	attrs, _ := json.Marshal(n.Attributes)
	var id uuid.UUID
	err := r.pool.QueryRow(ctx, `
		INSERT INTO graph_nodes (node_type,entity_id,account_ref,label,criticality,attributes,updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,now())
		ON CONFLICT (node_type, entity_id) DO UPDATE SET
			label=EXCLUDED.label, criticality=EXCLUDED.criticality,
			attributes=EXCLUDED.attributes, updated_at=now()
		RETURNING id`,
		n.NodeType, n.EntityID, n.AccountRef, n.Label, n.Criticality, attrs,
	).Scan(&id)
	return id, err
}

func (r *GraphRepo) UpsertEdge(ctx context.Context, e models.GraphEdge) error {
	attrs, _ := json.Marshal(e.Attributes)
	_, err := r.pool.Exec(ctx, `
		INSERT INTO graph_edges (src_node_id,dst_node_id,edge_type,weight,observed,attributes,updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,now())
		ON CONFLICT (src_node_id, dst_node_id, edge_type) DO UPDATE SET
			weight=EXCLUDED.weight, observed=EXCLUDED.observed,
			attributes=EXCLUDED.attributes, updated_at=now()`,
		e.SrcNodeID, e.DstNodeID, e.EdgeType, e.Weight, e.Observed, attrs)
	return err
}

// LoadGraph loads the full graph into memory for a given account scope (bounded working set).
func (r *GraphRepo) LoadGraph(ctx context.Context, accountRef string) ([]models.GraphNode, []models.GraphEdge, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id,node_type,entity_id,account_ref,label,criticality,attributes
		FROM graph_nodes WHERE account_ref=$1 OR account_ref=''`, accountRef)
	if err != nil {
		return nil, nil, fmt.Errorf("load nodes: %w", err)
	}
	defer rows.Close()
	var nodes []models.GraphNode
	for rows.Next() {
		var n models.GraphNode
		var attrsRaw []byte
		if err := rows.Scan(&n.ID, &n.NodeType, &n.EntityID, &n.AccountRef, &n.Label, &n.Criticality, &attrsRaw); err != nil {
			return nil, nil, err
		}
		_ = json.Unmarshal(attrsRaw, &n.Attributes)
		nodes = append(nodes, n)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	eRows, err := r.pool.Query(ctx, `
		SELECT ge.id,ge.src_node_id,ge.dst_node_id,ge.edge_type,ge.weight,ge.observed,ge.attributes
		FROM graph_edges ge
		JOIN graph_nodes gn ON gn.id=ge.src_node_id
		WHERE gn.account_ref=$1 OR gn.account_ref=''`, accountRef)
	if err != nil {
		return nil, nil, fmt.Errorf("load edges: %w", err)
	}
	defer eRows.Close()
	var edges []models.GraphEdge
	for eRows.Next() {
		var e models.GraphEdge
		var attrsRaw []byte
		if err := eRows.Scan(&e.ID, &e.SrcNodeID, &e.DstNodeID, &e.EdgeType, &e.Weight, &e.Observed, &attrsRaw); err != nil {
			return nil, nil, err
		}
		_ = json.Unmarshal(attrsRaw, &e.Attributes)
		edges = append(edges, e)
	}
	return nodes, edges, eRows.Err()
}

// ---------- CollectorRepo ---------------------------------------------------

type CollectorRepo struct{ pool *pgxpool.Pool }

func (r *CollectorRepo) StartRun(ctx context.Context, collector, accountRef string) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.pool.QueryRow(ctx, `
		INSERT INTO collector_runs (collector,account_ref,status,started_at)
		VALUES ($1,$2,'running',now()) RETURNING id`, collector, accountRef).Scan(&id)
	return id, err
}

func (r *CollectorRepo) FinishRun(ctx context.Context, id uuid.UUID, status string, in, upserted, errs int) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE collector_runs SET status=$1,records_in=$2,records_upserted=$3,errors=$4,finished_at=now()
		WHERE id=$5`, status, in, upserted, errs, id)
	return err
}

func (r *CollectorRepo) GetCursor(ctx context.Context, collector, accountRef string) (map[string]any, error) {
	var raw []byte
	err := r.pool.QueryRow(ctx,
		`SELECT cursor FROM collector_state WHERE collector=$1 AND account_ref=$2`,
		collector, accountRef).Scan(&raw)
	if err != nil {
		return map[string]any{}, nil // no cursor yet — full scan
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return m, nil
}

func (r *CollectorRepo) SetCursor(ctx context.Context, collector, accountRef string, cursor map[string]any) error {
	b, _ := json.Marshal(cursor)
	_, err := r.pool.Exec(ctx, `
		INSERT INTO collector_state (collector,account_ref,cursor,updated_at)
		VALUES ($1,$2,$3,now())
		ON CONFLICT (collector,account_ref) DO UPDATE SET cursor=$3, updated_at=now()`,
		collector, accountRef, b)
	return err
}
