package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nhiid/nhiid/internal/models"
)

type IdentityRepo struct{ pool *pgxpool.Pool }

// Upsert inserts or updates an identity keyed by (provider, external_id). Idempotent.
// If id.ID is set (collectors use a deterministic UUID derived from the ARN/email), that id is
// used on insert so cross-referencing rows (credentials, trust edges) can be built ahead of time;
// the id is never changed on conflict, preserving referential stability across re-runs.
func (r *IdentityRepo) Upsert(ctx context.Context, id models.Identity) (uuid.UUID, error) {
	attrs, _ := json.Marshal(id.Attributes)
	aiMeta, _ := json.Marshal(id.AIAgentMeta)
	if id.ID == uuid.Nil {
		id.ID = models.DeterministicID(string(id.Kind), id.Prov.ExternalID)
	}
	var uid uuid.UUID
	err := r.pool.QueryRow(ctx, `
		INSERT INTO identities
			(id, kind, name, arn_or_email, provider, account_ref, state, owner_id,
			 created_at_source, last_seen_at, last_rotated_at,
			 is_ai_agent, ai_agent_meta, attributes,
			 source, external_id, collector_run_id, collected_at, raw_hash,
			 updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,now())
		ON CONFLICT (provider, external_id) DO UPDATE SET
			name=EXCLUDED.name, arn_or_email=EXCLUDED.arn_or_email,
			state=EXCLUDED.state, owner_id=EXCLUDED.owner_id,
			last_seen_at=EXCLUDED.last_seen_at, last_rotated_at=EXCLUDED.last_rotated_at,
			is_ai_agent=EXCLUDED.is_ai_agent, ai_agent_meta=EXCLUDED.ai_agent_meta,
			attributes=EXCLUDED.attributes, collector_run_id=EXCLUDED.collector_run_id,
			collected_at=EXCLUDED.collected_at, raw_hash=EXCLUDED.raw_hash,
			updated_at=now()
		RETURNING id`,
		id.ID, id.Kind, id.Name, id.ARNOrEmail, id.Provider, id.Prov.AccountRef, id.State, id.OwnerID,
		id.CreatedAtSource, id.LastSeenAt, id.LastRotatedAt,
		id.IsAIAgent, aiMeta, attrs,
		id.Prov.Source, id.Prov.ExternalID, id.Prov.CollectorRunID, id.Prov.CollectedAt, id.Prov.RawHash,
	).Scan(&uid)
	if err != nil {
		return uuid.Nil, fmt.Errorf("upsert identity %s: %w", id.Prov.ExternalID, err)
	}
	return uid, nil
}

// UpdateRiskScore persists the computed score back to the identities row.
func (r *IdentityRepo) UpdateRiskScore(ctx context.Context, id uuid.UUID, score int, breakdown map[string]any) error {
	b, _ := json.Marshal(breakdown)
	_, err := r.pool.Exec(ctx,
		`UPDATE identities SET risk_score=$1, risk_breakdown=$2, updated_at=now() WHERE id=$3`,
		score, b, id)
	return err
}

// IdentityFilter carries search/filter parameters for list queries.
type IdentityFilter struct {
	Provider   string
	AccountRef string
	Kind       string
	State      string
	MinRisk    int
	HasFinding bool
	IsAIAgent  *bool
	Q          string // trgm search
	Cursor     uuid.UUID
	Limit      int
}

// List returns identities matching the filter, ordered by risk_score desc.
func (r *IdentityRepo) List(ctx context.Context, f IdentityFilter) ([]models.Identity, error) {
	if f.Limit == 0 || f.Limit > 200 {
		f.Limit = 50
	}
	var where []string
	var args []any
	n := func(v any) string { args = append(args, v); return fmt.Sprintf("$%d", len(args)) }

	if f.Provider != "" {
		where = append(where, "provider="+n(f.Provider))
	}
	if f.AccountRef != "" {
		where = append(where, "account_ref="+n(f.AccountRef))
	}
	if f.Kind != "" {
		where = append(where, "kind="+n(f.Kind))
	}
	if f.State != "" {
		where = append(where, "state="+n(f.State))
	}
	if f.MinRisk > 0 {
		where = append(where, "risk_score>="+n(f.MinRisk))
	}
	if f.IsAIAgent != nil {
		where = append(where, "is_ai_agent="+n(*f.IsAIAgent))
	}
	if f.Q != "" {
		where = append(where, "(name % "+n(f.Q)+" OR arn_or_email % "+n(f.Q)+")")
	}
	if f.Cursor != uuid.Nil {
		where = append(where, "risk_score < (SELECT risk_score FROM identities WHERE id="+n(f.Cursor)+")")
	}

	clause := ""
	if len(where) > 0 {
		clause = " WHERE " + strings.Join(where, " AND ")
	}
	q := "SELECT id,kind,name,arn_or_email,provider,account_ref,state,risk_score,is_ai_agent,last_seen_at,source,external_id,collected_at,attributes,ai_agent_meta FROM identities" +
		clause + " ORDER BY risk_score DESC LIMIT " + fmt.Sprintf("%d", f.Limit)

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Identity
	for rows.Next() {
		var id models.Identity
		var attrsRaw, aiMetaRaw []byte
		if err := rows.Scan(&id.ID, &id.Kind, &id.Name, &id.ARNOrEmail, &id.Provider,
			&id.Prov.AccountRef, &id.State, &id.RiskScore, &id.IsAIAgent,
			&id.LastSeenAt, &id.Prov.Source, &id.Prov.ExternalID, &id.Prov.CollectedAt,
			&attrsRaw, &aiMetaRaw); err != nil {
			return nil, err
		}
		// Attributes + AI-agent metadata drive detectors (ai_agent_overscoped) and suppressions
		// (break_glass), so the list path must hydrate them, not just the single-Get path.
		_ = json.Unmarshal(attrsRaw, &id.Attributes)
		_ = json.Unmarshal(aiMetaRaw, &id.AIAgentMeta)
		out = append(out, id)
	}
	return out, rows.Err()
}

// Get returns a single identity by UUID.
func (r *IdentityRepo) Get(ctx context.Context, id uuid.UUID) (*models.Identity, error) {
	var ident models.Identity
	var aiMetaRaw, attrsRaw, riskRaw []byte
	err := r.pool.QueryRow(ctx, `
		SELECT id,kind,name,arn_or_email,provider,account_ref,state,owner_id,
		       created_at_source,last_seen_at,last_rotated_at,
		       is_ai_agent,ai_agent_meta,risk_score,risk_breakdown,attributes,
		       source,external_id,collected_at,created_at,updated_at
		FROM identities WHERE id=$1`, id,
	).Scan(
		&ident.ID, &ident.Kind, &ident.Name, &ident.ARNOrEmail, &ident.Provider,
		&ident.Prov.AccountRef, &ident.State, &ident.OwnerID,
		&ident.CreatedAtSource, &ident.LastSeenAt, &ident.LastRotatedAt,
		&ident.IsAIAgent, &aiMetaRaw, &ident.RiskScore, &riskRaw, &attrsRaw,
		&ident.Prov.Source, &ident.Prov.ExternalID, &ident.Prov.CollectedAt,
		&ident.CreatedAt, &ident.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(aiMetaRaw, &ident.AIAgentMeta)
	_ = json.Unmarshal(riskRaw, &ident.RiskBreakdown)
	_ = json.Unmarshal(attrsRaw, &ident.Attributes)
	return &ident, nil
}

// TriageQueue returns identities ordered by urgency (highest risk + open findings first).
func (r *IdentityRepo) TriageQueue(ctx context.Context, limit int) ([]models.Identity, error) {
	if limit == 0 {
		limit = 25
	}
	rows, err := r.pool.Query(ctx, `
		SELECT i.id,i.kind,i.name,i.arn_or_email,i.provider,i.account_ref,i.state,
		       i.risk_score,i.is_ai_agent,i.last_seen_at,i.source,i.external_id
		FROM identities i
		WHERE EXISTS (SELECT 1 FROM findings f WHERE f.identity_id=i.id AND f.status='open')
		ORDER BY i.risk_score DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Identity
	for rows.Next() {
		var id models.Identity
		if err := rows.Scan(&id.ID, &id.Kind, &id.Name, &id.ARNOrEmail, &id.Provider,
			&id.Prov.AccountRef, &id.State, &id.RiskScore, &id.IsAIAgent,
			&id.LastSeenAt, &id.Prov.Source, &id.Prov.ExternalID); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// PeerPermissionP90 returns the 90th percentile permission count for a cohort.
func (r *IdentityRepo) PeerPermissionP90(ctx context.Context, accountRef string, kind models.IdentityKind) (int, error) {
	var p90 int
	err := r.pool.QueryRow(ctx, `
		SELECT COALESCE(percentile_cont(0.9) WITHIN GROUP (ORDER BY r.permission_count), 0)::int
		FROM identities i
		JOIN roles r ON r.account_ref = i.account_ref
		WHERE i.account_ref=$1 AND i.kind=$2`, accountRef, kind,
	).Scan(&p90)
	return p90, err
}

// UpdateLastSeen sets last_seen_at to the given time for an identity.
func (r *IdentityRepo) UpdateLastSeen(ctx context.Context, id uuid.UUID, t time.Time) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE identities SET last_seen_at=$1, updated_at=now() WHERE id=$2`, t, id)
	return err
}
