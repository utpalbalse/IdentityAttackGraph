package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nhiid/nhiid/internal/models"
)

// ---------- metrics queries ----------

// Count returns the total number of identities (gauge source).
func (r *IdentityRepo) Count(ctx context.Context) (int, error) {
	var n int
	err := r.pool.QueryRow(ctx, `SELECT count(*) FROM identities`).Scan(&n)
	return n, err
}

// CountOpenBySeverity returns open-finding counts keyed by severity.
func (r *FindingRepo) CountOpenBySeverity(ctx context.Context) (map[string]int, error) {
	rows, err := r.pool.Query(ctx, `SELECT severity, count(*) FROM findings WHERE status='open' GROUP BY severity`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			return nil, err
		}
		out[sev] = n
	}
	return out, rows.Err()
}

// NewestEventBySource returns the most recent usage-event time per source (for ingestion lag).
func (r *UsageRepo) NewestEventBySource(ctx context.Context) (map[string]time.Time, error) {
	rows, err := r.pool.Query(ctx, `SELECT source, max(event_time) FROM usage_events GROUP BY source`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var src string
		var t time.Time
		if err := rows.Scan(&src, &t); err != nil {
			return nil, err
		}
		out[src] = t
	}
	return out, rows.Err()
}

// This file holds the read/list and admin repositories backing the full REST surface:
// inventory lists, collector runs, suppressions, audit log, snapshots, and config settings.

// ---------- inventory list reads ----------

func (r *CredentialRepo) List(ctx context.Context, limit int) ([]models.Credential, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id,identity_id,cred_type,external_id,status,created_at_source,
		       last_used_at,last_used_region,last_used_service,expires_at,source,account_ref
		FROM credentials ORDER BY created_at DESC LIMIT $1`, limit)
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

func (r *SecretRepo) List(ctx context.Context, limit int) ([]models.Secret, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id,store,external_id,account_ref,name,last_rotated_at,rotation_enabled,
		       version_count,referenced_by_count,last_accessed_at,source
		FROM secrets ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Secret
	for rows.Next() {
		var s models.Secret
		if err := rows.Scan(&s.ID, &s.Store, &s.ExternalID, &s.AccountRef, &s.Name,
			&s.LastRotatedAt, &s.RotationEnabled, &s.VersionCount, &s.ReferencedByCount,
			&s.LastAccessedAt, &s.Source); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *WorkloadRepo) List(ctx context.Context, limit int) ([]models.Workload, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id,kind,external_id,account_ref,name,environment,identity_id,source
		FROM workloads ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Workload
	for rows.Next() {
		var w models.Workload
		if err := rows.Scan(&w.ID, &w.Kind, &w.ExternalID, &w.AccountRef, &w.Name,
			&w.Environment, &w.IdentityID, &w.Source); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func (r *RepoRepo) List(ctx context.Context, limit int) ([]models.Repository, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id,provider,external_id,org,name,visibility,default_branch,last_scanned_at,source
		FROM repositories ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Repository
	for rows.Next() {
		var repo models.Repository
		if err := rows.Scan(&repo.ID, &repo.Provider, &repo.ExternalID, &repo.Org, &repo.Name,
			&repo.Visibility, &repo.DefaultBranch, &repo.LastScannedAt, &repo.Source); err != nil {
			return nil, err
		}
		out = append(out, repo)
	}
	return out, rows.Err()
}

// ListRuns returns recent collector runs (provenance + ingestion status).
func (r *CollectorRepo) ListRuns(ctx context.Context, limit int) ([]models.CollectorRun, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id,collector,account_ref,records_in,records_upserted,errors,status,started_at,finished_at
		FROM collector_runs ORDER BY started_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.CollectorRun
	for rows.Next() {
		var cr models.CollectorRun
		if err := rows.Scan(&cr.ID, &cr.Collector, &cr.AccountRef, &cr.RecordsIn, &cr.RecordsUpserted,
			&cr.Errors, &cr.Status, &cr.StartedAt, &cr.FinishedAt); err != nil {
			return nil, err
		}
		out = append(out, cr)
	}
	return out, rows.Err()
}

// ---------- suppressions ----------

type SuppressionRepo struct{ pool *pgxpool.Pool }

func (r *SuppressionRepo) Create(ctx context.Context, s models.Suppression) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.pool.QueryRow(ctx, `
		INSERT INTO suppressions (detector,identity_id,reason,created_by,expires_at)
		VALUES (NULLIF($1,''),$2,$3,$4,$5) RETURNING id`,
		s.Detector, s.IdentityID, s.Reason, s.CreatedBy, s.ExpiresAt).Scan(&id)
	return id, err
}

// ListActive returns suppressions that have not expired (used by the detection worker).
func (r *SuppressionRepo) ListActive(ctx context.Context) ([]models.Suppression, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id,COALESCE(detector,''),identity_id,reason,created_by,expires_at,created_at
		FROM suppressions WHERE expires_at IS NULL OR expires_at > now()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Suppression
	for rows.Next() {
		var s models.Suppression
		if err := rows.Scan(&s.ID, &s.Detector, &s.IdentityID, &s.Reason, &s.CreatedBy, &s.ExpiresAt, &s.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *SuppressionRepo) List(ctx context.Context, limit int) ([]models.Suppression, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id,COALESCE(detector,''),identity_id,reason,created_by,expires_at,created_at
		FROM suppressions ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Suppression
	for rows.Next() {
		var s models.Suppression
		if err := rows.Scan(&s.ID, &s.Detector, &s.IdentityID, &s.Reason, &s.CreatedBy, &s.ExpiresAt, &s.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ---------- audit log ----------

type AuditRepo struct{ pool *pgxpool.Pool }

// Write records a mutation. Best-effort: callers log but don't fail the request on audit error.
func (r *AuditRepo) Write(ctx context.Context, e models.AuditEntry) error {
	before, _ := json.Marshal(e.Before)
	after, _ := json.Marshal(e.After)
	_, err := r.pool.Exec(ctx, `
		INSERT INTO audit_log (actor,action,target_type,target_id,before,after)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		e.Actor, e.Action, e.TargetType, e.TargetID, before, after)
	return err
}

func (r *AuditRepo) List(ctx context.Context, limit int) ([]models.AuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id,actor,action,COALESCE(target_type,''),COALESCE(target_id,''),before,after,at
		FROM audit_log ORDER BY at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.AuditEntry
	for rows.Next() {
		var e models.AuditEntry
		var before, after []byte
		if err := rows.Scan(&e.ID, &e.Actor, &e.Action, &e.TargetType, &e.TargetID, &before, &after, &e.At); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(before, &e.Before)
		_ = json.Unmarshal(after, &e.After)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---------- snapshots ----------

type SnapshotRepo struct{ pool *pgxpool.Pool }

// Create records a point-in-time snapshot, computing current entity counts itself.
func (r *SnapshotRepo) Create(ctx context.Context, scope map[string]any) (uuid.UUID, error) {
	counts := map[string]any{}
	for _, t := range []string{"identities", "credentials", "secrets", "roles", "trust_edges", "resource_bindings", "findings"} {
		var n int
		if err := r.pool.QueryRow(ctx, "SELECT count(*) FROM "+t).Scan(&n); err == nil {
			counts[t] = n
		}
	}
	sb, _ := json.Marshal(scope)
	cb, _ := json.Marshal(counts)
	var id uuid.UUID
	err := r.pool.QueryRow(ctx, `
		INSERT INTO snapshots (scope, entity_counts, finished_at) VALUES ($1,$2,now()) RETURNING id`,
		sb, cb).Scan(&id)
	return id, err
}

// Latest returns the id of the most recent snapshot, or nil if none exist (for finding provenance).
func (r *SnapshotRepo) Latest(ctx context.Context) (*uuid.UUID, error) {
	var id uuid.UUID
	err := r.pool.QueryRow(ctx, `SELECT id FROM snapshots ORDER BY started_at DESC LIMIT 1`).Scan(&id)
	if err != nil {
		return nil, nil // none yet
	}
	return &id, nil
}

func (r *SnapshotRepo) List(ctx context.Context, limit int) ([]models.Snapshot, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id,started_at,finished_at,scope,entity_counts
		FROM snapshots ORDER BY started_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Snapshot
	for rows.Next() {
		var s models.Snapshot
		var scope, counts []byte
		if err := rows.Scan(&s.ID, &s.StartedAt, &s.FinishedAt, &scope, &counts); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(scope, &s.Scope)
		_ = json.Unmarshal(counts, &s.EntityCounts)
		out = append(out, s)
	}
	return out, rows.Err()
}

// ---------- config settings ----------

type ConfigRepo struct{ pool *pgxpool.Pool }

// Get returns the raw JSON value for a key, or (nil,false) if unset.
func (r *ConfigRepo) Get(ctx context.Context, key string) ([]byte, bool, error) {
	var raw []byte
	err := r.pool.QueryRow(ctx, `SELECT value FROM config_settings WHERE key=$1`, key).Scan(&raw)
	if err != nil {
		return nil, false, nil // treat missing/any error as "unset"; caller falls back to file
	}
	return raw, true, nil
}

func (r *ConfigRepo) Set(ctx context.Context, key string, value []byte, updatedBy string) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO config_settings (key,value,updated_by,updated_at) VALUES ($1,$2,$3,now())
		ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_by=EXCLUDED.updated_by, updated_at=now()`,
		key, value, updatedBy)
	return err
}
