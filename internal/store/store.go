// Package store provides pgx-based repositories for every NHIID entity.
// All writes use ON CONFLICT ... DO UPDATE (idempotent upserts keyed by external_id).
// Queries are plain SQL; no ORM or codegen dependency.
package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store aggregates all repository handles and exposes a transaction helper.
type Store struct {
	pool *pgxpool.Pool

	Identities   *IdentityRepo
	Credentials  *CredentialRepo
	Secrets      *SecretRepo
	Roles        *RoleRepo
	TrustEdges   *TrustEdgeRepo
	Bindings     *BindingRepo
	Workloads    *WorkloadRepo
	Repos        *RepoRepo
	Exposures    *ExposureRepo
	Usage        *UsageRepo
	Findings     *FindingRepo
	Remediation  *RemediationRepo
	Graph        *GraphRepo
	Collectors   *CollectorRepo
	Suppressions *SuppressionRepo
	Audit        *AuditRepo
	Snapshots    *SnapshotRepo
	Config       *ConfigRepo
}

// New opens a pgxpool and wires all repositories.
func New(ctx context.Context, dsn string, maxConns, minConns int32) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	cfg.MaxConns = maxConns
	cfg.MinConns = minConns
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("open pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}
	s := &Store{pool: pool}
	s.Identities = &IdentityRepo{pool}
	s.Credentials = &CredentialRepo{pool}
	s.Secrets = &SecretRepo{pool}
	s.Roles = &RoleRepo{pool}
	s.TrustEdges = &TrustEdgeRepo{pool}
	s.Bindings = &BindingRepo{pool}
	s.Workloads = &WorkloadRepo{pool}
	s.Repos = &RepoRepo{pool}
	s.Exposures = &ExposureRepo{pool}
	s.Usage = &UsageRepo{pool}
	s.Findings = &FindingRepo{pool}
	s.Remediation = &RemediationRepo{pool}
	s.Graph = &GraphRepo{pool}
	s.Collectors = &CollectorRepo{pool}
	s.Suppressions = &SuppressionRepo{pool}
	s.Audit = &AuditRepo{pool}
	s.Snapshots = &SnapshotRepo{pool}
	s.Config = &ConfigRepo{pool}
	return s, nil
}

func (s *Store) Close() { s.pool.Close() }

// Tx runs fn inside a serializable transaction; rolls back on error.
func (s *Store) Tx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}

// Pool exposes the raw pool for rare cases (e.g. COPY FROM for bulk event inserts).
func (s *Store) Pool() *pgxpool.Pool { return s.pool }
