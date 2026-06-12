package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nhiid/nhiid/internal/models"
)

type FindingRepo struct{ pool *pgxpool.Pool }

// Upsert inserts or touches an existing open finding by fingerprint (dedupe).
func (r *FindingRepo) Upsert(ctx context.Context, f models.Finding) (uuid.UUID, error) {
	ev, _ := json.Marshal(f.Evidence)
	var id uuid.UUID
	err := r.pool.QueryRow(ctx, `
		INSERT INTO findings
			(detector,category,severity,confidence,identity_id,title,narrative,evidence,
			 fingerprint,status,risk_contribution,first_seen_at,last_seen_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'open',$10,now(),now())
		ON CONFLICT (fingerprint) WHERE status='open' DO UPDATE SET
			narrative=EXCLUDED.narrative, evidence=EXCLUDED.evidence,
			last_seen_at=now(), confidence=EXCLUDED.confidence, updated_at=now()
		RETURNING id`,
		f.Detector, f.Category, f.Severity, f.Confidence, f.IdentityID,
		f.Title, f.Narrative, ev, f.Fingerprint, f.RiskContribution,
	).Scan(&id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("upsert finding %s: %w", f.Detector, err)
	}
	return id, nil
}

type FindingFilter struct {
	Detector   string
	Severity   string
	Status     string
	IdentityID *uuid.UUID
	Limit      int
}

func (r *FindingRepo) List(ctx context.Context, f FindingFilter) ([]models.Finding, error) {
	if f.Limit == 0 || f.Limit > 500 {
		f.Limit = 100
	}
	var where []string
	var args []any
	n := func(v any) string { args = append(args, v); return fmt.Sprintf("$%d", len(args)) }

	if f.Status != "" {
		where = append(where, "status="+n(f.Status))
	} else {
		where = append(where, "status='open'")
	}
	if f.Detector != "" {
		where = append(where, "detector="+n(f.Detector))
	}
	if f.Severity != "" {
		where = append(where, "severity="+n(f.Severity))
	}
	if f.IdentityID != nil {
		where = append(where, "identity_id="+n(*f.IdentityID))
	}

	clause := ""
	if len(where) > 0 {
		clause = " WHERE " + strings.Join(where, " AND ")
	}
	q := "SELECT id,detector,category,severity,confidence,identity_id,title,narrative,evidence,fingerprint,status,risk_contribution,first_seen_at,last_seen_at FROM findings" +
		clause + " ORDER BY last_seen_at DESC LIMIT " + fmt.Sprintf("%d", f.Limit)

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Finding
	for rows.Next() {
		var fd models.Finding
		var evRaw []byte
		if err := rows.Scan(&fd.ID, &fd.Detector, &fd.Category, &fd.Severity, &fd.Confidence,
			&fd.IdentityID, &fd.Title, &fd.Narrative, &evRaw, &fd.Fingerprint,
			&fd.Status, &fd.RiskContribution, &fd.FirstSeenAt, &fd.LastSeenAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(evRaw, &fd.Evidence)
		out = append(out, fd)
	}
	return out, rows.Err()
}

func (r *FindingRepo) Get(ctx context.Context, id uuid.UUID) (*models.Finding, error) {
	var fd models.Finding
	var evRaw []byte
	err := r.pool.QueryRow(ctx, `
		SELECT id,detector,category,severity,confidence,identity_id,title,narrative,
		       evidence,fingerprint,status,risk_contribution,assignee,notes,first_seen_at,last_seen_at
		FROM findings WHERE id=$1`, id,
	).Scan(&fd.ID, &fd.Detector, &fd.Category, &fd.Severity, &fd.Confidence,
		&fd.IdentityID, &fd.Title, &fd.Narrative, &evRaw, &fd.Fingerprint,
		&fd.Status, &fd.RiskContribution, &fd.Assignee, &fd.Notes,
		&fd.FirstSeenAt, &fd.LastSeenAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(evRaw, &fd.Evidence)
	return &fd, nil
}

func (r *FindingRepo) UpdateStatus(ctx context.Context, id uuid.UUID, status, assignee, notes string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE findings SET status=$1, assignee=$2, notes=$3, updated_at=now() WHERE id=$4`,
		status, assignee, notes, id)
	return err
}
