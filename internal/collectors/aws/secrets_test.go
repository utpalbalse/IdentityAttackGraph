package aws

import (
	"testing"
	"time"

	"github.com/nhiid/nhiid/internal/models"
)

func TestNormalizeSecrets(t *testing.T) {
	accessed := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	rotated := time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC)
	in := []smSecret{
		{ARN: "arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/db-aB12", Name: "prod/db",
			RotationOn: true, LastAccessed: &accessed, LastRotated: &rotated, VersionCount: 3},
		{ARN: "arn:aws:secretsmanager:us-east-1:111122223333:secret:legacy-Cd34", Name: "legacy"},
	}
	out := normalizeSecrets(in, "aws:111122223333")
	if len(out) != 2 {
		t.Fatalf("secrets = %d, want 2", len(out))
	}

	s0 := out[0]
	if s0.Store != "aws_secretsmanager" || s0.ExternalID != in[0].ARN || s0.Name != "prod/db" {
		t.Errorf("s0 = %+v", s0)
	}
	if !s0.RotationEnabled || s0.VersionCount != 3 || s0.LastAccessedAt == nil || s0.LastRotatedAt == nil {
		t.Errorf("s0 metadata not mapped: %+v", s0)
	}
	if s0.AccountRef != "aws:111122223333" || s0.Source != "aws" {
		t.Errorf("s0 provenance = %s/%s", s0.AccountRef, s0.Source)
	}
	// Deterministic id keyed on the ARN.
	if s0.ID != models.DeterministicID("secret", in[0].ARN) {
		t.Errorf("s0.ID not deterministic on ARN")
	}

	// A never-accessed secret carries a nil LastAccessedAt so unused_secret can flag it.
	if out[1].LastAccessedAt != nil {
		t.Errorf("legacy secret should have nil LastAccessedAt, got %v", out[1].LastAccessedAt)
	}
}
