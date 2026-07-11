package aws

import (
	"context"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/nhiid/nhiid/internal/models"
)

// smSecret is the SDK-agnostic view of a Secrets Manager secret, so normalization is unit-testable
// without the AWS SDK (mirrors the policy analysis in policy.go).
type smSecret struct {
	ARN          string
	Name         string
	RotationOn   bool
	LastAccessed *time.Time
	LastRotated  *time.Time
	VersionCount int
}

// collectSecrets lists AWS Secrets Manager secrets and normalizes them into inventory records. The
// value is never fetched (GetSecretValue is not called) — only metadata. AWS does not expose a
// reference count, so `unused_secret` keys off LastAccessedDate (last retrieval of the value).
func (c *clients) collectSecrets(ctx context.Context, accountRef string) ([]models.Secret, error) {
	p := secretsmanager.NewListSecretsPaginator(c.sm, &secretsmanager.ListSecretsInput{})
	var raw []smSecret
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, s := range page.SecretList {
			raw = append(raw, fromSDKSecret(s))
		}
	}
	return normalizeSecrets(raw, accountRef), nil
}

func fromSDKSecret(s smtypes.SecretListEntry) smSecret {
	out := smSecret{
		ARN:          awssdk.ToString(s.ARN),
		Name:         awssdk.ToString(s.Name),
		RotationOn:   s.RotationEnabled != nil && *s.RotationEnabled,
		VersionCount: len(s.SecretVersionsToStages),
		LastAccessed: s.LastAccessedDate,
		LastRotated:  s.LastRotatedDate,
	}
	return out
}

// normalizeSecrets maps SDK-agnostic entries into models.Secret. Pure — unit-tested.
func normalizeSecrets(entries []smSecret, accountRef string) []models.Secret {
	out := make([]models.Secret, 0, len(entries))
	for _, e := range entries {
		out = append(out, models.Secret{
			ID:              models.DeterministicID("secret", e.ARN),
			Store:           "aws_secretsmanager",
			ExternalID:      e.ARN,
			AccountRef:      accountRef,
			Name:            e.Name,
			RotationEnabled: e.RotationOn,
			VersionCount:    e.VersionCount,
			LastRotatedAt:   e.LastRotated,
			LastAccessedAt:  e.LastAccessed,
			// AWS exposes no reference count; the unused signal comes from LastAccessedAt.
			ReferencedByCount: 0,
			Source:            "aws",
		})
	}
	return out
}
