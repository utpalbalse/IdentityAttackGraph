package detect

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/nhiid/nhiid/internal/models"
)

// highValuePatterns escalate a repo exposure to critical even before live verification.
var highValuePatterns = []string{"aws", "gcp", "azure", "private_key", "service_account", "secret_key", "ssh", "token", "rsa"}

// ExposureFinding builds a secret_exposed_in_repo finding from an exposure. Used both for
// identity-linked exposures and for repo-scoped exposures discovered by the secret scanner
// (identityID nil). Evidence carries the location + fingerprint only — never the secret value.
func ExposureFinding(ex models.Exposure, identityID *uuid.UUID, repoLabel string) models.Finding {
	sev := models.SevHigh
	if ex.Verified || isHighValuePattern(ex.Pattern) {
		sev = models.SevCritical
	}
	ev := map[string]any{
		"path": ex.Path, "line": ex.Line, "commit": ex.CommitSHA,
		"pattern": ex.Pattern, "verified": ex.Verified, "fingerprint": ex.Fingerprint,
	}
	if repoLabel != "" {
		ev["repository"] = repoLabel
	}
	where := ex.Path
	if repoLabel != "" {
		where = repoLabel + ":" + ex.Path
	}
	narr := fmt.Sprintf("Credential material (pattern %q) was found in repository at %s. "+
		"Rotate and revoke the exposed credential and purge it from history.", ex.Pattern, where)
	return models.Finding{
		Detector:    "secret_exposed_in_repo",
		Category:    "exposure",
		Severity:    sev,
		Confidence:  85,
		IdentityID:  identityID,
		Title:       "Credential material exposed in repository",
		Narrative:   narr,
		Evidence:    ev,
		Fingerprint: Fingerprint("secret_exposed_in_repo", identityID, []string{ex.Fingerprint}),
		Status:      "open",
	}
}

func isHighValuePattern(pattern string) bool {
	p := strings.ToLower(pattern)
	for _, k := range highValuePatterns {
		if strings.Contains(p, k) {
			return true
		}
	}
	return false
}
