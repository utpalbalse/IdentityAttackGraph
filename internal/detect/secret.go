package detect

import (
	"fmt"
	"time"

	"github.com/nhiid/nhiid/internal/models"
)

// UnusedSecretFinding flags a managed secret that nothing references and that has not been accessed
// within the staleness window — dead credential material that should be deleted to shrink the
// attack surface. It is identity-agnostic (raised by a dedicated worker pass over the secret
// inventory, like repo-scoped exposures), so it returns (finding, true) only when the secret
// actually qualifies. Evidence carries metadata only — never secret material.
func UnusedSecretFinding(sec models.Secret, staleWindow time.Duration, now time.Time) (models.Finding, bool) {
	if sec.ReferencedByCount > 0 {
		return models.Finding{}, false
	}
	if sec.LastAccessedAt != nil && now.Sub(*sec.LastAccessedAt) <= staleWindow {
		return models.Finding{}, false
	}
	last := "never"
	if sec.LastAccessedAt != nil {
		last = sec.LastAccessedAt.Format("2006-01-02")
	}
	ev := map[string]any{
		"store":            sec.Store,
		"secret":           sec.ExternalID,
		"name":             sec.Name,
		"referenced_by":    sec.ReferencedByCount,
		"last_accessed":    sec.LastAccessedAt,
		"rotation_enabled": sec.RotationEnabled,
	}
	narr := fmt.Sprintf("Secret %q in %s has no references and was last accessed %s. "+
		"Unreferenced secrets are dead credential material — delete them to shrink the attack surface.",
		sec.Name, sec.Store, last)
	return models.Finding{
		Detector:    "unused_secret",
		Category:    "hygiene",
		Severity:    models.SevLow,
		Confidence:  75,
		Title:       "Unused managed secret",
		Narrative:   narr,
		Evidence:    ev,
		Fingerprint: Fingerprint("unused_secret", nil, []string{sec.Store, sec.ExternalID}),
		Status:      "open",
	}, true
}
