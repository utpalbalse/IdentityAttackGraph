// Package detect implements NHIID's detection engine: rule-based detectors over current state
// and statistical anomaly detectors over usage history. Every detector returns evidence-backed,
// explainable findings with a stable fingerprint for dedupe. See docs/DETECTIONS.md.
package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/nhiid/nhiid/internal/graph"
	"github.com/nhiid/nhiid/internal/models"
)

// Subject is everything a detector needs about one identity. It is assembled by the worker from
// the store + graph engine, keeping detectors pure and unit-testable.
type Subject struct {
	Identity  models.Identity
	Owner     *models.Owner
	Creds     []models.Credential
	Roles     []models.Role
	Bindings  []models.ResourceBinding
	Trust     []models.TrustEdge
	Exposures []models.Exposure
	Workloads []models.Workload
	Usage     []models.UsageEvent // recent window, ascending by time
	Blast     graph.BlastRadius
	Paths     []graph.Path

	PeerPermissionP90 int
}

// Config holds detector thresholds (sourced from config.Detection).
type Config struct {
	StaleWindow         time.Duration
	MaxCredAge          time.Duration
	MaxRotationAge      time.Duration
	ImpossibleTravelKMH float64
	UsageSpikeSigma     float64
	AnomalyWarmupEvents int
	EgressAllowlist     []string // CIDRs; matched events suppressed
}

// Detector is a single detection rule.
type Detector interface {
	ID() string
	Detect(s Subject, cfg Config, now time.Time) []models.Finding
}

// Engine runs a set of detectors and applies dedupe by fingerprint.
type Engine struct {
	detectors []Detector
}

// NewEngine wires the default detector set (rule + anomaly).
func NewEngine() *Engine {
	return &Engine{detectors: []Detector{
		orphanedIdentity{}, staleIdentity{}, staleAccessKey{}, overPrivilegedSA{},
		conditionlessTrust{}, wildcardTrust{}, secretExposedInRepo{}, highBlastRadius{},
		aiAgentOverscoped{},
		impossibleTravel{}, unusualGeo{}, newASNOrRuntime{}, usageSpike{}, firstUseSensitive{},
		privilegeCreep{}, suspiciousRoleChain{},
	}}
}

// Run executes all detectors over a subject and returns deduped findings.
func (e *Engine) Run(s Subject, cfg Config, now time.Time) []models.Finding {
	var out []models.Finding
	seen := map[string]bool{}
	for _, d := range e.detectors {
		for _, f := range d.Detect(s, cfg, now) {
			if f.Fingerprint == "" {
				f.Fingerprint = Fingerprint(f.Detector, f.IdentityID, nil)
			}
			if seen[f.Fingerprint] {
				continue
			}
			seen[f.Fingerprint] = true
			if f.FirstSeenAt.IsZero() {
				f.FirstSeenAt = now
			}
			f.LastSeenAt = now
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return sevRank(out[i].Severity) > sevRank(out[j].Severity)
	})
	return out
}

// Fingerprint builds a stable dedupe key from detector + subject + salient evidence keys.
func Fingerprint(detector string, id *uuid.UUID, salient []string) string {
	h := sha256.New()
	h.Write([]byte(detector))
	if id != nil {
		h.Write([]byte(id.String()))
	}
	for _, s := range salient {
		h.Write([]byte("|" + s))
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

func sevRank(s models.Severity) int {
	switch s {
	case models.SevCritical:
		return 4
	case models.SevHigh:
		return 3
	case models.SevMedium:
		return 2
	case models.SevLow:
		return 1
	default:
		return 0
	}
}

// finding is a small constructor that fills common fields.
func finding(s Subject, detector, category string, sev models.Severity, conf int, title, narrative string, evidence map[string]any, salient ...string) models.Finding {
	id := s.Identity.ID
	return models.Finding{
		Detector:    detector,
		Category:    category,
		Severity:    sev,
		Confidence:  conf,
		IdentityID:  &id,
		Title:       title,
		Narrative:   narrative,
		Evidence:    evidence,
		Fingerprint: Fingerprint(detector, &id, salient),
		Status:      "open",
	}
}

func daysAgo(t *time.Time, now time.Time) float64 {
	if t == nil {
		return -1
	}
	return now.Sub(*t).Hours() / 24
}

func fmtDays(d float64) string { return fmt.Sprintf("%.0fd", d) }
