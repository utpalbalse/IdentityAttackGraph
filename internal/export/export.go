// Package export serializes findings and inventory to JSON, CSV, and SARIF 2.1.0.
// SARIF lets NHIID findings flow into GitHub code scanning, IDEs, and other SARIF consumers.
package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"
)

// FindingRow is the denormalized view of a finding used for export (identity joined in).
type FindingRow struct {
	Detector     string         `json:"detector"`
	Category     string         `json:"category"`
	Severity     string         `json:"severity"`
	Confidence   int            `json:"confidence"`
	IdentityName string         `json:"identity_name"`
	IdentityARN  string         `json:"identity_arn"`
	Account      string         `json:"account"`
	Title        string         `json:"title"`
	Narrative    string         `json:"narrative"`
	Status       string         `json:"status"`
	Evidence     map[string]any `json:"evidence,omitempty"`
	FirstSeen    time.Time      `json:"first_seen"`
	LastSeen     time.Time      `json:"last_seen"`
}

// InventoryRow is the denormalized identity view for export.
type InventoryRow struct {
	Name      string     `json:"name"`
	Kind      string     `json:"kind"`
	Provider  string     `json:"provider"`
	Account   string     `json:"account"`
	State     string     `json:"state"`
	RiskScore int        `json:"risk_score"`
	LastSeen  *time.Time `json:"last_seen,omitempty"`
}

// ----- findings: JSON / CSV / SARIF -----

func FindingsJSON(w io.Writer, rows []FindingRow) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{"findings": rows})
}

func FindingsCSV(w io.Writer, rows []FindingRow) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()
	if err := cw.Write([]string{"detector", "severity", "confidence", "identity", "account", "title", "status", "first_seen", "last_seen"}); err != nil {
		return err
	}
	for _, r := range rows {
		rec := []string{
			r.Detector, r.Severity, strconv.Itoa(r.Confidence), r.IdentityName, r.Account,
			r.Title, r.Status, r.FirstSeen.Format(time.RFC3339), r.LastSeen.Format(time.RFC3339),
		}
		if err := cw.Write(rec); err != nil {
			return err
		}
	}
	return cw.Error()
}

// FindingsSARIF emits a SARIF 2.1.0 log. Each detector becomes a rule; each finding a result.
// secret-exposure findings (with repo path/line evidence) get a physicalLocation; others get a
// logicalLocation naming the identity.
func FindingsSARIF(w io.Writer, rows []FindingRow) error {
	rulesIdx := map[string]int{}
	var rules []sarifRule
	var results []sarifResult

	for _, r := range rows {
		if _, ok := rulesIdx[r.Detector]; !ok {
			rulesIdx[r.Detector] = len(rules)
			rules = append(rules, sarifRule{
				ID:               r.Detector,
				Name:             r.Detector,
				ShortDescription: sarifText{Text: r.Title},
				Properties:       map[string]any{"category": r.Category},
			})
		}
		results = append(results, sarifResult{
			RuleID:    r.Detector,
			Level:     sarifLevel(r.Severity),
			Message:   sarifText{Text: r.Narrative},
			Locations: []sarifLocation{locationFor(r)},
			Properties: map[string]any{
				"severity":   r.Severity,
				"confidence": r.Confidence,
				"identity":   r.IdentityName,
				"account":    r.Account,
				"status":     r.Status,
			},
		})
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "IdentityAttackGraph",
				InformationURI: "https://github.com/utpalbalse/IdentityAttackGraph",
				Version:        "0.1.0",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func locationFor(r FindingRow) sarifLocation {
	// secret_exposed_in_repo evidence carries path (+ optional line) — emit a physical location.
	if path, ok := r.Evidence["path"].(string); ok && path != "" {
		region := (*sarifRegion)(nil)
		if line, ok := toInt(r.Evidence["line"]); ok && line > 0 {
			region = &sarifRegion{StartLine: line}
		}
		return sarifLocation{PhysicalLocation: &sarifPhysical{
			ArtifactLocation: sarifArtifact{URI: path},
			Region:           region,
		}}
	}
	name := r.IdentityName
	if name == "" {
		name = r.IdentityARN
	}
	return sarifLocation{LogicalLocations: []sarifLogical{{
		Name:               name,
		FullyQualifiedName: r.IdentityARN,
		Kind:               "resource",
	}}}
}

func sarifLevel(sev string) string {
	switch sev {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

// ----- inventory: JSON / CSV -----

func InventoryJSON(w io.Writer, rows []InventoryRow) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{"identities": rows})
}

func InventoryCSV(w io.Writer, rows []InventoryRow) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()
	if err := cw.Write([]string{"name", "kind", "provider", "account", "state", "risk_score", "last_seen"}); err != nil {
		return err
	}
	for _, r := range rows {
		last := ""
		if r.LastSeen != nil {
			last = r.LastSeen.Format(time.RFC3339)
		}
		if err := cw.Write([]string{r.Name, r.Kind, r.Provider, r.Account, r.State, strconv.Itoa(r.RiskScore), last}); err != nil {
			return err
		}
	}
	return cw.Error()
}

func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case json.Number:
		i, err := n.Int64()
		return int(i), err == nil
	}
	return 0, false
}

var _ = fmt.Sprint // reserved for future formatting helpers

// ----- SARIF types (2.1.0 subset) -----

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Version        string      `json:"version,omitempty"`
	Rules          []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name,omitempty"`
	ShortDescription sarifText      `json:"shortDescription"`
	Properties       map[string]any `json:"properties,omitempty"`
}
type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    sarifText       `json:"message"`
	Locations  []sarifLocation `json:"locations,omitempty"`
	Properties map[string]any  `json:"properties,omitempty"`
}
type sarifText struct {
	Text string `json:"text"`
}
type sarifLocation struct {
	PhysicalLocation *sarifPhysical `json:"physicalLocation,omitempty"`
	LogicalLocations []sarifLogical `json:"logicalLocations,omitempty"`
}
type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}
type sarifArtifact struct {
	URI string `json:"uri"`
}
type sarifRegion struct {
	StartLine int `json:"startLine,omitempty"`
}
type sarifLogical struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind               string `json:"kind,omitempty"`
}
