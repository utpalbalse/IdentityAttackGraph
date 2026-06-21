package repo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// parseReport auto-detects the report format (SecretSweep JSON or SARIF 2.1.0) and normalizes it.
func parseReport(raw []byte) ([]finding, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty report")
	}
	// SARIF is a JSON object with "runs"; SecretSweep JSON is an array (or {"findings":[...]}).
	if trimmed[0] == '{' && bytes.Contains(trimmed, []byte(`"runs"`)) {
		return parseSARIF(trimmed)
	}
	return parseSecretSweepJSON(trimmed)
}

// ----- SecretSweep JSON -----

type ssFinding struct {
	File     string `json:"file"`
	Path     string `json:"path"` // tolerate alternate key
	Line     int    `json:"line"`
	Name     string `json:"name"`
	Rule     string `json:"rule"` // tolerate alternate key
	Severity string `json:"severity"`
	Category string `json:"category"`
}

func parseSecretSweepJSON(raw []byte) ([]finding, error) {
	var arr []ssFinding
	if err := json.Unmarshal(raw, &arr); err != nil {
		// tolerate {"findings":[...]}
		var wrap struct {
			Findings []ssFinding `json:"findings"`
		}
		if err2 := json.Unmarshal(raw, &wrap); err2 != nil {
			return nil, err
		}
		arr = wrap.Findings
	}
	out := make([]finding, 0, len(arr))
	for _, f := range arr {
		file := firstNonEmpty(f.File, f.Path)
		rule := firstNonEmpty(f.Name, f.Rule)
		if file == "" || rule == "" {
			continue
		}
		out = append(out, finding{File: file, Line: f.Line, Rule: rule, Severity: strings.ToLower(f.Severity)})
	}
	return out, nil
}

// ----- SARIF 2.1.0 -----

type sarifReport struct {
	Runs []struct {
		Results []struct {
			RuleID    string `json:"ruleId"`
			Level     string `json:"level"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine int `json:"startLine"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

func parseSARIF(raw []byte) ([]finding, error) {
	var s sarifReport
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	var out []finding
	for _, run := range s.Runs {
		for _, r := range run.Results {
			f := finding{Rule: r.RuleID, Severity: sarifLevelToSeverity(r.Level)}
			if len(r.Locations) > 0 {
				pl := r.Locations[0].PhysicalLocation
				f.File = pl.ArtifactLocation.URI
				f.Line = pl.Region.StartLine
			}
			if f.File == "" || f.Rule == "" {
				continue
			}
			out = append(out, f)
		}
	}
	return out, nil
}

func sarifLevelToSeverity(level string) string {
	switch strings.ToLower(level) {
	case "error":
		return "high"
	case "warning":
		return "medium"
	default:
		return "low"
	}
}

// ----- helpers -----

func splitRepo(s string) (org, name string) {
	if i := strings.Index(s, "/"); i >= 0 {
		return s[:i], s[i+1:]
	}
	return "", s
}

// slug normalizes a rule/pattern name into a stable pattern token (e.g. "AWS Access Key" -> "aws_access_key").
func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	prevUnderscore := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevUnderscore = false
		default:
			if !prevUnderscore {
				b.WriteByte('_')
				prevUnderscore = true
			}
		}
	}
	return strings.Trim(b.String(), "_")
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }
