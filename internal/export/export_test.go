package export

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func sampleRows() []FindingRow {
	now := time.Now()
	return []FindingRow{
		{
			Detector: "secret_exposed_in_repo", Category: "exposure", Severity: "critical", Confidence: 85,
			IdentityName: "svc-billing", IdentityARN: "arn:aws:iam::123:user/svc-billing", Account: "aws:123",
			Title: "Credential exposed", Narrative: "Key found in repo.",
			Evidence: map[string]any{"path": ".env", "line": float64(12)}, Status: "open",
			FirstSeen: now, LastSeen: now,
		},
		{
			Detector: "over_privileged_sa", Category: "privilege", Severity: "high", Confidence: 78,
			IdentityName: "billing-admin", IdentityARN: "arn:aws:iam::123:role/billing-admin", Account: "aws:123",
			Title: "Over-privileged", Narrative: "Holds admin.", Status: "open", FirstSeen: now, LastSeen: now,
		},
	}
}

func TestFindingsSARIF_Valid(t *testing.T) {
	var buf bytes.Buffer
	if err := FindingsSARIF(&buf, sampleRows()); err != nil {
		t.Fatalf("sarif: %v", err)
	}
	var log map[string]any
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if log["version"] != "2.1.0" {
		t.Fatalf("expected version 2.1.0, got %v", log["version"])
	}
	runs := log["runs"].([]any)
	run := runs[0].(map[string]any)
	results := run["results"].([]any)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	// the first finding should carry a physicalLocation (repo path), the second a logicalLocation
	r0 := results[0].(map[string]any)
	locs := r0["locations"].([]any)
	loc0 := locs[0].(map[string]any)
	if _, ok := loc0["physicalLocation"]; !ok {
		t.Fatal("expected physicalLocation for repo-path finding")
	}
	rules := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("expected 2 dedup'd rules, got %d", len(rules))
	}
}

func TestFindingsCSV(t *testing.T) {
	var buf bytes.Buffer
	if err := FindingsCSV(&buf, sampleRows()); err != nil {
		t.Fatalf("csv: %v", err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "detector,severity,confidence") {
		t.Fatalf("unexpected header: %q", out[:40])
	}
	if strings.Count(out, "\n") < 3 { // header + 2 rows
		t.Fatalf("expected 3 lines, got %q", out)
	}
}

func TestSarifLevel(t *testing.T) {
	cases := map[string]string{"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
	for sev, want := range cases {
		if got := sarifLevel(sev); got != want {
			t.Errorf("sarifLevel(%q)=%q want %q", sev, got, want)
		}
	}
}
