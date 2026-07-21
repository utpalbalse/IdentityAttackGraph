package risk

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestShippedWeightsAreValid is the guard against someone editing configs/risk_weights.yaml into a
// state the engine would silently mis-score with.
func TestShippedWeightsAreValid(t *testing.T) {
	w, err := LoadWeights(filepath.Join("..", "..", "configs", "risk_weights.yaml"))
	if err != nil {
		t.Fatalf("shipped weights must load: %v", err)
	}

	var sum float64
	for _, v := range w.Weights {
		sum += v
	}
	if sum < 0.999 || sum > 1.001 {
		t.Errorf("shipped weights sum to %.4f, want 1.0", sum)
	}

	// The six documented factors, and only those (docs/RISK_MODEL.md).
	factors := []string{"privilege", "blast_radius", "exposure", "trust", "usage", "freshness"}
	for _, f := range factors {
		if _, ok := w.Weights[f]; !ok {
			t.Errorf("missing weight for factor %q", f)
		}
		if _, ok := w.Signals[f]; !ok {
			t.Errorf("missing signal table for factor %q", f)
		}
	}
	if len(w.Weights) != len(factors) {
		t.Errorf("got %d weights, want exactly %d", len(w.Weights), len(factors))
	}

	// Severity bands must be ordered, or severity() would mislabel scores.
	b := w.SeverityBands
	if !(b["low"] < b["medium"] && b["medium"] < b["high"] && b["high"] < b["critical"]) {
		t.Errorf("severity bands out of order: %v", b)
	}
}

func TestLoadWeightsMissingFile(t *testing.T) {
	if _, err := LoadWeights(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected an error for a missing weights file")
	}
}

func TestParseWeightsRejectsBadSum(t *testing.T) {
	// Sums to 0.60 — far enough outside the ~1.0 tolerance that composites would be meaningless.
	y := []byte(`
weights:
  privilege: 0.10
  blast_radius: 0.10
  exposure: 0.10
  trust: 0.10
  usage: 0.10
  freshness: 0.10
`)
	_, err := ParseWeightsYAML(y)
	if err == nil {
		t.Fatal("expected a validation error for weights that do not sum to ~1.0")
	}
	if !strings.Contains(err.Error(), "sum") {
		t.Errorf("error should explain the sum problem, got: %v", err)
	}
}

func TestParseWeightsRejectsMissingFactor(t *testing.T) {
	// freshness omitted; the remainder still sums to 1.0, so only the factor check catches it.
	y := []byte(`
weights:
  privilege: 0.25
  blast_radius: 0.25
  exposure: 0.20
  trust: 0.15
  usage: 0.15
`)
	_, err := ParseWeightsYAML(y)
	if err == nil {
		t.Fatal("expected a validation error for a missing factor")
	}
	if !strings.Contains(err.Error(), "freshness") {
		t.Errorf("error should name the missing factor, got: %v", err)
	}
}

func TestParseWeightsRejectsMalformedYAML(t *testing.T) {
	if _, err := ParseWeightsYAML([]byte("weights: [this is not a map")); err == nil {
		t.Fatal("expected a parse error for malformed YAML")
	}
}

// TestWeightsJSONRoundTrip covers the hot-reload path: weights are stored as JSON in config_settings
// and re-parsed by PUT /config/risk-weights, so a round trip must be lossless.
func TestWeightsJSONRoundTrip(t *testing.T) {
	orig, err := LoadWeights(filepath.Join("..", "..", "configs", "risk_weights.yaml"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	b, err := orig.JSON()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	back, err := ParseWeightsJSON(b)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}

	for k, v := range orig.Weights {
		if back.Weights[k] != v {
			t.Errorf("weight %s = %v, want %v", k, back.Weights[k], v)
		}
	}
	for factor, sigs := range orig.Signals {
		for name, pts := range sigs {
			if back.Signals[factor][name] != pts {
				t.Errorf("signal %s.%s = %d, want %d", factor, name, back.Signals[factor][name], pts)
			}
		}
	}
	for k, v := range orig.Urgency {
		if back.Urgency[k] != v {
			t.Errorf("urgency %s = %d, want %d", k, back.Urgency[k], v)
		}
	}
}

func TestParseWeightsJSONRejectsInvalid(t *testing.T) {
	if _, err := ParseWeightsJSON([]byte(`{"weights":{"privilege":1.0}}`)); err == nil {
		t.Fatal("expected a validation error for a JSON payload missing factors")
	}
	if _, err := ParseWeightsJSON([]byte(`{not json`)); err == nil {
		t.Fatal("expected a parse error for malformed JSON")
	}
}

// TestSigDefaultsToZero: an unset signal must contribute nothing rather than panic, so an operator
// can prune the config without breaking scoring.
func TestSigDefaultsToZero(t *testing.T) {
	w := &Weights{Signals: map[string]map[string]int{"privilege": {"admin_or_star": 60}}}
	if got := w.sig("privilege", "admin_or_star"); got != 60 {
		t.Errorf("sig = %d, want 60", got)
	}
	if got := w.sig("privilege", "no_such_signal"); got != 0 {
		t.Errorf("unknown signal = %d, want 0", got)
	}
	if got := w.sig("no_such_factor", "anything"); got != 0 {
		t.Errorf("unknown factor = %d, want 0", got)
	}
}
