package risk

import (
	"encoding/json"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Weights mirrors configs/risk_weights.yaml. Hot-reloadable; see docs/RISK_MODEL.md.
type Weights struct {
	Weights       map[string]float64        `yaml:"weights" json:"weights"`
	SeverityBands map[string]int            `yaml:"severity_bands" json:"severity_bands"`
	Signals       map[string]map[string]int `yaml:"signals" json:"signals"`
	Urgency       map[string]int            `yaml:"urgency" json:"urgency"`
}

// LoadWeights reads and validates the weights YAML file.
func LoadWeights(path string) (*Weights, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read weights %s: %w", path, err)
	}
	return ParseWeightsYAML(b)
}

// ParseWeightsYAML parses and validates weights from YAML bytes.
func ParseWeightsYAML(b []byte) (*Weights, error) {
	var w Weights
	if err := yaml.Unmarshal(b, &w); err != nil {
		return nil, fmt.Errorf("parse weights: %w", err)
	}
	if err := w.validate(); err != nil {
		return nil, err
	}
	return &w, nil
}

// ParseWeightsJSON parses and validates weights from JSON bytes (the form stored in the DB and
// accepted by PUT /config/risk-weights).
func ParseWeightsJSON(b []byte) (*Weights, error) {
	var w Weights
	if err := json.Unmarshal(b, &w); err != nil {
		return nil, fmt.Errorf("parse weights: %w", err)
	}
	if err := w.validate(); err != nil {
		return nil, err
	}
	return &w, nil
}

// JSON serializes the weights for storage / API responses.
func (w *Weights) JSON() ([]byte, error) { return json.Marshal(w) }

func (w *Weights) validate() error {
	var sum float64
	for _, v := range w.Weights {
		sum += v
	}
	if sum < 0.95 || sum > 1.05 {
		return fmt.Errorf("risk weights must sum to ~1.0, got %.3f", sum)
	}
	for _, f := range []string{"privilege", "blast_radius", "exposure", "trust", "usage", "freshness"} {
		if _, ok := w.Weights[f]; !ok {
			return fmt.Errorf("missing weight for factor %q", f)
		}
	}
	return nil
}

// sig returns the configured points for a signal in a factor, or 0 if unset.
func (w *Weights) sig(factor, name string) int {
	if m, ok := w.Signals[factor]; ok {
		return m[name]
	}
	return 0
}
