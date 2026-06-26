// Package notify delivers finding alerts to external sinks (Slack incoming webhook or a generic
// JSON webhook). It is intentionally small and fail-aware: Send returns an error on a non-2xx
// response so the caller can leave the finding un-stamped and retry on the next cycle (the worker's
// alert sweep marks alerted_at only after a successful Send).
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Alert is the denormalized view of a finding dispatched to a sink.
type Alert struct {
	FindingID    string         `json:"finding_id"`
	Detector     string         `json:"detector"`
	Severity     string         `json:"severity"`
	Category     string         `json:"category"`
	Title        string         `json:"title"`
	Narrative    string         `json:"narrative"`
	IdentityName string         `json:"identity_name,omitempty"`
	Account      string         `json:"account,omitempty"`
	FirstSeen    time.Time      `json:"first_seen"`
	Evidence     map[string]any `json:"evidence,omitempty"`
}

// Notifier dispatches a batch of alerts.
type Notifier interface {
	Send(ctx context.Context, alerts []Alert) error
	Kind() string
}

// Config configures the notifier.
type Config struct {
	Enabled     bool
	Kind        string // slack | webhook
	WebhookURL  string
	MinSeverity string
}

// New returns a Notifier, or (nil, nil) when alerting is disabled.
func New(cfg Config) (Notifier, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if cfg.WebhookURL == "" {
		return nil, fmt.Errorf("notify: enabled but webhook_url is empty (set NHIID_NOTIFY_WEBHOOK_URL)")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	switch strings.ToLower(cfg.Kind) {
	case "", "slack":
		return &slackNotifier{url: cfg.WebhookURL, client: client}, nil
	case "webhook":
		return &webhookNotifier{url: cfg.WebhookURL, client: client}, nil
	default:
		return nil, fmt.Errorf("notify: unknown kind %q (want slack|webhook)", cfg.Kind)
	}
}

// SeveritiesAtLeast returns the severity labels at or above min (default: all when min is unknown).
func SeveritiesAtLeast(min string) []string {
	order := []string{"info", "low", "medium", "high", "critical"}
	rank := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	floor := rank[strings.ToLower(min)] // unknown -> 0 -> everything
	out := make([]string, 0, len(order))
	for _, s := range order {
		if rank[s] >= floor {
			out = append(out, s)
		}
	}
	return out
}

// postJSON marshals v and POSTs it, returning an error on transport failure or a non-2xx status.
func postJSON(ctx context.Context, client *http.Client, url string, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("notify: webhook returned %s", resp.Status)
	}
	return nil
}

func severityEmoji(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🔵"
	default:
		return "⚪"
	}
}

// truncate keeps alert text terminal/Slack friendly.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
