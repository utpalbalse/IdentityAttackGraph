package notify

import (
	"context"
	"net/http"
	"time"
)

// webhookNotifier POSTs a generic JSON envelope, for routing into PagerDuty Events, a SOAR/SIEM
// intake, or a custom handler. The shape is stable: {"source","sent_at","count","alerts":[...]}.
type webhookNotifier struct {
	url    string
	client *http.Client
}

func (w *webhookNotifier) Kind() string { return "webhook" }

func (w *webhookNotifier) Send(ctx context.Context, alerts []Alert) error {
	if len(alerts) == 0 {
		return nil
	}
	return postJSON(ctx, w.client, w.url, map[string]any{
		"source":  "nhiid",
		"sent_at": time.Now().UTC().Format(time.RFC3339),
		"count":   len(alerts),
		"alerts":  alerts,
	})
}
