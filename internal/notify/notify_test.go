package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func sampleAlerts(n int) []Alert {
	out := make([]Alert, n)
	for i := range out {
		out[i] = Alert{
			FindingID: "f", Detector: "over_privileged_sa", Severity: "high",
			Title: "Over-privileged service identity", Narrative: "holds admin",
			IdentityName: "prod/deployer", Account: "k8s:demo", FirstSeen: time.Now(),
		}
	}
	return out
}

func TestSeveritiesAtLeast(t *testing.T) {
	got := SeveritiesAtLeast("high")
	want := map[string]bool{"high": true, "critical": true}
	if len(got) != 2 || !want[got[0]] || !want[got[1]] {
		t.Fatalf("SeveritiesAtLeast(high) = %v, want high+critical", got)
	}
	if len(SeveritiesAtLeast("info")) != 5 {
		t.Errorf("info should include all 5 severities")
	}
	if len(SeveritiesAtLeast("")) != 5 {
		t.Errorf("unknown/empty should default to all")
	}
}

func TestSlackPayloadShape(t *testing.T) {
	p := slackPayload(sampleAlerts(2))
	if txt, _ := p["text"].(string); !strings.Contains(txt, "2 new findings") {
		t.Errorf("fallback text = %q, want count summary", p["text"])
	}
	blocks, ok := p["blocks"].([]any)
	if !ok || len(blocks) != 3 { // 1 header + 2 sections
		t.Fatalf("blocks = %d, want 3", len(blocks))
	}
}

func TestNewDisabledReturnsNil(t *testing.T) {
	n, err := New(Config{Enabled: false})
	if err != nil || n != nil {
		t.Fatalf("disabled New = (%v, %v), want (nil, nil)", n, err)
	}
}

func TestNewEnabledRequiresURL(t *testing.T) {
	if _, err := New(Config{Enabled: true, Kind: "slack"}); err == nil {
		t.Error("enabled with empty webhook_url should error")
	}
}

func TestSendPostsAndFailsOnNon2xx(t *testing.T) {
	// success path
	var gotBody []byte
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer ok.Close()
	n, err := New(Config{Enabled: true, Kind: "webhook", WebhookURL: ok.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Send(context.Background(), sampleAlerts(1)); err != nil {
		t.Fatalf("Send to 200 server: %v", err)
	}
	var env map[string]any
	if json.Unmarshal(gotBody, &env) != nil || env["source"] != "nhiid" {
		t.Errorf("webhook envelope missing source=nhiid: %s", gotBody)
	}

	// failure path -> error so caller can retry
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer bad.Close()
	nb, _ := New(Config{Enabled: true, Kind: "webhook", WebhookURL: bad.URL})
	if err := nb.Send(context.Background(), sampleAlerts(1)); err == nil {
		t.Error("Send to 500 server should return an error")
	}
}
