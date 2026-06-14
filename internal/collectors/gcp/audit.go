package gcp

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nhiid/nhiid/internal/models"
	logging "google.golang.org/api/logging/v2"
)

// auditPayload is the subset of a Cloud Audit Log protoPayload we extract usage signal from.
type auditPayload struct {
	ServiceName        string `json:"serviceName"`
	MethodName         string `json:"methodName"`
	AuthenticationInfo struct {
		PrincipalEmail string `json:"principalEmail"`
	} `json:"authenticationInfo"`
	RequestMetadata struct {
		CallerIP                string `json:"callerIp"`
		CallerSuppliedUserAgent string `json:"callerSuppliedUserAgent"`
	} `json:"requestMetadata"`
}

// collectAudit pulls recent admin-activity audit entries and maps them to usage events. Best-effort:
// returns the advanced cursor and a non-nil error if the Logging API is unavailable (the caller
// treats this as degraded, not fatal).
func (c *clients) collectAudit(ctx context.Context, b *builder, projectID string, lookbackHours int, cursor map[string]any) (map[string]any, error) {
	now := time.Now().UTC()
	start := now.Add(-24 * time.Hour)
	if lookbackHours > 0 {
		start = now.Add(-time.Duration(lookbackHours) * time.Hour)
	}
	if ts, ok := cursor["audit_after"].(string); ok {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			start = t.Add(time.Second)
		}
	}

	filter := strings.Join([]string{
		`logName:"cloudaudit.googleapis.com"`,
		`timestamp>="` + start.Format(time.RFC3339) + `"`,
	}, " AND ")

	req := &logging.ListLogEntriesRequest{
		ResourceNames: []string{"projects/" + projectID},
		Filter:        filter,
		OrderBy:       "timestamp desc",
		PageSize:      1000,
	}
	resp, err := c.logging.Entries.List(req).Context(ctx).Do()
	if err != nil {
		return cursor, err
	}

	newest := start
	for _, e := range resp.Entries {
		t, _ := time.Parse(time.RFC3339, e.Timestamp)
		if t.After(newest) {
			newest = t
		}
		if len(e.ProtoPayload) == 0 {
			continue
		}
		var p auditPayload
		if err := json.Unmarshal(e.ProtoPayload, &p); err != nil {
			continue
		}
		if p.AuthenticationInfo.PrincipalEmail == "" {
			continue
		}
		principal := p.AuthenticationInfo.PrincipalEmail
		ue := models.UsageEvent{
			ID:          uuid.New(),
			IdentityID:  models.DeterministicID(string(models.KindGCPServiceAcct), principal),
			EventTime:   t,
			EventName:   p.MethodName,
			EventSource: p.ServiceName,
			UserAgent:   truncate(p.RequestMetadata.CallerSuppliedUserAgent, 256),
			AccountRef:  b.accountRef,
			Source:      "gcp",
		}
		if ip := net.ParseIP(p.RequestMetadata.CallerIP); ip != nil {
			ue.SrcIP = p.RequestMetadata.CallerIP
		}
		b.usage = append(b.usage, ue)
	}
	return map[string]any{"audit_after": newest.UTC().Format(time.RFC3339)}, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
