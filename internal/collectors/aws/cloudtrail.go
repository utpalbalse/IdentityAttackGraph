package aws

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/google/uuid"
	"github.com/nhiid/nhiid/internal/models"
)

// ctEvent is the subset of a CloudTrail event record we extract usage signal from.
type ctEvent struct {
	UserIdentity struct {
		Type           string `json:"type"`
		ARN            string `json:"arn"`
		PrincipalID    string `json:"principalId"`
		AccountID      string `json:"accountId"`
		SessionContext struct {
			SessionIssuer struct {
				ARN string `json:"arn"`
			} `json:"sessionIssuer"`
		} `json:"sessionContext"`
	} `json:"userIdentity"`
	EventName       string `json:"eventName"`
	EventSource     string `json:"eventSource"`
	AWSRegion       string `json:"awsRegion"`
	SourceIPAddress string `json:"sourceIPAddress"`
	UserAgent       string `json:"userAgent"`
	ErrorCode       string `json:"errorCode"`
	EventTime       string `json:"eventTime"`
}

const maxCloudTrailPages = 50 // ~2500 events/run; LookupEvents is rate-limited to ~2 req/s

// collectCloudTrail pulls identity-relevant events since the cursor and maps them to usage events.
// It returns the events plus the advanced cursor (newest event time seen).
func (c *clients) collectCloudTrail(ctx context.Context, accountRef string, cursor map[string]any, lookbackHours int) ([]models.UsageEvent, map[string]any, error) {
	now := time.Now().UTC()
	start := now.Add(-time.Duration(lookbackHours) * time.Hour)
	if lookbackHours == 0 {
		start = now.Add(-24 * time.Hour)
	}
	if ts, ok := cursor["cloudtrail_after"].(string); ok {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			start = t.Add(time.Second)
		}
	}

	input := &cloudtrail.LookupEventsInput{StartTime: &start, EndTime: &now}
	p := cloudtrail.NewLookupEventsPaginator(c.cloudtrail, input)

	var events []models.UsageEvent
	newest := start
	pages := 0
	for p.HasMorePages() && pages < maxCloudTrailPages {
		page, err := p.NextPage(ctx)
		if err != nil {
			return events, advanceCursor(newest), err
		}
		pages++
		for _, raw := range page.Events {
			et := awssdk.ToTime(raw.EventTime)
			if et.After(newest) {
				newest = et
			}
			body := awssdk.ToString(raw.CloudTrailEvent)
			if body == "" {
				continue
			}
			var ce ctEvent
			if err := json.Unmarshal([]byte(body), &ce); err != nil {
				continue
			}
			principal := normalizePrincipalARN(ce)
			if principal == "" {
				continue
			}
			identID := models.DeterministicID(string(kindFromARN(principal)), principal)
			ue := models.UsageEvent{
				ID:          uuid.New(),
				IdentityID:  identID,
				EventTime:   et,
				EventName:   firstNonEmpty(ce.EventName, awssdk.ToString(raw.EventName)),
				EventSource: ce.EventSource,
				SrcRegion:   ce.AWSRegion,
				UserAgent:   truncate(ce.UserAgent, 256),
				ErrorCode:   ce.ErrorCode,
				AccountRef:  accountRef,
				Source:      "aws",
			}
			if ip := net.ParseIP(ce.SourceIPAddress); ip != nil {
				ue.SrcIP = ce.SourceIPAddress // only set when a real IP (not a service hostname)
			}
			events = append(events, ue)
		}
	}
	return events, advanceCursor(newest), nil
}

func advanceCursor(newest time.Time) map[string]any {
	return map[string]any{"cloudtrail_after": newest.UTC().Format(time.RFC3339)}
}

// normalizePrincipalARN resolves the acting principal to a stable IAM ARN. Assumed-role sessions
// (arn:aws:sts::acct:assumed-role/Role/session) are mapped back to the underlying role ARN so usage
// attributes to the role identity, not the ephemeral session.
func normalizePrincipalARN(ce ctEvent) string {
	if issuer := ce.UserIdentity.SessionContext.SessionIssuer.ARN; issuer != "" {
		return issuer
	}
	arn := ce.UserIdentity.ARN
	if strings.Contains(arn, ":assumed-role/") {
		return assumedRoleToRoleARN(arn)
	}
	return arn
}

// assumedRoleToRoleARN converts an STS assumed-role ARN to its IAM role ARN.
func assumedRoleToRoleARN(arn string) string {
	// arn:aws:sts::123:assumed-role/RoleName/session → arn:aws:iam::123:role/RoleName
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 {
		return arn
	}
	acct := parts[4]
	tail := parts[5] // assumed-role/RoleName/session
	seg := strings.Split(tail, "/")
	if len(seg) < 2 {
		return arn
	}
	return "arn:aws:iam::" + acct + ":role/" + seg[1]
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
