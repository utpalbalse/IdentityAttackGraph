package notify

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// slackNotifier posts to a Slack incoming webhook using Block Kit, with a plain-text fallback for
// notifications/clients that don't render blocks.
type slackNotifier struct {
	url    string
	client *http.Client
}

func (s *slackNotifier) Kind() string { return "slack" }

func (s *slackNotifier) Send(ctx context.Context, alerts []Alert) error {
	if len(alerts) == 0 {
		return nil
	}
	return postJSON(ctx, s.client, s.url, slackPayload(alerts))
}

// slackPayload builds the Slack message. Slack caps a message at 50 blocks, so we render at most 20
// findings in detail and summarize the remainder.
func slackPayload(alerts []Alert) map[string]any {
	const maxDetailed = 20
	header := fmt.Sprintf("NHIID: %d new finding%s", len(alerts), plural(len(alerts)))

	blocks := []any{
		map[string]any{
			"type": "header",
			"text": map[string]any{"type": "plain_text", "text": header, "emoji": true},
		},
	}
	for i, a := range alerts {
		if i >= maxDetailed {
			blocks = append(blocks, map[string]any{
				"type": "context",
				"elements": []any{map[string]any{
					"type": "mrkdwn", "text": fmt.Sprintf("…and %d more", len(alerts)-maxDetailed),
				}},
			})
			break
		}
		blocks = append(blocks, map[string]any{
			"type": "section",
			"text": map[string]any{"type": "mrkdwn", "text": slackAlertText(a)},
		})
	}

	return map[string]any{
		"text":   header, // fallback shown in notifications
		"blocks": blocks,
	}
}

func slackAlertText(a Alert) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s *[%s] %s*\n", severityEmoji(a.Severity), strings.ToUpper(a.Severity), a.Title)
	meta := []string{"`" + a.Detector + "`"}
	if a.IdentityName != "" {
		meta = append(meta, "identity *"+a.IdentityName+"*")
	}
	if a.Account != "" {
		meta = append(meta, a.Account)
	}
	b.WriteString(strings.Join(meta, " · ") + "\n")
	b.WriteString(truncate(a.Narrative, 280))
	return b.String()
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
