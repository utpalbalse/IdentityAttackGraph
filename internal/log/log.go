// Package log configures slog with a secret-redacting handler. Per the threat model, secret
// material must never reach logs; this handler scrubs known credential-shaped values defensively.
package log

import (
	"context"
	"log/slog"
	"os"
	"regexp"
	"strings"
)

// secretPatterns match common credential shapes that must never be logged in cleartext.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),                       // AWS access key id
	regexp.MustCompile(`(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----`), // PEM private key
	regexp.MustCompile(`ghp_[0-9A-Za-z]{36}`),                    // GitHub PAT
	regexp.MustCompile(`(?i)"private_key"\s*:\s*"[^"]+"`),        // GCP SA JSON key
	regexp.MustCompile(`(?i)(secret|token|password|passwd)["':=\s]+[^\s"',]{8,}`),
}

const redacted = "***REDACTED***"

// New returns a slog.Logger that redacts secret-shaped values from all string attributes.
func New(level, format string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl, ReplaceAttr: redactAttr}
	var base slog.Handler
	if strings.ToLower(format) == "text" {
		base = slog.NewTextHandler(os.Stdout, opts)
	} else {
		base = slog.NewJSONHandler(os.Stdout, opts)
	}
	return slog.New(&redactHandler{base})
}

func redactAttr(_ []string, a slog.Attr) slog.Attr {
	if a.Value.Kind() == slog.KindString {
		a.Value = slog.StringValue(Redact(a.Value.String()))
	}
	return a
}

// Redact scrubs secret-shaped substrings from s.
func Redact(s string) string {
	for _, re := range secretPatterns {
		s = re.ReplaceAllString(s, redacted)
	}
	return s
}

type redactHandler struct{ slog.Handler }

func (h *redactHandler) Handle(ctx context.Context, r slog.Record) error {
	r.Message = Redact(r.Message)
	return h.Handler.Handle(ctx, r)
}

func (h *redactHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return &redactHandler{h.Handler.WithAttrs(as)}
}
func (h *redactHandler) WithGroup(name string) slog.Handler {
	return &redactHandler{h.Handler.WithGroup(name)}
}
