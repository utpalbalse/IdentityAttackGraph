// Package migrations embeds the versioned SQL schema so the migrate binary can apply it without
// needing the source tree at runtime (works inside a minimal container image).
package migrations

import "embed"

// FS holds every migration file (NNNN_name.sql), applied in lexical order by cmd/migrate.
//
//go:embed *.sql
var FS embed.FS
