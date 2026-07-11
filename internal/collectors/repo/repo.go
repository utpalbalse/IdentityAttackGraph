// Package repo turns repository secret exposures into normalized records. It has two sources:
//
//   - ReportPath: ingest a SecretSweep JSON or SARIF 2.1.0 report (compose with
//     https://github.com/utpalbalse/SecretSweep — run `secretsweep <repo> --json out.json` in CI,
//     then point this collector at out.json).
//   - ScanPath: scan a checked-out working tree directly with the built-in scanner (scan.go) — a
//     curated set of high-confidence provider patterns plus an entropy-guarded generic rule.
//
// Either way, per the threat model NHIID stores the location + a fingerprint, never the secret
// value. See docs/REPO_SCANNER.md.
package repo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/nhiid/nhiid/internal/collectors"
	"github.com/nhiid/nhiid/internal/models"
)

// Options configures one repository ingest. Provide either ReportPath (ingest a SecretSweep
// JSON/SARIF report) or ScanPath (scan a checked-out working tree with the built-in scanner).
type Options struct {
	ReportPath string // SecretSweep JSON or SARIF report
	ScanPath   string // path to a checked-out repo to scan directly (built-in scanner)
	Provider   string // github | gitlab (default github)
	Repo       string // "org/name"
	Org        string
	Name       string
	Visibility string // public | private | internal (default private)
}

type Collector struct{ opts Options }

func New(opts Options) *Collector { return &Collector{opts: opts} }

func (c *Collector) ID() string { return "repo" }

// finding is the normalized scanner finding both the JSON and SARIF parsers produce.
type finding struct {
	File     string
	Line     int
	Rule     string // pattern / secret-type name
	Severity string
}

func (c *Collector) Collect(ctx context.Context, accountRef string, cursor map[string]any) (collectors.Result, error) {
	var (
		findings []finding
		err      error
	)
	switch {
	case c.opts.ScanPath != "":
		if findings, err = scanDir(c.opts.ScanPath); err != nil {
			return collectors.Result{}, fmt.Errorf("scan %s: %w", c.opts.ScanPath, err)
		}
	case c.opts.ReportPath != "":
		raw, rerr := os.ReadFile(c.opts.ReportPath)
		if rerr != nil {
			return collectors.Result{}, fmt.Errorf("read report %s: %w", c.opts.ReportPath, rerr)
		}
		if findings, err = parseReport(raw); err != nil {
			return collectors.Result{}, fmt.Errorf("parse report: %w", err)
		}
	default:
		return collectors.Result{}, fmt.Errorf("repo: a report path or scan path is required")
	}

	provider := c.opts.Provider
	if provider == "" {
		provider = "github"
	}
	visibility := c.opts.Visibility
	if visibility == "" {
		visibility = "private"
	}
	org, name := c.opts.Org, c.opts.Name
	if c.opts.Repo != "" {
		org, name = splitRepo(c.opts.Repo)
	}
	if name == "" && c.opts.ScanPath != "" {
		name = filepath.Base(filepath.Clean(c.opts.ScanPath)) // derive repo name from the scanned dir
	}
	externalID := org + "/" + name
	now := time.Now().UTC()

	repoID := models.DeterministicID("repository", provider+":"+externalID)
	repository := models.Repository{
		ID: repoID, Provider: provider, ExternalID: externalID, Org: org, Name: name,
		Visibility: visibility, DefaultBranch: "main", LastScannedAt: &now, Source: "repo",
	}

	exposures := make([]models.Exposure, 0, len(findings))
	for _, f := range findings {
		rid := repoID
		exposures = append(exposures, models.Exposure{
			RepositoryID: &rid,
			Path:         f.File,
			Line:         f.Line,
			Pattern:      slug(f.Rule),
			Fingerprint:  fingerprint(externalID, f),
			Verified:     false, // SecretSweep flags exposure; live-verification is a separate step
			Source:       "repo",
		})
	}

	return collectors.Result{
		Repositories: []models.Repository{repository},
		Exposures:    exposures,
		NewCursor:    map[string]any{"scanned_at": now.Format(time.RFC3339), "findings": len(findings)},
	}, nil
}

func fingerprint(repo string, f finding) string {
	h := sha256.Sum256([]byte(repo + "|" + f.File + "|" + itoa(f.Line) + "|" + f.Rule))
	return "ss:" + hex.EncodeToString(h[:])[:24]
}
