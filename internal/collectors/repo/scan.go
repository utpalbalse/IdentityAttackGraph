package repo

import (
	"bufio"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// secretRule is one high-confidence secret pattern. When entropy is set, the last capture group must
// clear an entropy floor to fire (cuts false positives on non-secret `key = value` assignments).
type secretRule struct {
	name    string
	re      *regexp.Regexp
	entropy bool
}

// scanRules are curated high-signal provider patterns plus a guarded generic assignment rule.
// Patterns match the *shape* of a secret; the matched value is never stored (threat-model rule).
var scanRules = []secretRule{
	{name: "aws_akia", re: regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA)[0-9A-Z]{16}\b`)},
	{name: "github_pat", re: regexp.MustCompile(`\bgh[posru]_[0-9A-Za-z]{36,}\b`)},
	{name: "gcp_service_account_key", re: regexp.MustCompile(`"private_key"\s*:\s*"-----BEGIN`)},
	{name: "private_key", re: regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`)},
	{name: "slack_token", re: regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`)},
	{name: "google_api_key", re: regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`)},
	{name: "jwt", re: regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b`)},
	{name: "generic_secret_assignment", entropy: true,
		re: regexp.MustCompile(`(?i)(?:api[_-]?key|secret|token|password|passwd)\s*[:=]\s*['"]?([A-Za-z0-9/+=_\-]{16,})['"]?`)},
}

// skipDirs are never scanned (VCS metadata, vendored deps, build output).
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true,
	"build": true, ".venv": true, "venv": true, "target": true, ".terraform": true,
}

const (
	maxScanFileBytes = 1 << 20 // 1 MiB — skip larger files (likely assets/data)
	entropyFloor     = 3.5     // bits/char for the generic rule
)

// scanDir walks root and returns secret findings. Unreadable entries are skipped, not fatal.
func scanDir(root string) ([]finding, error) {
	var out []finding
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil || info.Size() == 0 || info.Size() > maxScanFileBytes {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			rel = path
		}
		out = append(out, scanFile(path, filepath.ToSlash(rel))...)
		return nil
	})
	return out, err
}

func scanFile(path, rel string) []finding {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []finding
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), maxScanFileBytes)
	line := 0
	for sc.Scan() {
		line++
		text := sc.Text()
		if strings.IndexByte(text, 0) >= 0 {
			return out // NUL byte -> binary file, stop scanning it
		}
		// Specific provider rules first; the generic assignment rule only fires as a fallback when
		// no specific rule matched the line (avoids double-reporting the same secret).
		specific := false
		genericHit := false
		for _, r := range scanRules {
			if r.entropy {
				if m := r.re.FindStringSubmatch(text); m != nil && shannonEntropy(m[len(m)-1]) >= entropyFloor {
					genericHit = true
				}
				continue
			}
			if r.re.MatchString(text) {
				specific = true
				out = append(out, finding{File: rel, Line: line, Rule: r.name, Severity: "high"})
			}
		}
		if genericHit && !specific {
			out = append(out, finding{File: rel, Line: line, Rule: "generic_secret_assignment", Severity: "high"})
		}
	}
	return out
}

// shannonEntropy returns the per-character Shannon entropy (bits) of s.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
