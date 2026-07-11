package repo

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nhiid/nhiid/internal/models"
)

func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestScanDirFindsSecrets(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".env", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nDB_HOST=localhost\n")
	writeFile(t, dir, "config/app.yaml", "api_key: 9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c\n")
	writeFile(t, dir, "id_rsa", "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n")
	writeFile(t, dir, "README.md", "just docs, api_key = short\n")           // 'short' -> low entropy, no fire
	writeFile(t, dir, "node_modules/pkg/leak.txt", "AKIAIOSFODNN7EXAMPLE\n") // skipped dir

	got, err := scanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	byRule := map[string]int{}
	for _, f := range got {
		byRule[f.Rule]++
		if f.File == "" || f.Line <= 0 {
			t.Errorf("finding missing location: %+v", f)
		}
	}
	if byRule["aws_akia"] != 1 {
		t.Errorf("aws_akia = %d, want 1 (node_modules must be skipped)", byRule["aws_akia"])
	}
	if byRule["private_key"] != 1 {
		t.Errorf("private_key = %d, want 1", byRule["private_key"])
	}
	if byRule["generic_secret_assignment"] != 1 {
		t.Errorf("generic_secret_assignment = %d, want 1 (high-entropy only)", byRule["generic_secret_assignment"])
	}
}

func TestScanCollectorEndToEnd(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "src/creds.py", "TOKEN = 'ghp_012345678901234567890123456789abcdef'\n")

	c := New(Options{ScanPath: dir, Repo: "acme/widgets", Visibility: "private"})
	res, err := c.Collect(context.Background(), "repo:acme/widgets", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Repositories) != 1 || res.Repositories[0].Name != "widgets" {
		t.Fatalf("repository = %+v", res.Repositories)
	}
	if len(res.Exposures) != 1 {
		t.Fatalf("exposures = %d, want 1", len(res.Exposures))
	}
	ex := res.Exposures[0]
	if ex.Pattern != "github_pat" || ex.Path != "src/creds.py" || ex.Line != 1 {
		t.Errorf("exposure = %+v", ex)
	}
	// Threat-model invariant: the secret value must never appear in any stored field.
	if containsSecret(ex, "ghp_012345678901234567890123456789abcdef") {
		t.Fatal("exposure leaked the secret value")
	}
}

func containsSecret(ex models.Exposure, secret string) bool {
	for _, s := range []string{ex.Path, ex.Pattern, ex.Fingerprint, ex.CommitSHA} {
		if s == secret {
			return true
		}
	}
	return false
}

func TestScanEntropyFloor(t *testing.T) {
	// A low-entropy assignment must not fire the generic rule.
	if h := shannonEntropy("aaaaaaaaaaaaaaaa"); h >= entropyFloor {
		t.Errorf("repeated chars entropy = %.2f, expected < %.1f", h, entropyFloor)
	}
	if h := shannonEntropy("9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c"); h < entropyFloor {
		t.Errorf("random hex entropy = %.2f, expected >= %.1f", h, entropyFloor)
	}
}
