package repo

import "testing"

func TestParseSecretSweepJSON(t *testing.T) {
	raw := []byte(`[
	  {"file":"src/.env","line":12,"name":"AWS Access Key","severity":"critical","category":"cloud","source":"file"},
	  {"file":"k8s/secret.yaml","line":7,"name":"Generic API Key","severity":"high","category":"generic","source":"k8s"}
	]`)
	out, err := parseReport(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 findings, got %d", len(out))
	}
	if out[0].File != "src/.env" || out[0].Line != 12 || out[0].Rule != "AWS Access Key" {
		t.Fatalf("bad first finding: %+v", out[0])
	}
}

func TestParseSecretSweepWrapped(t *testing.T) {
	raw := []byte(`{"findings":[{"file":"a.py","line":1,"name":"GCP Service Account Key","severity":"critical"}]}`)
	out, err := parseReport(raw)
	if err != nil || len(out) != 1 || out[0].Rule != "GCP Service Account Key" {
		t.Fatalf("wrapped parse failed: %v %+v", err, out)
	}
}

func TestParseSARIF(t *testing.T) {
	raw := []byte(`{
	  "version":"2.1.0",
	  "runs":[{"results":[
	    {"ruleId":"aws-access-key","level":"error","locations":[
	      {"physicalLocation":{"artifactLocation":{"uri":".env"},"region":{"startLine":3}}}]}
	  ]}]
	}`)
	out, err := parseReport(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].File != ".env" || out[0].Line != 3 || out[0].Severity != "high" {
		t.Fatalf("bad sarif finding: %+v", out)
	}
}

func TestSlug(t *testing.T) {
	cases := map[string]string{"AWS Access Key": "aws_access_key", "GCP SA Key!": "gcp_sa_key", "  Token  ": "token"}
	for in, want := range cases {
		if got := slug(in); got != want {
			t.Errorf("slug(%q)=%q want %q", in, got, want)
		}
	}
}

func TestSplitRepo(t *testing.T) {
	o, n := splitRepo("acme/billing")
	if o != "acme" || n != "billing" {
		t.Fatalf("splitRepo wrong: %q %q", o, n)
	}
}
