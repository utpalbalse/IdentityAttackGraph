package aws

import (
	"testing"

	"github.com/nhiid/nhiid/internal/models"
)

func TestCriticalityFromTag(t *testing.T) {
	crown := []string{"crown_jewel", "crown-jewel", "CrownJewel", "crown", "CRITICAL", " Crown_Jewel "}
	for _, v := range crown {
		if c, ok := criticalityFromTag(v); !ok || c != models.CritCrownJewel {
			t.Errorf("criticalityFromTag(%q) = %v/%v, want crown_jewel/true", v, c, ok)
		}
	}
	ranked := map[string]models.Criticality{"high": models.CritHigh, "medium": models.CritMedium, "med": models.CritMedium, "low": models.CritLow}
	for v, want := range ranked {
		if c, ok := criticalityFromTag(v); !ok || c != want {
			t.Errorf("criticalityFromTag(%q) = %v/%v, want %v/true", v, c, ok, want)
		}
	}
	for _, v := range []string{"", "sensitive", "p0", "yes"} {
		if _, ok := criticalityFromTag(v); ok {
			t.Errorf("criticalityFromTag(%q) should not parse", v)
		}
	}
}

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"arn:aws:s3:::prod-billing", "arn:aws:s3:::prod-billing", true}, // exact
		{"*", "arn:aws:s3:::anything", true},
		{"arn:aws:s3:::prod-*", "arn:aws:s3:::prod-billing", true},
		{"arn:aws:s3:::prod-billing/*", "arn:aws:s3:::prod-billing/data.csv", true},
		{"arn:aws:s3:::prod-billing/*", "arn:aws:s3:::prod-billing", false}, // no trailing object
		{"arn:aws:s3:::prod-?illing", "arn:aws:s3:::prod-billing", true},
		{"arn:aws:s3:::prod-?", "arn:aws:s3:::prod-billing", false},
		{"arn:aws:s3:::dev-*", "arn:aws:s3:::prod-billing", false},
		{"arn:aws:secretsmanager:*:*:secret:prod/*", "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/app/master-AbCd", true},
		{"", "x", false},
		{"*", "", true},
	}
	for _, c := range cases {
		if got := globMatch(c.pattern, c.s); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", c.pattern, c.s, got, c.want)
		}
	}
}

func TestResourceReaches(t *testing.T) {
	bucket := "arn:aws:s3:::prod-billing"
	cases := []struct {
		name, policyResource, tagged string
		want                         bool
	}{
		{"exact bucket", bucket, bucket, true},
		{"objects under tagged bucket", "arn:aws:s3:::prod-billing/*", bucket, true},
		{"star reaches everything", "*", bucket, true},
		{"prefix wildcard", "arn:aws:s3:::prod-*", bucket, true},
		{"unrelated bucket", "arn:aws:s3:::dev-scratch/*", bucket, false},
		{"different service", "arn:aws:dynamodb:us-east-1:1:table/prod", bucket, false},
		{"empty policy resource", "", bucket, false},
		{"tagged secret via bucket pattern", "arn:aws:s3:::prod-billing/*", "arn:aws:secretsmanager:us-east-1:1:secret:x", false},
	}
	for _, c := range cases {
		if got := resourceReaches(c.policyResource, c.tagged); got != c.want {
			t.Errorf("%s: resourceReaches(%q, %q) = %v, want %v", c.name, c.policyResource, c.tagged, got, c.want)
		}
	}
}

func TestServiceOfARN(t *testing.T) {
	cases := map[string]string{
		"arn:aws:s3:::prod-billing":                   "s3",
		"arn:aws:secretsmanager:us-east-1:1:secret:x": "secretsmanager",
		"arn:aws:dynamodb:us-east-1:1:table/prod":     "dynamodb",
		"*":          "*",
		"not-an-arn": "",
	}
	for arn, want := range cases {
		if got := serviceOfARN(arn); got != want {
			t.Errorf("serviceOfARN(%q) = %q, want %q", arn, got, want)
		}
	}
}

func TestActionsCoverService(t *testing.T) {
	if !actionsCoverService([]string{"s3:GetObject"}, "s3") {
		t.Error("s3 action should cover the s3 service")
	}
	if !actionsCoverService([]string{"ec2:DescribeInstances", "s3:PutObject"}, "s3") {
		t.Error("any matching action in the set should count")
	}
	if !actionsCoverService([]string{"*"}, "s3") || !actionsCoverService([]string{"*:*"}, "s3") {
		t.Error("full wildcard actions cover every service")
	}
	if actionsCoverService([]string{"ec2:DescribeInstances"}, "s3") {
		t.Error("an ec2-only action must NOT cover the s3 service")
	}
	if !actionsCoverService([]string{"ec2:DescribeInstances"}, "") {
		t.Error("an unknown service should not be used to exclude")
	}
}

// buildResolver is a small helper for the criticalityFor tests.
func buildResolver(pairs map[string]models.Criticality) *critResolver {
	r := newCritResolver()
	for arn, c := range pairs {
		r.set(arn, c)
	}
	return r
}

func TestCriticalityForElevatesTaggedResource(t *testing.T) {
	r := buildResolver(map[string]models.Criticality{
		"arn:aws:s3:::prod-billing": models.CritCrownJewel,
	})

	// A write to objects in the tagged bucket reaches the crown jewel.
	if got := r.criticalityFor("arn:aws:s3:::prod-billing/*", []string{"s3:PutObject"}); got != models.CritCrownJewel {
		t.Errorf("objects in tagged bucket = %v, want crown_jewel", got)
	}
	// Exact bucket ARN with an s3 action.
	if got := r.criticalityFor("arn:aws:s3:::prod-billing", []string{"s3:GetObject"}); got != models.CritCrownJewel {
		t.Errorf("exact bucket = %v, want crown_jewel", got)
	}
	// Admin-on-everything reaches it too.
	if got := r.criticalityFor("*", []string{"*"}); got != models.CritCrownJewel {
		t.Errorf("star resource with star action = %v, want crown_jewel", got)
	}
}

func TestCriticalityForRequiresActionToReachService(t *testing.T) {
	r := buildResolver(map[string]models.Criticality{
		"arn:aws:s3:::prod-billing": models.CritCrownJewel,
	})
	// Resource "*" but the action is ec2-only: it cannot touch the S3 crown jewel, so no elevation.
	if got := r.criticalityFor("*", []string{"ec2:DescribeInstances"}); got != models.CritLow {
		t.Errorf("ec2 action on * = %v, want low (must not elevate on an unrelated crown jewel)", got)
	}
}

func TestCriticalityForNoMatch(t *testing.T) {
	r := buildResolver(map[string]models.Criticality{
		"arn:aws:s3:::prod-billing": models.CritCrownJewel,
	})
	if got := r.criticalityFor("arn:aws:s3:::dev-scratch/*", []string{"s3:PutObject"}); got != models.CritLow {
		t.Errorf("untagged bucket = %v, want low", got)
	}
}

func TestCriticalityForTakesHighest(t *testing.T) {
	r := buildResolver(map[string]models.Criticality{
		"arn:aws:s3:::logs":         models.CritHigh,
		"arn:aws:s3:::prod-billing": models.CritCrownJewel,
	})
	// A policy on "*" reaches both; the crown jewel wins.
	if got := r.criticalityFor("*", []string{"s3:*"}); got != models.CritCrownJewel {
		t.Errorf("got %v, want the highest (crown_jewel)", got)
	}
}

func TestCriticalityForNilAndEmptyResolver(t *testing.T) {
	var nilR *critResolver
	if got := nilR.criticalityFor("arn:aws:s3:::prod-billing", []string{"s3:*"}); got != models.CritLow {
		t.Errorf("nil resolver = %v, want low", got)
	}
	if got := newCritResolver().criticalityFor("arn:aws:s3:::prod-billing", []string{"s3:*"}); got != models.CritLow {
		t.Errorf("empty resolver = %v, want low", got)
	}
	if nilR.len() != 0 {
		t.Error("nil resolver len should be 0")
	}
}

func TestResolverSetKeepsHighest(t *testing.T) {
	r := newCritResolver()
	r.set("arn:aws:s3:::b", models.CritMedium)
	r.set("arn:aws:s3:::b", models.CritCrownJewel)
	r.set("arn:aws:s3:::b", models.CritHigh) // lower than crown jewel; must not downgrade
	if r.tagged["arn:aws:s3:::b"] != models.CritCrownJewel {
		t.Errorf("set kept %v, want crown_jewel (highest wins)", r.tagged["arn:aws:s3:::b"])
	}
	r.set("", models.CritCrownJewel) // empty ARN ignored
	if r.len() != 1 {
		t.Errorf("len = %d, want 1", r.len())
	}
}

// TestAnalyzePoliciesElevatesTaggedBinding is the end-to-end check: a policy granting s3:* on a
// tagged crown-jewel bucket produces a crown_jewel binding, where without the tag it would cap at
// the action-inferred level.
func TestAnalyzePoliciesElevatesTaggedBinding(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Action":["s3:PutObject","s3:GetObject"],"Resource":"arn:aws:s3:::prod-billing/*"}]}`

	// Without tags: the action-inferred criticality for a specific (non-wildcard) resource is medium
	// at most (data-service write), never crown jewel.
	base := analyzePolicies([]string{doc}, nil)
	if len(base.Bindings) != 1 {
		t.Fatalf("want 1 binding, got %d", len(base.Bindings))
	}
	if base.Bindings[0].Criticality == models.CritCrownJewel {
		t.Fatal("without a tag, a binding must not be crown_jewel")
	}

	// With the bucket tagged, the same binding is elevated.
	r := buildResolver(map[string]models.Criticality{"arn:aws:s3:::prod-billing": models.CritCrownJewel})
	tagged := analyzePolicies([]string{doc}, r)
	if tagged.Bindings[0].Criticality != models.CritCrownJewel {
		t.Errorf("tagged bucket binding = %v, want crown_jewel", tagged.Bindings[0].Criticality)
	}
}

func TestAnalyzePoliciesTagDoesNotElevateUnreachableResource(t *testing.T) {
	// The policy touches a different bucket than the tagged one: no elevation.
	doc := `{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::dev-scratch/*"}]}`
	r := buildResolver(map[string]models.Criticality{"arn:aws:s3:::prod-billing": models.CritCrownJewel})
	a := analyzePolicies([]string{doc}, r)
	if a.Bindings[0].Criticality == models.CritCrownJewel {
		t.Error("a binding on an untagged bucket must not be elevated")
	}
}

func TestOptionsCriticalityTagKey(t *testing.T) {
	if got := (Options{}).criticalityTagKey(); got != DefaultCriticalityTagKey {
		t.Errorf("default = %q, want %q", got, DefaultCriticalityTagKey)
	}
	if got := (Options{CriticalityTagKey: "team:crit"}).criticalityTagKey(); got != "team:crit" {
		t.Errorf("override = %q, want team:crit", got)
	}
	if got := (Options{CriticalityTagKey: "-"}).criticalityTagKey(); got != "" {
		t.Errorf("disable sentinel = %q, want empty", got)
	}
}
