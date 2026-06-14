package aws

import "testing"

func TestAnalyzePolicies_AdminWildcard(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	a := analyzePolicies([]string{doc})
	if a.PrivilegeLevel != "admin" {
		t.Fatalf("expected admin, got %q", a.PrivilegeLevel)
	}
	if a.WildcardActionCount != 1 || a.WildcardResourceCount != 1 {
		t.Fatalf("expected 1 wildcard action and resource, got %d/%d", a.WildcardActionCount, a.WildcardResourceCount)
	}
}

func TestAnalyzePolicies_PrivEscalation(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Action":["iam:PassRole","lambda:CreateFunction"],"Resource":"*"}]}`
	a := analyzePolicies([]string{doc})
	if !a.HasPrivEscalation {
		t.Fatal("expected privilege escalation to be detected")
	}
	if a.PrivilegeLevel != "privileged" && a.PrivilegeLevel != "admin" {
		t.Fatalf("expected privileged level, got %q", a.PrivilegeLevel)
	}
}

func TestAnalyzePolicies_URLEncoded(t *testing.T) {
	// IAM returns documents URL-encoded; ensure we decode before parsing.
	encoded := `%7B%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22s3%3AGetObject%22%2C%22Resource%22%3A%22arn%3Aaws%3As3%3A%3A%3Ab%2F%2A%22%7D%5D%7D`
	a := analyzePolicies([]string{encoded})
	if a.PermissionCount != 1 {
		t.Fatalf("expected 1 permission from decoded policy, got %d", a.PermissionCount)
	}
	if len(a.Bindings) != 1 || a.Bindings[0].ResourceURN != "arn:aws:s3:::b/*" {
		t.Fatalf("expected one s3 binding, got %+v", a.Bindings)
	}
}

func TestAnalyzePolicies_ReadOnly(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Action":["s3:GetObject","ec2:DescribeInstances"],"Resource":"*"}]}`
	a := analyzePolicies([]string{doc})
	if a.PrivilegeLevel != "read" {
		t.Fatalf("expected read, got %q", a.PrivilegeLevel)
	}
	if a.HasPrivEscalation {
		t.Fatal("did not expect privilege escalation for read-only policy")
	}
}

func TestStringOrSlice(t *testing.T) {
	var s stringOrSlice
	if err := s.UnmarshalJSON([]byte(`"single"`)); err != nil || len(s) != 1 || s[0] != "single" {
		t.Fatalf("single string decode failed: %v %+v", err, s)
	}
	var arr stringOrSlice
	if err := arr.UnmarshalJSON([]byte(`["a","b"]`)); err != nil || len(arr) != 2 {
		t.Fatalf("array decode failed: %v %+v", err, arr)
	}
}
