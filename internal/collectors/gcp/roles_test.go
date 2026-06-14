package gcp

import (
	"testing"

	"github.com/nhiid/nhiid/internal/models"
)

func TestPrivilegeLevel(t *testing.T) {
	cases := []struct {
		roles []string
		want  string
	}{
		{[]string{"roles/owner"}, "admin"},
		{[]string{"roles/storage.admin"}, "admin"},
		{[]string{"roles/iam.serviceAccountTokenCreator"}, "privileged"},
		{[]string{"roles/storage.objectViewer"}, "read"},
		{[]string{"roles/pubsub.publisher"}, "write"},
	}
	for _, c := range cases {
		if got := privilegeLevel(c.roles); got != c.want {
			t.Errorf("privilegeLevel(%v)=%q want %q", c.roles, got, c.want)
		}
	}
}

func TestRoleCriticality(t *testing.T) {
	if roleCriticality("roles/owner") != models.CritCrownJewel {
		t.Error("owner should be crown_jewel")
	}
	if roleCriticality("roles/secretmanager.admin") != models.CritCrownJewel {
		t.Error("secretmanager.admin should be crown_jewel")
	}
	if roleCriticality("roles/compute.admin") != models.CritHigh {
		t.Error("compute.admin should be high")
	}
	if roleCriticality("roles/viewer") != models.CritLow {
		t.Error("viewer should be low")
	}
}

func TestImpersonationAndEscalation(t *testing.T) {
	if !impersonationRoles["roles/iam.serviceAccountTokenCreator"] {
		t.Error("tokenCreator must be an impersonation role")
	}
	if !hasEscalation([]string{"roles/iam.roleAdmin"}) {
		t.Error("roleAdmin must be escalation")
	}
	if hasEscalation([]string{"roles/storage.objectViewer"}) {
		t.Error("objectViewer is not escalation")
	}
}

func TestParseMember(t *testing.T) {
	cases := map[string][2]string{
		"serviceAccount:a@p.iam.gserviceaccount.com": {"serviceAccount", "a@p.iam.gserviceaccount.com"},
		"user:alice@example.com":                     {"user", "alice@example.com"},
		"allUsers":                                   {"allUsers", ""},
		"principalSet://iam.googleapis.com/x":        {"principalSet", "//iam.googleapis.com/x"},
	}
	for in, want := range cases {
		typ, id := parseMember(in)
		if typ != want[0] || id != want[1] {
			t.Errorf("parseMember(%q)=(%q,%q) want (%q,%q)", in, typ, id, want[0], want[1])
		}
	}
	if !isPublicMember("allUsers") || !isExternalMember("principalSet://x") || !isServiceAccountMember("serviceAccount:x") {
		t.Error("member classification helpers wrong")
	}
}
