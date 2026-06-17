package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func ok(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }

func do(h http.Handler, token string) int {
	req := httptest.NewRequest("GET", "/x", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestOffModeAllowsAll(t *testing.T) {
	a := New("off", nil)
	h := a.Authenticate(a.Require(RoleAdmin)(http.HandlerFunc(ok)))
	if code := do(h, ""); code != http.StatusOK {
		t.Fatalf("off mode should allow admin route, got %d", code)
	}
}

func TestTokenModeEnforces(t *testing.T) {
	a := New("token", []TokenEntry{
		{Token: "v", Subject: "viewer@x", Role: "viewer"},
		{Token: "a", Subject: "admin@x", Role: "admin"},
	})
	adminRoute := func() http.Handler { return a.Authenticate(a.Require(RoleAdmin)(http.HandlerFunc(ok))) }
	viewerRoute := func() http.Handler { return a.Authenticate(a.Require(RoleViewer)(http.HandlerFunc(ok))) }

	if code := do(adminRoute(), ""); code != http.StatusUnauthorized {
		t.Fatalf("no token should be 401, got %d", code)
	}
	if code := do(adminRoute(), "bad"); code != http.StatusUnauthorized {
		t.Fatalf("bad token should be 401, got %d", code)
	}
	if code := do(adminRoute(), "v"); code != http.StatusForbidden {
		t.Fatalf("viewer on admin route should be 403, got %d", code)
	}
	if code := do(adminRoute(), "a"); code != http.StatusOK {
		t.Fatalf("admin on admin route should be 200, got %d", code)
	}
	if code := do(viewerRoute(), "v"); code != http.StatusOK {
		t.Fatalf("viewer on viewer route should be 200, got %d", code)
	}
}

func TestParseRoleHierarchy(t *testing.T) {
	if !(RoleViewer < RoleAnalyst && RoleAnalyst < RoleAdmin) {
		t.Fatal("role ordering wrong")
	}
	if ParseRole("ADMIN") != RoleAdmin || ParseRole("nonsense") != RoleNone {
		t.Fatal("ParseRole wrong")
	}
}
