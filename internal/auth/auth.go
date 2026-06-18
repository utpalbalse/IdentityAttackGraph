// Package auth provides bearer-token RBAC for the API. Two modes:
//
//   - "off"   (default): no enforcement — every request is treated as admin. The demo and UI work
//     unauthenticated; the actor for audit still comes from the X-Actor header.
//   - "token": requests must carry `Authorization: Bearer <token>`; each token maps to a subject
//     and a role (viewer < analyst < admin). Per-route minimum roles are enforced.
//
// OIDC/JWT validation (RS256 via JWKS) is the intended production mode and slots in behind the same
// Authenticate middleware; see docs/AUTH.md.
package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
)

type Role int

const (
	RoleNone Role = iota
	RoleViewer
	RoleAnalyst
	RoleAdmin
)

func ParseRole(s string) Role {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "viewer":
		return RoleViewer
	case "analyst":
		return RoleAnalyst
	case "admin":
		return RoleAdmin
	default:
		return RoleNone
	}
}

func (r Role) String() string {
	switch r {
	case RoleViewer:
		return "viewer"
	case RoleAnalyst:
		return "analyst"
	case RoleAdmin:
		return "admin"
	default:
		return "none"
	}
}

// Principal is the authenticated caller.
type Principal struct {
	Subject string
	Role    Role
}

type ctxKey struct{}

// TokenEntry maps a bearer token to a subject + role (token-mode config).
type TokenEntry struct {
	Token   string `json:"token"`
	Subject string `json:"subject"`
	Role    string `json:"role"`
}

// Auth holds the resolved configuration.
type Auth struct {
	mode   string
	tokens map[string]Principal // token -> principal (token mode)
	jwt    *jwtValidator        // jwt mode
}

// New builds an Auth. mode is "off", "token", or "jwt". For token mode pass entries; for jwt mode
// pass jwtCfg. Returns an error only if jwt config is invalid.
func New(mode string, entries []TokenEntry, jwtCfg *JWTConfig) (*Auth, error) {
	a := &Auth{mode: strings.ToLower(strings.TrimSpace(mode)), tokens: map[string]Principal{}}
	if a.mode == "" {
		a.mode = "off"
	}
	for _, e := range entries {
		if e.Token == "" {
			continue
		}
		a.tokens[e.Token] = Principal{Subject: e.Subject, Role: ParseRole(e.Role)}
	}
	if a.mode == "jwt" {
		if jwtCfg == nil {
			return nil, errInvalid("jwt mode requires JWT config")
		}
		v, err := newJWTValidator(*jwtCfg)
		if err != nil {
			return nil, err
		}
		a.jwt = v
	}
	return a, nil
}

type errInvalid string

func (e errInvalid) Error() string { return string(e) }

// LoadTokens reads token entries from the NHIID_AUTH_TOKENS env var (JSON array) or, if empty, from
// the given file path (also JSON array). Returns nil if neither is set.
func LoadTokens(file string) ([]TokenEntry, error) {
	if raw := os.Getenv("NHIID_AUTH_TOKENS"); raw != "" {
		var out []TokenEntry
		return out, json.Unmarshal([]byte(raw), &out)
	}
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		var out []TokenEntry
		return out, json.Unmarshal(b, &out)
	}
	return nil, nil
}

func (a *Auth) Enforced() bool { return a.mode == "token" || a.mode == "jwt" }

// Authenticate resolves the principal and stores it in the request context. In token mode a missing
// or unknown token yields 401. In off mode every caller is admin (subject from X-Actor).
func (a *Auth) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p Principal
		switch a.mode {
		case "token":
			tok := bearer(r)
			pr, ok := a.tokens[tok]
			if tok == "" || !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			p = pr
		case "jwt":
			pr, err := a.jwt.validate(bearer(r))
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			p = pr
		default:
			// off mode: full access; subject from X-Actor for audit attribution.
			subj := r.Header.Get("X-Actor")
			if subj == "" {
				subj = "anonymous"
			}
			p = Principal{Subject: subj, Role: RoleAdmin}
		}
		ctx := context.WithValue(r.Context(), ctxKey{}, p)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Require returns middleware enforcing a minimum role. No-op effect in off mode (caller is admin).
func (a *Auth) Require(min Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, _ := FromContext(r.Context())
			if p.Role < min {
				http.Error(w, "forbidden: requires "+min.String(), http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// FromContext returns the authenticated principal, if any.
func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(Principal)
	return p, ok
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}
