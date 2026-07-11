package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// jwksServer stands up an OIDC provider: a JWKS endpoint exposing pub under kid, and a discovery
// document pointing at it.
func jwksServer(t *testing.T, kid string, pub *rsa.PublicKey) *httptest.Server {
	t.Helper()
	nB64 := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	eB64 := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	jwks := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":%q,"use":"sig","alg":"RS256","n":%q,"e":%q}]}`, kid, nB64, eB64)

	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(jwks)) })
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, srv.URL, srv.URL+"/jwks")
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func signRS256(t *testing.T, priv *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func TestJWKSValidateByURL(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t, "k1", &priv.PublicKey)

	v, err := newJWTValidator(JWTConfig{JWKSURL: srv.URL + "/jwks", RoleClaim: "role"})
	if err != nil {
		t.Fatal(err)
	}
	tok := signRS256(t, priv, "k1", jwt.MapClaims{"sub": "alice", "role": "admin"})
	p, err := v.validate(tok)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if p.Subject != "alice" || p.Role != RoleAdmin {
		t.Fatalf("principal = %+v, want alice/admin", p)
	}
}

func TestJWKSDiscoveryFromIssuer(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t, "k1", &priv.PublicKey)

	// Only the issuer is configured — the JWKS URI must be discovered from .well-known.
	v, err := newJWTValidator(JWTConfig{Issuer: srv.URL, RoleClaim: "role"})
	if err != nil {
		t.Fatal(err)
	}
	tok := signRS256(t, priv, "k1", jwt.MapClaims{"sub": "svc", "role": "analyst", "iss": srv.URL})
	p, err := v.validate(tok)
	if err != nil {
		t.Fatalf("validate via discovery: %v", err)
	}
	if p.Role != RoleAnalyst {
		t.Fatalf("role = %v, want analyst", p.Role)
	}
}

func TestJWKSUnknownKidRejected(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t, "k1", &priv.PublicKey)

	v, _ := newJWTValidator(JWTConfig{JWKSURL: srv.URL + "/jwks", RoleClaim: "role"})
	tok := signRS256(t, priv, "rogue-kid", jwt.MapClaims{"sub": "mallory", "role": "admin"})
	if _, err := v.validate(tok); err == nil {
		t.Fatal("token signed with an unknown kid must be rejected")
	}
}

func TestJWKSWrongKeyRejected(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t, "k1", &priv.PublicKey)

	v, _ := newJWTValidator(JWTConfig{JWKSURL: srv.URL + "/jwks", RoleClaim: "role"})
	// Signed with a different private key but the advertised kid — signature must fail.
	tok := signRS256(t, other, "k1", jwt.MapClaims{"sub": "mallory", "role": "admin"})
	if _, err := v.validate(tok); err == nil {
		t.Fatal("token signed with the wrong key must be rejected")
	}
}
