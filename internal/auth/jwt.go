package auth

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTConfig configures JWT/OIDC validation. HS256 uses Secret; RS256 (the OIDC shape) uses either a
// static IdP public key (PublicKeyPEM) or keys fetched automatically from a JWKS endpoint — set
// JWKSURL directly, or set only Issuer and the JWKS URI is discovered from the issuer's
// `.well-known/openid-configuration`. RoleClaim names the claim carrying the role/groups;
// Issuer/Audience are optional standard checks. JWKSTTL bounds key caching (default 15m).
type JWTConfig struct {
	Secret       string
	PublicKeyPEM []byte
	JWKSURL      string
	JWKSTTL      time.Duration
	RoleClaim    string
	Issuer       string
	Audience     string
}

type jwtValidator struct {
	cfg    JWTConfig
	rsaPub *rsa.PublicKey
	jwks   *jwksProvider
}

func newJWTValidator(cfg JWTConfig) (*jwtValidator, error) {
	if cfg.RoleClaim == "" {
		cfg.RoleClaim = "role"
	}
	v := &jwtValidator{cfg: cfg}
	if len(cfg.PublicKeyPEM) > 0 {
		pub, err := jwt.ParseRSAPublicKeyFromPEM(cfg.PublicKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("parse RSA public key: %w", err)
		}
		v.rsaPub = pub
	}
	// Enable JWKS auto-fetch when a JWKS URL is given, or when only an issuer is configured (no
	// static RS256 key and no HS256 secret) — the OIDC discovery path.
	if cfg.JWKSURL != "" || (cfg.Issuer != "" && v.rsaPub == nil && cfg.Secret == "") {
		v.jwks = newJWKSProvider(cfg.Issuer, cfg.JWKSURL, cfg.JWKSTTL)
	}
	if cfg.Secret == "" && v.rsaPub == nil && v.jwks == nil {
		return nil, errors.New("jwt mode requires a secret (HS256), a public key, or a JWKS URL/issuer (RS256)")
	}
	return v, nil
}

func (v *jwtValidator) validate(tokenStr string) (Principal, error) {
	keyfunc := func(t *jwt.Token) (any, error) {
		switch t.Method.(type) {
		case *jwt.SigningMethodHMAC:
			if v.cfg.Secret == "" {
				return nil, errors.New("HS-signed token but no secret configured")
			}
			return []byte(v.cfg.Secret), nil
		case *jwt.SigningMethodRSA:
			if v.jwks != nil {
				kid, _ := t.Header["kid"].(string)
				return v.jwks.keyByID(kid)
			}
			if v.rsaPub == nil {
				return nil, errors.New("RS-signed token but no public key configured")
			}
			return v.rsaPub, nil
		default:
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}
	}
	opts := []jwt.ParserOption{jwt.WithValidMethods([]string{"HS256", "RS256"})}
	if v.cfg.Issuer != "" {
		opts = append(opts, jwt.WithIssuer(v.cfg.Issuer))
	}
	if v.cfg.Audience != "" {
		opts = append(opts, jwt.WithAudience(v.cfg.Audience))
	}
	claims := jwt.MapClaims{}
	tok, err := jwt.ParseWithClaims(tokenStr, claims, keyfunc, opts...)
	if err != nil || !tok.Valid {
		return Principal{}, fmt.Errorf("invalid token: %w", err)
	}
	sub, _ := claims["sub"].(string)
	return Principal{Subject: sub, Role: extractRole(claims, v.cfg.RoleClaim)}, nil
}

// extractRole reads a role from a string claim, or the highest role from a groups array.
func extractRole(claims jwt.MapClaims, claim string) Role {
	switch v := claims[claim].(type) {
	case string:
		return ParseRole(v)
	case []any:
		best := RoleNone
		for _, g := range v {
			if r := ParseRole(fmt.Sprint(g)); r > best {
				best = r
			}
		}
		return best
	}
	return RoleNone
}
