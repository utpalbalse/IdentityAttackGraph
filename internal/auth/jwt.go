package auth

import (
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// JWTConfig configures JWT/OIDC validation. HS256 uses Secret; RS256 (the OIDC shape) uses an IdP
// public key in PEM. RoleClaim names the claim carrying the role/groups; Issuer/Audience are
// optional standard checks. (Auto-fetching RS256 keys from a JWKS URL is the remaining step toward
// full OIDC; a configured public key is already interoperable with any IdP.)
type JWTConfig struct {
	Secret       string
	PublicKeyPEM []byte
	RoleClaim    string
	Issuer       string
	Audience     string
}

type jwtValidator struct {
	cfg    JWTConfig
	rsaPub *rsa.PublicKey
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
	if cfg.Secret == "" && v.rsaPub == nil {
		return nil, errors.New("jwt mode requires a secret (HS256) or public key (RS256)")
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
