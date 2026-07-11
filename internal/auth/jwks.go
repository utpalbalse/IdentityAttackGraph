package auth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// jwksProvider fetches, parses, and caches RSA signing keys from an OIDC provider's JWKS endpoint,
// keyed by `kid`. The endpoint is either configured directly or discovered from the issuer's
// `.well-known/openid-configuration`. Keys are refreshed on TTL expiry or on a cache miss (which is
// exactly what happens after the IdP rotates a signing key), so validation keeps working across
// rotations with no restart. On a transient fetch failure a still-cached key is served (fail-safe).
type jwksProvider struct {
	issuer  string // for discovery when jwksURL is empty
	jwksURL string // explicit or discovered
	client  *http.Client
	ttl     time.Duration

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

func newJWKSProvider(issuer, jwksURL string, ttl time.Duration) *jwksProvider {
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return &jwksProvider{
		issuer:  issuer,
		jwksURL: jwksURL,
		client:  &http.Client{Timeout: 10 * time.Second},
		ttl:     ttl,
		keys:    map[string]*rsa.PublicKey{},
	}
}

// keyByID returns the RSA public key for kid, refreshing the JWKS if the key is unknown or the cache
// is stale. If a refresh fails but a matching key is already cached, the cached key is returned.
func (p *jwksProvider) keyByID(kid string) (*rsa.PublicKey, error) {
	p.mu.RLock()
	k, ok := p.keys[kid]
	fresh := !p.fetchedAt.IsZero() && time.Since(p.fetchedAt) < p.ttl
	p.mu.RUnlock()
	if ok && fresh {
		return k, nil
	}

	if err := p.refresh(); err != nil {
		if ok {
			return k, nil // serve the stale key rather than reject during an IdP blip
		}
		return nil, err
	}

	p.mu.RLock()
	defer p.mu.RUnlock()
	if k, ok := p.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("no JWKS signing key for kid %q", kid)
}

func (p *jwksProvider) refresh() error {
	url := p.jwksURL
	if url == "" {
		u, err := p.discover()
		if err != nil {
			return err
		}
		url = u
	}
	resp, err := p.client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks fetch %s: %s", url, resp.Status)
	}
	var set jwkSet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return fmt.Errorf("decode jwks: %w", err)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, jk := range set.Keys {
		if !strings.EqualFold(jk.Kty, "RSA") {
			continue // only RSA signing keys are supported (RS256)
		}
		if pk, err := jk.rsaKey(); err == nil {
			keys[jk.Kid] = pk
		}
	}
	if len(keys) == 0 {
		return errors.New("jwks contained no usable RSA keys")
	}
	p.mu.Lock()
	p.keys, p.fetchedAt, p.jwksURL = keys, time.Now(), url
	p.mu.Unlock()
	return nil
}

// discover resolves the JWKS URI from the issuer's OpenID configuration.
func (p *jwksProvider) discover() (string, error) {
	if p.issuer == "" {
		return "", errors.New("no jwks_url and no issuer to discover from")
	}
	url := strings.TrimRight(p.issuer, "/") + "/.well-known/openid-configuration"
	resp, err := p.client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("oidc discovery %s: %s", url, resp.Status)
	}
	var doc struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", fmt.Errorf("decode discovery doc: %w", err)
	}
	if doc.JWKSURI == "" {
		return "", errors.New("discovery document has no jwks_uri")
	}
	return doc.JWKSURI, nil
}

// jwk is a single JSON Web Key (the RSA subset we consume).
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"` // modulus, base64url
	E   string `json:"e"` // exponent, base64url
	Alg string `json:"alg"`
	Use string `json:"use"`
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

// rsaKey converts a JWK into an rsa.PublicKey.
func (k jwk) rsaKey() (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.N, "="))
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}
	eb, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.E, "="))
	if err != nil {
		return nil, fmt.Errorf("decode exponent: %w", err)
	}
	e := 0
	for _, b := range eb {
		e = e<<8 | int(b)
	}
	if e == 0 {
		return nil, errors.New("invalid zero exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}, nil
}
