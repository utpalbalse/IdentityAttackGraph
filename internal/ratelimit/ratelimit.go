// Package ratelimit provides a Redis-backed fixed-window limiter and HTTP middleware. This realizes
// the per-principal rate limiting called for in the threat model (DoS mitigation). It fails open:
// if Redis is unavailable the request is allowed, so an outage never blocks the platform.
package ratelimit

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/nhiid/nhiid/internal/auth"
	"github.com/redis/go-redis/v9"
)

// Limiter is a per-key fixed-window counter in Redis.
type Limiter struct {
	rdb    *redis.Client
	limit  int
	window time.Duration
}

// Connect parses a redis URL and returns a Limiter, or (nil,err) if the URL is bad. A nil Limiter
// is safe to use (Allow returns true), so callers can treat connection failure as "disabled".
func Connect(redisURL string, limit int, window time.Duration) (*Limiter, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, err
	}
	return &Limiter{rdb: redis.NewClient(opt), limit: limit, window: window}, nil
}

// Allow increments the window counter for key and reports whether it is within the limit.
// Fails open on Redis errors.
func (l *Limiter) Allow(ctx context.Context, key string) (allowed bool, remaining int) {
	if l == nil || l.rdb == nil {
		return true, l.limit
	}
	bucket := "rl:" + key + ":" + time.Now().Truncate(l.window).Format("150405")
	n, err := l.rdb.Incr(ctx, bucket).Result()
	if err != nil {
		return true, l.limit // fail open
	}
	if n == 1 {
		l.rdb.Expire(ctx, bucket, l.window)
	}
	rem := l.limit - int(n)
	if rem < 0 {
		rem = 0
	}
	return int(n) <= l.limit, rem
}

// Middleware enforces the limit per authenticated principal (or remote IP if unauthenticated),
// returning 429 with Retry-After when exceeded.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := clientKey(r)
		ok, remaining := l.Allow(r.Context(), key)
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
		if !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(l.window.Seconds())))
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func clientKey(r *http.Request) string {
	if p, ok := auth.FromContext(r.Context()); ok && p.Subject != "" {
		return "sub:" + p.Subject
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return "ip:" + ip
	}
	return "ip:" + r.RemoteAddr
}
