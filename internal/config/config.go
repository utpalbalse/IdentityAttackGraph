// Package config loads NHIID configuration from a YAML file with environment overrides.
// Override any leaf via NHIID_<SECTION>_<KEY>, e.g. NHIID_DATABASE_DSN. Secrets should be
// supplied via env / a secret store, never committed to the YAML.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server    Server    `yaml:"server"`
	Database  Database  `yaml:"database"`
	Queue     Queue     `yaml:"queue"`
	Cache     Cache     `yaml:"cache"`
	Telemetry Telemetry `yaml:"telemetry"`
	Detection Detection `yaml:"detection"`
	Risk      Risk      `yaml:"risk"`
	Auth      Auth      `yaml:"auth"`
	Notify    Notify    `yaml:"notify"`
}

// Notify configures outbound alerting for new findings. Disabled by default. The worker's alert
// sweep dispatches findings at or above MinSeverity to a Slack incoming webhook or a generic JSON
// webhook. See internal/notify + docs/ALERTING.md.
type Notify struct {
	Enabled     bool   `yaml:"enabled"`
	Kind        string `yaml:"kind"`         // slack | webhook
	WebhookURL  string `yaml:"webhook_url"`  // supply via NHIID_NOTIFY_WEBHOOK_URL in production
	MinSeverity string `yaml:"min_severity"` // info|low|medium|high|critical
}

// Auth configures API RBAC. Mode "off" (default) leaves the API open; "token" enforces bearer-token
// roles. Tokens come from NHIID_AUTH_TOKENS (JSON) or TokensFile. See internal/auth + docs/AUTH.md.
type Auth struct {
	Mode       string `yaml:"mode"`
	TokensFile string `yaml:"tokens_file"`
	// jwt mode (mode: "jwt")
	JWTSecret        string `yaml:"jwt_secret"`          // HS256 shared secret
	JWTPublicKeyFile string `yaml:"jwt_public_key_file"` // RS256 IdP public key (PEM)
	JWTRoleClaim     string `yaml:"jwt_role_claim"`      // claim holding role/groups (default "role")
	JWTIssuer        string `yaml:"jwt_issuer"`
	JWTAudience      string `yaml:"jwt_audience"`
}

type Server struct {
	HTTPAddr        string `yaml:"http_addr"`
	MetricsAddr     string `yaml:"metrics_addr"`
	ReadTimeout     int    `yaml:"read_timeout_seconds"`
	WriteTimeout    int    `yaml:"write_timeout_seconds"`
	RateLimitPerMin int    `yaml:"rate_limit_per_min"` // 0 disables the Redis rate limiter
}

type Database struct {
	DSN      string `yaml:"dsn"`
	MaxConns int32  `yaml:"max_conns"`
	MinConns int32  `yaml:"min_conns"`
}

type Queue struct {
	NATSURL string `yaml:"nats_url"`
	Stream  string `yaml:"stream"`
}

type Cache struct {
	RedisURL string `yaml:"redis_url"`
}

type Telemetry struct {
	LogLevel     string `yaml:"log_level"`
	LogFormat    string `yaml:"log_format"`
	OTelEndpoint string `yaml:"otel_endpoint"`
}

type Detection struct {
	StaleWindowDays        int      `yaml:"stale_window_days"`
	MaxCredAgeDays         int      `yaml:"max_cred_age_days"`
	MaxRotationAgeDays     int      `yaml:"max_rotation_age_days"`
	ImpossibleTravelMaxKMH float64  `yaml:"impossible_travel_max_kmh"`
	UsageSpikeSigma        float64  `yaml:"usage_spike_sigma"`
	AnomalyWarmupEvents    int      `yaml:"anomaly_warmup_events"`
	EgressAllowlist        []string `yaml:"egress_allowlist"`
}

type Risk struct {
	WeightsFile string `yaml:"weights_file"`
}

// Load reads the YAML at path then applies NHIID_* env overrides for common leaves.
func Load(path string) (*Config, error) {
	c := Defaults()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config %s: %w", path, err)
		}
		if err := yaml.Unmarshal(b, c); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	}
	applyEnv(c)
	return c, c.Validate()
}

// Defaults returns a usable local-dev configuration.
func Defaults() *Config {
	return &Config{
		Server:    Server{HTTPAddr: ":8080", MetricsAddr: ":9090", ReadTimeout: 15, WriteTimeout: 30, RateLimitPerMin: 600},
		Database:  Database{DSN: "postgres://nhiid:nhiid@localhost:5432/nhiid?sslmode=disable", MaxConns: 20, MinConns: 2},
		Queue:     Queue{NATSURL: "nats://localhost:4222", Stream: "nhiid-jobs"},
		Cache:     Cache{RedisURL: "redis://localhost:6379/0"},
		Telemetry: Telemetry{LogLevel: "info", LogFormat: "json"},
		Detection: Detection{
			StaleWindowDays: 90, MaxCredAgeDays: 365, MaxRotationAgeDays: 180,
			ImpossibleTravelMaxKMH: 900, UsageSpikeSigma: 4, AnomalyWarmupEvents: 50,
		},
		Risk:   Risk{WeightsFile: "configs/risk_weights.yaml"},
		Auth:   Auth{Mode: "off"},
		Notify: Notify{Enabled: false, Kind: "slack", MinSeverity: "high"},
	}
}

func applyEnv(c *Config) {
	if v := os.Getenv("NHIID_DATABASE_DSN"); v != "" {
		c.Database.DSN = v
	}
	if v := os.Getenv("NHIID_QUEUE_NATS_URL"); v != "" {
		c.Queue.NATSURL = v
	}
	if v := os.Getenv("NHIID_CACHE_REDIS_URL"); v != "" {
		c.Cache.RedisURL = v
	}
	if v := os.Getenv("NHIID_SERVER_HTTP_ADDR"); v != "" {
		c.Server.HTTPAddr = v
	}
	if v := os.Getenv("NHIID_TELEMETRY_LOG_LEVEL"); v != "" {
		c.Telemetry.LogLevel = v
	}
	if v := os.Getenv("NHIID_RISK_WEIGHTS_FILE"); v != "" {
		c.Risk.WeightsFile = v
	}
	if v := os.Getenv("NHIID_AUTH_MODE"); v != "" {
		c.Auth.Mode = v
	}
	if v := os.Getenv("NHIID_AUTH_TOKENS_FILE"); v != "" {
		c.Auth.TokensFile = v
	}
	if v := os.Getenv("NHIID_AUTH_JWT_SECRET"); v != "" {
		c.Auth.JWTSecret = v
	}
	if v := os.Getenv("NHIID_NOTIFY_WEBHOOK_URL"); v != "" {
		c.Notify.WebhookURL = v
	}
	if v := os.Getenv("NHIID_NOTIFY_ENABLED"); v != "" {
		c.Notify.Enabled = v == "true" || v == "1"
	}
	if v := os.Getenv("NHIID_NOTIFY_KIND"); v != "" {
		c.Notify.Kind = v
	}
	if v := os.Getenv("NHIID_NOTIFY_MIN_SEVERITY"); v != "" {
		c.Notify.MinSeverity = v
	}
}

func (c *Config) Validate() error {
	if c.Database.DSN == "" {
		return fmt.Errorf("database.dsn is required")
	}
	if !strings.HasPrefix(c.Server.HTTPAddr, ":") && !strings.Contains(c.Server.HTTPAddr, ":") {
		return fmt.Errorf("server.http_addr must be host:port")
	}
	return nil
}

// envInt is a small helper for callers wiring extra overrides.
func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

var _ = envInt
