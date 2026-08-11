// Package config centralizes environment and secret-file configuration.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config contains all runtime settings for the HTTP API and NATS callout.
type Config struct {
	HTTPAddr                 string
	PublicURL                string
	AllowedRouteSuffix       string
	OIDCIssuerURL            string
	OIDCClientID             string
	OIDCClientSecret         string
	OIDCScopes               []string
	CookieSecret             []byte
	TicketSecret             []byte
	TicketTTL                time.Duration
	NATSURLs                 []string
	NATSPublicURLs           []string
	NATSCalloutUser          string
	NATSCalloutPassword      string
	NATSAuthIssuerSeed       []byte
	NATSAuthXKeySeed         []byte
	NATSInternalServerToken  string
	NATSTunnelAccount        string
	NATSRequestSubjectPrefix string
}

// Load resolves environment values and reads secret material from *_FILE paths.
func Load() (Config, error) {
	cfg := Config{
		HTTPAddr:                 envOr("LFP_AUTH_HTTP_ADDR", ":8080"),
		PublicURL:                strings.TrimRight(os.Getenv("LFP_AUTH_PUBLIC_URL"), "/"),
		AllowedRouteSuffix:       os.Getenv("LFP_AUTH_ROUTE_SUFFIX"),
		OIDCIssuerURL:            os.Getenv("LFP_AUTH_OIDC_ISSUER_URL"),
		OIDCClientID:             os.Getenv("LFP_AUTH_OIDC_CLIENT_ID"),
		OIDCScopes:               splitCSV(envOr("LFP_AUTH_OIDC_SCOPES", "openid,profile,email,entitlements")),
		NATSURLs:                 splitCSV(envOr("LFP_AUTH_NATS_URLS", "nats://127.0.0.1:4222")),
		NATSPublicURLs:           splitCSV(envOr("LFP_AUTH_NATS_PUBLIC_URLS", envOr("LFP_AUTH_NATS_URLS", "nats://127.0.0.1:4222"))),
		NATSCalloutUser:          envOr("LFP_AUTH_NATS_CALLOUT_USER", "auth-svc"),
		NATSTunnelAccount:        envOr("LFP_AUTH_NATS_TUNNEL_ACCOUNT", "TUNNELS"),
		NATSRequestSubjectPrefix: envOr("LFP_AUTH_NATS_SUBJECT_PREFIX", "lfp.v1.connect"),
	}

	var err error
	if cfg.OIDCClientSecret, err = readSecretString("LFP_AUTH_OIDC_CLIENT_SECRET_FILE"); err != nil {
		return Config{}, err
	}
	if cfg.CookieSecret, err = readSecret("LFP_AUTH_COOKIE_SECRET_FILE"); err != nil {
		return Config{}, err
	}
	if cfg.TicketSecret, err = readSecret("LFP_AUTH_TICKET_SECRET_FILE"); err != nil {
		return Config{}, err
	}
	if cfg.NATSCalloutPassword, err = readSecretString("LFP_AUTH_NATS_CALLOUT_PASSWORD_FILE"); err != nil {
		return Config{}, err
	}
	if cfg.NATSAuthIssuerSeed, err = readSecret("LFP_AUTH_NATS_ISSUER_SEED_FILE"); err != nil {
		return Config{}, err
	}
	if cfg.NATSInternalServerToken, err = readSecretString("LFP_AUTH_NATS_INTERNAL_SERVER_TOKEN_FILE"); err != nil {
		return Config{}, err
	}
	if path := os.Getenv("LFP_AUTH_NATS_XKEY_SEED_FILE"); path != "" {
		if cfg.NATSAuthXKeySeed, err = os.ReadFile(path); err != nil {
			return Config{}, fmt.Errorf("read LFP_AUTH_NATS_XKEY_SEED_FILE: %w", err)
		}
		cfg.NATSAuthXKeySeed = []byte(strings.TrimSpace(string(cfg.NATSAuthXKeySeed)))
	}

	ttlMinutes, err := strconv.Atoi(envOr("LFP_AUTH_TICKET_TTL_MINUTES", "15"))
	if err != nil || ttlMinutes < 1 || ttlMinutes > 1440 {
		return Config{}, errors.New("LFP_AUTH_TICKET_TTL_MINUTES must be between 1 and 1440")
	}
	cfg.TicketTTL = time.Duration(ttlMinutes) * time.Minute

	if cfg.PublicURL == "" || cfg.AllowedRouteSuffix == "" || cfg.OIDCIssuerURL == "" || cfg.OIDCClientID == "" {
		return Config{}, errors.New("LFP_AUTH_PUBLIC_URL, LFP_AUTH_ROUTE_SUFFIX, LFP_AUTH_OIDC_ISSUER_URL, and LFP_AUTH_OIDC_CLIENT_ID are required")
	}
	if len(cfg.CookieSecret) < 32 || len(cfg.TicketSecret) < 32 {
		return Config{}, errors.New("cookie and ticket secrets must each contain at least 32 bytes")
	}
	if cfg.OIDCClientSecret == "" || cfg.NATSCalloutPassword == "" || len(cfg.NATSAuthIssuerSeed) == 0 || cfg.NATSInternalServerToken == "" {
		return Config{}, errors.New("OIDC, NATS callout, issuer, and internal server secrets must not be empty")
	}
	return cfg, nil
}

func readSecretString(envName string) (string, error) {
	value, err := readSecret(envName)
	return strings.TrimSpace(string(value)), err
}

func readSecret(envName string) ([]byte, error) {
	path := os.Getenv(envName)
	if path == "" {
		return nil, fmt.Errorf("%s is required", envName)
	}
	value, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", envName, err)
	}
	return []byte(strings.TrimSpace(string(value))), nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func splitCSV(value string) []string {
	values := make([]string, 0)
	for item := range strings.SplitSeq(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			values = append(values, item)
		}
	}
	return values
}
