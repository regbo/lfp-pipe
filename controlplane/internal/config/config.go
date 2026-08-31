// Package config centralizes environment and secret-file configuration.
package config

import (
	"errors"
	"flag"
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
	AuthentikAPIURL          string
	AuthentikAPIToken        string
	AuthentikApplicationSlug string
	IdentityProvisioner      string
	IdentityApplicationSlug  string
	IdentityApplicationName  string
	OAuthTokenURL            string
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
	Brand                    BrandConfig
}

// BrandConfig is the runtime-selectable identity exposed to the web console.
type BrandConfig struct {
	Name        string `json:"name"`
	LogoURL     string `json:"logo_url"`
	Wordmark    string `json:"wordmark"`
	FaviconURL  string `json:"favicon_url"`
	Color       string `json:"color"`
	ColorStrong string `json:"color_strong"`
	Ink         string `json:"ink"`
}

// Load resolves environment values and reads secret material from *_FILE paths.
func Load() (Config, error) {
	return LoadArgs(os.Args[1:])
}

// LoadArgs resolves CLI flags over environment variables and typed defaults.
func LoadArgs(args []string) (Config, error) {
	cfg := Config{
		HTTPAddr:                 envOr("LFP_AUTH_HTTP_ADDR", ":8080"),
		PublicURL:                strings.TrimRight(os.Getenv("LFP_AUTH_PUBLIC_URL"), "/"),
		AllowedRouteSuffix:       os.Getenv("LFP_AUTH_ROUTE_SUFFIX"),
		OIDCIssuerURL:            os.Getenv("LFP_AUTH_OIDC_ISSUER_URL"),
		OIDCClientID:             os.Getenv("LFP_AUTH_OIDC_CLIENT_ID"),
		OIDCScopes:               splitCSV(envOr("LFP_AUTH_OIDC_SCOPES", "openid,profile,email,entitlements")),
		AuthentikAPIURL:          strings.TrimRight(os.Getenv("LFP_AUTH_AUTHENTIK_API_URL"), "/"),
		AuthentikApplicationSlug: envOr("LFP_AUTH_AUTHENTIK_APPLICATION_SLUG", "lfp-pipe"),
		IdentityProvisioner:      strings.ToLower(strings.TrimSpace(os.Getenv("LFP_AUTH_IDENTITY_PROVISIONER"))),
		IdentityApplicationSlug:  strings.TrimSpace(os.Getenv("LFP_AUTH_IDENTITY_APPLICATION_SLUG")),
		IdentityApplicationName:  envOr("LFP_AUTH_IDENTITY_APPLICATION_NAME", "LFP Pipe routes"),
		OAuthTokenURL:            os.Getenv("LFP_AUTH_OAUTH_TOKEN_URL"),
		NATSURLs:                 splitCSV(envOr("LFP_AUTH_NATS_URLS", "nats://127.0.0.1:4222")),
		NATSPublicURLs:           splitCSV(envOr("LFP_AUTH_NATS_PUBLIC_URLS", envOr("LFP_AUTH_NATS_URLS", "tls://pipe.example.com:4222"))),
		NATSCalloutUser:          envOr("LFP_AUTH_NATS_CALLOUT_USER", "auth-svc"),
		NATSTunnelAccount:        envOr("LFP_AUTH_NATS_TUNNEL_ACCOUNT", "TUNNELS"),
		NATSRequestSubjectPrefix: envOr("LFP_AUTH_NATS_SUBJECT_PREFIX", "lfp.v1.connect"),
		Brand: BrandConfig{
			Name:        envOr("LFP_AUTH_BRAND_NAME", "LFP Pipe"),
			LogoURL:     envOr("LFP_AUTH_BRAND_LOGO_URL", "/assets/lfp-coral.svg"),
			Wordmark:    envOr("LFP_AUTH_BRAND_WORDMARK", "pipe"),
			FaviconURL:  envOr("LFP_AUTH_BRAND_FAVICON_URL", "/assets/lfp-favicon.svg"),
			Color:       envOr("LFP_AUTH_BRAND_COLOR", "#ff6f61"),
			ColorStrong: envOr("LFP_AUTH_BRAND_COLOR_STRONG", "#e85c50"),
			Ink:         envOr("LFP_AUTH_BRAND_INK", "#0b1426"),
		},
	}
	if cfg.IdentityApplicationSlug == "" {
		cfg.IdentityApplicationSlug = cfg.AuthentikApplicationSlug + "-routes"
	}
	flags := flag.NewFlagSet("lfp-connect-auth", flag.ContinueOnError)
	flags.StringVar(&cfg.Brand.Name, "brand-name", cfg.Brand.Name, "management website brand name")
	flags.StringVar(&cfg.Brand.LogoURL, "brand-logo-url", cfg.Brand.LogoURL, "management website monogram URL")
	flags.StringVar(&cfg.Brand.Wordmark, "brand-wordmark", cfg.Brand.Wordmark, "management website lowercase wordmark")
	flags.StringVar(&cfg.Brand.FaviconURL, "brand-favicon-url", cfg.Brand.FaviconURL, "management website favicon URL")
	flags.StringVar(&cfg.Brand.Color, "brand-color", cfg.Brand.Color, "management website primary color")
	flags.StringVar(&cfg.Brand.ColorStrong, "brand-color-strong", cfg.Brand.ColorStrong, "management website hover color")
	flags.StringVar(&cfg.Brand.Ink, "brand-ink", cfg.Brand.Ink, "management website foreground ink")
	if err := flags.Parse(args); err != nil {
		return Config{}, err
	}

	var err error
	if cfg.OIDCClientSecret, err = readSecretString("LFP_AUTH_OIDC_CLIENT_SECRET_FILE"); err != nil {
		return Config{}, err
	}
	if cfg.AuthentikAPIToken, err = readSecretString("LFP_AUTH_AUTHENTIK_API_TOKEN_FILE"); err != nil {
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

	if cfg.PublicURL == "" || cfg.AllowedRouteSuffix == "" || cfg.OIDCIssuerURL == "" || cfg.OIDCClientID == "" || cfg.AuthentikAPIURL == "" || cfg.OAuthTokenURL == "" {
		return Config{}, errors.New("public URL, route suffix, OIDC, Authentik API, and OAuth token URL settings are required")
	}
	if len(cfg.CookieSecret) < 32 || len(cfg.TicketSecret) < 32 {
		return Config{}, errors.New("cookie and ticket secrets must each contain at least 32 bytes")
	}
	if cfg.OIDCClientSecret == "" || cfg.AuthentikAPIToken == "" || cfg.NATSCalloutPassword == "" || len(cfg.NATSAuthIssuerSeed) == 0 || cfg.NATSInternalServerToken == "" {
		return Config{}, errors.New("OIDC, Authentik API, NATS callout, issuer, and internal server secrets must not be empty")
	}
	if cfg.Brand.Name == "" || cfg.Brand.LogoURL == "" || cfg.Brand.Wordmark == "" || cfg.Brand.FaviconURL == "" {
		return Config{}, errors.New("brand name, logo URL, wordmark, and favicon URL must not be empty")
	}
	if cfg.IdentityProvisioner != "" && cfg.IdentityProvisioner != "authentik" {
		return Config{}, fmt.Errorf("unsupported identity provisioner %q", cfg.IdentityProvisioner)
	}
	if cfg.IdentityProvisioner != "" && (cfg.IdentityApplicationSlug == "" || cfg.IdentityApplicationName == "") {
		return Config{}, errors.New("identity application slug and name must not be empty when provisioning is enabled")
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
