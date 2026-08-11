// Package httpapi exposes Authentik login and route-ticket issuance endpoints.
package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/securecookie"
	"github.com/regbo/lfp-pipe/controlplane/internal/config"
	"github.com/regbo/lfp-pipe/controlplane/internal/routeauth"
	"github.com/regbo/lfp-pipe/controlplane/internal/ticket"
	"golang.org/x/oauth2"
)

const (
	sessionCookie = "lfp_connect_session"
	flowCookie    = "lfp_connect_oidc_flow"
)

// Server serves browser authentication and tunnel-token requests.
type Server struct {
	cfg          config.Config
	logger       *slog.Logger
	oauth        oauth2.Config
	verifier     *oidc.IDTokenVerifier
	cookies      *securecookie.SecureCookie
	tickets      *ticket.Signer
	cookieSecure bool
}

type browserSession struct {
	Subject      string   `json:"sub"`
	Name         string   `json:"name"`
	Email        string   `json:"email"`
	Entitlements []string `json:"entitlements"`
	ExpiresUnix  int64    `json:"expires_unix"`
}

type oidcFlow struct {
	State    string `json:"state"`
	Verifier string `json:"verifier"`
	Expires  int64  `json:"expires"`
}

// New discovers Authentik and constructs the API handler.
func New(ctx context.Context, cfg config.Config, tickets *ticket.Signer, logger *slog.Logger) (*Server, error) {
	provider, err := oidc.NewProvider(ctx, cfg.OIDCIssuerURL)
	if err != nil {
		return nil, fmt.Errorf("discover Authentik OIDC provider: %w", err)
	}
	hashKey := sha512.Sum512(cfg.CookieSecret)
	blockKey := sha256.Sum256(append([]byte("lfp-connect-cookie:"), cfg.CookieSecret...))
	codec := securecookie.New(hashKey[:], blockKey[:])
	codec.MaxAge(int((12 * time.Hour).Seconds()))

	return &Server{
		cfg:    cfg,
		logger: logger,
		oauth: oauth2.Config{
			ClientID:     cfg.OIDCClientID,
			ClientSecret: cfg.OIDCClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.PublicURL + "/api/auth/callback",
			Scopes:       cfg.OIDCScopes,
		},
		verifier:     provider.Verifier(&oidc.Config{ClientID: cfg.OIDCClientID}),
		cookies:      codec,
		tickets:      tickets,
		cookieSecure: strings.EqualFold(mustURLScheme(cfg.PublicURL), "https"),
	}, nil
}

// Handler returns the complete API router.
func (s *Server) Handler() http.Handler {
	router := chi.NewRouter()
	router.Use(s.securityHeaders)
	router.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	router.Get("/api/auth/login", s.login)
	router.Get("/api/auth/callback", s.callback)
	router.Post("/api/auth/logout", s.logout)
	router.Get("/api/me", s.me)
	router.Post("/api/tunnel-tokens", s.issueTunnelToken)
	return router
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	state := oauth2.GenerateVerifier()
	verifier := oauth2.GenerateVerifier()
	flow := oidcFlow{State: state, Verifier: verifier, Expires: time.Now().Add(10 * time.Minute).Unix()}
	if err := s.setCookie(w, flowCookie, flow, 10*time.Minute); err != nil {
		s.internalError(w, err)
		return
	}
	http.Redirect(w, r, s.oauth.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	var flow oidcFlow
	if err := s.readCookie(r, flowCookie, &flow); err != nil || flow.Expires < time.Now().Unix() || r.URL.Query().Get("state") != flow.State {
		writeError(w, http.StatusBadRequest, "The sign-in request expired. Please try again.")
		return
	}
	oauthToken, err := s.oauth.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(flow.Verifier))
	if err != nil {
		s.logger.Warn("OIDC code exchange failed", "error", err)
		writeError(w, http.StatusUnauthorized, "Authentik did not accept the sign-in response.")
		return
	}
	rawIDToken, ok := oauthToken.Extra("id_token").(string)
	if !ok {
		writeError(w, http.StatusUnauthorized, "Authentik did not return an ID token.")
		return
	}
	idToken, err := s.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		s.logger.Warn("OIDC ID token verification failed", "error", err)
		writeError(w, http.StatusUnauthorized, "Authentik returned an invalid ID token.")
		return
	}

	var claims map[string]json.RawMessage
	if err := idToken.Claims(&claims); err != nil {
		s.internalError(w, fmt.Errorf("decode ID token claims: %w", err))
		return
	}
	session := browserSession{
		Subject:      stringClaim(claims, "sub"),
		Name:         firstNonEmpty(stringClaim(claims, "name"), stringClaim(claims, "preferred_username")),
		Email:        stringClaim(claims, "email"),
		Entitlements: entitlementClaims(claims),
		ExpiresUnix:  idToken.Expiry.Unix(),
	}
	if session.Subject == "" {
		writeError(w, http.StatusUnauthorized, "Authentik token is missing a subject.")
		return
	}
	maxAge := time.Until(idToken.Expiry)
	if maxAge > 12*time.Hour {
		maxAge = 12 * time.Hour
	}
	if err := s.setCookie(w, sessionCookie, session, maxAge); err != nil {
		s.internalError(w, err)
		return
	}
	s.clearCookie(w, flowCookie)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) logout(w http.ResponseWriter, _ *http.Request) {
	s.clearCookie(w, sessionCookie)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	session, err := s.requireIdentity(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Sign in with Authentik to continue.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"subject":              session.Subject,
		"name":                 session.Name,
		"email":                session.Email,
		"entitlements":         session.Entitlements,
		"required_entitlement": s.cfg.AllowedRouteSuffix,
		"route_pattern":        "*." + s.cfg.AllowedRouteSuffix,
	})
}

func (s *Server) issueTunnelToken(w http.ResponseWriter, r *http.Request) {
	session, err := s.requireIdentity(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Sign in with Authentik to continue.")
		return
	}
	var request struct {
		Hostname   string `json:"hostname"`
		ClientName string `json:"client_name"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "Provide a hostname and client name.")
		return
	}
	route, entitlement, err := routeauth.MatchStrictSubdomain(session.Entitlements, request.Hostname, s.cfg.AllowedRouteSuffix)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	clientID, err := routeauth.ClientID(request.ClientName)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	subject, err := routeauth.Subject(s.cfg.NATSRequestSubjectPrefix, route)
	if err != nil {
		s.internalError(w, err)
		return
	}
	value, expires, err := s.tickets.Issue(session.Subject, clientID, route, entitlement)
	if err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"token":           value,
		"expires_at":      expires,
		"hostname":        route,
		"client_id":       clientID,
		"request_subject": subject,
		"nats_urls":       s.cfg.NATSPublicURLs,
	})
}

func (s *Server) requireIdentity(r *http.Request) (*browserSession, error) {
	const prefix = "Bearer "
	if authorization := r.Header.Get("Authorization"); strings.HasPrefix(authorization, prefix) {
		raw := strings.TrimSpace(strings.TrimPrefix(authorization, prefix))
		if raw == "" {
			return nil, errors.New("bearer token is empty")
		}
		verified, err := s.verifier.Verify(r.Context(), raw)
		if err != nil {
			return nil, fmt.Errorf("verify Authentik bearer token: %w", err)
		}
		var claims map[string]json.RawMessage
		if err := verified.Claims(&claims); err != nil {
			return nil, fmt.Errorf("decode Authentik bearer claims: %w", err)
		}
		identity := &browserSession{
			Subject:      stringClaim(claims, "sub"),
			Name:         firstNonEmpty(stringClaim(claims, "name"), stringClaim(claims, "preferred_username")),
			Email:        stringClaim(claims, "email"),
			Entitlements: entitlementClaims(claims),
			ExpiresUnix:  verified.Expiry.Unix(),
		}
		if identity.Subject == "" || identity.ExpiresUnix <= time.Now().Unix() {
			return nil, errors.New("bearer identity is incomplete or expired")
		}
		return identity, nil
	}
	return s.requireSession(r)
}

func (s *Server) requireSession(r *http.Request) (*browserSession, error) {
	var session browserSession
	if err := s.readCookie(r, sessionCookie, &session); err != nil {
		return nil, err
	}
	if session.Subject == "" || session.ExpiresUnix <= time.Now().Unix() {
		return nil, errors.New("session expired")
	}
	return &session, nil
}

func (s *Server) setCookie(w http.ResponseWriter, name string, value any, maxAge time.Duration) error {
	encoded, err := s.cookies.Encode(name, value)
	if err != nil {
		return fmt.Errorf("encode %s cookie: %w", name, err)
	}
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: encoded, Path: "/", HttpOnly: true, Secure: s.cookieSecure,
		SameSite: http.SameSiteLaxMode, MaxAge: int(maxAge.Seconds()),
	})
	return nil
}

func (s *Server) readCookie(r *http.Request, name string, target any) error {
	cookie, err := r.Cookie(name)
	if err != nil {
		return err
	}
	return s.cookies.Decode(name, cookie.Value, target)
}

func (s *Server) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", HttpOnly: true, Secure: s.cookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

func (s *Server) internalError(w http.ResponseWriter, err error) {
	s.logger.Error("request failed", "error", err)
	writeError(w, http.StatusInternalServerError, "The control plane could not complete the request.")
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func entitlementClaims(claims map[string]json.RawMessage) []string {
	for _, key := range []string{"lfp_entitlements", "entitlements"} {
		raw := claims[key]
		var names []string
		if len(raw) != 0 && json.Unmarshal(raw, &names) == nil {
			return names
		}
		names = nil
		var objects []struct {
			Name     string `json:"name"`
			Hostname string `json:"hostname"`
		}
		if len(raw) != 0 && json.Unmarshal(raw, &objects) == nil {
			for _, object := range objects {
				names = append(names, firstNonEmpty(object.Hostname, object.Name))
			}
			return names
		}
	}
	return []string{}
}

func stringClaim(claims map[string]json.RawMessage, name string) string {
	var value string
	_ = json.Unmarshal(claims[name], &value)
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func mustURLScheme(value string) string {
	parsed, _ := url.Parse(value)
	return parsed.Scheme
}
