// Package httpapi exposes Authentik login and route-ticket issuance endpoints.
package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/securecookie"
	authentikapi "github.com/regbo/lfp-pipe/controlplane/internal/authentik"
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
	authentik    *authentikapi.Client
	cookieSecure bool
	devices      *deviceRegistry
}

type deviceState struct {
	Username string    `json:"username"`
	Name     string    `json:"name"`
	Version  string    `json:"version"`
	Platform string    `json:"platform"`
	LastSeen time.Time `json:"last_seen"`
	Online   bool      `json:"online"`
}

type deviceRegistry struct {
	sync.Mutex
	devices     map[string]deviceState
	subscribers map[string]map[chan struct{}]struct{}
	enrollments map[string]*deviceEnrollment
}

type deviceEnrollment struct {
	Code      string    `json:"code"`
	PollToken string    `json:"-"`
	DeviceID  string    `json:"device_id"`
	Name      string    `json:"name"`
	Platform  string    `json:"platform"`
	Version   string    `json:"version"`
	Expires   time.Time `json:"expires_at"`
	Username  string    `json:"username,omitempty"`
	Secret    string    `json:"client_secret,omitempty"`
	Claimed   bool      `json:"claimed"`
}

func newDeviceRegistry() *deviceRegistry {
	return &deviceRegistry{devices: make(map[string]deviceState), subscribers: make(map[string]map[chan struct{}]struct{}), enrollments: make(map[string]*deviceEnrollment)}
}

func (r *deviceRegistry) touch(device deviceState) {
	r.Lock()
	defer r.Unlock()
	device.LastSeen = time.Now().UTC()
	device.Online = true
	r.devices[device.Username] = device
}

func (r *deviceRegistry) list() []deviceState {
	r.Lock()
	defer r.Unlock()
	result := make([]deviceState, 0, len(r.devices))
	for _, device := range r.devices {
		result = append(result, device)
	}
	return result
}

func (r *deviceRegistry) subscribe(username string) (chan struct{}, func()) {
	r.Lock()
	defer r.Unlock()
	updates := make(chan struct{}, 1)
	if r.subscribers[username] == nil {
		r.subscribers[username] = make(map[chan struct{}]struct{})
	}
	r.subscribers[username][updates] = struct{}{}
	return updates, func() { r.Lock(); defer r.Unlock(); delete(r.subscribers[username], updates) }
}

func (r *deviceRegistry) notify(username string) {
	r.Lock()
	defer r.Unlock()
	for updates := range r.subscribers[username] {
		select {
		case updates <- struct{}{}:
		default:
		}
	}
}

type browserSession struct {
	Subject      string   `json:"sub"`
	Name         string   `json:"name"`
	Email        string   `json:"email"`
	Entitlements []string `json:"entitlements"`
	ExpiresUnix  int64    `json:"expires_unix"`
	Username     string   `json:"username"`
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
		authentik:    authentikapi.NewClient(cfg.AuthentikAPIURL, cfg.AuthentikAPIToken),
		cookieSecure: strings.EqualFold(mustURLScheme(cfg.PublicURL), "https"),
		devices:      newDeviceRegistry(),
	}, nil
}

// Handler returns the complete API router.
func (s *Server) Handler() http.Handler {
	router := chi.NewRouter()
	router.Use(s.securityHeaders)
	router.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	router.Get("/api/branding", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, s.cfg.Brand)
	})
	router.Get("/api/auth/login", s.login)
	router.Get("/api/auth/callback", s.callback)
	router.Post("/api/auth/logout", s.logout)
	router.Get("/api/me", s.me)
	router.Post("/api/tunnel-tokens", s.issueTunnelToken)
	router.Get("/api/service-principals", s.listServicePrincipals)
	router.Post("/api/service-principals", s.createServicePrincipal)
	router.Get("/api/service-principals/{id}/config", s.getServicePrincipalConfig)
	router.Put("/api/service-principals/{id}/config", s.putServicePrincipalConfig)
	router.Delete("/api/service-principals/{id}", s.deleteServicePrincipal)
	router.Get("/api/client-settings", s.getMachineClientSettings)
	router.Get("/api/client-config", s.getMachineClientConfig)
	router.Get("/api/client-events", s.getMachineClientEvents)
	router.Get("/api/managed-clients", s.listManagedClients)
	router.Post("/api/enrollments", s.createEnrollment)
	router.Get("/api/enrollments/{code}", s.getEnrollment)
	router.Get("/api/enrollments", s.listEnrollments)
	router.Post("/api/enrollments/{code}/claim", s.claimEnrollment)
	return router
}

type servicePrincipal struct {
	ID          int    `json:"id"`
	Username    string `json:"username"`
	Name        string `json:"name"`
	ClientID    string `json:"client_id"`
	Entitlement string `json:"entitlement"`
}

type principalMetadata struct {
	Managed      bool
	OwnerSubject string
	OwnerEmail   string
	ClientID     string
	Entitlement  string
	ConfigTOML   string
}

func (s *Server) listServicePrincipals(w http.ResponseWriter, r *http.Request) {
	session, err := s.requireSession(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Sign in with Authentik to continue.")
		return
	}
	users, err := s.authentik.ListServiceAccounts(r.Context())
	if err != nil {
		s.internalError(w, err)
		return
	}
	principals := make([]servicePrincipal, 0)
	for _, user := range users {
		metadata := metadataFromUser(user)
		if metadata.Managed && metadata.OwnerSubject == session.Subject {
			principals = append(principals, servicePrincipal{
				ID: user.PK, Username: user.Username, Name: user.Name, ClientID: metadata.ClientID,
				Entitlement: metadata.Entitlement,
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"service_principals": principals})
}

func (s *Server) createServicePrincipal(w http.ResponseWriter, r *http.Request) {
	session, err := s.requireSession(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Sign in with Authentik to continue.")
		return
	}
	var request struct {
		Name        string `json:"name"`
		Entitlement string `json:"entitlement"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "Provide a name and entitlement.")
		return
	}
	name, err := routeauth.ClientID(request.Name)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	entitlement, err := ownedEntitlement(session.Entitlements, request.Entitlement, s.cfg.AllowedRouteSuffix)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	target, err := s.authentik.FindEntitlement(r.Context(), s.cfg.AuthentikApplicationSlug, entitlement)
	if err != nil {
		s.internalError(w, err)
		return
	}
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		s.internalError(w, fmt.Errorf("generate service principal suffix: %w", err))
		return
	}
	displayName := "lfp-pipe-" + name + "-" + hex.EncodeToString(suffix)
	attributes := map[string]any{
		"lfp_pipe": map[string]any{
			"managed": true, "owner_subject": session.Subject, "owner_email": session.Email,
			"client_id": name, "entitlement": entitlement,
		},
	}
	created, err := s.authentik.CreateServiceAccount(r.Context(), displayName)
	if err != nil {
		s.internalError(w, err)
		return
	}
	attributes["lfp_pipe"].(map[string]any)["config_toml"] = s.defaultClientConfig(name, entitlement, created.Username)
	if err := s.authentik.UpdateUserAttributes(r.Context(), created.UserPK, attributes); err != nil {
		_ = s.authentik.DeleteUser(r.Context(), created.UserPK)
		s.internalError(w, fmt.Errorf("store service principal ownership: %w", err))
		return
	}
	if err := s.authentik.BindUser(r.Context(), created.UserPK, target.PBMUUID); err != nil {
		_ = s.authentik.DeleteUser(r.Context(), created.UserPK)
		s.internalError(w, fmt.Errorf("bind service principal entitlement: %w", err))
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"service_principal": servicePrincipal{
			ID: created.UserPK, Username: created.Username, Name: displayName, ClientID: name,
			Entitlement: entitlement,
		},
		"client_secret": created.Token,
		"oauth": map[string]any{
			"token_url": s.cfg.OAuthTokenURL, "client_id": s.cfg.OIDCClientID,
			"control_plane_url": s.cfg.PublicURL, "scopes": s.cfg.OIDCScopes,
			"nats_urls": s.cfg.NATSPublicURLs,
		},
	})
}

func (s *Server) defaultClientConfig(clientID, hostname, username string) string {
	natsURL := "tls://nats.example.com:443"
	if len(s.cfg.NATSPublicURLs) > 0 {
		natsURL = s.cfg.NATSPublicURLs[0]
	}
	return fmt.Sprintf(`[defaults]
nats_url = %q
relay_mode = "auto"
claim_ack_timeout_ms = 1500
backend_addr = "127.0.0.1:443"
http_backend_addr = "127.0.0.1:80"

[defaults.oauth]
token_url = %q
provider_client_id = %q
username = %q
client_secret_file = "__central__"
control_plane_url = %q
scopes = ["openid", "profile", "entitlements"]
renew_before_seconds = 60

[[routes]]
client_id = %q
hostname = %q
`, natsURL, s.cfg.OAuthTokenURL, s.cfg.OIDCClientID, username, s.cfg.PublicURL, clientID, hostname)
}

func (s *Server) deleteServicePrincipal(w http.ResponseWriter, r *http.Request) {
	session, err := s.requireSession(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Sign in with Authentik to continue.")
		return
	}
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil || id < 1 {
		writeError(w, http.StatusBadRequest, "Invalid service principal ID.")
		return
	}
	user, err := s.authentik.GetUser(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "Service principal was not found.")
		return
	}
	metadata := metadataFromUser(user)
	if !metadata.Managed || metadata.OwnerSubject != session.Subject {
		writeError(w, http.StatusForbidden, "You do not own this service principal.")
		return
	}
	if err := s.authentik.DeleteUser(r.Context(), id); err != nil {
		s.internalError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func metadataFromUser(user authentikapi.User) principalMetadata {
	root, _ := user.Attributes["lfp_pipe"].(map[string]any)
	metadata := principalMetadata{}
	metadata.Managed, _ = root["managed"].(bool)
	metadata.OwnerSubject, _ = root["owner_subject"].(string)
	metadata.OwnerEmail, _ = root["owner_email"].(string)
	metadata.ClientID, _ = root["client_id"].(string)
	metadata.Entitlement, _ = root["entitlement"].(string)
	metadata.ConfigTOML, _ = root["config_toml"].(string)
	return metadata
}

func (s *Server) ownedPrincipal(r *http.Request) (authentikapi.User, principalMetadata, error) {
	session, err := s.requireSession(r)
	if err != nil {
		return authentikapi.User{}, principalMetadata{}, errors.New("authentication required")
	}
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil || id < 1 {
		return authentikapi.User{}, principalMetadata{}, errors.New("invalid principal ID")
	}
	user, err := s.authentik.GetUser(r.Context(), id)
	if err != nil {
		return authentikapi.User{}, principalMetadata{}, err
	}
	metadata := metadataFromUser(user)
	if !metadata.Managed || metadata.OwnerSubject != session.Subject {
		return authentikapi.User{}, principalMetadata{}, errors.New("principal is not owned by this user")
	}
	return user, metadata, nil
}

func (s *Server) getServicePrincipalConfig(w http.ResponseWriter, r *http.Request) {
	_, metadata, err := s.ownedPrincipal(r)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"config_toml": metadata.ConfigTOML})
}

func (s *Server) putServicePrincipalConfig(w http.ResponseWriter, r *http.Request) {
	user, metadata, err := s.ownedPrincipal(r)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	var request struct {
		ConfigTOML string `json:"config_toml"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256*1024))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || strings.TrimSpace(request.ConfigTOML) == "" {
		writeError(w, http.StatusBadRequest, "Provide a non-empty TOML configuration.")
		return
	}
	root, _ := user.Attributes["lfp_pipe"].(map[string]any)
	if root == nil {
		root = map[string]any{}
	}
	root["config_toml"] = request.ConfigTOML
	if err := s.authentik.UpdateUserAttributes(r.Context(), user.PK, map[string]any{"lfp_pipe": root}); err != nil {
		s.internalError(w, err)
		return
	}
	metadata.ConfigTOML = request.ConfigTOML
	s.devices.notify(user.Username)
	writeJSON(w, http.StatusOK, map[string]string{"config_toml": metadata.ConfigTOML})
}

func (s *Server) getMachineClientConfig(w http.ResponseWriter, r *http.Request) {
	identity, err := s.requireIdentity(r)
	if err != nil || identity.Username == "" {
		writeError(w, http.StatusUnauthorized, "An Authentik machine token is required.")
		return
	}
	s.devices.touch(deviceState{Username: identity.Username, Name: r.Header.Get("X-LFP-Pipe-Device"), Version: r.Header.Get("X-LFP-Pipe-Version"), Platform: r.Header.Get("X-LFP-Pipe-Platform")})
	users, err := s.authentik.ListServiceAccounts(r.Context())
	if err != nil {
		s.internalError(w, err)
		return
	}
	for _, user := range users {
		if user.Username == identity.Username {
			metadata := metadataFromUser(user)
			if metadata.Managed && metadata.ConfigTOML != "" {
				writeJSON(w, http.StatusOK, map[string]any{"config_toml": metadata.ConfigTOML, "username": identity.Username})
				return
			}
		}
	}
	writeError(w, http.StatusNotFound, "No central configuration is assigned to this client.")
}

func (s *Server) getMachineClientEvents(w http.ResponseWriter, r *http.Request) {
	identity, err := s.requireIdentity(r)
	if err != nil || identity.Username == "" {
		writeError(w, http.StatusUnauthorized, "An Authentik machine token is required.")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "Streaming is unavailable.")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	updates, unsubscribe := s.devices.subscribe(identity.Username)
	defer unsubscribe()
	s.devices.touch(deviceState{Username: identity.Username, Name: r.Header.Get("X-LFP-Pipe-Device"), Version: r.Header.Get("X-LFP-Pipe-Version"), Platform: r.Header.Get("X-LFP-Pipe-Platform")})
	_, _ = fmt.Fprint(w, "event: ready\ndata: connected\n\n")
	flusher.Flush()
	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-updates:
			_, _ = fmt.Fprint(w, "event: config\ndata: changed\n\n")
			flusher.Flush()
		case <-heartbeat.C:
			s.devices.touch(deviceState{Username: identity.Username, Name: r.Header.Get("X-LFP-Pipe-Device"), Version: r.Header.Get("X-LFP-Pipe-Version"), Platform: r.Header.Get("X-LFP-Pipe-Platform")})
			_, _ = fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

func (s *Server) listManagedClients(w http.ResponseWriter, r *http.Request) {
	session, err := s.requireSession(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Sign in with Authentik to continue.")
		return
	}
	users, err := s.authentik.ListServiceAccounts(r.Context())
	if err != nil {
		s.internalError(w, err)
		return
	}
	owned := make(map[string]authentikapi.User)
	for _, user := range users {
		metadata := metadataFromUser(user)
		if metadata.Managed && metadata.OwnerSubject == session.Subject {
			owned[user.Username] = user
		}
	}
	seen := make(map[string]deviceState)
	for _, device := range s.devices.list() {
		if _, ok := owned[device.Username]; ok {
			device.Online = time.Since(device.LastSeen) < 45*time.Second
			seen[device.Username] = device
		}
	}
	clients := make([]deviceState, 0, len(owned))
	for username, user := range owned {
		if device, ok := seen[username]; ok {
			clients = append(clients, device)
		} else {
			clients = append(clients, deviceState{Username: username, Name: user.Name})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"managed_clients": clients})
}

func (s *Server) createEnrollment(w http.ResponseWriter, r *http.Request) {
	var request struct {
		DeviceID string `json:"device_id"`
		Name     string `json:"name"`
		Platform string `json:"platform"`
		Version  string `json:"version"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&request) != nil || request.DeviceID == "" {
		writeError(w, http.StatusBadRequest, "Device identity is required.")
		return
	}
	bytes := make([]byte, 5)
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		s.internalError(w, err)
		return
	}
	if _, err := rand.Read(tokenBytes); err != nil {
		s.internalError(w, err)
		return
	}
	code := strings.ToUpper(hex.EncodeToString(bytes))
	enrollment := &deviceEnrollment{Code: code, PollToken: hex.EncodeToString(tokenBytes), DeviceID: request.DeviceID, Name: request.Name, Platform: request.Platform, Version: request.Version, Expires: time.Now().Add(10 * time.Minute).UTC()}
	s.devices.Lock()
	s.devices.enrollments[code] = enrollment
	s.devices.Unlock()
	writeJSON(w, http.StatusCreated, map[string]any{"code": code, "poll_token": enrollment.PollToken, "claim_url": s.cfg.PublicURL + "/?enroll=" + code, "expires_at": enrollment.Expires})
}

func (s *Server) getEnrollment(w http.ResponseWriter, r *http.Request) {
	code := strings.ToUpper(chi.URLParam(r, "code"))
	s.devices.Lock()
	defer s.devices.Unlock()
	enrollment := s.devices.enrollments[code]
	if enrollment == nil || time.Now().After(enrollment.Expires) || r.Header.Get("Authorization") != "Bearer "+enrollment.PollToken {
		writeError(w, http.StatusNotFound, "Enrollment expired.")
		return
	}
	if !enrollment.Claimed {
		writeJSON(w, http.StatusAccepted, map[string]any{"status": "pending"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "claimed", "username": enrollment.Username, "client_secret": enrollment.Secret})
	delete(s.devices.enrollments, code)
}

func (s *Server) listEnrollments(w http.ResponseWriter, r *http.Request) {
	if _, err := s.requireSession(r); err != nil {
		writeError(w, http.StatusUnauthorized, "Sign in with Authentik to continue.")
		return
	}
	s.devices.Lock()
	defer s.devices.Unlock()
	result := make([]deviceEnrollment, 0)
	for _, enrollment := range s.devices.enrollments {
		if !enrollment.Claimed && time.Now().Before(enrollment.Expires) {
			result = append(result, *enrollment)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"enrollments": result})
}

func (s *Server) claimEnrollment(w http.ResponseWriter, r *http.Request) {
	session, err := s.requireSession(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Sign in with Authentik to continue.")
		return
	}
	code := strings.ToUpper(chi.URLParam(r, "code"))
	var request struct {
		Entitlement string `json:"entitlement"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&request) != nil {
		writeError(w, http.StatusBadRequest, "Entitlement is required.")
		return
	}
	entitlement, err := ownedEntitlement(session.Entitlements, request.Entitlement, s.cfg.AllowedRouteSuffix)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	s.devices.Lock()
	enrollment := s.devices.enrollments[code]
	s.devices.Unlock()
	if enrollment == nil || time.Now().After(enrollment.Expires) {
		writeError(w, http.StatusNotFound, "Enrollment expired.")
		return
	}
	name, err := routeauth.ClientID(enrollment.Name)
	if err != nil {
		name = "managed-client"
	}
	created, err := s.authentik.CreateServiceAccount(r.Context(), name)
	if err != nil {
		s.internalError(w, err)
		return
	}
	attributes := map[string]any{"lfp_pipe": map[string]any{"managed": true, "owner_subject": session.Subject, "owner_email": session.Email, "client_id": name, "entitlement": entitlement}}
	attributes["lfp_pipe"].(map[string]any)["config_toml"] = s.defaultClientConfig(name, entitlement, created.Username)
	if err := s.authentik.UpdateUserAttributes(r.Context(), created.UserPK, attributes); err != nil {
		s.internalError(w, err)
		return
	}
	if target, err := s.authentik.FindEntitlement(r.Context(), s.cfg.AuthentikApplicationSlug, entitlement); err == nil {
		_ = s.authentik.BindUser(r.Context(), created.UserPK, target.PBMUUID)
	}
	s.devices.Lock()
	enrollment.Username = created.Username
	enrollment.Secret = created.Token
	enrollment.Claimed = true
	s.devices.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"status":            "claimed",
		"service_principal": servicePrincipal{ID: created.UserPK, Username: created.Username, Name: enrollment.Name, ClientID: name, Entitlement: entitlement},
	})
}

func (s *Server) getMachineClientSettings(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"token_url":          s.cfg.OAuthTokenURL,
		"provider_client_id": s.cfg.OIDCClientID,
		"scopes":             s.cfg.OIDCScopes,
	})
}

func ownedEntitlement(values []string, requested, parent string) (string, error) {
	requested = strings.TrimPrefix(strings.TrimSpace(requested), "route:")
	normalized, err := routeauth.NormalizeHostname(requested)
	if err != nil {
		return "", err
	}
	if normalized != parent && !strings.HasSuffix(normalized, "."+parent) {
		return "", fmt.Errorf("entitlement must belong to %s", parent)
	}
	for _, value := range values {
		value = strings.TrimPrefix(strings.TrimSpace(value), "route:")
		if candidate, normalizeErr := routeauth.NormalizeHostname(value); normalizeErr == nil && candidate == normalized {
			return normalized, nil
		}
	}
	return "", fmt.Errorf("you do not own entitlement %s", normalized)
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
		Username:     stringClaim(claims, "preferred_username"),
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
		"control_plane_url":    s.cfg.PublicURL,
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
		"expires_unix":    expires.Unix(),
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
			Username:     stringClaim(claims, "preferred_username"),
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
