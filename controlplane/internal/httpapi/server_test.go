package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/securecookie"
	authentikapi "github.com/regbo/lfp-pipe/controlplane/internal/authentik"
	"golang.org/x/oauth2"
)

func TestDefaultManagedClientConfigEnablesTLSTermination(t *testing.T) {
	t.Parallel()
	config := (&Server{}).defaultClientConfig("client", "host.pipe.example.com", "principal")
	if !strings.Contains(config, "[defaults.acme]\nproduction = true") {
		t.Fatalf("managed client config should enable production TLS termination:\n%s", config)
	}
}

func TestEntitlementClaimsAcceptNamesAndObjects(t *testing.T) {
	t.Parallel()
	stringClaims := map[string]json.RawMessage{
		"entitlements": json.RawMessage(`["subdomain.domain"]`),
	}
	if got := entitlementClaims(stringClaims); !reflect.DeepEqual(got, []string{"subdomain.domain"}) {
		t.Fatalf("unexpected string entitlements %#v", got)
	}
	objectClaims := map[string]json.RawMessage{
		"lfp_entitlements": json.RawMessage(`[{"hostname":"subdomain.domain"}]`),
	}
	if got := entitlementClaims(objectClaims); !reflect.DeepEqual(got, []string{"subdomain.domain"}) {
		t.Fatalf("unexpected object entitlements %#v", got)
	}
}

func TestManagedClientStatesDistinguishUnknownOnlineAndOffline(t *testing.T) {
	t.Parallel()
	registry := newDeviceRegistry()
	registry.record(deviceState{Username: "online", LastSeen: time.Now().UTC(), Online: true})
	registry.record(deviceState{Username: "offline", LastSeen: time.Now().UTC().Add(-deviceOnlineLease - time.Second), Online: true})
	server := &Server{devices: registry}
	owned := map[string]authentikapi.User{
		"unknown": {Username: "unknown", Name: "Unknown"},
		"online":  {Username: "online", Name: "Online"},
		"offline": {Username: "offline", Name: "Offline"},
	}
	states := server.managedClientStates(owned)
	if len(states) != 3 {
		t.Fatalf("unexpected managed client count %d", len(states))
	}
	byUsername := make(map[string]deviceState, len(states))
	for _, state := range states {
		byUsername[state.Username] = state
	}
	if byUsername["unknown"].Known || byUsername["unknown"].Online {
		t.Fatalf("unknown presence was reported as authoritative: %#v", byUsername["unknown"])
	}
	if !byUsername["online"].Known || !byUsername["online"].Online {
		t.Fatalf("fresh presence was not online: %#v", byUsername["online"])
	}
	if !byUsername["offline"].Known || byUsername["offline"].Online {
		t.Fatalf("stale presence was not offline: %#v", byUsername["offline"])
	}
}

func TestDeviceRegistryRejectsOlderCrossReplicaPresence(t *testing.T) {
	t.Parallel()
	registry := newDeviceRegistry()
	updates, unsubscribe := registry.subscribePresence()
	defer unsubscribe()
	newer := deviceState{Username: "client", Name: "new", LastSeen: time.Now().UTC(), Online: true}
	registry.record(newer)
	select {
	case <-updates:
	case <-time.After(time.Second):
		t.Fatal("presence subscriber was not notified")
	}
	registry.record(deviceState{Username: "client", Name: "old", LastSeen: newer.LastSeen.Add(-time.Minute), Online: true})
	states := registry.list()
	if len(states) != 1 || states[0].Name != "new" {
		t.Fatalf("older presence replaced newer state: %#v", states)
	}
}

func TestManagedClientConfigStatusComparesAppliedAndDesiredRevisions(t *testing.T) {
	t.Parallel()
	registry := newDeviceRegistry()
	registry.record(deviceState{
		Username: "client", LastSeen: time.Now().UTC(), Online: true,
		AppliedConfigRevision: configRevision("old"),
	})
	server := &Server{devices: registry}
	owned := map[string]authentikapi.User{
		"client": {
			Username: "client",
			Attributes: map[string]any{"lfp_pipe": map[string]any{
				"managed": true, "config_toml": "new",
			}},
		},
	}
	state := server.managedClientStates(owned)[0]
	if state.ConfigSynced || state.DesiredConfigRevision != configRevision("new") {
		t.Fatalf("stale applied configuration was reported as synchronized: %#v", state)
	}

	registry.record(deviceState{
		Username: "client", LastSeen: time.Now().UTC().Add(time.Second), Online: true,
		AppliedConfigRevision: configRevision("new"),
	})
	state = server.managedClientStates(owned)[0]
	if !state.ConfigSynced {
		t.Fatalf("matching applied configuration was not synchronized: %#v", state)
	}
}

func TestConfigRevisionIsStableAndContentSensitive(t *testing.T) {
	t.Parallel()
	if configRevision("same") != configRevision("same") {
		t.Fatal("equal documents produced different revisions")
	}
	if configRevision("old") == configRevision("new") {
		t.Fatal("different documents produced the same revision")
	}
}

func TestOwnedEntitlementRequiresExactEffectiveEntitlement(t *testing.T) {
	t.Parallel()
	got, err := ownedEntitlement([]string{"route:pipe.example.com"}, "pipe.example.com", "pipe.example.com")
	if err != nil || got != "pipe.example.com" {
		t.Fatalf("unexpected entitlement result %q: %v", got, err)
	}
	if _, err := ownedEntitlement([]string{"team.pipe.example.com"}, "pipe.example.com", "pipe.example.com"); err == nil {
		t.Fatal("expected parent entitlement ownership to be denied")
	}
}

func TestMetadataFromUser(t *testing.T) {
	t.Parallel()
	metadata := metadataFromUser(authentikapi.User{Attributes: map[string]any{
		"lfp_pipe": map[string]any{
			"managed": true, "owner_subject": "owner", "owner_email": "owner@example.com",
			"entitlement": "pipe.example.com",
		},
	}})
	if !metadata.Managed || metadata.OwnerSubject != "owner" || metadata.Entitlement != "pipe.example.com" {
		t.Fatalf("unexpected metadata %#v", metadata)
	}
}

func TestIdentityProvisioningInputValidation(t *testing.T) {
	t.Parallel()
	if !hostnameBelongsTo("chat.pipe.example.com", "pipe.example.com") {
		t.Fatal("expected child hostname to belong to entitlement")
	}
	if hostnameBelongsTo("chat.other.example.com", "pipe.example.com") {
		t.Fatal("unexpected cross-entitlement hostname match")
	}
	if got, err := normalizeIdentityCallbackPath(""); err != nil || got != "/_lfp/auth/callback" {
		t.Fatalf("unexpected default callback %q: %v", got, err)
	}
	if _, err := normalizeIdentityCallbackPath("/oauth/callback?next=x"); err == nil {
		t.Fatal("expected non-reserved callback to be rejected")
	}
}

func TestSafeReturnToAllowsOnlyLocalApplicationPaths(t *testing.T) {
	t.Parallel()
	longPath := "/" + strings.Repeat("a", maxReturnToLength)
	tests := map[string]string{
		"":                              "/",
		"/machines?tab=routes#path-1":   "/machines?tab=routes#path-1",
		"settings":                      "/",
		"https://attacker.example/path": "/",
		"//attacker.example/path":       "/",
		"/%2f%2fattacker.example/path":  "/",
		"/api/auth/callback":            "/",
		"/machines\\attacker.example":   "/",
		longPath:                        "/",
	}
	for input, expected := range tests {
		if got := safeReturnTo(input); got != expected {
			t.Errorf("safeReturnTo(%q) = %q, want %q", input, got, expected)
		}
	}
}

func TestLoginKeepsBoundedConcurrentOIDCFlows(t *testing.T) {
	t.Parallel()
	server := newOIDCTestServer()
	var flowCookieValue *http.Cookie
	for index := 0; index < maxOIDCFlows+2; index++ {
		returnTo := "/page-" + strconv.Itoa(index)
		request := httptest.NewRequest(http.MethodGet, "http://pipe.example/api/auth/login?return_to="+url.QueryEscape(returnTo), nil)
		if flowCookieValue != nil {
			request.AddCookie(flowCookieValue)
		}
		response := httptest.NewRecorder()
		server.login(response, request)
		if response.Code != http.StatusFound {
			t.Fatalf("login %d returned %d", index, response.Code)
		}
		flowCookieValue = response.Result().Cookies()[0]
	}

	var stored oidcFlowCookie
	if err := server.cookies.Decode(flowCookie, flowCookieValue.Value, &stored); err != nil {
		t.Fatalf("decode flow cookie: %v", err)
	}
	if len(stored.Flows) != maxOIDCFlows {
		t.Fatalf("stored %d flows, want %d", len(stored.Flows), maxOIDCFlows)
	}
	if stored.Flows[0].ReturnTo != "/page-2" || stored.Flows[len(stored.Flows)-1].ReturnTo != "/page-5" {
		t.Fatalf("unexpected bounded flows: %#v", stored.Flows)
	}
}

func TestConsumeOIDCFlowMatchesStateAndPreservesOthers(t *testing.T) {
	t.Parallel()
	now := time.Unix(100, 0)
	flows := []oidcFlow{
		{State: "expired", Verifier: "expired", ReturnTo: "/expired", Expires: now.Add(-time.Second).Unix()},
		{State: "first", Verifier: "first-verifier", ReturnTo: "/first", Expires: now.Add(time.Minute).Unix()},
		{State: "second", Verifier: "second-verifier", ReturnTo: "/second", Expires: now.Add(time.Minute).Unix()},
	}
	flow, remaining, found := consumeOIDCFlow(flows, "first", now)
	if !found || flow.ReturnTo != "/first" {
		t.Fatalf("unexpected selected flow: %#v, found=%v", flow, found)
	}
	if len(remaining) != 1 || remaining[0].State != "second" {
		t.Fatalf("unexpected remaining flows: %#v", remaining)
	}
}

func TestStaleCallbackRedirectsAnAuthenticatedBrowser(t *testing.T) {
	t.Parallel()
	server := newOIDCTestServer()
	value, err := server.cookies.Encode(sessionCookie, browserSession{Subject: "user", ExpiresUnix: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatalf("encode session: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://pipe.example/api/auth/callback?state=stale", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: value})
	response := httptest.NewRecorder()
	server.callback(response, request)
	if response.Code != http.StatusFound || response.Header().Get("Location") != "/" {
		t.Fatalf("stale authenticated callback returned %d to %q", response.Code, response.Header().Get("Location"))
	}
}

func newOIDCTestServer() *Server {
	return &Server{
		oauth: oauth2.Config{
			ClientID:    "client",
			Endpoint:    oauth2.Endpoint{AuthURL: "https://auth.example/authorize"},
			RedirectURL: "https://pipe.example/api/auth/callback",
		},
		cookies: securecookie.New([]byte(strings.Repeat("h", 32)), []byte(strings.Repeat("b", 32))),
	}
}
