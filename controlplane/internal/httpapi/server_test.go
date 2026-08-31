package httpapi

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	authentikapi "github.com/regbo/lfp-pipe/controlplane/internal/authentik"
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
