package httpapi

import (
	"encoding/json"
	"reflect"
	"testing"

	authentikapi "github.com/regbo/lfp-pipe/controlplane/internal/authentik"
)

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

func TestOwnedEntitlementRequiresExactEffectiveEntitlement(t *testing.T) {
	t.Parallel()
	got, err := ownedEntitlement([]string{"route:pipe.lfpconnect.io"}, "pipe.lfpconnect.io", "pipe.lfpconnect.io")
	if err != nil || got != "pipe.lfpconnect.io" {
		t.Fatalf("unexpected entitlement result %q: %v", got, err)
	}
	if _, err := ownedEntitlement([]string{"team.pipe.lfpconnect.io"}, "pipe.lfpconnect.io", "pipe.lfpconnect.io"); err == nil {
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
