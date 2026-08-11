package httpapi

import (
	"encoding/json"
	"reflect"
	"testing"
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
