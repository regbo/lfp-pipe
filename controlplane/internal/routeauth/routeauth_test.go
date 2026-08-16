package routeauth

import "testing"

func TestAuthorizeStrictSubdomain(t *testing.T) {
	t.Parallel()
	route, err := AuthorizeStrictSubdomain([]string{"subdomain.domain"}, "Cool.Subdomain.Domain.", "subdomain.domain")
	if err != nil {
		t.Fatal(err)
	}
	if route != "cool.subdomain.domain" {
		t.Fatalf("unexpected route %q", route)
	}
}

func TestExactRouteEntitlement(t *testing.T) {
	t.Parallel()
	route, entitlement, err := MatchStrictSubdomain(
		[]string{"desktop.pipe.example.com"},
		"desktop.pipe.example.com",
		"pipe.example.com",
	)
	if err != nil {
		t.Fatal(err)
	}
	if route != "desktop.pipe.example.com" || entitlement != route {
		t.Fatalf("unexpected grant route=%q entitlement=%q", route, entitlement)
	}
}

func TestMostSpecificEntitlementWins(t *testing.T) {
	t.Parallel()
	_, entitlement, err := MatchStrictSubdomain(
		[]string{"pipe.example.com", "team.pipe.example.com"},
		"app.team.pipe.example.com",
		"pipe.example.com",
	)
	if err != nil {
		t.Fatal(err)
	}
	if entitlement != "team.pipe.example.com" {
		t.Fatalf("unexpected entitlement %q", entitlement)
	}
}

func TestAuthorizeRejectsApexAndSibling(t *testing.T) {
	t.Parallel()
	for _, route := range []string{"subdomain.domain", "other.domain"} {
		if _, err := AuthorizeStrictSubdomain([]string{"subdomain.domain"}, route, "subdomain.domain"); err == nil {
			t.Fatalf("expected %q to be rejected", route)
		}
	}
}

func TestSubjectReversesDomainLabels(t *testing.T) {
	t.Parallel()
	subject, err := Subject("lfp.v1.connect", "cool.subdomain.domain")
	if err != nil {
		t.Fatal(err)
	}
	if subject != "lfp.v1.connect.domain.subdomain.cool" {
		t.Fatalf("unexpected subject %q", subject)
	}
}
