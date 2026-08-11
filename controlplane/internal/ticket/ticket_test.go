package ticket

import (
	"testing"
	"time"
)

func TestTicketRoundTrip(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	signer := NewSigner([]byte("01234567890123456789012345678901"), 15*time.Minute)
	signer.now = func() time.Time { return now }

	value, expires, err := signer.Issue("authentik-user", "client-a", "cool.subdomain.domain", "subdomain.domain")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := signer.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Route != "cool.subdomain.domain" || !expires.Equal(now.Add(15*time.Minute)) {
		t.Fatalf("unexpected claims %#v", claims)
	}
}
