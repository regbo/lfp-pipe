package natsauth

import (
	"testing"
	"time"

	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/regbo/lfp-pipe/controlplane/internal/config"
	"github.com/regbo/lfp-pipe/controlplane/internal/ticket"
)

func TestTunnelTicketProducesExactRoutePermissions(t *testing.T) {
	t.Parallel()
	issuer, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	userPublic, err := user.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	signer := ticket.NewSigner([]byte("01234567890123456789012345678901"), 15*time.Minute)
	value, _, err := signer.Issue("authentik-subject", "unraid-east", "cool.subdomain.domain", "subdomain.domain")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		AllowedRouteSuffix:       "subdomain.domain",
		NATSTunnelAccount:        "TUNNELS",
		NATSRequestSubjectPrefix: "lfp.v1.connect",
		NATSInternalServerToken:  "internal-only",
	}
	encoded, err := authorize(&jwt.AuthorizationRequest{
		UserNkey:       userPublic,
		ConnectOptions: jwt.ConnectOptions{Token: value},
	}, cfg, signer, issuer)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := jwt.DecodeUserClaims(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(claims.Sub.Allow) != 2 || claims.Sub.Allow[0] != "lfp.v1.connect.domain.subdomain.cool" {
		t.Fatalf("unexpected subscribe permissions %#v", claims.Sub.Allow)
	}
	if claims.Resp == nil || claims.Resp.MaxMsgs != 1 {
		t.Fatalf("expected one-response permission, got %#v", claims.Resp)
	}
}

func TestInternalServerTokenGetsPublisherPermissions(t *testing.T) {
	t.Parallel()
	issuer, _ := nkeys.CreateAccount()
	user, _ := nkeys.CreateUser()
	userPublic, _ := user.PublicKey()
	cfg := config.Config{
		NATSTunnelAccount:        "TUNNELS",
		NATSRequestSubjectPrefix: "lfp.v1.connect",
		NATSInternalServerToken:  "internal-only",
	}
	encoded, err := authorize(&jwt.AuthorizationRequest{
		UserNkey:       userPublic,
		ConnectOptions: jwt.ConnectOptions{Token: "internal-only"},
	}, cfg, ticket.NewSigner([]byte("01234567890123456789012345678901"), time.Minute), issuer)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := jwt.DecodeUserClaims(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(claims.Pub.Allow) == 0 || claims.Pub.Allow[0] != "lfp.v1.connect.>" {
		t.Fatalf("unexpected publish permissions %#v", claims.Pub.Allow)
	}
}
