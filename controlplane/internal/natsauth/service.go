// Package natsauth maps trusted internal credentials and route tickets to NATS permissions.
package natsauth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/regbo/lfp-pipe/controlplane/internal/config"
	"github.com/regbo/lfp-pipe/controlplane/internal/routeauth"
	"github.com/regbo/lfp-pipe/controlplane/internal/ticket"
	callout "github.com/synadia-io/callout.go"
)

// Service owns the NATS connection and Auth Callout endpoint.
type Service struct {
	nats     *nats.Conn
	callout  *callout.AuthorizationService
	close    sync.Once
	closeErr error
}

// NATS returns the shared authenticated connection used by control-plane
// features that must remain consistent across HTTP API replicas.
func (s *Service) NATS() *nats.Conn {
	if s == nil {
		return nil
	}
	return s.nats
}

// Start connects and registers a horizontally scalable Auth Callout endpoint.
func Start(ctx context.Context, cfg config.Config, tickets *ticket.Signer, logger *slog.Logger) (*Service, error) {
	issuer, err := nkeys.FromSeed(cfg.NATSAuthIssuerSeed)
	if err != nil {
		return nil, fmt.Errorf("parse NATS auth issuer seed: %w", err)
	}
	nc, err := nats.Connect(
		strings.Join(cfg.NATSURLs, ","),
		nats.UserInfo(cfg.NATSCalloutUser, cfg.NATSCalloutPassword),
		nats.Name("lfp-connect-auth-callout"),
		nats.MaxReconnects(-1),
	)
	if err != nil {
		return nil, fmt.Errorf("connect Auth Callout to NATS: %w", err)
	}

	authorizer := func(req *jwt.AuthorizationRequest) (string, error) {
		return authorize(req, cfg, tickets, issuer)
	}
	options := []callout.Option{
		callout.Name("lfp_connect_auth"),
		callout.Authorizer(authorizer),
		callout.ResponseSignerKey(issuer),
		callout.AsyncWorkers(8),
		callout.ErrCallback(func(err error) { logger.Warn("NATS authorization request failed", "error", err) }),
	}
	if len(cfg.NATSAuthXKeySeed) > 0 {
		xkey, keyErr := nkeys.FromSeed(cfg.NATSAuthXKeySeed)
		if keyErr != nil {
			nc.Close()
			return nil, fmt.Errorf("parse NATS Auth Callout xkey: %w", keyErr)
		}
		options = append(options, callout.EncryptionKey(xkey))
	}
	authService, err := callout.NewAuthorizationService(nc, options...)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("start NATS Auth Callout: %w", err)
	}
	service := &Service{nats: nc, callout: authService}
	go func() {
		<-ctx.Done()
		_ = service.Close()
	}()
	return service, nil
}

// Close gracefully stops the callout and NATS connection.
func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	s.close.Do(func() {
		var errs []error
		if s.callout != nil {
			errs = append(errs, s.callout.Stop())
		}
		if s.nats != nil {
			if err := s.nats.Drain(); err != nil {
				errs = append(errs, err)
			}
			s.nats.Close()
		}
		s.closeErr = errors.Join(errs...)
	})
	return s.closeErr
}

func authorize(req *jwt.AuthorizationRequest, cfg config.Config, tickets *ticket.Signer, issuer nkeys.KeyPair) (string, error) {
	provided := []byte(req.ConnectOptions.Token)
	expected := []byte(cfg.NATSInternalServerToken)
	if len(provided) == len(expected) && subtle.ConstantTimeCompare(provided, expected) == 1 {
		claims := jwt.NewUserClaims(req.UserNkey)
		claims.Name = "lfp-pipe-server"
		claims.Audience = cfg.NATSTunnelAccount
		claims.Expires = time.Now().Add(12 * time.Hour).Unix()
		claims.Pub.Allow.Add(cfg.NATSRequestSubjectPrefix + ".>")
		claims.Pub.Allow.Add("_LFP_INBOX.>")
		claims.Sub.Allow.Add("_INBOX.>")
		return claims.Encode(issuer)
	}

	claims, err := tickets.Parse(req.ConnectOptions.Token)
	if err != nil {
		return "", fmt.Errorf("validate tunnel ticket: %w", err)
	}
	if _, err := routeauth.AuthorizeStrictSubdomain([]string{claims.Entitlement}, claims.Route, cfg.AllowedRouteSuffix); err != nil {
		return "", fmt.Errorf("authorize tunnel route: %w", err)
	}
	subject, err := routeauth.Subject(cfg.NATSRequestSubjectPrefix, claims.Route)
	if err != nil {
		return "", fmt.Errorf("map tunnel route subject: %w", err)
	}

	user := jwt.NewUserClaims(req.UserNkey)
	user.Name = claims.ClientID
	user.Audience = cfg.NATSTunnelAccount
	user.Expires = claims.ExpiresAt.Unix()
	// A tunnel claim is a two-phase request/reply exchange: the client replies
	// to the server inbox and supplies its own inbox for the winner ack. NATS
	// response permissions alone reject that publish-with-reply shape, so grant
	// the server inbox namespace explicitly. The server still validates the
	// connection ID and selected client before accepting a data connection.
	user.Pub.Allow.Add("_INBOX.>")
	user.Sub.Allow.Add(subject)
	user.Sub.Allow.Add("_LFP_INBOX." + claims.ClientID + ".>")
	user.Resp = &jwt.ResponsePermission{MaxMsgs: 1, Expires: 5 * time.Second}
	return user.Encode(issuer)
}
