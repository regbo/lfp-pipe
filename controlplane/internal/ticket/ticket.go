// Package ticket signs and validates short-lived tunnel authorization tickets.
package ticket

import (
	"errors"
	"fmt"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

const issuer = "lfp-connect"

// Claims are the authorization facts consumed by the NATS Auth Callout.
type Claims struct {
	Route       string `json:"route"`
	Entitlement string `json:"entitlement"`
	ClientID    string `json:"client_id"`
	jwt.RegisteredClaims
}

// Signer creates and validates HMAC-signed route tickets.
type Signer struct {
	secret []byte
	ttl    time.Duration
	now    func() time.Time
}

// NewSigner constructs a ticket signer.
func NewSigner(secret []byte, ttl time.Duration) *Signer {
	return &Signer{secret: secret, ttl: ttl, now: time.Now}
}

// Issue creates a ticket for one client and exact route.
func (s *Signer) Issue(subject, clientID, route, entitlement string) (string, time.Time, error) {
	now := s.now().UTC()
	expires := now.Add(s.ttl)
	claims := Claims{
		Route:       route,
		Entitlement: entitlement,
		ClientID:    clientID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   subject,
			Audience:  jwt.ClaimStrings{"nats"},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-5 * time.Second)),
			ExpiresAt: jwt.NewNumericDate(expires),
		},
	}
	value, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.secret)
	return value, expires, err
}

// Parse validates a route ticket and returns its claims.
func (s *Signer) Parse(value string) (*Claims, error) {
	claims := &Claims{}
	parsed, err := jwt.ParseWithClaims(value, claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("unexpected ticket signing method")
		}
		return s.secret, nil
	}, jwt.WithAudience("nats"), jwt.WithIssuer(issuer), jwt.WithTimeFunc(s.now))
	if err != nil || !parsed.Valid {
		return nil, fmt.Errorf("invalid tunnel ticket: %w", err)
	}
	if claims.Route == "" || claims.ClientID == "" || claims.Subject == "" {
		return nil, errors.New("invalid tunnel ticket: required claims are missing")
	}
	return claims, nil
}
