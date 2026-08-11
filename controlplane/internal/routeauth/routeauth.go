// Package routeauth normalizes route entitlements and maps routes to NATS subjects.
package routeauth

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/net/idna"
)

var clientIDPattern = regexp.MustCompile(`[^a-z0-9_-]+`)

// NormalizeHostname returns a lowercase ASCII hostname without a trailing dot.
func NormalizeHostname(value string) (string, error) {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil || ascii == "" || strings.ContainsAny(ascii, " *>\t\r\n") {
		return "", errors.New("hostname is invalid")
	}
	for _, label := range strings.Split(ascii, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", errors.New("hostname is invalid")
		}
	}
	return ascii, nil
}

// AuthorizeStrictSubdomain requires an entitlement namespace covering a strict
// descendant of the configured root namespace.
func AuthorizeStrictSubdomain(entitlements []string, requested, parent string) (string, error) {
	route, _, err := MatchStrictSubdomain(entitlements, requested, parent)
	return route, err
}

// MatchStrictSubdomain returns the normalized route and most-specific
// entitlement that covers it. An entitlement owns its exact name and all of
// its descendants, while the configured parent remains an unclaimable apex.
func MatchStrictSubdomain(entitlements []string, requested, parent string) (string, string, error) {
	route, err := NormalizeHostname(requested)
	if err != nil {
		return "", "", err
	}
	parent, err = NormalizeHostname(parent)
	if err != nil {
		return "", "", fmt.Errorf("configured route suffix: %w", err)
	}
	if route == parent || !strings.HasSuffix(route, "."+parent) {
		return "", "", fmt.Errorf("route must be a strict subdomain of %s", parent)
	}

	matched := ""
	for _, entitlement := range entitlements {
		entitlement = strings.TrimPrefix(strings.TrimSpace(entitlement), "route:")
		value, normalizeErr := NormalizeHostname(entitlement)
		if normalizeErr != nil || (value != parent && !strings.HasSuffix(value, "."+parent)) {
			continue
		}
		if (route == value || strings.HasSuffix(route, "."+value)) && len(value) > len(matched) {
			matched = value
		}
	}
	if matched == "" {
		return "", "", fmt.Errorf("no entitlement covers %s", route)
	}
	return route, matched, nil
}

// Subject returns the fully qualified reversed-domain NATS request subject.
func Subject(prefix, hostname string) (string, error) {
	hostname, err := NormalizeHostname(hostname)
	if err != nil {
		return "", err
	}
	labels := strings.Split(hostname, ".")
	slices.Reverse(labels)
	return strings.TrimSuffix(prefix, ".") + "." + strings.Join(labels, "."), nil
}

// ClientID converts a display name into a stable NATS inbox token.
func ClientID(value string) (string, error) {
	value = strings.Trim(clientIDPattern.ReplaceAllString(strings.ToLower(value), "-"), "-")
	if len(value) < 2 || len(value) > 48 {
		return "", errors.New("client name must produce 2 to 48 URL-safe characters")
	}
	return value, nil
}
