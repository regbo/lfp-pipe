// Package identity defines provider-neutral identity provisioning capabilities.
package identity

import "context"

// Actor is the verified management-console identity used for authorization.
type Actor struct {
	Subject  string
	Username string
	Email    string
}

// Provider describes an optional identity provisioning integration.
type Provider struct {
	ID           string   `json:"id"`
	DisplayName  string   `json:"display_name"`
	Capabilities []string `json:"capabilities"`
}

// Group is a provider group that can be used as a Pipe route role.
type Group struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ApplicationRequest describes the high-level access setup Pipe needs.
// Provider-specific objects such as OAuth providers and applications remain
// implementation details behind Service.
type ApplicationRequest struct {
	Hostname     string
	CallbackPath string
	Group        string
}

// ApplicationResult contains the non-secret OIDC settings a Pipe client needs.
type ApplicationResult struct {
	ProviderID     string   `json:"provider_id"`
	Application    string   `json:"application"`
	Issuer         string   `json:"issuer"`
	ClientID       string   `json:"client_id"`
	Scopes         []string `json:"scopes"`
	CallbackPath   string   `json:"callback_path"`
	CallbackURL    string   `json:"callback_url"`
	Group          string   `json:"group,omitempty"`
	CreatedObjects []string `json:"created_objects"`
}

// Service is the extension point for Authentik or a future identity system.
type Service interface {
	Provider() Provider
	IsAdmin(context.Context, Actor) (bool, error)
	ListGroups(context.Context) ([]Group, error)
	ProvisionApplication(context.Context, ApplicationRequest) (ApplicationResult, error)
}
