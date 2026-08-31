package authentik

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/regbo/lfp-pipe/controlplane/internal/identity"
)

const (
	strictRedirect = "strict"
	publicClient   = "public"
)

type redirectURI struct {
	MatchingMode    string `json:"matching_mode"`
	URL             string `json:"url"`
	RedirectURIType string `json:"redirect_uri_type,omitempty"`
}

type oauthProvider struct {
	PK                      int           `json:"pk"`
	Name                    string        `json:"name"`
	AuthenticationFlow      *string       `json:"authentication_flow"`
	AuthorizationFlow       string        `json:"authorization_flow"`
	InvalidationFlow        string        `json:"invalidation_flow"`
	PropertyMappings        []string      `json:"property_mappings"`
	AssignedApplicationSlug string        `json:"assigned_application_slug"`
	ClientType              string        `json:"client_type"`
	ClientID                string        `json:"client_id"`
	IncludeClaimsInIDToken  bool          `json:"include_claims_in_id_token"`
	SigningKey              *string       `json:"signing_key"`
	RedirectURIs            []redirectURI `json:"redirect_uris"`
	SubMode                 string        `json:"sub_mode"`
}

type managedApplication struct {
	PK       string `json:"pk"`
	Name     string `json:"name"`
	Slug     string `json:"slug"`
	Provider *int   `json:"provider"`
}

type managedGroup struct {
	PK   string `json:"pk"`
	Name string `json:"name"`
}

// Provisioner implements identity.Service with a dedicated public OIDC app.
// The public client uses PKCE, so no browser-client secret is copied to machines.
type Provisioner struct {
	client        *Client
	sourceAppSlug string
	routeAppSlug  string
	routeAppName  string
	issuerBaseURL string
	mu            sync.Mutex
}

// NewProvisioner constructs the optional Authentik provisioning adapter.
func NewProvisioner(client *Client, sourceAppSlug, routeAppSlug, routeAppName string) *Provisioner {
	base := strings.TrimSuffix(client.baseURL, "/api/v3")
	return &Provisioner{
		client: client, sourceAppSlug: sourceAppSlug, routeAppSlug: routeAppSlug,
		routeAppName: routeAppName, issuerBaseURL: strings.TrimRight(base, "/"),
	}
}

func (p *Provisioner) Provider() identity.Provider {
	return identity.Provider{ID: "authentik", DisplayName: "Authentik", Capabilities: []string{"applications", "groups", "oidc"}}
}

func (p *Provisioner) IsAdmin(ctx context.Context, actor identity.Actor) (bool, error) {
	if strings.TrimSpace(actor.Username) == "" {
		return false, nil
	}
	user, err := p.client.FindUserByUsername(ctx, actor.Username)
	if err != nil {
		return false, err
	}
	return user.IsActive && user.IsSuperuser, nil
}

func (p *Provisioner) ListGroups(ctx context.Context) ([]identity.Group, error) {
	var response page[managedGroup]
	if err := p.client.request(ctx, http.MethodGet, "/core/groups/?ordering=name&page_size=1000", nil, &response); err != nil {
		return nil, err
	}
	groups := make([]identity.Group, 0, len(response.Results))
	for _, group := range response.Results {
		groups = append(groups, identity.Group{ID: group.PK, Name: group.Name})
	}
	sort.Slice(groups, func(i, j int) bool { return strings.ToLower(groups[i].Name) < strings.ToLower(groups[j].Name) })
	return groups, nil
}

func (p *Provisioner) ProvisionApplication(ctx context.Context, request identity.ApplicationRequest) (identity.ApplicationResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	callbackURL := "https://" + request.Hostname + request.CallbackPath
	provider, created, err := p.ensureRouteApplication(ctx, callbackURL)
	if err != nil {
		return identity.ApplicationResult{}, err
	}
	groupName := strings.TrimSpace(request.Group)
	if groupName != "" {
		groupCreated, groupErr := p.ensureGroup(ctx, groupName)
		if groupErr != nil {
			return identity.ApplicationResult{}, groupErr
		}
		if groupCreated {
			created = append(created, "group")
		}
	}
	return identity.ApplicationResult{
		ProviderID: "authentik", Application: p.routeAppName,
		Issuer:   p.issuerBaseURL + "/application/o/" + p.routeAppSlug + "/",
		ClientID: provider.ClientID, Scopes: []string{"openid", "profile", "email"},
		CallbackPath: request.CallbackPath, CallbackURL: callbackURL, Group: groupName,
		CreatedObjects: created,
	}, nil
}

func (p *Provisioner) ensureRouteApplication(ctx context.Context, callbackURL string) (oauthProvider, []string, error) {
	provider, found, err := p.findProvider(ctx, p.routeAppSlug)
	if err != nil {
		return oauthProvider{}, nil, err
	}
	created := make([]string, 0, 3)
	if !found {
		source, sourceFound, sourceErr := p.findProvider(ctx, p.sourceAppSlug)
		if sourceErr != nil {
			return oauthProvider{}, nil, sourceErr
		}
		if !sourceFound {
			return oauthProvider{}, nil, fmt.Errorf("Authentik source application %q has no OAuth provider", p.sourceAppSlug)
		}
		body := map[string]any{
			"name": p.routeAppName, "authentication_flow": source.AuthenticationFlow,
			"authorization_flow": source.AuthorizationFlow, "invalidation_flow": source.InvalidationFlow,
			"property_mappings": source.PropertyMappings, "client_type": publicClient,
			"grant_types": []string{"authorization_code"}, "client_id": p.routeAppSlug,
			"include_claims_in_id_token": true, "signing_key": source.SigningKey,
			"redirect_uris": []redirectURI{{MatchingMode: strictRedirect, URL: callbackURL, RedirectURIType: "authorization"}},
			"sub_mode":      source.SubMode, "issuer_mode": "per_provider",
		}
		if err := p.client.request(ctx, http.MethodPost, "/providers/oauth2/", body, &provider); err != nil {
			// Another control-plane replica may have won the idempotent create race.
			if current, currentFound, refetchErr := p.findProvider(ctx, p.routeAppSlug); refetchErr == nil && currentFound {
				provider = current
			} else {
				return oauthProvider{}, nil, err
			}
		} else {
			created = append(created, "oauth_provider")
			var application managedApplication
			appBody := map[string]any{
				"name": p.routeAppName, "slug": p.routeAppSlug, "provider": provider.PK,
				"meta_hide": true, "meta_description": "Browser sign-in for LFP Pipe routes",
			}
			if err := p.client.request(ctx, http.MethodPost, "/core/applications/", appBody, &application); err != nil {
				if _, appFound, refetchErr := p.findApplication(ctx, p.routeAppSlug); refetchErr != nil || !appFound {
					return oauthProvider{}, nil, fmt.Errorf("create Authentik route application: %w", err)
				}
			} else {
				created = append(created, "application")
			}
		}
	}
	if provider.ClientType != publicClient {
		return oauthProvider{}, nil, fmt.Errorf("Authentik application %q must use a public OAuth client", p.routeAppSlug)
	}
	if provider.ClientID == "" {
		return oauthProvider{}, nil, fmt.Errorf("Authentik application %q has no OAuth client ID", p.routeAppSlug)
	}
	for _, redirect := range provider.RedirectURIs {
		if redirect.URL == callbackURL && redirect.MatchingMode == strictRedirect {
			return provider, created, nil
		}
	}
	provider.RedirectURIs = append(provider.RedirectURIs, redirectURI{MatchingMode: strictRedirect, URL: callbackURL, RedirectURIType: "authorization"})
	if err := p.client.request(ctx, http.MethodPatch, fmt.Sprintf("/providers/oauth2/%d/", provider.PK), map[string]any{"redirect_uris": provider.RedirectURIs}, &provider); err != nil {
		return oauthProvider{}, nil, fmt.Errorf("add Authentik callback URI: %w", err)
	}
	created = append(created, "redirect_uri")
	return provider, created, nil
}

func (p *Provisioner) findProvider(ctx context.Context, appSlug string) (oauthProvider, bool, error) {
	var response page[oauthProvider]
	if err := p.client.request(ctx, http.MethodGet, "/providers/oauth2/?page_size=1000", nil, &response); err != nil {
		return oauthProvider{}, false, err
	}
	for _, provider := range response.Results {
		if provider.AssignedApplicationSlug == appSlug {
			return provider, true, nil
		}
	}
	return oauthProvider{}, false, nil
}

func (p *Provisioner) findApplication(ctx context.Context, slug string) (managedApplication, bool, error) {
	query := url.Values{"slug": {slug}, "page_size": {"2"}}
	var response page[managedApplication]
	if err := p.client.request(ctx, http.MethodGet, "/core/applications/?"+query.Encode(), nil, &response); err != nil {
		return managedApplication{}, false, err
	}
	for _, application := range response.Results {
		if application.Slug == slug {
			return application, true, nil
		}
	}
	return managedApplication{}, false, nil
}

func (p *Provisioner) ensureGroup(ctx context.Context, name string) (bool, error) {
	query := url.Values{"name": {name}, "page_size": {"100"}}
	var response page[managedGroup]
	if err := p.client.request(ctx, http.MethodGet, "/core/groups/?"+query.Encode(), nil, &response); err != nil {
		return false, err
	}
	for _, group := range response.Results {
		if group.Name == name {
			return false, nil
		}
	}
	var created managedGroup
	err := p.client.request(ctx, http.MethodPost, "/core/groups/", map[string]any{
		"name": name, "is_superuser": false,
		"attributes": map[string]any{"lfp_pipe": map[string]any{"managed": true, "kind": "route_access"}},
	}, &created)
	if err != nil {
		return false, fmt.Errorf("create Authentik group: %w", err)
	}
	return true, nil
}

var _ identity.Service = (*Provisioner)(nil)
