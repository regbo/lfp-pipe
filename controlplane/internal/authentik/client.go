// Package authentik provides the narrow administrative API surface needed by LFP Pipe.
package authentik

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client manages LFP Pipe service accounts and entitlement bindings.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// User is the Authentik service-account representation used by the control plane.
type User struct {
	PK         int            `json:"pk"`
	UID        string         `json:"uid"`
	Username   string         `json:"username"`
	Name       string         `json:"name"`
	Type       string         `json:"type"`
	IsActive   bool           `json:"is_active"`
	Attributes map[string]any `json:"attributes"`
}

// CreatedServiceAccount contains the one-time app password returned by Authentik.
type CreatedServiceAccount struct {
	Username string `json:"username"`
	Token    string `json:"token"`
	UserUID  string `json:"user_uid"`
	UserPK   int    `json:"user_pk"`
}

// Entitlement identifies an application entitlement and its binding target.
type Entitlement struct {
	Name    string `json:"name"`
	PBMUUID string `json:"pbm_uuid"`
}

type application struct {
	PK   string `json:"pk"`
	Slug string `json:"slug"`
}

type page[T any] struct {
	Results []T `json:"results"`
}

// NewClient constructs an Authentik API client without exposing its bearer token.
func NewClient(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http:    &http.Client{Timeout: 20 * time.Second},
	}
}

// ListServiceAccounts returns service-account users for owner filtering by the caller.
func (c *Client) ListServiceAccounts(ctx context.Context) ([]User, error) {
	var response page[User]
	if err := c.request(ctx, http.MethodGet, "/core/users/?type=service_account&page_size=100", nil, &response); err != nil {
		return nil, err
	}
	return response.Results, nil
}

// GetUser returns one Authentik user.
func (c *Client) GetUser(ctx context.Context, pk int) (User, error) {
	var user User
	err := c.request(ctx, http.MethodGet, fmt.Sprintf("/core/users/%d/", pk), nil, &user)
	return user, err
}

// CreateServiceAccount creates a non-expiring service account and one app password.
func (c *Client) CreateServiceAccount(ctx context.Context, name string) (CreatedServiceAccount, error) {
	var created CreatedServiceAccount
	err := c.request(ctx, http.MethodPost, "/core/users/service_account/", map[string]any{
		"name": name, "create_group": false, "expiring": false,
	}, &created)
	return created, err
}

// UpdateUserAttributes persists LFP Pipe ownership metadata after account creation.
// Authentik's service-account convenience endpoint does not persist attributes.
func (c *Client) UpdateUserAttributes(ctx context.Context, pk int, attributes map[string]any) error {
	return c.request(ctx, http.MethodPatch, fmt.Sprintf("/core/users/%d/", pk), map[string]any{
		"attributes": attributes,
	}, nil)
}

// DeleteUser deletes a managed service account and its dependent bindings.
func (c *Client) DeleteUser(ctx context.Context, pk int) error {
	return c.request(ctx, http.MethodDelete, fmt.Sprintf("/core/users/%d/", pk), nil, nil)
}

// FindEntitlement resolves an entitlement within the configured application slug.
func (c *Client) FindEntitlement(ctx context.Context, appSlug, name string) (Entitlement, error) {
	var apps page[application]
	if err := c.request(ctx, http.MethodGet, "/core/applications/?page_size=100", nil, &apps); err != nil {
		return Entitlement{}, err
	}
	var appPK string
	for _, app := range apps.Results {
		if app.Slug == appSlug {
			appPK = app.PK
			break
		}
	}
	if appPK == "" {
		return Entitlement{}, fmt.Errorf("Authentik application %q was not found", appSlug)
	}
	query := url.Values{"app": {appPK}, "page_size": {"100"}}
	var entitlements page[Entitlement]
	if err := c.request(ctx, http.MethodGet, "/core/application_entitlements/?"+query.Encode(), nil, &entitlements); err != nil {
		return Entitlement{}, err
	}
	for _, entitlement := range entitlements.Results {
		if entitlement.Name == name {
			return entitlement, nil
		}
	}
	return Entitlement{}, fmt.Errorf("Authentik entitlement %q was not found", name)
}

// BindUser grants one user an application entitlement.
func (c *Client) BindUser(ctx context.Context, userPK int, target string) error {
	return c.request(ctx, http.MethodPost, "/policies/bindings/", map[string]any{
		"policy": nil, "group": nil, "user": userPK, "target": target,
		"negate": false, "enabled": true, "order": 0, "timeout": 30, "failure_result": false,
	}, nil)
}

func (c *Client) request(ctx context.Context, method, path string, body, target any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode Authentik request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return fmt.Errorf("construct Authentik request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("call Authentik API: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		limited, _ := io.ReadAll(io.LimitReader(response.Body, 4*1024))
		return fmt.Errorf("Authentik API returned %s: %s", response.Status, strings.TrimSpace(string(limited)))
	}
	if target == nil || response.StatusCode == http.StatusNoContent {
		_, _ = io.Copy(io.Discard, response.Body)
		return nil
	}
	if err := json.NewDecoder(response.Body).Decode(target); err != nil {
		return fmt.Errorf("decode Authentik response: %w", err)
	}
	return nil
}
