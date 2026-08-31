package authentik

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/regbo/lfp-pipe/controlplane/internal/identity"
)

func TestProvisionerCreatesPublicPKCEApplicationAndGroupIdempotently(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	source := oauthProvider{
		PK: 7, Name: "LFP Pipe", AuthorizationFlow: "authorization-flow",
		InvalidationFlow: "invalidation-flow", PropertyMappings: []string{"openid", "profile"},
		AssignedApplicationSlug: "lfp-pipe", ClientType: "confidential", ClientID: "lfp-pipe",
		SubMode: "hashed_user_id",
	}
	var route *oauthProvider
	groups := []managedGroup{}
	createdApplications := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v3/core/users/":
			_ = json.NewEncoder(w).Encode(page[User]{Results: []User{{Username: "admin", IsActive: true, IsSuperuser: true}}})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v3/providers/oauth2/":
			providers := []oauthProvider{source}
			if route != nil {
				providers = append(providers, *route)
			}
			_ = json.NewEncoder(w).Encode(page[oauthProvider]{Results: providers})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v3/providers/oauth2/":
			var created oauthProvider
			if err := json.NewDecoder(r.Body).Decode(&created); err != nil {
				t.Fatal(err)
			}
			created.PK = 8
			route = &created
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(created)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v3/core/applications/":
			createdApplications++
			route.AssignedApplicationSlug = "lfp-pipe-routes"
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(managedApplication{Slug: "lfp-pipe-routes", Name: "LFP Pipe routes"})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v3/core/groups/":
			_ = json.NewEncoder(w).Encode(page[managedGroup]{Results: groups})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v3/core/groups/":
			var group managedGroup
			if err := json.NewDecoder(r.Body).Decode(&group); err != nil {
				t.Fatal(err)
			}
			group.PK = "group-id"
			groups = append(groups, group)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(group)
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.String(), http.StatusNotFound)
		}
	}))
	defer server.Close()

	provisioner := NewProvisioner(NewClient(server.URL+"/api/v3", "token"), "lfp-pipe", "lfp-pipe-routes", "LFP Pipe routes")
	admin, err := provisioner.IsAdmin(context.Background(), identity.Actor{Username: "admin"})
	if err != nil || !admin {
		t.Fatalf("expected active superuser, admin=%v err=%v", admin, err)
	}
	request := identity.ApplicationRequest{Hostname: "chat.pipe.example.com", CallbackPath: "/_lfp/auth/callback", Group: "Chat users"}
	first, err := provisioner.ProvisionApplication(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.ClientID != "lfp-pipe-routes" || !strings.HasSuffix(first.Issuer, "/application/o/lfp-pipe-routes/") {
		t.Fatalf("unexpected application result %#v", first)
	}
	if route == nil || route.ClientType != publicClient || len(route.RedirectURIs) != 1 || route.RedirectURIs[0].MatchingMode != strictRedirect {
		t.Fatalf("public provider was not created correctly: %#v", route)
	}
	second, err := provisioner.ProvisionApplication(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if createdApplications != 1 || len(groups) != 1 || len(second.CreatedObjects) != 0 {
		t.Fatalf("provisioning was not idempotent: apps=%d groups=%d result=%#v", createdApplications, len(groups), second)
	}
}
