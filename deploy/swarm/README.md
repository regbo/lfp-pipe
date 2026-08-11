# LFP Connect Swarm control plane

This stack runs a three-replica Core NATS cluster, the Go Authentik/NATS Auth
Callout service, the Bun-built web console, and one public `lfp-pipe-server`.
Tunnel payloads continue to flow directly through `lfp-pipe`; NATS remains the
control plane.

## Authorization model

Set `LFP_ROUTE_SUFFIX=subdomain.domain`. An Authentik application entitlement
named exactly `subdomain.domain` may be bound directly to a user or to any of
the user's groups. A signed-in holder can issue a short-lived credential for a
strict descendant such as `cool.subdomain.domain` but not for the apex or a
sibling domain.

More-specific entitlements are supported as namespaces too. For example,
`cool.subdomain.domain` authorizes that exact route and descendants beneath it,
without granting sibling routes. Non-interactive callers may present a verified
Authentik access token in `Authorization: Bearer ...` to the same
`POST /api/tunnel-tokens` endpoint.

The credential authorizes these NATS resources only:

```text
subscribe: _LFP_INBOX.<client-id>.>
subscribe: lfp.v1.connect.domain.subdomain.cool
publish:   one response to a received request
```

Multiple clients can receive credentials for the same route. They all submit a
claim and the public server keeps its existing round-robin winner selection.

## Authentik application

Create an OAuth2/OIDC provider and application for LFP Connect:

- Redirect URI: `https://connect.example.com/api/auth/callback`
- Scopes: `openid profile email entitlements`
- Client type: confidential
- Issuer mode: per-provider (the recommended Authentik default)

Create the application entitlement `subdomain.domain`, then bind the users or
team groups that may issue tunnel credentials. The built-in `entitlements`
scope places effective direct and group entitlements in the signed token.

The Go API performs OIDC authorization-code flow with PKCE. It accepts only a
verified ID token from the configured issuer and client, then checks the exact
entitlement again before issuing a route credential.

## NATS callout keys

Generate a dedicated Account NKey for signing Auth Callout responses and a
Curve NKey for encrypting callout request/reply payloads:

```sh
nsc generate nkey --account
nsc generate nkey --curve
```

Each command prints a private seed followed by its public key. Put the Account
seed in the `nats_auth_issuer_seed` Swarm secret and the Curve seed in
`nats_auth_xkey_seed`. Put only their public values in the deployment
environment as `NATS_AUTH_ISSUER_PUBLIC_KEY` and
`NATS_AUTH_XKEY_PUBLIC_KEY`.

The Account seed can authorize NATS connections and must be treated as a
high-value secret. Never place either seed in this repository or an image.

## External Swarm secrets

Create these external secrets before deploying. The examples intentionally
read values from protected files or standard input rather than command-line
arguments:

```sh
docker secret create authentik_client_secret ~/.secrets/authentik/lfp-connect/client-secret
openssl rand -base64 48 | docker secret create lfp_cookie_secret -
openssl rand -base64 48 | docker secret create lfp_ticket_secret -
openssl rand -base64 36 | docker secret create nats_callout_password -
openssl rand -base64 36 | docker secret create nats_system_password -
docker secret create nats_auth_issuer_seed ~/.secrets/nats/lfp-connect/auth-issuer-seed
docker secret create nats_auth_xkey_seed ~/.secrets/nats/lfp-connect/auth-xkey-seed
openssl rand -base64 48 | docker secret create nats_internal_server_token -
```

Use restrictive permissions on every source file. The stack mounts secrets
under `/run/secrets`; no secret value is declared in the stack environment.
NATS reads its password files in the container entrypoint immediately before
starting the server.

## Build and deploy

Images must be pushed to a registry reachable by every Swarm node, or loaded on
every node:

```sh
docker build -t registry.example.com/lfp-connect-auth:latest ./controlplane
docker build -t registry.example.com/lfp-connect-web:latest ./controlplane/web
docker build -f Dockerfile.server -t registry.example.com/lfp-pipe-server:latest .
docker push registry.example.com/lfp-connect-auth:latest
docker push registry.example.com/lfp-connect-web:latest
docker push registry.example.com/lfp-pipe-server:latest
```

Copy `.env.example` to a protected deployment environment file, set its public
values, then export them and deploy from this directory:

```sh
cd deploy/swarm
set -a
. ./.env
set +a
docker stack config --compose-file stack.yml >/dev/null
docker stack deploy --with-registry-auth --compose-file stack.yml lfp
```

Terminate HTTPS in an existing edge proxy and forward the control-plane origin
to the published web port. `LFP_AUTH_PUBLIC_URL` must be the browser-visible
HTTPS origin. The Authentik redirect URI must match it exactly.

## Configure a tunnel client

The web console returns a token, normalized client ID, request subject, NATS
URLs, and expiration. Store the token in a protected file and configure the
client with the returned values:

```toml
client_id = "unraid-east"
nats_url = "nats://nats.example.com:4222"
nats_token_file = "/run/secrets/lfp_route_token"
request_subject = "lfp.v1.connect.domain.subdomain.cool"

[[backend_rules]]
pattern = "cool.subdomain.domain"
backend_addr = "127.0.0.1:8080"
```

The configured `client_id` must match the one embedded in the issued ticket;
this also scopes the client's NATS reply inbox. Reissue and replace the ticket
before expiration, then reconnect the client.

## Current security boundary

The NATS control plane is authenticated and route-scoped. The reverse data
socket still uses the repository's existing connection-ID prefix and is not yet
cryptographically authenticated. Keep port 7001 restricted to trusted tunnel
client networks until the planned TLS callback capability is implemented.
