# lfp-pipe

`lfp-pipe` publishes TCP services that live behind NAT or a firewall. A public
server accepts ingress traffic, announces it over NATS, and a matching private
client creates the reverse data connection to the server. The application bytes
then flow directly through that paired TCP connection.

The workspace produces two binaries:

- `lfp-pipe-server` accepts public and reverse data connections.
- `lfp-pipe-client` claims matching requests and connects to private backends.

The `shared` crate owns configuration, protocol types, routing, logging, and the
relay implementation used by both binaries. See
[`docs/llm/UTILITIES.md`](docs/llm/UTILITIES.md) for the shared utility catalog.

## How a connection works

1. A public TCP client connects to the server.
2. The server detects TLS SNI or an HTTP `Host` header when available.
3. The server publishes a `ConnectionRequest` over NATS.
4. Eligible clients claim the request; the server selects one round-robin.
5. The selected client connects to its private backend and opens a reverse TCP
   connection to the server's advertised data address.
6. A short prefix binds the reverse connection to the waiting public socket.
7. Server and client relay bytes bidirectionally until either side closes.

NATS is the control plane only. Payload traffic does not pass through NATS.

The public listener can also forward selected TLS connections directly by SNI,
allowing a TLS-first NATS endpoint to share the HTTPS port:

```toml
[[sni_passthrough_routes]]
hostname = "nats-pipe.example.com"
backend_addr = "127.0.0.1:4222"
```

NATS must use `tls.handshake_first: true`, and clients must enable TLS-first
(the lfp-pipe Rust NATS client does this for `tls://` URLs). Classic NATS is
server-first and cannot be identified by sniffing client bytes on a shared
listener. The passthrough keeps NATS TLS and authentication end-to-end.

Alternatively, enable the `async-nats` WebSocket transport by configuring a
`ws://` or `wss://` NATS URL. This is opt-in and preserves the complete URL path,
so a reverse proxy can route `wss://pipe.example.com/nats` beside management
HTTP traffic on one hostname and port. Existing `nats://` and `tls://` URLs keep
their current direct-TCP behavior.

> [!WARNING]
> The reverse data connection currently has no cryptographic authentication.
> The random connection ID is a binding token, not a durable authentication
> mechanism. Restrict the data listener to trusted networks until authenticated
> handshakes are implemented. NATS credentials protect only the control plane.

## Relay performance

On Linux, `relay_mode = "auto"` probes `tokio-splice2` once and uses kernel
`splice(2)` when it works. It falls back to Tokio's buffered relay with 256 KiB
per direction. `splice` forces the Linux backend, while `buffered` is portable
and is always used on Windows and macOS.

The larger buffered fallback reduces syscall and wakeup pressure, but it is not
a guaranteed throughput improvement: socket autotuning, congestion control,
latency, CPU, and the public-server hairpin can dominate. Benchmark the public
path before and after tuning. Expected `BrokenPipe` and connection-reset errors
during browser speed tests are debug events rather than warning spam.

## Build and run

Rust stable is the only build requirement. [mise](https://mise.jdx.dev/) is
optional and supplies convenient development tasks.

```powershell
cargo build --workspace --release
cargo run -p server -- --config .\server.example.toml
cargo run -p client -- --config .\client.example.toml
```

Every option appears in the generated help:

```text
lfp-pipe-server --help
lfp-pipe-client --help
```

For the local LibreSpeed stack, use `mise run server-dev` in one terminal and
`mise run client-dev` in another. Caddy listens on `9443`, LibreSpeed is bound to
loopback port `8080`, and the example route is `wsl.regbodesktop.local`.

## Configuration

Configuration is layered predictably:

```text
CLI flag > environment variable > TOML file > typed default
```

Both programs accept `--config` / `LFP_PIPE_CONFIG` and `--log-filter` /
`RUST_LOG`. Server overrides use these environment variables:

| Flag | Environment variable |
| --- | --- |
| `--public-listen` | `LFP_PIPE_PUBLIC_LISTEN` |
| `--data-listen` | `LFP_PIPE_DATA_LISTEN` |
| `--advertised-data-addr` | `LFP_PIPE_ADVERTISED_DATA_ADDR` |
| `--nats-url` | `LFP_PIPE_NATS_URL` |
| `--relay-mode` | `LFP_PIPE_RELAY_MODE` |
| `--request-subject` | `LFP_PIPE_REQUEST_SUBJECT` |
| `--claim-timeout-ms` | `LFP_PIPE_CLAIM_TIMEOUT_MS` |
| `--pending-timeout-ms` | `LFP_PIPE_PENDING_TIMEOUT_MS` |

Client-specific overrides are:

| Flag | Environment variable |
| --- | --- |
| `--client-id` | `LFP_PIPE_CLIENT_ID` |
| `--nats-url` | `LFP_PIPE_NATS_URL` |
| `--relay-mode` | `LFP_PIPE_RELAY_MODE` |
| `--request-subject` | `LFP_PIPE_REQUEST_SUBJECT` |
| `--claim-ack-timeout-ms` | `LFP_PIPE_CLAIM_ACK_TIMEOUT_MS` |

Backend rules are structured and therefore remain TOML-only. Start from
[`server.example.toml`](server.example.toml) and
[`client.example.toml`](client.example.toml). For an unattended client, create
an Authentik service principal in the management console and start from
[`client.oauth.example.toml`](client.oauth.example.toml). The client exchanges
the service-account app password for an Authentik access token, requests an
exact-route NATS ticket from the control plane, and reconnects with a renewed
ticket before expiration. Keep the one-time app password in a protected file;
do not put real NATS or OAuth credentials in tracked configuration.

One process can also maintain several independently authenticated hostnames.
Start from [`client.multi.example.toml`](client.multi.example.toml): shared
transport, backend, and Authentik values live under `[defaults]` and
`[defaults.oauth]`, while each `[[routes]]` entry supplies its `client_id` and
exact `hostname`. Route-level values win over shared defaults, including a
nested `[routes.oauth]` table for the most recently declared route. The full
precedence order is CLI/environment override, route value, shared default,
then typed default. Because `client_id` must remain unique per active route,
the `--client-id` override is rejected when a file contains multiple routes.

Each route gets its own OAuth ticket renewal and NATS subscription. If one
route fails, the process exits so a service supervisor can restart the whole
declared set instead of silently leaving only some hostnames available. The
original flat single-route format remains supported without changes.

### Protect an HTTP backend with OAuth JWTs

Use [`client.ollama.example.toml`](client.ollama.example.toml) to expose a local
Ollama listener while requiring a bearer access token. The client acts as an
OAuth resource server: it does not run an interactive login redirect. It
validates the token signature, exact `iss`, at least one configured `aud`,
`exp`, optional `nbf`, and the configured roles before connecting to Ollama.
Invalid or missing credentials receive `401`; a valid token without the
required role receives `403`.

The configuration keeps three trust boundaries separate:

- `[oauth]` obtains route-scoped NATS credentials for the tunnel client.
- `[acme]` terminates public HTTPS locally.
- `[authorization]` authenticates each HTTP connection before backend access.

Protected and path-routed hostnames require ACME. This prevents an encrypted
TLS path from bypassing HTTP routing or JWT inspection. Add one or more
`[[routes.path_routes]]` entries to send a segment-boundary prefix to another
backend under the same certificate. `strip_path_prefix = true` turns a public
request such as `/ollama/api/tags` into `/api/tags` for Ollama. The most-specific
matching prefix wins and the hostname's ordinary `backend_addr` is the fallback.
Set `backend_host` when the private service validates the HTTP `Host` header;
for example, Ollama commonly needs `backend_host = "127.0.0.1:11434"`.

Only HTTP/1.1 is advertised on the locally terminated TLS connection. A path
route can have its own `[routes.path_routes.authorization]` policy, leaving the
rest of the hostname available for a browser-oriented Authentik forward-auth
proxy. The bearer header is removed before forwarding by default; set
`forward_authorization = true` only when the private backend must receive it.

### Desktop tray

On Windows, macOS, and GTK-based Linux desktops, the client automatically adds
an lfp-pipe system-tray icon. Its menu shows the process status and can open the
active TOML file or its folder, validate and reload the configuration, or stop
the client. Reload starts a replacement with the same arguments only after the
TOML parses successfully.

Use `--tray always` to require desktop integration or `--tray never` for a
headless service. `LFP_PIPE_TRAY=auto|always|never` provides the same centralized
environment setting; CLI flags continue to take precedence.

`issuer` is also the OIDC discovery base, so `jwks_uri` is normally omitted.
For an Authentik per-provider issuer, use the exact trailing-slash issuer shown
in its discovery document. Set `jwks_uri` explicitly if discovery is not
available. Successfully fetched keys are persisted to `jwks_cache_file`; when
Authentik or its JWKS endpoint is temporarily unavailable, the client uses that
file for up to `jwks_max_stale_seconds`. Set the value to `0` only for a
deliberately static, manually managed key set with no staleness limit.

Authentik must put the expected audience and role/group claim into the access
token. For example, configure a `groups` scope/property mapping and require
`ollama-users`. Role claim paths may be nested, such as
`roles_claim = "realm_access.roles"`, and `role_match` may be `any` or `all`.
Issuer wildcards are intentionally unsupported because verification keys must
remain bound to one exact issuer. The implementation follows the JWT best
practice requirements to verify algorithms, issuer, and audience described by
[RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html).

Example request after obtaining an Authentik access token:

```sh
curl https://services.pipe.example.com/ollama/api/tags \
  -H "Authorization: Bearer $OLLAMA_ACCESS_TOKEN"
```

### Automatic certificates

Routes can terminate TLS inside `lfp-pipe-client` without Caddy or another
local listener. Add `[acme]` to a legacy file, or `[defaults.acme]` with an
optional `[routes.acme]` override in a multi-route file. The client uses
TLS-ALPN-01 over the existing public tunnel, stores the ACME account and
certificate below `cache_dir/<hostname>`, and forwards decrypted bytes to
`backend_addr`. No additional client port is opened.

```toml
[defaults]
backend_addr = "127.0.0.1:8080"
http_backend_addr = "127.0.0.1:8080"

[defaults.acme]
contacts = ["mailto:admin@example.com"]
cache_dir = "/var/lib/lfp-pipe/acme"
production = false
```

Staging is the default to protect production CA rate limits. Set
`production = true` only after the route works end to end, or set
`directory_url` for another ACME-compatible CA. Treat `cache_dir` as secret
material because it contains account and certificate private keys. On Unix the
client creates each hostname directory with mode `0700`.

Set `enabled = false` in `[routes.acme]` when a route should opt out of an
inherited `[defaults.acme]` block.

When ACME is enabled, TLS is terminated and sent to `backend_addr` as plaintext.
Plain HTTP is detected and sent to `http_backend_addr`; if that setting is
omitted it falls back to `backend_addr`. Automatic TLS uses the buffered relay,
so explicit `relay_mode = "splice"` is rejected while `auto` and `buffered` work.

Routes that terminate TLS locally can send plaintext HTTP to a separate
listener without another tunnel. Set `backend_addr` to the TLS/default socket
and `http_backend_addr` to Caddy's HTTP socket. The client peeks at the first
tunneled bytes and sends HTTP requests—including `/.well-known/acme-challenge/`
for ACME HTTP-01—to the HTTP backend while TLS remains on the default backend.

## Logging

The default filter is `info,async_nats=warn`: startup and operational state are
visible, while per-connection events stay quiet. Enable targeted diagnostics
without recompiling:

```powershell
lfp-pipe-client --config client.toml --log-filter "info,client=debug,shared=debug"
$env:RUST_LOG = "info,server=debug,shared=trace"
```

Logging uses `tracing`, so disabled debug callsites are filtered before events
are formatted. The one debug path that constructs a route-pattern list is also
guarded explicitly, avoiding that allocation when debug logging is disabled.
NATS URL parse errors deliberately omit the URL to avoid leaking credentials.

## Tests

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
```

Linux-specific splice behavior should also be tested on Linux (WSL is fine).
The relay tests cover explicit buffered/splice modes, large asymmetric payloads,
half-closes, and fallback behavior.

## Releases

Pushing a semantic version tag such as `v1.2.3` runs the tagged-release matrix
for Linux x86-64/ARM64, Windows x86-64/ARM64, and macOS Intel/Apple Silicon.
Each platform is tested natively, packaged with both binaries, checksummed, and
attached to a GitHub release. Each archive has a conventional `bin/` directory
that mise's GitHub backend discovers after extraction.

Install both binaries from the latest compatible GitHub release:

```text
mise use -g github:regbo/lfp-pipe
lfp-pipe-server --help
lfp-pipe-client --help
```

If the repository is private, provide mise with GitHub access through its
normal `GITHUB_TOKEN`, `MISE_GITHUB_TOKEN`, or authenticated GitHub CLI lookup;
do not put the token in this repository or on the command line.

For an ephemeral pinned invocation, use:

```text
mise exec github:regbo/lfp-pipe@0.1.1 -- lfp-pipe-server --version
```

Create the next tag from a clean worktree with:

```text
mise run version:bump patch
mise run version:bump minor --push
mise run version:bump major
```

## Deployment

- [`deploy/swarm01/README.md`](deploy/swarm01/README.md) documents the public
  native systemd server.
- [`deploy/swarm/README.md`](deploy/swarm/README.md) documents the Authentik,
  NATS Auth Callout, web console, and Docker Swarm control plane.
- [`deploy/unraid/README.md`](deploy/unraid/README.md) documents the native
  LFPConnect client/server supervisors and LibreSpeed backend.

Current LibreSpeed public endpoint: `http://swarm01.lfpconnect.io:7443/`.
