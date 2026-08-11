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
