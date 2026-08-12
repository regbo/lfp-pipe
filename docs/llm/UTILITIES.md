# Shared utility catalog

Use this index to find the narrow shared extension point before adding logic to
the server or client crates.

| Public utility | Location | Responsibility | Main consumers |
|---|---|---|---|
| `parse_server_runtime`, `parse_client_runtime`, `DesktopMode` | `shared/src/cli.rs` | Resolve Clap flags and environment variables, then layer them over TOML configuration; client parsing expands all route sessions and selects automatic/required/headless desktop integration. | Binary entry points |
| `desktop::run`, `desktop::is_available` | `client/src/desktop.rs` | Host the portable tray-icon/winit event loop, expose status/open-config/exit actions, watch the active file, surface validation warnings, and supervise the async tunnel runtime on a worker thread. | Client binary on Windows, macOS, and desktop Linux |
| `config_source::run_central` | `client/src/config_source.rs` | Fetch, authenticate, validate, and continuously synchronize centrally managed route documents while retaining the last valid running configuration. | Headless and desktop tunnel clients |
| `desktop_settings` | `client/src/desktop_settings.rs` | Provide desktop-first remote-management defaults, short-lived browser enrollment, private per-user credentials, management-origin preferences, and native start-at-boot integration. | Cross-platform desktop client |
| `ServerConfig`, `SniPassthroughRoute`, `ClientConfig`, `BackendRule` | `shared/src/config.rs` | Define concrete typed component configuration, exact direct TLS/SNI passthrough routes, defaults, and tunnel routing data. | CLI, server, client |
| `ClientConfigDefaults`, `ClientRouteConfig`, `ClientPathRouteConfig`, `CentralClientBootstrap`, `load_client_configs` | `shared/src/config.rs` | Inherit shared settings into independently authenticated hostname sessions and path-specific backends, or select a minimal central-control-plane bootstrap, while retaining the legacy format. | Multi-route tunnel client |
| `ClientOAuthConfig` | `shared/src/config.rs` | Configure Authentik machine credentials and automatic route-ticket renewal without storing NATS tickets. | Tunnel client |
| `ClientAuthorizationConfig`, `ClientAuthorizationDefaults` | `shared/src/config.rs` | Configure exact-issuer/audience JWT validation, role policy, and bounded-staleness JWKS caching for protected HTTP routes. | Tunnel client |
| `ClientAcmeConfig`, `ClientAcmeDefaults` | `shared/src/config.rs` | Configure inheritable TLS-ALPN-01 certificate acquisition, persistent key caching, and local TLS termination. | Tunnel client |
| `extract_http_host`, `looks_like_http_prefix` | `shared/src/http.rs` | Detect supported HTTP prefixes and extract a normalized Host header. | Public server routing |
| `JwtAuthorizer` | `client/src/authorization.rs` | Fetch/discover and cache JWKS, validate bearer JWTs, enforce roles, return HTTP denials, and strip credentials before backend forwarding. | Plaintext and ACME-terminated client relays |
| `copy_bidirectional_with_mode` | `shared/src/io.rs` | Select splice or bounded buffered bidirectional TCP forwarding. | Server and client relays |
| `copy_bidirectional_buffered` | `shared/src/io.rs` | Forward arbitrary Tokio streams such as locally terminated TLS with the standard bounded buffers. | ACME TLS relay |
| `init`, `is_expected_disconnect` | `shared/src/logging.rs` | Initialize low-noise tracing and classify normal peer teardown. | Binary entry points and relay loops |
| `connect_nats` | `shared/src/nats.rs` | Establish a deterministic NATS control-plane connection. | Server and client startup |
| `connect_nats_with_token` | `shared/src/nats.rs` | Establish NATS connections from short-lived in-memory OAuth exchanges. | OAuth tunnel client |
| `BrandConfig`, `/api/branding` | `controlplane/internal/config`, `controlplane/internal/httpapi` | Resolve CLI-over-environment management branding and expose it to the static web console. | Auth service and management web |
| `hostname_request_subject` | `shared/src/routing.rs` | Convert a validated hostname into a reversed-domain NATS subject. | Domain-scoped control plane |
| `PrefixEnvelope` | `shared/src/prefix.rs` | Encode and validate the versioned callback-to-ingress binding prefix. | Client callback and public server |
| `ConnectionRequest`, `ConnectionClaim`, `ConnectionClaimAck` | `shared/src/protocol.rs` | Define JSON messages exchanged over NATS. | Server and client control plane |
| `matches_pattern`, `matches_path_prefix`, `select_backend_for_path` | `shared/src/routing.rs` | Select exact/wildcard hostname rules and the most-specific segment-boundary HTTP path backend. | Tunnel client |
| `extract_sni`, `validate_tls_record_header` | `shared/src/tls.rs` | Validate TLS handshake records and extract ClientHello SNI. | Public server routing |
