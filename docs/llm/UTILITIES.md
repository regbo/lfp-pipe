# Shared utility catalog

Use this index to find the narrow shared extension point before adding logic to
the server or client crates.

| Public utility | Location | Responsibility | Main consumers |
|---|---|---|---|
| `parse_server_runtime`, `parse_client_runtime` | `shared/src/cli.rs` | Resolve Clap flags and environment variables, then layer them over TOML configuration; client parsing expands all route sessions. | Binary entry points |
| `ServerConfig`, `ClientConfig`, `BackendRule` | `shared/src/config.rs` | Define concrete typed component configuration, defaults, and routing data. | CLI, server, client |
| `ClientConfigDefaults`, `ClientRouteConfig`, `load_client_configs` | `shared/src/config.rs` | Inherit shared settings into independently authenticated hostname sessions while retaining the legacy single-route format. | Multi-route tunnel client |
| `ClientOAuthConfig` | `shared/src/config.rs` | Configure Authentik machine credentials and automatic route-ticket renewal without storing NATS tickets. | Tunnel client |
| `extract_http_host`, `looks_like_http_prefix` | `shared/src/http.rs` | Detect supported HTTP prefixes and extract a normalized Host header. | Public server routing |
| `copy_bidirectional_with_mode` | `shared/src/io.rs` | Select splice or bounded buffered bidirectional TCP forwarding. | Server and client relays |
| `init`, `is_expected_disconnect` | `shared/src/logging.rs` | Initialize low-noise tracing and classify normal peer teardown. | Binary entry points and relay loops |
| `connect_nats` | `shared/src/nats.rs` | Establish a deterministic NATS control-plane connection. | Server and client startup |
| `connect_nats_with_token` | `shared/src/nats.rs` | Establish NATS connections from short-lived in-memory OAuth exchanges. | OAuth tunnel client |
| `hostname_request_subject` | `shared/src/routing.rs` | Convert a validated hostname into a reversed-domain NATS subject. | Domain-scoped control plane |
| `PrefixEnvelope` | `shared/src/prefix.rs` | Encode and validate the versioned callback-to-ingress binding prefix. | Client callback and public server |
| `ConnectionRequest`, `ConnectionClaim`, `ConnectionClaimAck` | `shared/src/protocol.rs` | Define JSON messages exchanged over NATS. | Server and client control plane |
| `matches_pattern`, `select_backend` | `shared/src/routing.rs` | Apply ordered exact, wildcard, and default backend rules. | Tunnel client |
| `extract_sni`, `validate_tls_record_header` | `shared/src/tls.rs` | Validate TLS handshake records and extract ClientHello SNI. | Public server routing |
