//! Typed TOML configuration and the override layer shared by both binaries.
//!
//! Client files support two shapes. The original flat shape describes one
//! route and remains supported. The multi-route shape declares shared values
//! under `[defaults]` and independently authenticated hostnames under
//! `[[routes]]`. Resolution is deliberately shallow and predictable:
//!
//! `CLI/environment override > route value > shared default > typed default`.
//!
//! OAuth fields follow the same rule, except `hostname` always comes from its
//! route. This lets one Authentik service principal and secret file serve all
//! of its entitled hostnames without copying credentials into every entry.
//!
//! ```toml
//! [defaults]
//! nats_url = "tls://nats-pipe.example.com:443"
//! backend_addr = "127.0.0.1:443"
//! http_backend_addr = "127.0.0.1:80"
//!
//! [defaults.oauth]
//! token_url = "https://auth.example.com/application/o/token/"
//! provider_client_id = "lfp-pipe"
//! username = "lfp-pipe-team"
//! client_secret_file = "/run/secrets/client-secret"
//! control_plane_url = "https://manage-pipe.example.com"
//!
//! [defaults.acme]
//! contacts = ["mailto:admin@example.com"]
//! cache_dir = "~/.cache/lfp-pipe/acme"
//! production = false
//!
//! [[routes]]
//! client_id = "site-a"
//! hostname = "site-a.pipe.example.com"
//!
//! [[routes]]
//! client_id = "site-b"
//! hostname = "site-b.pipe.example.com"
//! backend_addr = "127.0.0.1:8443"
//! ```

use std::{collections::HashSet, fs, path::Path};

use anyhow::Context;
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

/// Minimal bootstrap document for centrally managed client configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct CentralClientBootstrap {
    /// Browser-visible management origin serving the authorized configuration.
    pub control_plane_url: String,
    /// Select centrally managed configuration instead of local route entries.
    #[serde(default)]
    pub control_plane_config: bool,
    /// Authentik service-account username; environment or CLI may provide it.
    #[serde(default)]
    pub username: Option<String>,
    /// File containing the Authentik service-account app password.
    #[serde(default)]
    pub client_secret_file: Option<String>,
}

/// Public-server configuration loaded from TOML and optional CLI overrides.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Address accepting public ingress connections.
    pub public_listen: String,
    /// Address accepting callback/data connections from tunnel clients.
    pub data_listen: String,
    /// Reachable callback address advertised to clients.
    pub advertised_data_addr: Option<String>,
    /// NATS URL used exclusively for control-plane messages.
    pub nats_url: String,
    /// Optional file containing a NATS bearer token.
    #[serde(default)]
    pub nats_token_file: Option<String>,
    /// Stream-copy implementation used after a callback is paired.
    #[serde(default)]
    pub relay_mode: RelayMode,
    /// NATS subject on which connection requests are published.
    #[serde(default = "default_request_subject")]
    pub request_subject: String,
    /// Append reversed hostname labels to the request subject.
    #[serde(default)]
    pub domain_subject_routing: bool,
    /// Maximum wait for at least one client claim.
    #[serde(default = "default_claim_timeout_ms")]
    pub claim_timeout_ms: u64,
    /// Maximum wait for the winning client's callback socket.
    #[serde(default = "default_pending_timeout_ms")]
    pub pending_timeout_ms: u64,
    /// Exact TLS SNI routes forwarded directly from the public listener.
    ///
    /// This is suitable for TLS-first protocols such as NATS with
    /// `handshake_first: true`; TLS remains end-to-end to the backend.
    #[serde(default)]
    pub sni_passthrough_routes: Vec<SniPassthroughRoute>,
}

/// One exact TLS hostname forwarded directly by the public server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SniPassthroughRoute {
    /// Exact, case-insensitive TLS Server Name Indication value.
    pub hostname: String,
    /// TCP destination that terminates TLS and handles the application protocol.
    pub backend_addr: String,
}

/// Optional server values supplied by Clap after CLI/environment resolution.
#[derive(Debug, Default)]
pub struct ServerOverrides {
    /// Override for [`ServerConfig::public_listen`].
    pub public_listen: Option<String>,
    /// Override for [`ServerConfig::data_listen`].
    pub data_listen: Option<String>,
    /// Override for [`ServerConfig::advertised_data_addr`]; empty clears it.
    pub advertised_data_addr: Option<String>,
    /// Override for [`ServerConfig::nats_url`].
    pub nats_url: Option<String>,
    /// Override for [`ServerConfig::nats_token_file`].
    pub nats_token_file: Option<String>,
    /// Override for [`ServerConfig::relay_mode`].
    pub relay_mode: Option<RelayMode>,
    /// Override for [`ServerConfig::request_subject`].
    pub request_subject: Option<String>,
    /// Override for [`ServerConfig::domain_subject_routing`].
    pub domain_subject_routing: Option<bool>,
    /// Override for [`ServerConfig::claim_timeout_ms`].
    pub claim_timeout_ms: Option<u64>,
    /// Override for [`ServerConfig::pending_timeout_ms`].
    pub pending_timeout_ms: Option<u64>,
}

/// Available bidirectional stream-copy implementations.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum RelayMode {
    /// Probe Linux splice once and use the buffered implementation if unavailable.
    #[default]
    Auto,
    /// Always use Tokio's userspace buffered copy.
    Buffered,
    /// Require Linux splice and surface setup failures.
    Splice,
}

impl ServerConfig {
    /// Return the callback address placed in each connection request.
    pub fn server_data_addr(&self) -> &str {
        self.advertised_data_addr
            .as_deref()
            .unwrap_or(&self.data_listen)
    }

    /// Apply already-resolved CLI/environment values over the TOML values.
    pub fn with_overrides(mut self, overrides: ServerOverrides) -> Self {
        if let Some(value) = overrides.public_listen {
            self.public_listen = value;
        }
        if let Some(value) = overrides.data_listen {
            self.data_listen = value;
        }
        if let Some(value) = overrides.advertised_data_addr {
            self.advertised_data_addr = (!value.is_empty()).then_some(value);
        }
        if let Some(value) = overrides.nats_url {
            self.nats_url = value;
        }
        if let Some(value) = overrides.nats_token_file {
            self.nats_token_file = (!value.is_empty()).then_some(value);
        }
        if let Some(value) = overrides.relay_mode {
            self.relay_mode = value;
        }
        if let Some(value) = overrides.request_subject {
            self.request_subject = value;
        }
        if let Some(value) = overrides.domain_subject_routing {
            self.domain_subject_routing = value;
        }
        if let Some(value) = overrides.claim_timeout_ms {
            self.claim_timeout_ms = value;
        }
        if let Some(value) = overrides.pending_timeout_ms {
            self.pending_timeout_ms = value;
        }
        self
    }
}

/// Private-backend client configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Stable identifier included in claims and callback prefixes.
    pub client_id: String,
    /// NATS URL used exclusively for control-plane messages.
    pub nats_url: String,
    /// Optional file containing a NATS bearer token.
    #[serde(default)]
    pub nats_token_file: Option<String>,
    /// Optional Authentik exchange used to obtain and renew route-scoped NATS tickets.
    #[serde(default)]
    pub oauth: Option<ClientOAuthConfig>,
    /// Optional automatic certificate acquisition and local TLS termination.
    #[serde(default)]
    pub acme: Option<ClientAcmeConfig>,
    /// Optional JWT policy enforced before any HTTP request reaches a backend.
    #[serde(default)]
    pub authorization: Option<ClientAuthorizationConfig>,
    /// Stream-copy implementation used between callback and backend sockets.
    #[serde(default)]
    pub relay_mode: RelayMode,
    /// NATS subject from which connection requests are consumed.
    #[serde(default = "default_request_subject")]
    pub request_subject: String,
    /// Maximum wait for the server to accept or reject a claim.
    #[serde(default = "default_claim_ack_timeout_ms")]
    pub claim_ack_timeout_ms: u64,
    /// Ordered hostname-to-backend routing rules.
    pub backend_rules: Vec<BackendRule>,
}

/// JWT resource-server policy protecting a private HTTP backend.
///
/// Issuer and audience matching are exact by design. Wildcard issuer matching
/// would allow tokens from a different tenant or Authentik provider to cross
/// an authorization boundary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientAuthorizationConfig {
    /// Exact JWT `iss` claim and OIDC issuer used for discovery.
    pub issuer: String,
    /// One or more accepted JWT `aud` values.
    pub audiences: Vec<String>,
    /// Explicit JWKS endpoint; omitted to use OIDC discovery from `issuer`.
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// Persistent JWKS cache used when discovery or Authentik is unavailable.
    #[serde(default = "default_jwks_cache_file")]
    pub jwks_cache_file: String,
    /// Dot-separated claim path containing a string or array of role names.
    #[serde(default = "default_roles_claim")]
    pub roles_claim: String,
    /// Roles required in the configured claim. Empty means signature/claims only.
    #[serde(default)]
    pub required_roles: Vec<String>,
    /// Forward the caller's bearer token to the private backend.
    #[serde(default)]
    pub forward_authorization: bool,
    /// Whether any or all configured roles must be present.
    #[serde(default)]
    pub role_match: RoleMatch,
    /// Explicit asymmetric JWS algorithm allowlist.
    #[serde(default = "default_jwt_algorithms")]
    pub algorithms: Vec<String>,
    /// Allowed clock skew for `exp` and `nbf` validation.
    #[serde(default = "default_jwt_leeway_seconds")]
    pub leeway_seconds: u64,
    /// Refresh remotely obtained JWKS after this interval.
    #[serde(default = "default_jwks_refresh_seconds")]
    pub jwks_refresh_seconds: u64,
    /// Maximum age of a cached JWKS when the identity provider is unavailable.
    #[serde(default = "default_jwks_max_stale_seconds")]
    pub jwks_max_stale_seconds: u64,
    /// Maximum time to wait for the first complete HTTP header block.
    #[serde(default = "default_auth_header_timeout_ms")]
    pub header_timeout_ms: u64,
    /// Maximum accepted HTTP request-header size.
    #[serde(default = "default_auth_max_header_bytes")]
    pub max_header_bytes: usize,
}

/// Required-role matching semantics.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RoleMatch {
    /// At least one configured role must be present.
    #[default]
    Any,
    /// Every configured role must be present.
    All,
}

/// Authentik machine credential and control-plane exchange configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientOAuthConfig {
    /// Authentik OAuth token endpoint.
    pub token_url: String,
    /// Public OAuth provider client identifier.
    pub provider_client_id: String,
    /// Authentik service-account username.
    pub username: String,
    /// File containing the one-time service-account app password.
    pub client_secret_file: String,
    /// Browser-visible LFP Pipe control-plane origin.
    pub control_plane_url: String,
    /// Exact hostname for which route tickets are requested.
    pub hostname: String,
    /// OAuth scopes requested from Authentik.
    #[serde(default = "default_oauth_scopes")]
    pub scopes: Vec<String>,
    /// Renew the NATS connection this many seconds before ticket expiry.
    #[serde(default = "default_oauth_renew_before_seconds")]
    pub renew_before_seconds: u64,
}

/// Automatic certificate settings for one concrete client route.
///
/// The client uses TLS-ALPN-01 over the existing tunnel, so enabling this does
/// not bind or expose another local port. Certificates and account keys are
/// persisted below [`Self::cache_dir`] and reused across restarts and renewals.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientAcmeConfig {
    /// Exact DNS name placed on the certificate and validated by the CA.
    pub domain: String,
    /// ACME account contacts, normally `mailto:user@example.com` values.
    #[serde(default)]
    pub contacts: Vec<String>,
    /// Persistent directory containing ACME account keys and certificates.
    #[serde(default = "default_acme_cache_dir")]
    pub cache_dir: String,
    /// Use Let's Encrypt production instead of its rate-limit-safe staging CA.
    #[serde(default)]
    pub production: bool,
    /// Optional custom ACME directory URL, taking precedence over `production`.
    #[serde(default)]
    pub directory_url: Option<String>,
}

/// Optional client values supplied by Clap after CLI/environment resolution.
#[derive(Debug, Clone, Default)]
pub struct ClientOverrides {
    /// Override for [`ClientConfig::client_id`].
    pub client_id: Option<String>,
    /// Override for [`ClientConfig::nats_url`].
    pub nats_url: Option<String>,
    /// Override for [`ClientConfig::nats_token_file`].
    pub nats_token_file: Option<String>,
    /// Override for [`ClientConfig::relay_mode`].
    pub relay_mode: Option<RelayMode>,
    /// Override for [`ClientConfig::request_subject`].
    pub request_subject: Option<String>,
    /// Override for [`ClientConfig::claim_ack_timeout_ms`].
    pub claim_ack_timeout_ms: Option<u64>,
}

/// Shared values inherited by every route in a multi-route client file.
///
/// Put stable transport, credential, and backend values here. A route may
/// override any field, which is useful when most hostnames terminate at Caddy
/// on ports 80/443 but one hostname maps to a different local service.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ClientConfigDefaults {
    /// Default NATS URL used exclusively for control-plane messages.
    #[serde(default)]
    pub nats_url: Option<String>,
    /// Default file containing a NATS bearer token.
    #[serde(default)]
    pub nats_token_file: Option<String>,
    /// Default Authentik exchange settings shared by route sessions.
    #[serde(default)]
    pub oauth: Option<ClientOAuthDefaults>,
    /// Default automatic certificate settings shared by route sessions.
    #[serde(default)]
    pub acme: Option<ClientAcmeDefaults>,
    /// Default JWT authorization settings shared by protected routes.
    #[serde(default)]
    pub authorization: Option<ClientAuthorizationDefaults>,
    /// Default stream-copy implementation.
    #[serde(default)]
    pub relay_mode: Option<RelayMode>,
    /// Default NATS connection-request subject.
    #[serde(default)]
    pub request_subject: Option<String>,
    /// Default maximum wait for the server's claim decision.
    #[serde(default)]
    pub claim_ack_timeout_ms: Option<u64>,
    /// Default private destination for TLS or raw TCP traffic.
    #[serde(default)]
    pub backend_addr: Option<String>,
    /// Default HTTP Host value presented to a selected backend.
    #[serde(default)]
    pub backend_host: Option<String>,
    /// Default private destination for plaintext HTTP traffic.
    #[serde(default)]
    pub http_backend_addr: Option<String>,
    /// Default standard reverse-proxy forwarding-header behavior.
    #[serde(default)]
    pub proxy_headers: Option<bool>,
}

/// Inheritable JWT authorization settings for multi-route client files.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ClientAuthorizationDefaults {
    /// Whether this route inherits or enables authorization.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Exact JWT issuer.
    #[serde(default)]
    pub issuer: Option<String>,
    /// Accepted JWT audiences.
    #[serde(default)]
    pub audiences: Option<Vec<String>>,
    /// Optional explicit JWKS endpoint.
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// Persistent JWKS cache file.
    #[serde(default)]
    pub jwks_cache_file: Option<String>,
    /// Dot-separated role claim path.
    #[serde(default)]
    pub roles_claim: Option<String>,
    /// Required role names.
    #[serde(default)]
    pub required_roles: Option<Vec<String>>,
    /// Whether to forward the caller's bearer token to the private backend.
    #[serde(default)]
    pub forward_authorization: Option<bool>,
    /// Any/all matching mode.
    #[serde(default)]
    pub role_match: Option<RoleMatch>,
    /// Explicit asymmetric JWS algorithm allowlist.
    #[serde(default)]
    pub algorithms: Option<Vec<String>>,
    /// JWT clock-skew allowance.
    #[serde(default)]
    pub leeway_seconds: Option<u64>,
    /// Remote JWKS refresh interval.
    #[serde(default)]
    pub jwks_refresh_seconds: Option<u64>,
    /// Maximum acceptable fallback-cache age.
    #[serde(default)]
    pub jwks_max_stale_seconds: Option<u64>,
    /// HTTP header read timeout.
    #[serde(default)]
    pub header_timeout_ms: Option<u64>,
    /// Maximum HTTP request-header size.
    #[serde(default)]
    pub max_header_bytes: Option<usize>,
}

/// Inheritable Authentik settings for multi-route client files.
///
/// All fields are optional at this layer because a route can fill in or
/// replace individual values. Once defaults and route values are merged, every
/// required OAuth field is validated before any network session is started.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ClientOAuthDefaults {
    /// Authentik OAuth token endpoint.
    #[serde(default)]
    pub token_url: Option<String>,
    /// Public OAuth provider client identifier.
    #[serde(default)]
    pub provider_client_id: Option<String>,
    /// Authentik service-account username.
    #[serde(default)]
    pub username: Option<String>,
    /// File containing the service-account app password.
    #[serde(default)]
    pub client_secret_file: Option<String>,
    /// Browser-visible LFP Pipe control-plane origin.
    #[serde(default)]
    pub control_plane_url: Option<String>,
    /// OAuth scopes requested from Authentik.
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    /// Renew the NATS connection this many seconds before ticket expiry.
    #[serde(default)]
    pub renew_before_seconds: Option<u64>,
}

/// Inheritable automatic certificate settings for multi-route client files.
///
/// The certificate domain is intentionally absent: every expanded route uses
/// its own exact `hostname`, preventing a shared default from accidentally
/// requesting a certificate for the wrong route.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ClientAcmeDefaults {
    /// Whether this route should inherit or enable automatic TLS termination.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// ACME account contacts, normally `mailto:user@example.com` values.
    #[serde(default)]
    pub contacts: Option<Vec<String>>,
    /// Persistent directory containing ACME account keys and certificates.
    #[serde(default)]
    pub cache_dir: Option<String>,
    /// Use Let's Encrypt production instead of its staging CA.
    #[serde(default)]
    pub production: Option<bool>,
    /// Optional custom ACME directory URL for private CAs or Pebble tests.
    #[serde(default)]
    pub directory_url: Option<String>,
}

/// One independently authenticated hostname in a multi-route client file.
///
/// Each entry expands into a normal [`ClientConfig`] with one hostname and an
/// optional ordered set of path-specific backend rules. Consequently OAuth
/// acquisition, NATS subscription, ticket renewal, and failures are isolated
/// per hostname while sharing one process.
#[derive(Debug, Clone, Deserialize)]
pub struct ClientRouteConfig {
    /// Stable identifier included in claims and callback prefixes.
    pub client_id: String,
    /// Exact hostname used for OAuth ticket issuance and backend matching.
    pub hostname: String,
    /// Optional backend pattern; defaults to the exact hostname.
    #[serde(default)]
    pub pattern: Option<String>,
    /// Route-specific NATS URL override.
    #[serde(default)]
    pub nats_url: Option<String>,
    /// Route-specific NATS bearer-token file override.
    #[serde(default)]
    pub nats_token_file: Option<String>,
    /// Route-specific Authentik settings layered over shared OAuth defaults.
    #[serde(default)]
    pub oauth: Option<ClientOAuthDefaults>,
    /// Route-specific ACME settings layered over shared ACME defaults.
    #[serde(default)]
    pub acme: Option<ClientAcmeDefaults>,
    /// Route-specific JWT policy layered over shared authorization defaults.
    #[serde(default)]
    pub authorization: Option<ClientAuthorizationDefaults>,
    /// Route-specific stream-copy implementation override.
    #[serde(default)]
    pub relay_mode: Option<RelayMode>,
    /// Route-specific NATS connection-request subject override.
    #[serde(default)]
    pub request_subject: Option<String>,
    /// Route-specific claim acknowledgement timeout override.
    #[serde(default)]
    pub claim_ack_timeout_ms: Option<u64>,
    /// Route-specific private destination for TLS or raw TCP traffic.
    #[serde(default)]
    pub backend_addr: Option<String>,
    /// Route-specific HTTP Host value presented to the backend.
    #[serde(default)]
    pub backend_host: Option<String>,
    /// Route-specific private destination for plaintext HTTP traffic.
    #[serde(default)]
    pub http_backend_addr: Option<String>,
    /// Route-specific standard forwarding-header override.
    #[serde(default)]
    pub proxy_headers: Option<bool>,
    /// More-specific HTTP path backends served by this hostname/certificate.
    #[serde(default)]
    pub path_routes: Vec<ClientPathRouteConfig>,
}

/// One path-specific backend nested beneath a multi-route hostname.
#[derive(Debug, Clone, Deserialize)]
pub struct ClientPathRouteConfig {
    /// URL path prefix, matched on a segment boundary.
    pub path_prefix: String,
    /// Private destination for requests under this prefix.
    pub backend_addr: String,
    /// HTTP Host value presented to this backend instead of the public host.
    #[serde(default)]
    pub backend_host: Option<String>,
    /// Remove the prefix before forwarding to the backend.
    #[serde(default)]
    pub strip_path_prefix: bool,
    /// Set safe standard forwarding headers before proxying.
    #[serde(default)]
    pub proxy_headers: Option<bool>,
    /// Optional JWT policy for only this path backend.
    #[serde(default)]
    pub authorization: Option<ClientAuthorizationDefaults>,
}

#[derive(Debug, Deserialize)]
struct MultiRouteClientConfig {
    #[serde(default)]
    defaults: ClientConfigDefaults,
    routes: Vec<ClientRouteConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ClientConfigDocument {
    MultiRoute(MultiRouteClientConfig),
    Legacy(ClientConfig),
}

impl ClientConfig {
    /// Apply already-resolved CLI/environment values over the TOML values.
    pub fn with_overrides(mut self, overrides: ClientOverrides) -> Self {
        if let Some(value) = overrides.client_id {
            self.client_id = value;
        }
        if let Some(value) = overrides.nats_url {
            self.nats_url = value;
        }
        if let Some(value) = overrides.nats_token_file {
            self.nats_token_file = (!value.is_empty()).then_some(value);
        }
        if let Some(value) = overrides.relay_mode {
            self.relay_mode = value;
        }
        if let Some(value) = overrides.request_subject {
            self.request_subject = value;
        }
        if let Some(value) = overrides.claim_ack_timeout_ms {
            self.claim_ack_timeout_ms = value;
        }
        self
    }
}

/// One ordered hostname pattern and its private TCP backend.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackendRule {
    /// Exact host, `*.suffix` wildcard, or empty string for non-HTTP/TLS traffic.
    #[serde(default)]
    pub pattern: String,
    /// Optional HTTP URL path prefix, matched on a segment boundary.
    #[serde(default)]
    pub path_prefix: Option<String>,
    /// Remove [`Self::path_prefix`] before forwarding the HTTP request.
    #[serde(default)]
    pub strip_path_prefix: bool,
    /// Set safe standard forwarding headers before proxying HTTP.
    #[serde(default = "default_true")]
    pub proxy_headers: bool,
    /// Socket address dialed by the client when this rule matches.
    pub backend_addr: String,
    /// Optional HTTP Host value substituted before forwarding.
    #[serde(default)]
    pub backend_host: Option<String>,
    /// Optional destination for plaintext HTTP, including ACME HTTP-01 requests.
    #[serde(default)]
    pub http_backend_addr: Option<String>,
    /// Optional JWT policy applied only when this backend rule is selected.
    #[serde(default)]
    pub authorization: Option<ClientAuthorizationConfig>,
}

impl BackendRule {
    /// Resolve shorthand `:PORT` backend addresses to loopback.
    pub fn resolved_backend_addr(&self) -> String {
        resolve_loopback_shorthand(&self.backend_addr)
    }

    /// Resolve the plaintext HTTP destination, falling back to the default backend.
    pub fn resolved_http_backend_addr(&self) -> String {
        if let Some(address) = self.http_backend_addr.as_deref() {
            resolve_loopback_shorthand(address)
        } else {
            self.resolved_backend_addr()
        }
    }
}

fn resolve_loopback_shorthand(address: &str) -> String {
    if address.starts_with(':') {
        format!("127.0.0.1{address}")
    } else {
        address.to_string()
    }
}

fn default_request_subject() -> String {
    "tunnel.connect.request".to_string()
}

fn default_true() -> bool {
    true
}

fn default_claim_timeout_ms() -> u64 {
    3_000
}

fn default_pending_timeout_ms() -> u64 {
    10_000
}

fn default_claim_ack_timeout_ms() -> u64 {
    1_500
}

fn default_oauth_scopes() -> Vec<String> {
    vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
        "entitlements".to_string(),
    ]
}

fn default_oauth_renew_before_seconds() -> u64 {
    60
}

fn default_roles_claim() -> String {
    "groups".to_string()
}

fn default_jwt_algorithms() -> Vec<String> {
    vec!["RS256".to_string()]
}

fn default_jwt_leeway_seconds() -> u64 {
    30
}

fn default_jwks_cache_file() -> String {
    "~/.cache/lfp-pipe/auth/jwks.json".to_string()
}

fn default_acme_cache_dir() -> String {
    "~/.cache/lfp-pipe/acme".to_string()
}

fn default_jwks_refresh_seconds() -> u64 {
    3_600
}

fn default_jwks_max_stale_seconds() -> u64 {
    604_800
}

fn default_auth_header_timeout_ms() -> u64 {
    5_000
}

fn default_auth_max_header_bytes() -> usize {
    32 * 1024
}

/// Load server TOML without applying CLI or environment overrides.
pub fn load_server_config(path: &Path) -> anyhow::Result<ServerConfig> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read server config {}", path.display()))?;
    let config: ServerConfig = toml::from_str(&raw)
        .with_context(|| format!("failed to parse server config {}", path.display()))?;
    validate_server_config(&config)
        .with_context(|| format!("invalid server config {}", path.display()))?;
    Ok(config)
}

fn validate_server_config(config: &ServerConfig) -> anyhow::Result<()> {
    let mut hostnames = HashSet::new();
    for route in &config.sni_passthrough_routes {
        let hostname = route.hostname.trim().to_ascii_lowercase();
        anyhow::ensure!(
            !hostname.is_empty(),
            "SNI passthrough hostname cannot be empty"
        );
        anyhow::ensure!(
            !route.backend_addr.trim().is_empty(),
            "SNI passthrough backend_addr cannot be empty for {}",
            route.hostname
        );
        anyhow::ensure!(
            hostnames.insert(hostname),
            "duplicate SNI passthrough hostname {}",
            route.hostname
        );
    }
    Ok(())
}

/// Load client TOML without applying CLI or environment overrides.
pub fn load_client_config(path: &Path) -> anyhow::Result<ClientConfig> {
    let mut configs = load_client_configs(path)?;
    anyhow::ensure!(
        configs.len() == 1,
        "client config {} contains {} routes; use load_client_configs",
        path.display(),
        configs.len()
    );
    Ok(configs.remove(0))
}

/// Load one legacy client or expand a multi-route TOML file into route sessions.
///
/// Multi-route expansion completes all inheritance and validation up front.
/// Callers therefore receive the same concrete [`ClientConfig`] type used by
/// the legacy runtime and do not need configuration-shape branches.
///
/// # Errors
///
/// Returns an error when the file cannot be read, neither supported TOML shape
/// can be parsed, inherited required values are missing, or route client IDs
/// are duplicated within the process.
pub fn load_client_configs(path: &Path) -> anyhow::Result<Vec<ClientConfig>> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read client config {}", path.display()))?;
    parse_client_configs(&raw)
        .with_context(|| format!("failed to parse client config {}", path.display()))
}

/// Detect the small bootstrap shape used by remote-managed desktop clients.
pub fn load_central_client_bootstrap(
    path: &Path,
) -> anyhow::Result<Option<CentralClientBootstrap>> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read client config {}", path.display()))?;
    let value: toml::Value = toml::from_str(&raw)
        .with_context(|| format!("failed to parse client config {}", path.display()))?;
    let enabled = value
        .get("control_plane_config")
        .and_then(toml::Value::as_bool)
        .unwrap_or(false);
    if !enabled {
        return Ok(None);
    }
    let bootstrap = toml::from_str(&raw)
        .with_context(|| format!("failed to parse central bootstrap {}", path.display()))?;
    Ok(Some(bootstrap))
}

/// Parse a client configuration document received from the control plane.
pub fn parse_client_config_document(raw: &str) -> anyhow::Result<Vec<ClientConfig>> {
    parse_client_configs(raw)
}

fn parse_client_configs(raw: &str) -> anyhow::Result<Vec<ClientConfig>> {
    let document: ClientConfigDocument = toml::from_str(raw)?;
    let configs = match document {
        ClientConfigDocument::Legacy(config) => vec![config],
        ClientConfigDocument::MultiRoute(config) => {
            expand_client_routes(config).context("invalid multi-route client config")?
        }
    };
    for config in &configs {
        validate_client_config(config)?;
    }
    Ok(configs)
}

fn validate_client_config(config: &ClientConfig) -> anyhow::Result<()> {
    let has_path_routes = config
        .backend_rules
        .iter()
        .any(|rule| rule.path_prefix.is_some());
    let has_authorization = config.authorization.is_some()
        || config
            .backend_rules
            .iter()
            .any(|rule| rule.authorization.is_some());
    anyhow::ensure!(
        (!has_path_routes && !has_authorization) || config.acme.is_some(),
        "path routing and authorization require [acme] so HTTPS can be inspected"
    );
    let fallback_count = config
        .backend_rules
        .iter()
        .filter(|rule| rule.path_prefix.is_none())
        .count();
    anyhow::ensure!(
        !has_path_routes || fallback_count == 1,
        "path routing requires exactly one fallback backend without path_prefix"
    );
    let mut prefixes = HashSet::new();
    for rule in &config.backend_rules {
        if let Some(prefix) = &rule.path_prefix {
            anyhow::ensure!(
                prefix.starts_with('/') && !prefix.contains(['?', '#']),
                "backend path_prefix must start with '/' and omit query/fragment"
            );
            anyhow::ensure!(
                prefixes.insert(prefix),
                "backend path_prefix {prefix} is duplicated"
            );
        }
        if let Some(authorization) = &rule.authorization {
            validate_authorization(authorization)?;
        }
    }
    if let Some(authorization) = &config.authorization {
        validate_authorization(authorization)?;
    }
    Ok(())
}

fn validate_authorization(authorization: &ClientAuthorizationConfig) -> anyhow::Result<()> {
    anyhow::ensure!(
        !authorization.issuer.trim().is_empty(),
        "authorization.issuer cannot be empty"
    );
    anyhow::ensure!(
        !authorization.audiences.is_empty(),
        "authorization.audiences cannot be empty"
    );
    anyhow::ensure!(
        !authorization.jwks_cache_file.trim().is_empty(),
        "authorization.jwks_cache_file cannot be empty"
    );
    anyhow::ensure!(
        !authorization.algorithms.is_empty(),
        "authorization.algorithms cannot be empty"
    );
    anyhow::ensure!(
        authorization.header_timeout_ms > 0,
        "authorization.header_timeout_ms must be positive"
    );
    anyhow::ensure!(
        authorization.max_header_bytes >= 1024,
        "authorization.max_header_bytes must be at least 1024"
    );
    Ok(())
}

fn expand_client_routes(document: MultiRouteClientConfig) -> anyhow::Result<Vec<ClientConfig>> {
    anyhow::ensure!(
        !document.routes.is_empty(),
        "at least one [[routes]] entry is required"
    );
    let mut client_ids = HashSet::new();
    document
        .routes
        .into_iter()
        .enumerate()
        .map(|(index, route)| {
            anyhow::ensure!(
                client_ids.insert(route.client_id.clone()),
                "route {} repeats client_id {}",
                index + 1,
                route.client_id
            );
            expand_client_route(&document.defaults, route)
                .with_context(|| format!("route {}", index + 1))
        })
        .collect()
}

fn expand_client_route(
    defaults: &ClientConfigDefaults,
    route: ClientRouteConfig,
) -> anyhow::Result<ClientConfig> {
    anyhow::ensure!(
        !route.client_id.trim().is_empty(),
        "client_id cannot be empty"
    );
    anyhow::ensure!(
        !route.hostname.trim().is_empty(),
        "hostname cannot be empty"
    );
    let nats_url = route
        .nats_url
        .or_else(|| defaults.nats_url.clone())
        .context("nats_url is required in the route or [defaults]")?;
    let backend_addr = route
        .backend_addr
        .or_else(|| defaults.backend_addr.clone())
        .context("backend_addr is required in the route or [defaults]")?;
    let oauth = merge_oauth_defaults(
        defaults.oauth.as_ref(),
        route.oauth.as_ref(),
        &route.hostname,
    )?;
    let acme = merge_acme_defaults(defaults.acme.as_ref(), route.acme.as_ref(), &route.hostname)?;
    let authorization = merge_authorization_defaults(
        defaults.authorization.as_ref(),
        route.authorization.as_ref(),
    )?;
    let pattern = route.pattern.unwrap_or_else(|| route.hostname.clone());
    let mut backend_rules = vec![BackendRule {
        pattern: pattern.clone(),
        path_prefix: None,
        strip_path_prefix: false,
        proxy_headers: route
            .proxy_headers
            .or(defaults.proxy_headers)
            .unwrap_or(true),
        backend_addr,
        backend_host: route.backend_host.or_else(|| defaults.backend_host.clone()),
        http_backend_addr: route
            .http_backend_addr
            .or_else(|| defaults.http_backend_addr.clone()),
        authorization: None,
    }];
    for path_route in route.path_routes {
        let path_authorization = merge_authorization_defaults(
            route
                .authorization
                .as_ref()
                .or(defaults.authorization.as_ref()),
            path_route.authorization.as_ref(),
        )?;
        backend_rules.push(BackendRule {
            pattern: pattern.clone(),
            path_prefix: Some(path_route.path_prefix),
            strip_path_prefix: path_route.strip_path_prefix,
            proxy_headers: path_route
                .proxy_headers
                .or(route.proxy_headers)
                .or(defaults.proxy_headers)
                .unwrap_or(true),
            backend_addr: path_route.backend_addr,
            backend_host: path_route.backend_host,
            http_backend_addr: None,
            authorization: path_authorization,
        });
    }

    Ok(ClientConfig {
        client_id: route.client_id,
        nats_url,
        nats_token_file: route
            .nats_token_file
            .or_else(|| defaults.nats_token_file.clone()),
        oauth,
        acme,
        authorization,
        relay_mode: route.relay_mode.or(defaults.relay_mode).unwrap_or_default(),
        request_subject: route
            .request_subject
            .or_else(|| defaults.request_subject.clone())
            .unwrap_or_else(default_request_subject),
        claim_ack_timeout_ms: route
            .claim_ack_timeout_ms
            .or(defaults.claim_ack_timeout_ms)
            .unwrap_or_else(default_claim_ack_timeout_ms),
        backend_rules,
    })
}

fn merge_authorization_defaults(
    defaults: Option<&ClientAuthorizationDefaults>,
    route: Option<&ClientAuthorizationDefaults>,
) -> anyhow::Result<Option<ClientAuthorizationConfig>> {
    if defaults.is_none() && route.is_none() {
        return Ok(None);
    }
    let enabled = route
        .and_then(|settings| settings.enabled)
        .or_else(|| defaults.and_then(|settings| settings.enabled))
        .unwrap_or(true);
    if !enabled {
        return Ok(None);
    }
    let string_value = |select: fn(&ClientAuthorizationDefaults) -> &Option<String>, name: &str| {
        route
            .and_then(|settings| select(settings).clone())
            .or_else(|| defaults.and_then(|settings| select(settings).clone()))
            .with_context(|| {
                format!("authorization.{name} is required in the route or [defaults.authorization]")
            })
    };
    let list_value = |select: fn(&ClientAuthorizationDefaults) -> &Option<Vec<String>>| {
        route
            .and_then(|settings| select(settings).clone())
            .or_else(|| defaults.and_then(|settings| select(settings).clone()))
    };

    Ok(Some(ClientAuthorizationConfig {
        issuer: string_value(|settings| &settings.issuer, "issuer")?,
        audiences: list_value(|settings| &settings.audiences).context(
            "authorization.audiences is required in the route or [defaults.authorization]",
        )?,
        jwks_uri: route
            .and_then(|settings| settings.jwks_uri.clone())
            .or_else(|| defaults.and_then(|settings| settings.jwks_uri.clone())),
        jwks_cache_file: route
            .and_then(|settings| settings.jwks_cache_file.clone())
            .or_else(|| defaults.and_then(|settings| settings.jwks_cache_file.clone()))
            .unwrap_or_else(default_jwks_cache_file),
        roles_claim: route
            .and_then(|settings| settings.roles_claim.clone())
            .or_else(|| defaults.and_then(|settings| settings.roles_claim.clone()))
            .unwrap_or_else(default_roles_claim),
        required_roles: list_value(|settings| &settings.required_roles).unwrap_or_default(),
        forward_authorization: route
            .and_then(|settings| settings.forward_authorization)
            .or_else(|| defaults.and_then(|settings| settings.forward_authorization))
            .unwrap_or(false),
        role_match: route
            .and_then(|settings| settings.role_match)
            .or_else(|| defaults.and_then(|settings| settings.role_match))
            .unwrap_or_default(),
        algorithms: list_value(|settings| &settings.algorithms)
            .unwrap_or_else(default_jwt_algorithms),
        leeway_seconds: route
            .and_then(|settings| settings.leeway_seconds)
            .or_else(|| defaults.and_then(|settings| settings.leeway_seconds))
            .unwrap_or_else(default_jwt_leeway_seconds),
        jwks_refresh_seconds: route
            .and_then(|settings| settings.jwks_refresh_seconds)
            .or_else(|| defaults.and_then(|settings| settings.jwks_refresh_seconds))
            .unwrap_or_else(default_jwks_refresh_seconds),
        jwks_max_stale_seconds: route
            .and_then(|settings| settings.jwks_max_stale_seconds)
            .or_else(|| defaults.and_then(|settings| settings.jwks_max_stale_seconds))
            .unwrap_or_else(default_jwks_max_stale_seconds),
        header_timeout_ms: route
            .and_then(|settings| settings.header_timeout_ms)
            .or_else(|| defaults.and_then(|settings| settings.header_timeout_ms))
            .unwrap_or_else(default_auth_header_timeout_ms),
        max_header_bytes: route
            .and_then(|settings| settings.max_header_bytes)
            .or_else(|| defaults.and_then(|settings| settings.max_header_bytes))
            .unwrap_or_else(default_auth_max_header_bytes),
    }))
}

fn merge_acme_defaults(
    defaults: Option<&ClientAcmeDefaults>,
    route: Option<&ClientAcmeDefaults>,
    hostname: &str,
) -> anyhow::Result<Option<ClientAcmeConfig>> {
    if defaults.is_none() && route.is_none() {
        return Ok(None);
    }
    let enabled = route
        .and_then(|settings| settings.enabled)
        .or_else(|| defaults.and_then(|settings| settings.enabled))
        .unwrap_or(true);
    if !enabled {
        return Ok(None);
    }

    let cache_dir = route
        .and_then(|settings| settings.cache_dir.clone())
        .or_else(|| defaults.and_then(|settings| settings.cache_dir.clone()))
        .unwrap_or_else(default_acme_cache_dir);
    anyhow::ensure!(
        !cache_dir.trim().is_empty(),
        "acme.cache_dir cannot be empty"
    );

    Ok(Some(ClientAcmeConfig {
        domain: hostname.to_string(),
        contacts: route
            .and_then(|settings| settings.contacts.clone())
            .or_else(|| defaults.and_then(|settings| settings.contacts.clone()))
            .unwrap_or_default(),
        cache_dir,
        production: route
            .and_then(|settings| settings.production)
            .or_else(|| defaults.and_then(|settings| settings.production))
            .unwrap_or(false),
        directory_url: route
            .and_then(|settings| settings.directory_url.clone())
            .or_else(|| defaults.and_then(|settings| settings.directory_url.clone())),
    }))
}

fn merge_oauth_defaults(
    defaults: Option<&ClientOAuthDefaults>,
    route: Option<&ClientOAuthDefaults>,
    hostname: &str,
) -> anyhow::Result<Option<ClientOAuthConfig>> {
    if defaults.is_none() && route.is_none() {
        return Ok(None);
    }

    let value = |select: fn(&ClientOAuthDefaults) -> &Option<String>, name: &str| {
        route
            .and_then(|settings| select(settings).clone())
            .or_else(|| defaults.and_then(|settings| select(settings).clone()))
            .with_context(|| format!("oauth.{name} is required in the route or [defaults.oauth]"))
    };
    let token_url = value(|settings| &settings.token_url, "token_url")?;
    let provider_client_id = value(
        |settings| &settings.provider_client_id,
        "provider_client_id",
    )?;
    let username = value(|settings| &settings.username, "username")?;
    let client_secret_file = value(
        |settings| &settings.client_secret_file,
        "client_secret_file",
    )?;
    let control_plane_url = value(|settings| &settings.control_plane_url, "control_plane_url")?;

    Ok(Some(ClientOAuthConfig {
        token_url,
        provider_client_id,
        username,
        client_secret_file,
        control_plane_url,
        hostname: hostname.to_string(),
        scopes: route
            .and_then(|settings| settings.scopes.clone())
            .or_else(|| defaults.and_then(|settings| settings.scopes.clone()))
            .unwrap_or_else(default_oauth_scopes),
        renew_before_seconds: route
            .and_then(|settings| settings.renew_before_seconds)
            .or_else(|| defaults.and_then(|settings| settings.renew_before_seconds))
            .unwrap_or_else(default_oauth_renew_before_seconds),
    }))
}

#[cfg(test)]
mod tests {
    use super::{
        ClientConfig, ClientOverrides, RelayMode, ServerConfig, ServerOverrides,
        parse_client_configs,
    };

    #[test]
    fn server_defaults_and_overrides_are_layered() {
        let config: ServerConfig = toml::from_str(
            r#"
                public_listen = "127.0.0.1:7443"
                data_listen = "127.0.0.1:7001"
                advertised_data_addr = "public.example:7001"
                nats_url = "nats://localhost:4222"
            "#,
        )
        .expect("server TOML");
        assert_eq!(config.relay_mode, RelayMode::Auto);

        let config = config.with_overrides(ServerOverrides {
            public_listen: Some("0.0.0.0:8443".into()),
            advertised_data_addr: Some(String::new()),
            relay_mode: Some(RelayMode::Buffered),
            ..ServerOverrides::default()
        });
        assert_eq!(config.public_listen, "0.0.0.0:8443");
        assert_eq!(config.advertised_data_addr, None);
        assert_eq!(config.relay_mode, RelayMode::Buffered);
        assert_eq!(config.claim_timeout_ms, 3_000);
    }

    #[test]
    fn client_overrides_preserve_structured_routes() {
        let config: ClientConfig = toml::from_str(
            r#"
                client_id = "client-a"
                nats_url = "nats://localhost:4222"

                [[backend_rules]]
                pattern = "example.test"
                backend_addr = ":8080"
            "#,
        )
        .expect("client TOML");
        let config = config.with_overrides(ClientOverrides {
            client_id: Some("client-b".into()),
            ..ClientOverrides::default()
        });
        assert_eq!(config.client_id, "client-b");
        assert_eq!(
            config.backend_rules[0].resolved_backend_addr(),
            "127.0.0.1:8080"
        );
    }

    #[test]
    fn client_oauth_defaults_scopes_and_renewal() {
        let config: ClientConfig = toml::from_str(
            r#"
                client_id = "client-a"
                nats_url = "tls://nats.example.com:443"

                [oauth]
                token_url = "https://auth.example.com/application/o/token/"
                provider_client_id = "lfp-pipe"
                username = "lfp-pipe-client-a"
                client_secret_file = "/run/secrets/client-secret"
                control_plane_url = "https://manage-pipe.example.com"
                hostname = "client-a.pipe.example.com"

                [[backend_rules]]
                pattern = "client-a.pipe.example.com"
                backend_addr = ":443"
            "#,
        )
        .expect("OAuth client TOML");
        let oauth = config.oauth.expect("OAuth configuration");
        assert_eq!(oauth.renew_before_seconds, 60);
        assert!(oauth.scopes.iter().any(|scope| scope == "entitlements"));
        assert!(config.backend_rules[0].http_backend_addr.is_none());
        assert_eq!(
            config.backend_rules[0].resolved_http_backend_addr(),
            config.backend_rules[0].resolved_backend_addr()
        );
    }

    #[test]
    fn multi_route_clients_inherit_shared_oauth_and_backends() {
        let configs = parse_client_configs(
            r#"
                [defaults]
                nats_url = "tls://nats.example.com:443"
                backend_addr = ":443"
                http_backend_addr = ":80"
                relay_mode = "buffered"

                [defaults.oauth]
                token_url = "https://auth.example.com/application/o/token/"
                provider_client_id = "lfp-pipe"
                username = "lfp-pipe-team"
                client_secret_file = "/run/secrets/client-secret"
                control_plane_url = "https://manage-pipe.example.com"

                [defaults.acme]
                contacts = ["mailto:admin@example.com"]
                cache_dir = "/var/lib/lfp-pipe/acme"

                [[routes]]
                client_id = "alpha"
                hostname = "alpha.pipe.example.com"

                [[routes]]
                client_id = "beta"
                hostname = "beta.pipe.example.com"
                backend_addr = ":8443"

                [routes.acme]
                enabled = false
            "#,
        )
        .expect("multi-route config");

        assert_eq!(configs.len(), 2);
        assert_eq!(configs[0].relay_mode, RelayMode::Buffered);
        assert_eq!(
            configs[0].backend_rules[0].pattern,
            "alpha.pipe.example.com"
        );
        assert_eq!(
            configs[0].backend_rules[0].resolved_backend_addr(),
            "127.0.0.1:443"
        );
        assert_eq!(
            configs[0].backend_rules[0].resolved_http_backend_addr(),
            "127.0.0.1:80"
        );
        assert_eq!(
            configs[1].backend_rules[0].resolved_backend_addr(),
            "127.0.0.1:8443"
        );
        assert_eq!(
            configs[1].oauth.as_ref().expect("OAuth").hostname,
            "beta.pipe.example.com"
        );
        assert_eq!(
            configs[1].oauth.as_ref().expect("OAuth").username,
            "lfp-pipe-team"
        );
        let first_acme = configs[0].acme.as_ref().expect("ACME");
        assert_eq!(first_acme.domain, "alpha.pipe.example.com");
        assert_eq!(first_acme.cache_dir, "/var/lib/lfp-pipe/acme");
        assert!(!first_acme.production);
        assert_eq!(configs[1].acme, None);
    }

    #[test]
    fn multi_route_client_allows_nested_route_oauth_overrides() {
        let configs = parse_client_configs(
            r#"
                [defaults]
                nats_url = "tls://nats.example.com:443"
                backend_addr = ":443"

                [defaults.oauth]
                token_url = "https://auth.example.com/application/o/token/"
                provider_client_id = "lfp-pipe"
                username = "shared-principal"
                client_secret_file = "/run/secrets/client-secret"
                control_plane_url = "https://manage-pipe.example.com"

                [[routes]]
                client_id = "special"
                hostname = "special.pipe.example.com"

                [routes.oauth]
                username = "special-principal"
            "#,
        )
        .expect("route OAuth override");

        let oauth = configs[0].oauth.as_ref().expect("OAuth");
        assert_eq!(oauth.username, "special-principal");
        assert_eq!(oauth.provider_client_id, "lfp-pipe");
    }

    #[test]
    fn multi_route_client_rejects_duplicate_client_ids() {
        let error = parse_client_configs(
            r#"
                [defaults]
                nats_url = "nats://localhost:4222"
                backend_addr = ":8080"

                [[routes]]
                client_id = "duplicate"
                hostname = "one.example.com"

                [[routes]]
                client_id = "duplicate"
                hostname = "two.example.com"
            "#,
        )
        .expect_err("duplicate IDs must fail");
        assert!(
            format!("{error:#}").contains("repeats client_id duplicate"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn checked_in_multi_route_example_stays_parseable() {
        let configs = parse_client_configs(include_str!("../../client.multi.example.toml"))
            .expect("checked-in multi-route example");
        assert_eq!(configs.len(), 2);
        assert_eq!(configs[0].client_id, "desktop-web");
        assert_eq!(configs[1].client_id, "desktop-admin");
        assert!(!configs[0].acme.as_ref().expect("first ACME").production);
        assert!(configs[1].acme.as_ref().expect("second ACME").production);
    }

    #[test]
    fn checked_in_ollama_example_has_normalized_authorization() {
        let configs = parse_client_configs(include_str!("../../client.ollama.example.toml"))
            .expect("checked-in Ollama example");
        let config = &configs[0];
        let ollama = &config.backend_rules[1];
        let authorization = ollama.authorization.as_ref().expect("authorization");
        assert_eq!(ollama.resolved_backend_addr(), "127.0.0.1:11434");
        assert_eq!(ollama.backend_host.as_deref(), Some("127.0.0.1:11434"));
        assert_eq!(ollama.path_prefix.as_deref(), Some("/ollama"));
        assert!(ollama.strip_path_prefix);
        assert!(ollama.proxy_headers);
        assert_eq!(authorization.audiences, ["ollama"]);
        assert_eq!(authorization.roles_claim, "groups");
        assert_eq!(authorization.required_roles, ["ollama-users"]);
        assert!(!authorization.forward_authorization);
        assert!(config.acme.is_some());
        assert!(config.oauth.is_some());
    }

    #[test]
    fn path_routes_preserve_requests_and_set_forwarding_headers_by_default() {
        let configs = parse_client_configs(
            r#"
                [defaults]
                nats_url = "nats://localhost:4222"
                backend_addr = "127.0.0.1:8080"

                [defaults.acme]
                contacts = ["mailto:admin@example.com"]
                cache_dir = "~/.cache/lfp-pipe/acme"

                [[routes]]
                client_id = "service"
                hostname = "service.example.com"

                [[routes.path_routes]]
                path_prefix = "/xyz"
                backend_addr = "127.0.0.1:9000"
            "#,
        )
        .expect("path route defaults");

        let fallback = &configs[0].backend_rules[0];
        let path = &configs[0].backend_rules[1];
        assert!(fallback.proxy_headers);
        assert!(path.proxy_headers);
        assert!(!path.strip_path_prefix);
        assert_eq!(path.backend_host, None);
    }

    #[test]
    fn forwarding_header_setting_inherits_and_allows_path_override() {
        let configs = parse_client_configs(
            r#"
                [defaults]
                nats_url = "nats://localhost:4222"
                backend_addr = "127.0.0.1:8080"
                proxy_headers = false

                [defaults.acme]
                contacts = ["mailto:admin@example.com"]
                cache_dir = "~/.cache/lfp-pipe/acme"

                [[routes]]
                client_id = "service"
                hostname = "service.example.com"

                [[routes.path_routes]]
                path_prefix = "/xyz"
                backend_addr = "127.0.0.1:9000"
                proxy_headers = true
            "#,
        )
        .expect("proxy header overrides");

        assert!(!configs[0].backend_rules[0].proxy_headers);
        assert!(configs[0].backend_rules[1].proxy_headers);
    }

    #[test]
    fn authorization_requires_local_tls_termination() {
        let error = parse_client_configs(
            r#"
                client_id = "unsafe"
                nats_url = "nats://localhost:4222"

                [authorization]
                issuer = "https://auth.example/application/o/api/"
                audiences = ["api"]
                jwks_cache_file = "/var/cache/api-jwks.json"

                [[backend_rules]]
                pattern = "api.example.com"
                backend_addr = ":11434"
            "#,
        )
        .expect_err("authorization without TLS termination must fail");
        assert!(
            format!("{error:#}").contains("require [acme]"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn route_can_disable_inherited_authorization() {
        let configs = parse_client_configs(
            r#"
                [defaults]
                nats_url = "nats://localhost:4222"
                backend_addr = ":8080"

                [defaults.authorization]
                issuer = "https://auth.example/application/o/api/"
                audiences = ["api"]
                jwks_cache_file = "/var/cache/api-jwks.json"

                [[routes]]
                client_id = "public"
                hostname = "public.example.com"

                [routes.authorization]
                enabled = false
            "#,
        )
        .expect("authorization opt-out");
        assert!(configs[0].authorization.is_none());
    }

    #[test]
    fn legacy_client_can_opt_into_automatic_certificates() {
        let configs = parse_client_configs(
            r#"
                client_id = "legacy"
                nats_url = "nats://localhost:4222"

                [acme]
                domain = "legacy.example.com"
                contacts = ["mailto:admin@example.com"]
                cache_dir = "/var/lib/lfp-pipe/acme"

                [[backend_rules]]
                pattern = "legacy.example.com"
                backend_addr = ":8080"
            "#,
        )
        .expect("legacy ACME client");

        let acme = configs[0].acme.as_ref().expect("ACME");
        assert_eq!(acme.domain, "legacy.example.com");
        assert!(!acme.production);
        assert_eq!(acme.directory_url, None);
    }
}
