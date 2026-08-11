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
    /// Default private destination for plaintext HTTP traffic.
    #[serde(default)]
    pub http_backend_addr: Option<String>,
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

/// One independently authenticated hostname in a multi-route client file.
///
/// Each entry expands into a normal [`ClientConfig`] with exactly one
/// [`BackendRule`]. Consequently OAuth acquisition, NATS subscription, ticket
/// renewal, and failures are isolated per hostname while sharing one process.
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
    /// Route-specific private destination for plaintext HTTP traffic.
    #[serde(default)]
    pub http_backend_addr: Option<String>,
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
    /// Socket address dialed by the client when this rule matches.
    pub backend_addr: String,
    /// Optional destination for plaintext HTTP, including ACME HTTP-01 requests.
    #[serde(default)]
    pub http_backend_addr: Option<String>,
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

/// Load server TOML without applying CLI or environment overrides.
pub fn load_server_config(path: &Path) -> anyhow::Result<ServerConfig> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read server config {}", path.display()))?;
    toml::from_str(&raw)
        .with_context(|| format!("failed to parse server config {}", path.display()))
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

fn parse_client_configs(raw: &str) -> anyhow::Result<Vec<ClientConfig>> {
    let document: ClientConfigDocument = toml::from_str(raw)?;
    match document {
        ClientConfigDocument::Legacy(config) => Ok(vec![config]),
        ClientConfigDocument::MultiRoute(config) => {
            expand_client_routes(config).context("invalid multi-route client config")
        }
    }
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

    Ok(ClientConfig {
        client_id: route.client_id,
        nats_url,
        nats_token_file: route
            .nats_token_file
            .or_else(|| defaults.nats_token_file.clone()),
        oauth,
        relay_mode: route.relay_mode.or(defaults.relay_mode).unwrap_or_default(),
        request_subject: route
            .request_subject
            .or_else(|| defaults.request_subject.clone())
            .unwrap_or_else(default_request_subject),
        claim_ack_timeout_ms: route
            .claim_ack_timeout_ms
            .or(defaults.claim_ack_timeout_ms)
            .unwrap_or_else(default_claim_ack_timeout_ms),
        backend_rules: vec![BackendRule {
            pattern: route.pattern.unwrap_or(route.hostname),
            backend_addr,
            http_backend_addr: route
                .http_backend_addr
                .or_else(|| defaults.http_backend_addr.clone()),
        }],
    })
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

                [[routes]]
                client_id = "alpha"
                hostname = "alpha.pipe.example.com"

                [[routes]]
                client_id = "beta"
                hostname = "beta.pipe.example.com"
                backend_addr = ":8443"
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
    }
}
