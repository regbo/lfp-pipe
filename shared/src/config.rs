//! Typed TOML configuration and the override layer shared by both binaries.

use std::{fs, path::Path};

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
#[derive(Debug, Default)]
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
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read client config {}", path.display()))?;
    toml::from_str(&raw)
        .with_context(|| format!("failed to parse client config {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::{ClientConfig, ClientOverrides, RelayMode, ServerConfig, ServerOverrides};

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
}
