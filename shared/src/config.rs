use std::{fs, path::Path};

use anyhow::Context;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub public_listen: String,
    pub data_listen: String,
    pub advertised_data_addr: Option<String>,
    pub nats_url: String,
    #[serde(default = "default_request_subject")]
    pub request_subject: String,
    #[serde(default = "default_claim_timeout_ms")]
    pub claim_timeout_ms: u64,
    #[serde(default = "default_pending_timeout_ms")]
    pub pending_timeout_ms: u64,
}

impl ServerConfig {
    pub fn server_data_addr(&self) -> &str {
        self.advertised_data_addr
            .as_deref()
            .unwrap_or(&self.data_listen)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub client_id: String,
    pub nats_url: String,
    #[serde(default = "default_request_subject")]
    pub request_subject: String,
    #[serde(default = "default_claim_ack_timeout_ms")]
    pub claim_ack_timeout_ms: u64,
    pub backend_rules: Vec<BackendRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackendRule {
    #[serde(default)]
    pub pattern: String,
    pub backend_addr: String,
}

impl BackendRule {
    pub fn resolved_backend_addr(&self) -> String {
        if self.backend_addr.starts_with(':') {
            format!("127.0.0.1{}", self.backend_addr)
        } else {
            self.backend_addr.clone()
        }
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

pub fn load_server_config(path: &Path) -> anyhow::Result<ServerConfig> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read server config {}", path.display()))?;
    toml::from_str(&raw)
        .with_context(|| format!("failed to parse server config {}", path.display()))
}

pub fn load_client_config(path: &Path) -> anyhow::Result<ClientConfig> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read client config {}", path.display()))?;
    toml::from_str(&raw)
        .with_context(|| format!("failed to parse client config {}", path.display()))
}
