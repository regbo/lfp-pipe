//! NATS connection setup shared by the public server and private client.

use std::fs;

use anyhow::{Context, anyhow, ensure};
use async_nats::{Client, ConnectOptions};
use url::Url;

/// Connect to NATS while preserving the configured server and credential order.
///
/// Discovery is intentionally disabled because callback coordination should not
/// silently move to an address that is unreachable from one side of the tunnel.
pub async fn connect_nats(
    nats_url: &str,
    token_file: Option<&str>,
    inbox_prefix: Option<&str>,
) -> anyhow::Result<Client> {
    let parsed = Url::parse(nats_url).context("failed to parse NATS URL")?;

    ensure!(
        matches!(parsed.scheme(), "nats" | "tls"),
        "unsupported NATS URL scheme {}",
        parsed.scheme()
    );

    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("NATS URL missing host"))?;
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| anyhow!("NATS URL missing port"))?;
    let connect_url = format!("{}://{host}:{port}", parsed.scheme());

    let mut options = ConnectOptions::new()
        .ignore_discovered_servers()
        .retain_servers_order();

    if let Some(prefix) = inbox_prefix {
        options = options.custom_inbox_prefix(prefix);
    }

    if let Some(path) = token_file {
        let token = fs::read_to_string(path)
            .with_context(|| format!("failed to read NATS token file {path}"))?;
        options = options.token(token.trim().to_string());
    }

    if token_file.is_none() && (!parsed.username().is_empty() || parsed.password().is_some()) {
        options = options.user_and_password(
            parsed.username().to_string(),
            parsed.password().unwrap_or_default().to_string(),
        );
    }

    if parsed.scheme() == "tls" {
        options = options.require_tls(true).tls_first();
    }

    options
        .connect(connect_url)
        .await
        .with_context(|| format!("failed to connect to NATS at {host}:{port}"))
}
