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
    let token = token_file
        .map(|path| {
            fs::read_to_string(path)
                .with_context(|| format!("failed to read NATS token file {path}"))
        })
        .transpose()?;
    connect_nats_with_token(nats_url, token.as_deref().map(str::trim), inbox_prefix).await
}

/// Connect to NATS with an in-memory bearer token obtained through OAuth.
pub async fn connect_nats_with_token(
    nats_url: &str,
    token: Option<&str>,
    inbox_prefix: Option<&str>,
) -> anyhow::Result<Client> {
    let parsed = Url::parse(nats_url).context("failed to parse NATS URL")?;

    ensure!(
        matches!(parsed.scheme(), "nats" | "tls" | "ws" | "wss"),
        "unsupported NATS URL scheme {}",
        parsed.scheme()
    );

    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("NATS URL missing host"))?;
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| anyhow!("NATS URL missing port"))?;
    // Preserve WebSocket paths such as `/nats`; reverse proxies use them to
    // multiplex the otherwise normal NATS protocol with HTTPS on one origin.
    let connect_url = if matches!(parsed.scheme(), "ws" | "wss") {
        let mut public_url = parsed.clone();
        public_url
            .set_username("")
            .map_err(|_| anyhow!("failed to normalize NATS WebSocket username"))?;
        public_url
            .set_password(None)
            .map_err(|_| anyhow!("failed to normalize NATS WebSocket password"))?;
        public_url.to_string()
    } else {
        format!("{}://{host}:{port}", parsed.scheme())
    };

    let mut options = ConnectOptions::new()
        .ignore_discovered_servers()
        .retain_servers_order();

    if let Some(prefix) = inbox_prefix {
        options = options.custom_inbox_prefix(prefix);
    }

    if let Some(token) = token {
        options = options.token(token.to_string());
    }

    if token.is_none() && (!parsed.username().is_empty() || parsed.password().is_some()) {
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

#[cfg(test)]
mod tests {
    use url::Url;

    #[test]
    fn websocket_url_retains_reverse_proxy_path() {
        let parsed = Url::parse("wss://pipe.example.com/nats").expect("url");
        assert_eq!(parsed.scheme(), "wss");
        assert_eq!(parsed.path(), "/nats");
    }
}
