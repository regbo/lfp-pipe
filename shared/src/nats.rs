use anyhow::{Context, anyhow, ensure};
use async_nats::{Client, ConnectOptions};
use url::Url;

pub async fn connect_nats(nats_url: &str) -> anyhow::Result<Client> {
    let parsed = Url::parse(nats_url)
        .with_context(|| format!("failed to parse NATS URL {nats_url}"))?;

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

    if !parsed.username().is_empty() || parsed.password().is_some() {
        options = options.user_and_password(
            parsed.username().to_string(),
            parsed.password().unwrap_or_default().to_string(),
        );
    }

    if parsed.scheme() == "tls" {
        options = options.require_tls(true);
    }

    options
        .connect(connect_url)
        .await
        .with_context(|| format!("failed to connect to NATS at {host}:{port}"))
}
