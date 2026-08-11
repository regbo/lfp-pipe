//! Private-side tunnel client runtime.

#![warn(missing_docs)]

mod oauth;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow};
use async_nats::{Client, Message};
use futures::StreamExt;
use shared::{
    config::{BackendRule, ClientConfig, RelayMode},
    io::copy_bidirectional_with_mode,
    logging::is_expected_disconnect,
    nats::{connect_nats, connect_nats_with_token},
    prefix::PrefixEnvelope,
    protocol::{ConnectionClaim, ConnectionClaimAck, ConnectionRequest, decode_json, encode_json},
    routing::select_backend,
};
use tokio::{
    io::AsyncWriteExt,
    net::TcpStream,
    time::{sleep, timeout},
};
use tracing::{Level, debug, enabled, info, warn};

#[derive(Clone)]
struct AppState {
    config: ClientConfig,
    nats: Client,
}

/// Subscribe for matching requests and bridge accepted tunnels to backends.
pub async fn run(config: ClientConfig) -> anyhow::Result<()> {
    // NATS and HTTPS share Rustls but enable different provider defaults. Select
    // Ring once so both transports use one deterministic process-wide provider.
    let _ = rustls::crypto::ring::default_provider().install_default();
    if let Some(oauth) = config.oauth.clone() {
        return run_oauth(config, oauth).await;
    }
    let inbox_prefix = format!("_LFP_INBOX.{}", config.client_id);
    let nats = connect_nats(
        &config.nats_url,
        config.nats_token_file.as_deref(),
        Some(&inbox_prefix),
    )
    .await
    .context("failed to connect to NATS")?;
    process_messages(config.clone(), nats, config.request_subject.clone(), None).await
}

async fn run_oauth(
    config: ClientConfig,
    oauth_config: shared::config::ClientOAuthConfig,
) -> anyhow::Result<()> {
    loop {
        let ticket = match oauth::obtain_ticket(&oauth_config, &config.client_id).await {
            Ok(ticket) => ticket,
            Err(error) => {
                warn!(?error, "OAuth ticket exchange failed; retrying");
                sleep(Duration::from_secs(10)).await;
                continue;
            }
        };
        if ticket.client_id != config.client_id {
            return Err(anyhow!(
                "control plane normalized client ID to {}; configure that exact value",
                ticket.client_id
            ));
        }
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
        if ticket.expires_unix <= now {
            warn!("control plane returned an expired NATS ticket; retrying");
            sleep(Duration::from_secs(5)).await;
            continue;
        }
        let lifetime = (ticket.expires_unix - now) as u64;
        let renew_after = if lifetime > oauth_config.renew_before_seconds + 5 {
            lifetime - oauth_config.renew_before_seconds
        } else {
            (lifetime / 2).max(1)
        };
        let inbox_prefix = format!("_LFP_INBOX.{}", config.client_id);
        let nats = match connect_nats_with_token(
            &ticket.nats_urls[0],
            Some(&ticket.token),
            Some(&inbox_prefix),
        )
        .await
        {
            Ok(client) => client,
            Err(error) => {
                warn!(
                    ?error,
                    "OAuth-authenticated NATS connection failed; retrying"
                );
                sleep(Duration::from_secs(5)).await;
                continue;
            }
        };
        if let Err(error) = process_messages(
            config.clone(),
            nats,
            ticket.request_subject,
            Some(Duration::from_secs(renew_after)),
        )
        .await
        {
            warn!(?error, "OAuth NATS session ended; obtaining a new ticket");
            sleep(Duration::from_secs(2)).await;
        }
    }
}

async fn process_messages(
    config: ClientConfig,
    nats: Client,
    request_subject: String,
    renew_after: Option<Duration>,
) -> anyhow::Result<()> {
    let mut subscriber = nats
        .subscribe(request_subject.clone())
        .await
        .context("failed to subscribe to request subject")?;

    let state = AppState { config, nats };
    info!(
        client_id = %state.config.client_id,
        request_subject = %request_subject,
        backend_rules = state.config.backend_rules.len(),
        "client listening for tunnel requests"
    );

    let handle = |message: Message, state: AppState| {
        tokio::spawn(async move {
            if let Err(error) = handle_request(message, state).await {
                if is_expected_disconnect(&error) {
                    debug!(?error, "tunnel peer closed connection");
                } else {
                    warn!(?error, "client request handling failed");
                }
            }
        })
    };

    if let Some(duration) = renew_after {
        let renewal = sleep(duration);
        tokio::pin!(renewal);
        loop {
            tokio::select! {
                _ = &mut renewal => {
                    info!("renewing OAuth-backed NATS ticket");
                    return Ok(());
                }
                message = subscriber.next() => match message {
                    Some(message) => { handle(message, state.clone()); }
                    None => return Err(anyhow!("NATS subscription ended before OAuth renewal")),
                }
            }
        }
    }

    while let Some(message) = subscriber.next().await {
        handle(message, state.clone());
    }

    Ok(())
}

async fn handle_request(message: Message, state: AppState) -> anyhow::Result<()> {
    let request: ConnectionRequest = decode_json(&message.payload)?;
    let backend = match select_backend(&state.config.backend_rules, request.hostname.as_deref()) {
        Some(rule) => rule.clone(),
        None => {
            // Building the pattern list is diagnostic-only; avoid its
            // allocation entirely when debug tracing is disabled.
            if enabled!(Level::DEBUG) {
                let patterns: Vec<&str> = state
                    .config
                    .backend_rules
                    .iter()
                    .map(|rule| rule.pattern.as_str())
                    .collect();
                debug!(
                    hostname = request.hostname.as_deref().unwrap_or("<default>"),
                    ?patterns,
                    "request does not match this client"
                );
            }
            return Ok(());
        }
    };

    let ack = submit_claim(&state, &message, &request).await?;
    if !ack.accepted {
        debug!(
            connection_id = %request.connection_id,
            reason = ack.reason.as_deref().unwrap_or("claim rejected"),
            "server selected another client"
        );
        return Ok(());
    }

    debug!(
        connection_id = %request.connection_id,
        client_id = %state.config.client_id,
        backend = %backend.backend_addr,
        "claim accepted, opening tunnel"
    );
    bridge_connection(
        &state.config.client_id,
        &request,
        &backend,
        state.config.relay_mode,
    )
    .await
}

async fn submit_claim(
    state: &AppState,
    message: &Message,
    request: &ConnectionRequest,
) -> anyhow::Result<ConnectionClaimAck> {
    let reply_subject = message
        .reply
        .clone()
        .or_else(|| Some(request.reply_subject.clone().into()))
        .ok_or_else(|| anyhow!("request missing reply subject"))?;

    let ack_subject = state.nats.new_inbox();
    let mut ack_subscription = state
        .nats
        .subscribe(ack_subject.clone())
        .await
        .context("failed to subscribe to claim ack subject")?;

    let claim = ConnectionClaim {
        client_id: state.config.client_id.clone(),
        connection_id: request.connection_id.clone(),
    };

    debug!(
        connection_id = %request.connection_id,
        reply_subject = %reply_subject,
        ack_subject = %ack_subject,
        "submitting tunnel claim"
    );
    state
        .nats
        .publish_with_reply(reply_subject, ack_subject, encode_json(&claim)?.into())
        .await
        .context("failed to publish connection claim")?;

    let ack_message = timeout(
        Duration::from_millis(state.config.claim_ack_timeout_ms),
        ack_subscription.next(),
    )
    .await
    .context("timed out waiting for claim ack")?
    .ok_or_else(|| anyhow!("claim ack subscription ended unexpectedly"))?;

    debug!(
        connection_id = %request.connection_id,
        "received claim ack"
    );
    decode_json(&ack_message.payload)
}

async fn bridge_connection(
    client_id: &str,
    request: &ConnectionRequest,
    backend: &BackendRule,
    relay_mode: RelayMode,
) -> anyhow::Result<()> {
    let backend_addr = backend.resolved_backend_addr();
    let mut backend_stream = TcpStream::connect(&backend_addr)
        .await
        .with_context(|| format!("failed to connect backend {backend_addr}"))?;
    let mut server_stream = TcpStream::connect(&request.server_data_addr)
        .await
        .with_context(|| format!("failed to connect server {}", request.server_data_addr))?;

    let prefix = PrefixEnvelope::new(client_id, &request.connection_id);
    server_stream
        .write_all(&prefix.encode_line()?)
        .await
        .context("failed to write prefix envelope")?;

    let (to_server, to_backend) =
        copy_bidirectional_with_mode(&mut server_stream, &mut backend_stream, relay_mode)
            .await
            .context("copy_bidirectional failed")?;
    debug!(to_server, to_backend, "client relay finished");
    Ok(())
}

#[cfg(test)]
mod tests {
    use shared::{config::BackendRule, routing::select_backend};

    #[test]
    fn selects_matching_backend_rule() {
        let rules = vec![BackendRule {
            pattern: "*.example.com".to_string(),
            backend_addr: "127.0.0.1:443".to_string(),
        }];

        let selected = select_backend(&rules, Some("api.example.com")).expect("match");
        assert_eq!(selected.backend_addr, "127.0.0.1:443");
    }
}
