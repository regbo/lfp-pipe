//! Private-side tunnel client runtime.

#![warn(missing_docs)]

mod acme;
mod oauth;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow};
use async_nats::{Client, Message};
use futures::StreamExt;
use shared::{
    config::{BackendRule, ClientConfig, RelayMode},
    http::looks_like_http_prefix,
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
    task::JoinSet,
    time::{sleep, timeout},
};
use tracing::{Level, debug, enabled, info, warn};

#[derive(Clone)]
struct AppState {
    config: ClientConfig,
    nats: Client,
    acme: Option<acme::AcmeRuntime>,
}

/// Subscribe for matching requests and bridge accepted tunnels to backends.
pub async fn run(config: ClientConfig) -> anyhow::Result<()> {
    // NATS and HTTPS share Rustls but enable different provider defaults. Select
    // Ring once so both transports use one deterministic process-wide provider.
    let _ = rustls::crypto::ring::default_provider().install_default();
    run_session(config).await
}

/// Run all route sessions expanded from one multi-route configuration file.
///
/// Each route owns its NATS subscription and OAuth renewal loop. This is
/// required for route-scoped credentials: one service principal may be
/// entitled to several hostnames, but each hostname receives its own ticket.
/// If any route exits or fails, the process returns an error so a supervisor
/// can restart the complete, declarative set instead of leaving partial
/// coverage running unnoticed.
///
/// # Errors
///
/// Returns an error if no routes were supplied, a route task panics, or any
/// route's authentication, NATS subscription, or renewal loop terminates.
pub async fn run_all(configs: Vec<ClientConfig>) -> anyhow::Result<()> {
    anyhow::ensure!(!configs.is_empty(), "at least one client route is required");
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut sessions = JoinSet::new();
    for config in configs {
        let client_id = config.client_id.clone();
        sessions.spawn(async move { (client_id, run_session(config).await) });
    }

    let joined = sessions
        .join_next()
        .await
        .context("client route task ended unexpectedly")?;
    let (client_id, result) = joined.context("client route task panicked")?;
    match result {
        Ok(()) => Err(anyhow!("client route {client_id} stopped unexpectedly")),
        Err(error) => Err(error).with_context(|| format!("client route {client_id} failed")),
    }
}

async fn run_session(config: ClientConfig) -> anyhow::Result<()> {
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

    let acme = if let Some(acme_config) = config.acme.clone() {
        anyhow::ensure!(
            config.backend_rules.len() == 1,
            "automatic certificates require exactly one backend rule per client route"
        );
        let backend = config.backend_rules[0].clone();
        anyhow::ensure!(
            backend.pattern.eq_ignore_ascii_case(&acme_config.domain),
            "automatic certificate domain must exactly match its backend pattern"
        );
        Some(acme::AcmeRuntime::start(
            acme_config,
            backend,
            config.relay_mode,
        )?)
    } else {
        None
    };

    let state = AppState { config, nats, acme };
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

    bridge_connection(
        &state.config.client_id,
        &request,
        &backend,
        state.config.relay_mode,
        state.acme.as_ref(),
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
    acme: Option<&acme::AcmeRuntime>,
) -> anyhow::Result<()> {
    let mut server_stream = TcpStream::connect(&request.server_data_addr)
        .await
        .with_context(|| format!("failed to connect server {}", request.server_data_addr))?;

    let prefix = PrefixEnvelope::new(client_id, &request.connection_id);
    server_stream
        .write_all(&prefix.encode_line()?)
        .await
        .context("failed to write prefix envelope")?;

    let (backend_addr, plaintext_http) =
        select_protocol_backend(backend, &server_stream, acme.is_some()).await?;
    if let Some(acme) = acme
        && !plaintext_http
    {
        debug!(
            connection_id = %request.connection_id,
            client_id,
            "handing tunneled TLS to automatic certificate runtime"
        );
        return acme.accept(server_stream).await;
    }
    debug!(
        connection_id = %request.connection_id,
        client_id,
        backend = %backend_addr,
        plaintext_http,
        "claim accepted, opening tunnel"
    );
    let mut backend_stream = TcpStream::connect(&backend_addr)
        .await
        .with_context(|| format!("failed to connect backend {backend_addr}"))?;

    let (to_server, to_backend) =
        copy_bidirectional_with_mode(&mut server_stream, &mut backend_stream, relay_mode)
            .await
            .context("copy_bidirectional failed")?;
    debug!(to_server, to_backend, "client relay finished");
    Ok(())
}

async fn select_protocol_backend(
    backend: &BackendRule,
    server_stream: &TcpStream,
    inspect_http: bool,
) -> anyhow::Result<(String, bool)> {
    if backend.http_backend_addr.is_none() && !inspect_http {
        return Ok((backend.resolved_backend_addr(), false));
    }

    // HTTP and TLS both send bytes before Caddy responds. Bound the peek so
    // backend-first or raw protocols still fall back to the default endpoint.
    let mut prefix = [0_u8; 24];
    let plaintext_http =
        match timeout(Duration::from_secs(2), server_stream.peek(&mut prefix)).await {
            Ok(Ok(read)) => read > 0 && looks_like_http_prefix(&prefix[..read]),
            Ok(Err(error)) => return Err(error).context("failed to inspect tunneled protocol"),
            Err(_) => false,
        };
    let address = if plaintext_http {
        backend.resolved_http_backend_addr()
    } else {
        backend.resolved_backend_addr()
    };
    Ok((address, plaintext_http))
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::{config::BackendRule, routing::select_backend};
    use tokio::net::TcpListener;

    #[test]
    fn selects_matching_backend_rule() {
        let rules = vec![BackendRule {
            pattern: "*.example.com".to_string(),
            backend_addr: "127.0.0.1:443".to_string(),
            http_backend_addr: Some("127.0.0.1:80".to_string()),
        }];

        let selected = select_backend(&rules, Some("api.example.com")).expect("match");
        assert_eq!(selected.backend_addr, "127.0.0.1:443");
        assert_eq!(selected.resolved_http_backend_addr(), "127.0.0.1:80");
    }

    #[tokio::test]
    async fn protocol_backend_is_opt_in_and_routes_plain_http() -> anyhow::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let mut peer = TcpStream::connect(listener.local_addr()?).await?;
        let (server_stream, _) = listener.accept().await?;
        peer.write_all(b"GET / HTTP/1.1\r\n").await?;

        let split = BackendRule {
            pattern: "example.com".to_string(),
            backend_addr: "127.0.0.1:443".to_string(),
            http_backend_addr: Some("127.0.0.1:80".to_string()),
        };
        assert_eq!(
            select_protocol_backend(&split, &server_stream, false).await?,
            ("127.0.0.1:80".to_string(), true)
        );

        let unsplit = BackendRule {
            http_backend_addr: None,
            ..split
        };
        assert_eq!(
            select_protocol_backend(&unsplit, &server_stream, false).await?,
            ("127.0.0.1:443".to_string(), false)
        );
        assert_eq!(
            select_protocol_backend(&unsplit, &server_stream, true).await?,
            ("127.0.0.1:443".to_string(), true)
        );
        Ok(())
    }
}
