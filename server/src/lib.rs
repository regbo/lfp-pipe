//! Public ingress and callback-pairing server runtime.

#![warn(missing_docs)]

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, anyhow};
use async_nats::Client;
use futures::StreamExt;
use shared::{
    config::{ServerConfig, SniPassthroughRoute},
    http::{extract_http_host, looks_like_http_prefix},
    io::copy_bidirectional_with_mode,
    logging::is_expected_disconnect,
    nats::connect_nats,
    prefix::PrefixEnvelope,
    protocol::{ConnectionClaim, ConnectionClaimAck, ConnectionRequest, decode_json, encode_json},
    routing::hostname_request_subject,
    tls::{extract_sni, validate_tls_record_header},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex,
    time::{Instant, sleep, timeout},
};
use tracing::{debug, info, warn};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    config: ServerConfig,
    nats: Client,
    pending: Arc<Mutex<HashMap<String, PendingConnection>>>,
    route_claim_cursor: Arc<Mutex<HashMap<String, usize>>>,
}

struct PendingConnection {
    ingress: TcpStream,
    client_id: String,
    expires_at: Instant,
}

/// Accept public ingress and client callback sockets until either listener fails.
pub async fn run(config: ServerConfig) -> anyhow::Result<()> {
    let nats = connect_nats(&config.nats_url, config.nats_token_file.as_deref(), None)
        .await
        .context("failed to connect to NATS")?;
    let public_listener = TcpListener::bind(&config.public_listen)
        .await
        .with_context(|| format!("failed to bind public listener {}", config.public_listen))?;
    let data_listener = TcpListener::bind(&config.data_listen)
        .await
        .with_context(|| format!("failed to bind data listener {}", config.data_listen))?;

    let state = AppState {
        config,
        nats,
        pending: Arc::new(Mutex::new(HashMap::new())),
        route_claim_cursor: Arc::new(Mutex::new(HashMap::new())),
    };

    info!(
        public_listen = %state.config.public_listen,
        data_listen = %state.config.data_listen,
        advertised_data_addr = %state.config.server_data_addr(),
        request_subject = %state.config.request_subject,
        domain_subject_routing = state.config.domain_subject_routing,
        "server listening"
    );

    let public_task = tokio::spawn(accept_public_loop(public_listener, state.clone()));
    let data_task = tokio::spawn(accept_data_loop(data_listener, state));

    public_task.await??;
    data_task.await??;
    Ok(())
}

async fn accept_public_loop(listener: TcpListener, state: AppState) -> anyhow::Result<()> {
    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .context("accept on public listener failed")?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_ingress(stream, peer, state).await {
                if is_expected_disconnect(&error) {
                    debug!(%peer, ?error, "ingress peer closed connection");
                } else {
                    warn!(%peer, ?error, "ingress connection failed");
                }
            }
        });
    }
}

async fn accept_data_loop(listener: TcpListener, state: AppState) -> anyhow::Result<()> {
    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .context("accept on data listener failed")?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_client_data(stream, state).await {
                if is_expected_disconnect(&error) {
                    debug!(%peer, ?error, "callback peer closed connection");
                } else {
                    warn!(%peer, ?error, "client data connection failed");
                }
            }
        });
    }
}

async fn handle_ingress(
    stream: TcpStream,
    peer: std::net::SocketAddr,
    state: AppState,
) -> anyhow::Result<()> {
    let (hostname, tls) = detect_hostname(&stream).await?;
    if let Some(route) =
        select_sni_passthrough(&state.config.sni_passthrough_routes, hostname.as_deref())
    {
        let mut backend = TcpStream::connect(&route.backend_addr)
            .await
            .with_context(|| format!("connect SNI passthrough backend {}", route.backend_addr))?;
        debug!(
            hostname = %route.hostname,
            backend_addr = %route.backend_addr,
            "forwarding direct SNI passthrough"
        );
        let mut ingress = stream;
        let (upstream, downstream) =
            copy_bidirectional_with_mode(&mut ingress, &mut backend, state.config.relay_mode)
                .await
                .context("copy SNI passthrough stream")?;
        debug!(upstream, downstream, "SNI passthrough finished");
        return Ok(());
    }
    let connection_id = Uuid::new_v4().to_string();
    let claim = broadcast_and_wait_for_claim(
        &state,
        &connection_id,
        hostname.as_deref(),
        peer.ip().to_string(),
        tls,
    )
    .await?;
    let route_label = hostname.as_deref().unwrap_or("<default>");

    debug!(%connection_id, hostname = route_label, client_id = %claim.client_id, "accepted tunnel claim");

    let expires_at = Instant::now() + Duration::from_millis(state.config.pending_timeout_ms);
    {
        let mut pending = state.pending.lock().await;
        pending.insert(
            connection_id.clone(),
            PendingConnection {
                ingress: stream,
                client_id: claim.client_id.clone(),
                expires_at,
            },
        );
    }

    spawn_pending_cleanup(state, connection_id);
    Ok(())
}

fn select_sni_passthrough<'a>(
    routes: &'a [SniPassthroughRoute],
    hostname: Option<&str>,
) -> Option<&'a SniPassthroughRoute> {
    let hostname = hostname?;
    routes
        .iter()
        .find(|route| route.hostname.eq_ignore_ascii_case(hostname))
}

async fn detect_hostname(stream: &TcpStream) -> anyhow::Result<(Option<String>, bool)> {
    let mut size = 512usize;
    let max_size = 16 * 1024;

    loop {
        let mut buf = vec![0_u8; size];
        let peeked = stream
            .peek(&mut buf)
            .await
            .context("failed to peek ingress bytes")?;
        if peeked == 0 {
            return Ok((None, false));
        }
        buf.truncate(peeked);

        match validate_tls_record_header(&buf) {
            Ok(()) => match extract_sni(&buf) {
                Ok(value) => return Ok((value, true)),
                Err(error) if size < max_size => {
                    debug!(?error, size, "client hello incomplete, peeking more");
                    size = (size * 2).min(max_size);
                }
                Err(error) => return Err(error),
            },
            Err(_) => {
                if let Some(host) = extract_http_host(&buf) {
                    return Ok((Some(host), false));
                }
                if size < max_size && looks_like_http_prefix(&buf) {
                    debug!(size, "http request incomplete, peeking more");
                    size = (size * 2).min(max_size);
                    continue;
                }
                return Ok((None, false));
            }
        }
    }
}

async fn broadcast_and_wait_for_claim(
    state: &AppState,
    connection_id: &str,
    hostname: Option<&str>,
    client_ip: String,
    tls: bool,
) -> anyhow::Result<ConnectionClaim> {
    let reply_subject = state.nats.new_inbox();
    let mut claims = state
        .nats
        .subscribe(reply_subject.clone())
        .await
        .context("failed to subscribe to claim inbox")?;

    let request = ConnectionRequest {
        connection_id: connection_id.to_string(),
        hostname: hostname.map(ToOwned::to_owned),
        client_ip: Some(client_ip),
        tls,
        reply_subject: reply_subject.clone(),
        server_data_addr: state.config.server_data_addr().to_string(),
        deadline_unix_ms: unix_time_ms() + state.config.claim_timeout_ms,
    };

    let request_subject = if state.config.domain_subject_routing {
        let hostname =
            hostname.ok_or_else(|| anyhow!("hostname is required for domain subject routing"))?;
        hostname_request_subject(&state.config.request_subject, hostname)
            .ok_or_else(|| anyhow!("hostname cannot be represented as a NATS subject"))?
    } else {
        state.config.request_subject.clone()
    };

    state
        .nats
        .publish_with_reply(
            request_subject,
            reply_subject,
            encode_json(&request)?.into(),
        )
        .await
        .context("failed to publish connection request")?;

    let first_claim = timeout(
        Duration::from_millis(state.config.claim_timeout_ms),
        claims.next(),
    )
    .await
    .context("timed out waiting for client claim")?
    .ok_or_else(|| anyhow!("claim subscription ended unexpectedly"))?;

    let mut claim_messages = vec![first_claim];
    let collection_deadline =
        Instant::now() + Duration::from_millis(state.config.claim_timeout_ms.min(100));
    loop {
        let remaining = collection_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }

        match timeout(remaining, claims.next()).await {
            Ok(Some(message)) => claim_messages.push(message),
            Ok(None) | Err(_) => break,
        }
    }

    let mut valid_claims = Vec::with_capacity(claim_messages.len());
    for claim_message in claim_messages {
        let claim: ConnectionClaim = decode_json(&claim_message.payload)?;
        if claim.connection_id != connection_id {
            return Err(anyhow!("claim connection id mismatch"));
        }
        valid_claims.push((claim, claim_message.reply));
    }
    valid_claims.sort_by(|left, right| left.0.client_id.cmp(&right.0.client_id));

    let route_key = hostname
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_else(|| "<default>".to_string());
    let winner_index = next_claim_index(state, &route_key, valid_claims.len()).await;

    let winner = valid_claims[winner_index].0.clone();
    for (index, (claim, ack_subject)) in valid_claims.into_iter().enumerate() {
        if let Some(ack_subject) = ack_subject {
            let accepted = index == winner_index;
            let ack = ConnectionClaimAck {
                accepted,
                client_id: claim.client_id.clone(),
                connection_id: claim.connection_id.clone(),
                reason: (!accepted).then(|| "another client won round-robin selection".to_string()),
            };
            state
                .nats
                .publish(ack_subject, encode_json(&ack)?.into())
                .await
                .context("failed to publish claim ack")?;
        }
    }

    Ok(winner)
}

async fn next_claim_index(state: &AppState, route_key: &str, claim_count: usize) -> usize {
    let mut cursors = state.route_claim_cursor.lock().await;
    let cursor = cursors.entry(route_key.to_string()).or_insert(0);
    let selected = *cursor % claim_count;
    *cursor = (*cursor + 1) % claim_count;
    selected
}

fn spawn_pending_cleanup(state: AppState, connection_id: String) {
    tokio::spawn(async move {
        sleep(Duration::from_millis(state.config.pending_timeout_ms)).await;
        let removed = {
            let mut pending = state.pending.lock().await;
            match pending.get(&connection_id) {
                Some(entry) if entry.expires_at <= Instant::now() => pending.remove(&connection_id),
                _ => None,
            }
        };

        if let Some(mut entry) = removed {
            warn!(%connection_id, client_id = %entry.client_id, "pending tunnel expired");
            let _ = entry.ingress.shutdown().await;
        }
    });
}

async fn handle_client_data(stream: TcpStream, state: AppState) -> anyhow::Result<()> {
    let (prefix, mut stream) = read_prefix(stream).await?;

    let mut pending = state.pending.lock().await;
    let entry = pending
        .remove(&prefix.connection_id)
        .ok_or_else(|| anyhow!("unknown or expired connection id"))?;
    if entry.client_id != prefix.client_id {
        return Err(anyhow!(
            "prefix client_id {} does not match winning client {}",
            prefix.client_id,
            entry.client_id
        ));
    }
    drop(pending);

    debug!(
        connection_id = %prefix.connection_id,
        client_id = %prefix.client_id,
        "binding claimed tunnel"
    );

    relay_streams(entry.ingress, &mut stream, state.config.relay_mode).await
}

async fn read_prefix(stream: TcpStream) -> anyhow::Result<(PrefixEnvelope, TcpStream)> {
    let mut stream = stream;
    let mut line = Vec::new();

    loop {
        let mut byte = [0_u8; 1];
        let read = stream
            .read(&mut byte)
            .await
            .context("failed to read prefix line")?;
        if read == 0 {
            return Err(anyhow!("client data socket closed before prefix"));
        }

        line.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
        if line.len() > 4096 {
            return Err(anyhow!("prefix line is too large"));
        }
    }

    let prefix = PrefixEnvelope::decode_line(&line)?;
    Ok((prefix, stream))
}

async fn relay_streams(
    mut ingress: TcpStream,
    data_stream: &mut TcpStream,
    relay_mode: shared::config::RelayMode,
) -> anyhow::Result<()> {
    let (upstream, downstream) =
        copy_bidirectional_with_mode(&mut ingress, data_stream, relay_mode)
            .await
            .context("copy_bidirectional failed")?;
    debug!(upstream, downstream, "tunnel relay finished");
    Ok(())
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use shared::{config::SniPassthroughRoute, prefix::PrefixEnvelope};

    use super::select_sni_passthrough;

    #[test]
    fn prefix_round_trip_for_server_binding() {
        let prefix = PrefixEnvelope::new("client-a", "conn-a");
        let encoded = prefix.encode_line().expect("encode");
        let decoded = PrefixEnvelope::decode_line(&encoded).expect("decode");
        assert_eq!(decoded.client_id, "client-a");
        assert_eq!(decoded.connection_id, "conn-a");
    }

    #[test]
    fn direct_sni_passthrough_matches_exact_hostname_case_insensitively() {
        let routes = vec![SniPassthroughRoute {
            hostname: "nats-pipe.example.com".into(),
            backend_addr: "127.0.0.1:4222".into(),
        }];
        let selected = select_sni_passthrough(&routes, Some("NATS-PIPE.EXAMPLE.COM"));
        assert_eq!(selected, routes.first());
        assert!(select_sni_passthrough(&routes, Some("other.example.com")).is_none());
        assert!(select_sni_passthrough(&routes, None).is_none());
    }
}
