//! Cross-platform bidirectional TCP forwarding.
//!
//! Linux prefers `splice(2)` through `tokio-splice2`; other platforms and
//! unsupported Linux kernels use a bounded userspace buffer.

use crate::config::RelayMode;
use anyhow::Context;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

#[cfg(target_os = "linux")]
use {
    anyhow::ensure,
    tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::OnceCell,
        time::{Duration, timeout},
    },
    tracing::warn,
};

#[cfg(target_os = "linux")]
static SPLICE_RELAY_SUPPORTED: OnceCell<bool> = OnceCell::const_new();

// Tokio defaults to 8 KiB per direction. A larger fallback reduces userspace
// wakeups without the per-connection memory cost of multi-megabyte buffers.
const BUFFERED_RELAY_SIZE: usize = 256 * 1024;

#[cfg(target_os = "linux")]
/// Copy both directions using the automatic Linux relay policy.
pub async fn copy_bidirectional(
    left: &mut TcpStream,
    right: &mut TcpStream,
) -> anyhow::Result<(u64, u64)> {
    copy_bidirectional_with_mode(left, right, RelayMode::Auto).await
}

#[cfg(target_os = "linux")]
/// Copy both directions using an explicit relay policy.
///
/// Automatic mode falls back only when splice setup fails before bytes move.
/// Runtime errors after partial forwarding are returned to avoid duplicating
/// bytes through a second implementation.
pub async fn copy_bidirectional_with_mode(
    left: &mut TcpStream,
    right: &mut TcpStream,
    relay_mode: RelayMode,
) -> anyhow::Result<(u64, u64)> {
    if matches!(relay_mode, RelayMode::Buffered) {
        return buffered_copy_bidirectional(left, right).await;
    }

    if matches!(relay_mode, RelayMode::Splice) {
        return splice_copy_bidirectional(left, right).await;
    }

    let splice_supported = *SPLICE_RELAY_SUPPORTED
        .get_or_init(|| async {
            match timeout(Duration::from_secs(2), probe_splice_relay()).await {
                Ok(Ok(())) => true,
                Ok(Err(error)) => {
                    warn!(?error, "splice relay probe failed; using Tokio relay");
                    false
                }
                Err(_) => {
                    warn!("splice relay probe timed out; using Tokio relay");
                    false
                }
            }
        })
        .await;

    if splice_supported {
        // The outer error can only come from pipe creation, before bytes move,
        // so falling back here cannot duplicate a partially relayed stream.
        match tokio_splice2::copy_bidirectional(left, right).await {
            Ok(traffic) => {
                let tx = traffic.tx as u64;
                let rx = traffic.rx as u64;
                traffic
                    .into_result()
                    .with_context(|| {
                        format!(
                            "tokio-splice2 relay failed after {tx} bytes left-to-right and {rx} bytes right-to-left"
                        )
                    })?;
                return Ok((tx, rx));
            }
            Err(error) => {
                warn!(?error, "splice setup failed; using Tokio relay");
            }
        }
    }

    buffered_copy_bidirectional(left, right).await
}

#[cfg(target_os = "linux")]
async fn splice_copy_bidirectional(
    left: &mut TcpStream,
    right: &mut TcpStream,
) -> anyhow::Result<(u64, u64)> {
    let traffic = tokio_splice2::copy_bidirectional(left, right)
        .await
        .context("failed to initialize tokio-splice2 relay")?;
    let tx = traffic.tx as u64;
    let rx = traffic.rx as u64;
    traffic.into_result().with_context(|| {
        format!(
            "tokio-splice2 relay failed after {tx} bytes left-to-right and {rx} bytes right-to-left"
        )
    })?;
    Ok((tx, rx))
}

#[cfg(target_os = "linux")]
async fn probe_splice_relay() -> anyhow::Result<()> {
    const PREFIX: &[u8] = b"probe-prefix\n";
    const REQUEST: &[u8] = b"GET /probe HTTP/1.1\r\nHost: splice-probe.local\r\n\r\n";
    const RESPONSE: &[u8] = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";

    let left_listener = TcpListener::bind("127.0.0.1:0").await?;
    let right_listener = TcpListener::bind("127.0.0.1:0").await?;
    let (left_connect, left_accept) = tokio::join!(
        TcpStream::connect(left_listener.local_addr()?),
        left_listener.accept()
    );
    let (right_connect, right_accept) = tokio::join!(
        TcpStream::connect(right_listener.local_addr()?),
        right_listener.accept()
    );
    let mut left_peer = left_connect?;
    let (mut left_relay, _) = left_accept?;
    let mut right_peer = right_connect?;
    let (mut right_relay, _) = right_accept?;

    // Match the real relay state: routing peeks at ingress, while the server
    // consumes a prefix from the callback socket before forwarding begins.
    right_peer.write_all(PREFIX).await?;
    let mut prefix = vec![0; PREFIX.len()];
    right_relay.read_exact(&mut prefix).await?;
    ensure!(prefix == PREFIX, "splice probe prefix mismatch");
    left_peer.write_all(REQUEST).await?;
    let mut peeked_request = vec![0; REQUEST.len()];
    let peeked = left_relay.peek(&mut peeked_request).await?;
    ensure!(peeked > 0, "splice probe request peek was empty");
    ensure!(
        peeked_request[..peeked] == REQUEST[..peeked],
        "splice probe peek mismatch"
    );

    let relay = tokio::spawn(async move {
        let traffic = tokio_splice2::copy_bidirectional(&mut left_relay, &mut right_relay).await?;
        traffic.into_result()
    });

    let mut request = vec![0; REQUEST.len()];
    right_peer.read_exact(&mut request).await?;
    ensure!(request == REQUEST, "splice probe request mismatch");

    right_peer.write_all(RESPONSE).await?;
    let mut response = vec![0; RESPONSE.len()];
    left_peer.read_exact(&mut response).await?;
    ensure!(response == RESPONSE, "splice probe response mismatch");

    left_peer.shutdown().await?;
    right_peer.shutdown().await?;
    relay.await??;
    Ok(())
}

/// Copy both directions between arbitrary Tokio streams with bounded buffers.
///
/// TLS streams cannot use Linux `splice(2)` because encryption is processed in
/// userspace. This generic path keeps the same buffer sizing and diagnostics as
/// the TCP-only fallback used by the regular tunnel relay.
pub async fn copy_bidirectional_buffered<L, R>(
    left: &mut L,
    right: &mut R,
) -> anyhow::Result<(u64, u64)>
where
    L: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional_with_sizes(left, right, BUFFERED_RELAY_SIZE, BUFFERED_RELAY_SIZE)
        .await
        .context("tokio copy_bidirectional failed")
}

async fn buffered_copy_bidirectional(
    left: &mut TcpStream,
    right: &mut TcpStream,
) -> anyhow::Result<(u64, u64)> {
    copy_bidirectional_buffered(left, right).await
}

#[cfg(not(target_os = "linux"))]
/// Copy both directions with the portable buffered relay.
pub async fn copy_bidirectional(
    left: &mut TcpStream,
    right: &mut TcpStream,
) -> anyhow::Result<(u64, u64)> {
    buffered_copy_bidirectional(left, right).await
}

#[cfg(not(target_os = "linux"))]
/// Copy both directions; non-Linux targets always use the buffered relay.
pub async fn copy_bidirectional_with_mode(
    left: &mut TcpStream,
    right: &mut TcpStream,
    _relay_mode: RelayMode,
) -> anyhow::Result<(u64, u64)> {
    buffered_copy_bidirectional(left, right).await
}

#[cfg(test)]
mod tests {
    use anyhow::ensure;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;

    #[tokio::test]
    async fn buffered_relay_moves_large_bidirectional_payloads() -> anyhow::Result<()> {
        const REQUEST_SIZE: usize = 2 * 1024 * 1024;
        const RESPONSE_SIZE: usize = 1024 * 1024;

        let left_listener = TcpListener::bind("127.0.0.1:0").await?;
        let right_listener = TcpListener::bind("127.0.0.1:0").await?;
        let (left_connect, left_accept) = tokio::join!(
            TcpStream::connect(left_listener.local_addr()?),
            left_listener.accept()
        );
        let (right_connect, right_accept) = tokio::join!(
            TcpStream::connect(right_listener.local_addr()?),
            right_listener.accept()
        );
        let mut left_peer = left_connect?;
        let (mut left_relay, _) = left_accept?;
        let mut right_peer = right_connect?;
        let (mut right_relay, _) = right_accept?;

        let relay = tokio::spawn(async move {
            copy_bidirectional_with_mode(&mut left_relay, &mut right_relay, RelayMode::Buffered)
                .await
        });
        let left = tokio::spawn(async move {
            left_peer.write_all(&vec![0x5a; REQUEST_SIZE]).await?;
            let mut response = vec![0; RESPONSE_SIZE];
            left_peer.read_exact(&mut response).await?;
            ensure!(response.iter().all(|byte| *byte == 0xa5));
            left_peer.shutdown().await?;
            anyhow::Ok(())
        });
        let right = tokio::spawn(async move {
            let mut request = vec![0; REQUEST_SIZE];
            right_peer.read_exact(&mut request).await?;
            ensure!(request.iter().all(|byte| *byte == 0x5a));
            right_peer.write_all(&vec![0xa5; RESPONSE_SIZE]).await?;
            right_peer.shutdown().await?;
            anyhow::Ok(())
        });

        left.await??;
        right.await??;
        let (upstream, downstream) = relay.await??;
        ensure!(upstream == REQUEST_SIZE as u64);
        ensure!(downstream == RESPONSE_SIZE as u64);
        Ok(())
    }

    async fn relay_handles_peeked_and_preconsumed_sockets(
        relay_mode: RelayMode,
    ) -> anyhow::Result<()> {
        const PREFIX: &[u8] = b"test-prefix\n";
        const REQUEST: &[u8] = b"request";
        const RESPONSE: &[u8] = b"response";

        let left_listener = TcpListener::bind("127.0.0.1:0").await?;
        let right_listener = TcpListener::bind("127.0.0.1:0").await?;
        let (left_connect, left_accept) = tokio::join!(
            TcpStream::connect(left_listener.local_addr()?),
            left_listener.accept()
        );
        let (right_connect, right_accept) = tokio::join!(
            TcpStream::connect(right_listener.local_addr()?),
            right_listener.accept()
        );
        let mut left_peer = left_connect?;
        let (mut left_relay, _) = left_accept?;
        let mut right_peer = right_connect?;
        let (mut right_relay, _) = right_accept?;

        right_peer.write_all(PREFIX).await?;
        let mut prefix = vec![0; PREFIX.len()];
        right_relay.read_exact(&mut prefix).await?;
        left_peer.write_all(REQUEST).await?;
        let mut peeked = vec![0; REQUEST.len()];
        left_relay.peek(&mut peeked).await?;

        let relay = tokio::spawn(async move {
            copy_bidirectional_with_mode(&mut left_relay, &mut right_relay, relay_mode).await
        });

        let mut request = vec![0; REQUEST.len()];
        right_peer.read_exact(&mut request).await?;
        ensure!(request == REQUEST, "adaptive relay request mismatch");
        right_peer.write_all(RESPONSE).await?;
        let mut response = vec![0; RESPONSE.len()];
        left_peer.read_exact(&mut response).await?;
        ensure!(response == RESPONSE, "adaptive relay response mismatch");

        left_peer.shutdown().await?;
        right_peer.shutdown().await?;
        let (upstream, downstream) = relay.await??;
        ensure!(
            upstream == REQUEST.len() as u64,
            "unexpected upstream count"
        );
        ensure!(
            downstream == RESPONSE.len() as u64,
            "unexpected downstream count"
        );
        Ok(())
    }

    #[tokio::test]
    async fn adaptive_relay_handles_peeked_and_preconsumed_sockets() -> anyhow::Result<()> {
        relay_handles_peeked_and_preconsumed_sockets(RelayMode::Auto).await
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn splice_relay_handles_peeked_and_preconsumed_sockets() -> anyhow::Result<()> {
        relay_handles_peeked_and_preconsumed_sockets(RelayMode::Splice).await
    }
}
