//! Automatic certificate acquisition and local TLS termination for a route.
//!
//! `rustls-acme` drives TLS-ALPN-01 over sockets that already traversed the
//! public tunnel. No listener is opened on the client machine. Successful
//! handshakes yield decrypted streams which are copied to the route's normal
//! backend address.

use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, anyhow};
use futures::StreamExt;
use rustls_acme::{AcmeConfig, caches::DirCache};
use shared::{
    config::{ClientAcmeConfig, RelayMode},
    io::copy_bidirectional_buffered,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
    sync::mpsc,
};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, info, warn};

use crate::{BackendRuntime, authorization, request_limits, select_runtime_for_path};

/// Cloneable ingress handle owned by request-processing tasks.
#[derive(Clone)]
pub(crate) struct AcmeRuntime {
    sender: mpsc::Sender<(TcpStream, Option<String>)>,
}

struct IngressStream {
    stream: TcpStream,
    client_ip: Option<String>,
}

impl AsyncRead for IngressStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for IngressStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.stream).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

impl AcmeRuntime {
    /// Start certificate management for one exact hostname and its path backends.
    pub(crate) fn start(
        config: ClientAcmeConfig,
        backends: Arc<Vec<BackendRuntime>>,
        relay_mode: RelayMode,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !matches!(relay_mode, RelayMode::Splice),
            "automatic TLS termination cannot use splice relay mode; use auto or buffered"
        );
        let cache_root = crate::paths::expand_home(&config.cache_dir)?;
        let cache_dir = domain_cache_dir(&cache_root, &config.domain);
        prepare_cache_dir(&cache_dir)?;
        let (sender, receiver) = mpsc::channel(64);
        tokio::spawn(async move {
            if let Err(error) = run_acme(config, cache_dir, backends, receiver).await {
                warn!(?error, "ACME TLS runtime stopped");
            }
        });
        Ok(Self { sender })
    }

    /// Submit one tunneled TLS connection to the ACME-aware acceptor.
    pub(crate) async fn accept(
        &self,
        stream: TcpStream,
        client_ip: Option<String>,
    ) -> anyhow::Result<()> {
        self.sender
            .send((stream, client_ip))
            .await
            .map_err(|_| anyhow!("ACME TLS runtime is not available"))
    }
}

async fn run_acme(
    config: ClientAcmeConfig,
    cache_dir: PathBuf,
    backends: Arc<Vec<BackendRuntime>>,
    receiver: mpsc::Receiver<(TcpStream, Option<String>)>,
) -> anyhow::Result<()> {
    let mut acme = AcmeConfig::new([&config.domain]).contact(config.contacts.iter());
    acme = if let Some(directory_url) = config.directory_url.as_deref() {
        acme.directory(directory_url)
    } else {
        acme.directory_lets_encrypt(config.production)
    };
    let tcp_incoming = ReceiverStream::new(receiver)
        .map(|(stream, client_ip)| Ok::<_, io::Error>(IngressStream { stream, client_ip }));
    // Advertising only HTTP/1.1 avoids handing HTTP/2 frames to ordinary
    // plaintext backends that do not implement h2c.
    let mut tls_incoming = acme
        .cache(DirCache::new(cache_dir))
        .tokio_incoming(tcp_incoming, vec![b"http/1.1".to_vec()]);

    info!(
        domain = %config.domain,
        production = config.production,
        "automatic certificate runtime started"
    );
    while let Some(connection) = tls_incoming.next().await {
        match connection {
            Ok(tls_stream) => {
                let backends = backends.clone();
                let domain = config.domain.clone();
                let client_ip = tls_stream.get_ref().get_ref().0.get_ref().client_ip.clone();
                tokio::spawn(async move {
                    if let Err(error) =
                        bridge_tls(tls_stream, &domain, client_ip.as_deref(), &backends).await
                    {
                        warn!(?error, domain = %domain, "ACME TLS relay failed");
                    }
                });
            }
            Err(error) => warn!(?error, domain = %config.domain, "ACME TLS accept failed"),
        }
    }
    debug!(domain = %config.domain, "ACME TLS ingress channel closed");
    Ok(())
}

async fn bridge_tls<T>(
    mut tls_stream: T,
    hostname: &str,
    client_ip: Option<&str>,
    backends: &[BackendRuntime],
) -> anyhow::Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (maximum, header_timeout) = request_limits(backends);
    let request =
        authorization::read_request_header(&mut tls_stream, maximum, header_timeout).await?;
    let path = authorization::request_path(&request)?;
    let backend = select_runtime_for_path(backends, Some(hostname), path)
        .context("HTTP request has no matching backend")?;
    let mut request = match &backend.authorization {
        Some(authorizer) => {
            authorizer
                .authorize_request(&mut tls_stream, request)
                .await?
        }
        None => request,
    };
    if backend.rule.strip_path_prefix {
        request = authorization::strip_request_path_prefix(
            request,
            backend
                .rule
                .path_prefix
                .as_deref()
                .context("missing path_prefix")?,
        )?;
    }
    if backend.rule.proxy_headers {
        request = authorization::set_proxy_headers(request, client_ip, "https")?;
    }
    if let Some(host) = backend.rule.backend_host.as_deref() {
        request = authorization::set_host_header(request, host)?;
    }
    let backend_addr = backend.rule.resolved_backend_addr();
    let mut backend_stream = TcpStream::connect(&backend_addr)
        .await
        .with_context(|| format!("failed to connect backend {backend_addr}"))?;
    backend_stream
        .write_all(&request)
        .await
        .context("forward routed HTTP request headers")?;
    let (to_client, to_backend) = copy_bidirectional_buffered(&mut tls_stream, &mut backend_stream)
        .await
        .context("ACME TLS copy_bidirectional failed")?;
    debug!(to_client, to_backend, "ACME TLS relay finished");
    Ok(())
}

fn prepare_cache_dir(path: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(path)
        .with_context(|| format!("failed to create ACME cache directory {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).with_context(|| {
            format!(
                "failed to secure ACME cache directory permissions {}",
                path.display()
            )
        })?;
    }
    Ok(())
}

fn domain_cache_dir(root: &Path, domain: &str) -> PathBuf {
    // Never treat a configured hostname as a path. The per-domain directory
    // also prevents concurrent route sessions from racing over cache files.
    let component: String = domain
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-') {
                character
            } else {
                '_'
            }
        })
        .collect();
    root.join(component)
}

#[cfg(test)]
mod tests {
    use super::{AcmeRuntime, domain_cache_dir};
    use shared::config::{BackendRule, ClientAcmeConfig, RelayMode};
    use std::path::Path;
    use std::sync::Arc;

    #[test]
    fn domain_cache_directory_cannot_escape_root() {
        let path = domain_cache_dir(Path::new("cache"), "../../bad/domain");
        assert_eq!(path, Path::new("cache").join(".._.._bad_domain"));
    }

    #[test]
    fn automatic_tls_rejects_splice_before_touching_cache() {
        let error = AcmeRuntime::start(
            ClientAcmeConfig {
                domain: "example.com".to_string(),
                contacts: Vec::new(),
                cache_dir: "unused".to_string(),
                production: false,
                directory_url: None,
            },
            Arc::new(vec![crate::BackendRuntime {
                rule: BackendRule {
                    pattern: "example.com".to_string(),
                    path_prefix: None,
                    strip_path_prefix: false,
                    proxy_headers: true,
                    backend_addr: ":8080".to_string(),
                    backend_host: None,
                    http_backend_addr: None,
                    authorization: None,
                },
                authorization: None,
            }]),
            RelayMode::Splice,
        )
        .err()
        .expect("splice must fail");
        assert!(error.to_string().contains("cannot use splice"));
    }
}
