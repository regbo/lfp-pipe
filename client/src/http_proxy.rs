//! Request-level HTTP/1.1 proxying for routed and authenticated backends.

use std::{convert::Infallible, str::FromStr, sync::Arc, time::Duration};

use anyhow::{Context, anyhow};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{
    Request, Response, StatusCode, Uri,
    body::Incoming,
    client::conn::http1 as client_http1,
    header::{self, HeaderName, HeaderValue},
    server::conn::http1 as server_http1,
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::{
    io::{AsyncRead, AsyncWrite, copy_bidirectional},
    net::TcpStream,
    time::timeout,
};
use tracing::{debug, warn};

use crate::{
    BackendRuntime,
    authorization::{AuthResponse, AuthenticatedIdentity, AuthorizationDecision},
    select_runtime_for_path,
};

type ProxyBody = BoxBody<Bytes, hyper::Error>;

const IDENTITY_HEADERS: [&str; 12] = [
    "x-forwarded-user",
    "x-forwarded-email",
    "x-forwarded-groups",
    "x-auth-request-user",
    "x-auth-request-email",
    "x-auth-request-groups",
    "x-auth-request-preferred-username",
    "x-authentik-uid",
    "x-authentik-username",
    "x-authentik-name",
    "x-authentik-email",
    "x-authentik-groups",
];

pub(crate) async fn serve<S>(
    stream: S,
    hostname: String,
    client_ip: Option<String>,
    scheme: &'static str,
    backends: Arc<Vec<BackendRuntime>>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (maximum, header_timeout) = request_limits(&backends);
    let service = service_fn(move |request| {
        let hostname = hostname.clone();
        let client_ip = client_ip.clone();
        let backends = backends.clone();
        async move {
            let response =
                handle_request(request, &hostname, client_ip.as_deref(), scheme, backends).await;
            Ok::<_, Infallible>(response)
        }
    });
    let mut builder = server_http1::Builder::new();
    builder
        .keep_alive(true)
        .timer(TokioTimer::new())
        .header_read_timeout(header_timeout)
        .max_buf_size(maximum.max(8 * 1024));
    builder
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades()
        .await
        .context("serve inspected HTTP connection")
}

fn request_limits(backends: &[BackendRuntime]) -> (usize, Duration) {
    backends
        .iter()
        .filter_map(|backend| backend.authorization.as_ref())
        .fold(
            (32 * 1024, Duration::from_secs(5)),
            |(maximum, timeout), authorizer| {
                let (policy_maximum, policy_timeout) = authorizer.request_limits();
                (maximum.min(policy_maximum), timeout.min(policy_timeout))
            },
        )
}

async fn handle_request(
    mut request: Request<Incoming>,
    hostname: &str,
    client_ip: Option<&str>,
    scheme: &str,
    backends: Arc<Vec<BackendRuntime>>,
) -> Response<ProxyBody> {
    match handle_request_inner(&mut request, hostname, client_ip, scheme, &backends).await {
        Ok(RequestAction::Respond(response)) => local_response(response),
        Ok(RequestAction::Forward(backend)) => {
            forward_request(request, backend.rule.resolved_http_backend_addr()).await
        }
        Err(error) => {
            warn!(?error, "HTTP proxy request failed");
            error_response(StatusCode::BAD_GATEWAY, "bad gateway")
        }
    }
}

enum RequestAction<'a> {
    Respond(AuthResponse),
    Forward(&'a BackendRuntime),
}

async fn handle_request_inner<'a>(
    request: &mut Request<Incoming>,
    hostname: &str,
    client_ip: Option<&str>,
    scheme: &str,
    backends: &'a [BackendRuntime],
) -> anyhow::Result<RequestAction<'a>> {
    let path = request.uri().path();
    let endpoint_authorizer = backends
        .iter()
        .filter_map(|backend| backend.authorization.as_ref())
        .find(|authorizer| authorizer.handles_endpoint(path));
    if let Some(authorizer) = endpoint_authorizer {
        return match authorizer
            .authorize(request.method(), request.uri(), request.headers())
            .await
        {
            AuthorizationDecision::Respond(response) => Ok(RequestAction::Respond(response)),
            AuthorizationDecision::Allow(_) => Err(anyhow!("OIDC endpoint was not handled")),
        };
    }

    let backend = select_runtime_for_path(backends, Some(hostname), path)
        .context("HTTP request has no matching backend")?;
    let identity = if let Some(authorizer) = &backend.authorization {
        match authorizer
            .authorize(request.method(), request.uri(), request.headers())
            .await
        {
            AuthorizationDecision::Allow(identity) => {
                if !authorizer.forward_authorization() {
                    request.headers_mut().remove(header::AUTHORIZATION);
                }
                identity
            }
            AuthorizationDecision::Respond(response) => {
                return Ok(RequestAction::Respond(response));
            }
        }
    } else {
        None
    };

    prepare_request(request, backend, client_ip, scheme, identity.as_ref())?;
    Ok(RequestAction::Forward(backend))
}

fn prepare_request<B>(
    request: &mut Request<B>,
    backend: &BackendRuntime,
    client_ip: Option<&str>,
    scheme: &str,
    identity: Option<&AuthenticatedIdentity>,
) -> anyhow::Result<()> {
    let original_host = request
        .headers()
        .get(header::HOST)
        .cloned()
        .context("HTTP request must contain a Host header")?;

    for name in IDENTITY_HEADERS {
        request.headers_mut().remove(name);
    }
    if let Some(identity) = identity {
        set_header(request, "x-forwarded-user", &identity.username)?;
        set_header(request, "x-auth-request-user", &identity.username)?;
        set_header(
            request,
            "x-auth-request-preferred-username",
            &identity.username,
        )?;
        set_header(request, "x-authentik-uid", &identity.subject)?;
        set_header(request, "x-authentik-username", &identity.username)?;
        set_header(
            request,
            "x-authentik-name",
            identity.name.as_deref().unwrap_or(&identity.username),
        )?;
        if let Some(email) = &identity.email {
            set_header(request, "x-forwarded-email", email)?;
            set_header(request, "x-auth-request-email", email)?;
            set_header(request, "x-authentik-email", email)?;
        }
        if !identity.groups.is_empty() {
            let groups = identity.groups.join(",");
            set_header(request, "x-forwarded-groups", &groups)?;
            set_header(request, "x-auth-request-groups", &groups)?;
            set_header(request, "x-authentik-groups", &identity.groups.join("|"))?;
        }
    }

    if backend.rule.strip_path_prefix {
        let prefix = backend
            .rule
            .path_prefix
            .as_deref()
            .context("missing path_prefix")?;
        *request.uri_mut() = strip_uri_prefix(request.uri(), prefix)?;
    }
    if backend.rule.proxy_headers {
        for name in [
            header::FORWARDED.as_str(),
            "x-forwarded-for",
            "x-forwarded-proto",
            "x-forwarded-host",
        ] {
            request.headers_mut().remove(name);
        }
        if let Some(client_ip) = client_ip.filter(|value| !value.trim().is_empty()) {
            set_header(request, "x-forwarded-for", client_ip)?;
        }
        request.headers_mut().insert(
            HeaderName::from_static("x-forwarded-proto"),
            HeaderValue::from_str(scheme).context("invalid forwarded scheme")?,
        );
        request.headers_mut().insert(
            HeaderName::from_static("x-forwarded-host"),
            original_host.clone(),
        );
        if !request.headers().contains_key(header::ACCEPT_ENCODING) {
            request
                .headers_mut()
                .insert(header::ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
        }
    }
    if let Some(host) = backend.rule.backend_host.as_deref() {
        request.headers_mut().insert(
            header::HOST,
            HeaderValue::from_str(host).context("invalid backend Host header")?,
        );
    }
    Ok(())
}

fn set_header<B>(request: &mut Request<B>, name: &'static str, value: &str) -> anyhow::Result<()> {
    request.headers_mut().insert(
        HeaderName::from_static(name),
        HeaderValue::from_str(value).with_context(|| format!("invalid {name} value"))?,
    );
    Ok(())
}

fn strip_uri_prefix(uri: &Uri, prefix: &str) -> anyhow::Result<Uri> {
    let prefix = prefix.trim_end_matches('/');
    let path = uri.path();
    let remainder = path
        .strip_prefix(prefix)
        .filter(|value| value.is_empty() || value.starts_with('/'))
        .context("HTTP request path does not match configured prefix")?;
    let rewritten = if remainder.is_empty() { "/" } else { remainder };
    let path_and_query = match uri.query() {
        Some(query) => format!("{rewritten}?{query}"),
        None => rewritten.to_string(),
    };
    Uri::from_str(&path_and_query).context("construct rewritten request URI")
}

async fn forward_request(
    mut request: Request<Incoming>,
    backend_addr: String,
) -> Response<ProxyBody> {
    let stream = match timeout(Duration::from_secs(10), TcpStream::connect(&backend_addr)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            warn!(?error, backend = %backend_addr, "connect HTTP backend failed");
            return error_response(StatusCode::BAD_GATEWAY, "backend unavailable");
        }
        Err(_) => return error_response(StatusCode::GATEWAY_TIMEOUT, "backend timed out"),
    };
    let (mut sender, connection) = match client_http1::handshake(TokioIo::new(stream)).await {
        Ok(parts) => parts,
        Err(error) => {
            warn!(?error, backend = %backend_addr, "start HTTP backend connection failed");
            return error_response(StatusCode::BAD_GATEWAY, "backend unavailable");
        }
    };
    tokio::spawn(async move {
        if let Err(error) = connection.with_upgrades().await {
            debug!(?error, "HTTP backend connection ended");
        }
    });

    let upgrading = request.headers().contains_key(header::UPGRADE);
    let downstream_upgrade = upgrading.then(|| hyper::upgrade::on(&mut request));
    let mut response = match sender.send_request(request).await {
        Ok(response) => response,
        Err(error) => {
            warn!(?error, backend = %backend_addr, "HTTP backend request failed");
            return error_response(StatusCode::BAD_GATEWAY, "backend request failed");
        }
    };
    if response.status() == StatusCode::SWITCHING_PROTOCOLS
        && let Some(downstream_upgrade) = downstream_upgrade
    {
        let upstream_upgrade = hyper::upgrade::on(&mut response);
        tokio::spawn(async move {
            match tokio::try_join!(downstream_upgrade, upstream_upgrade) {
                Ok((downstream, upstream)) => {
                    let mut downstream = TokioIo::new(downstream);
                    let mut upstream = TokioIo::new(upstream);
                    if let Err(error) = copy_bidirectional(&mut downstream, &mut upstream).await {
                        debug!(?error, "upgraded HTTP relay ended");
                    }
                }
                Err(error) => debug!(?error, "HTTP upgrade failed"),
            }
        });
    }
    response.map(|body| body.boxed())
}

fn local_response(response: AuthResponse) -> Response<ProxyBody> {
    let mut output = Response::new(full_body(response.body));
    *output.status_mut() = response.status;
    *output.headers_mut() = response.headers;
    output
}

fn error_response(status: StatusCode, message: &'static str) -> Response<ProxyBody> {
    let body = Bytes::from(format!("{{\"error\":\"{message}\"}}\n"));
    let mut response = Response::new(full_body(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

fn full_body(body: Bytes) -> ProxyBody {
    Full::new(body).map_err(|never| match never {}).boxed()
}

#[cfg(test)]
mod tests {
    use super::{prepare_request, strip_uri_prefix};
    use crate::{BackendRuntime, authorization::AuthenticatedIdentity};
    use hyper::{Request, Uri, header};
    use shared::config::BackendRule;

    #[test]
    fn path_prefix_rewrite_preserves_query() {
        let uri: Uri = "/api/jobs?stream=false".parse().expect("URI");
        assert_eq!(
            strip_uri_prefix(&uri, "/api")
                .expect("rewritten")
                .to_string(),
            "/jobs?stream=false"
        );
    }

    #[test]
    fn proxy_request_replaces_spoofed_headers_with_verified_identity() {
        let backend = BackendRuntime {
            rule: BackendRule {
                pattern: "service.example".to_string(),
                path_prefix: Some("/api".to_string()),
                strip_path_prefix: true,
                proxy_headers: true,
                backend_addr: "127.0.0.1:8080".to_string(),
                backend_host: Some("127.0.0.1:8080".to_string()),
                http_backend_addr: None,
                authorization: None,
            },
            authorization: None,
        };
        let mut request = Request::builder()
            .uri("/api/jobs?stream=false")
            .header(header::HOST, "service.example")
            .header("x-forwarded-for", "203.0.113.99")
            .header("x-forwarded-user", "attacker")
            .header("x-authentik-uid", "attacker")
            .body(())
            .expect("request");

        let identity = AuthenticatedIdentity {
            subject: "stable-subject".to_string(),
            username: "regbo".to_string(),
            name: Some("Reggie Pierce".to_string()),
            email: Some("regbo@example.com".to_string()),
            groups: vec!["chat-users".to_string(), "operators".to_string()],
            expires_unix: u64::MAX,
        };
        prepare_request(
            &mut request,
            &backend,
            Some("198.51.100.24"),
            "https",
            Some(&identity),
        )
        .expect("prepared request");

        assert_eq!(request.uri().to_string(), "/jobs?stream=false");
        assert_eq!(request.headers()[header::HOST], "127.0.0.1:8080");
        assert_eq!(request.headers()["x-forwarded-for"], "198.51.100.24");
        assert_eq!(request.headers()["x-forwarded-host"], "service.example");
        assert_eq!(request.headers()["x-forwarded-user"], "regbo");
        assert_eq!(request.headers()["x-authentik-uid"], "stable-subject");
        assert_eq!(request.headers()["x-authentik-username"], "regbo");
        assert_eq!(request.headers()["x-authentik-name"], "Reggie Pierce");
        assert_eq!(request.headers()["x-authentik-email"], "regbo@example.com");
        assert_eq!(
            request.headers()["x-authentik-groups"],
            "chat-users|operators"
        );
    }
}
