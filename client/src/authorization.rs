//! Fail-closed JWT authorization for HTTP backends.

use std::{
    fs,
    io::Write,
    path::Path,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use anyhow::{Context, anyhow, bail, ensure};
use atomic_write_file::AtomicWriteFile;
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    jwk::{JwkSet, PublicKeyUse},
};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use shared::config::{ClientAuthorizationConfig, RoleMatch};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{Mutex, RwLock},
    time::timeout,
};
use tracing::{debug, warn};

const MAX_HTTP_HEADERS: usize = 128;

#[derive(Debug, Deserialize)]
struct DiscoveryDocument {
    issuer: String,
    jwks_uri: String,
}

#[derive(Clone)]
pub(crate) struct JwtAuthorizer {
    config: Arc<ClientAuthorizationConfig>,
    algorithms: Arc<Vec<Algorithm>>,
    http: Client,
    keys: Arc<RwLock<KeyState>>,
    refresh: Arc<Mutex<Instant>>,
}

struct KeyState {
    set: JwkSet,
    obtained_at: SystemTime,
}

#[derive(Debug)]
enum Denial {
    Unauthorized(anyhow::Error),
    Forbidden(anyhow::Error),
}

impl JwtAuthorizer {
    pub(crate) async fn load(config: ClientAuthorizationConfig) -> anyhow::Result<Self> {
        let mut config = config;
        config.jwks_cache_file = crate::paths::expand_home(&config.jwks_cache_file)?
            .to_string_lossy()
            .into_owned();
        let algorithms = config
            .algorithms
            .iter()
            .map(|value| parse_algorithm(value))
            .collect::<anyhow::Result<Vec<_>>>()?;
        ensure!(
            !algorithms.is_empty(),
            "JWT algorithm allowlist cannot be empty"
        );
        let http = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("construct JWT key HTTP client")?;

        let remote = fetch_jwks(&http, &config).await;
        let state = match remote {
            Ok(set) => {
                persist_jwks(Path::new(&config.jwks_cache_file), &set)?;
                KeyState {
                    set,
                    obtained_at: SystemTime::now(),
                }
            }
            Err(remote_error) => {
                let cached = load_cached_jwks(&config).with_context(|| {
                    format!("identity provider unavailable ({remote_error:#}) and JWKS cache is unusable")
                })?;
                warn!(?remote_error, cache = %config.jwks_cache_file, "using cached JWKS");
                cached
            }
        };

        Ok(Self {
            config: Arc::new(config),
            algorithms: Arc::new(algorithms),
            http,
            keys: Arc::new(RwLock::new(state)),
            refresh: Arc::new(Mutex::new(Instant::now())),
        })
    }

    pub(crate) async fn authorize_request<S>(
        &self,
        stream: &mut S,
        request: Vec<u8>,
    ) -> anyhow::Result<Vec<u8>>
    where
        S: AsyncWrite + Unpin,
    {
        let header_end = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|index| index + 4)
            .unwrap_or(request.len());
        if header_end > self.config.max_header_bytes {
            let denial =
                Denial::Unauthorized(anyhow!("HTTP request headers exceed configured limit"));
            write_denial(stream, &denial).await?;
            bail!("HTTP request authorization denied: headers exceed configured limit");
        }
        match self.authorize_header(&request).await {
            Ok(()) => {
                if self.config.forward_authorization {
                    Ok(request)
                } else {
                    strip_authorization_header(&request)
                }
            }
            Err(denial) => {
                let message = match &denial {
                    Denial::Unauthorized(error) | Denial::Forbidden(error) => format!("{error:#}"),
                };
                write_denial(stream, &denial).await?;
                bail!("HTTP request authorization denied: {message}")
            }
        }
    }

    pub(crate) fn request_limits(&self) -> (usize, Duration) {
        (
            self.config.max_header_bytes,
            Duration::from_millis(self.config.header_timeout_ms),
        )
    }

    async fn authorize_header(&self, bytes: &[u8]) -> Result<(), Denial> {
        let token = bearer_token(bytes).map_err(Denial::Unauthorized)?;
        self.refresh_if_due(false)
            .await
            .map_err(Denial::Unauthorized)?;
        let header = decode_header(token)
            .map_err(|error| Denial::Unauthorized(anyhow!("invalid JWT header: {error}")))?;
        if !self.algorithms.contains(&header.alg) {
            return Err(Denial::Unauthorized(anyhow!(
                "JWT algorithm is not allowed"
            )));
        }
        let kid = header
            .kid
            .as_deref()
            .ok_or_else(|| Denial::Unauthorized(anyhow!("JWT header is missing kid")))?;

        let mut key = self.key_for(kid, header.alg).await;
        if key.is_err() {
            self.refresh_if_due(true)
                .await
                .map_err(Denial::Unauthorized)?;
            key = self.key_for(kid, header.alg).await;
        }
        let key = key.map_err(Denial::Unauthorized)?;
        let mut validation = Validation::new(header.alg);
        validation.leeway = self.config.leeway_seconds;
        validation.validate_nbf = true;
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&self.config.audiences);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        let claims = decode::<Value>(token, &key, &validation)
            .map_err(|error| Denial::Unauthorized(anyhow!("JWT validation failed: {error}")))?
            .claims;

        let roles = if self.config.required_roles.is_empty() {
            None
        } else {
            Some(claim_strings(&claims, &self.config.roles_claim).map_err(Denial::Forbidden)?)
        };
        let role_ok = match self.config.role_match {
            RoleMatch::Any => {
                self.config.required_roles.is_empty()
                    || self.config.required_roles.iter().any(|required| {
                        roles
                            .as_ref()
                            .is_some_and(|roles| roles.contains(required.as_str()))
                    })
            }
            RoleMatch::All => self.config.required_roles.iter().all(|required| {
                roles
                    .as_ref()
                    .is_some_and(|roles| roles.contains(required.as_str()))
            }),
        };
        if !role_ok {
            return Err(Denial::Forbidden(anyhow!("required JWT role is missing")));
        }
        Ok(())
    }

    async fn key_for(&self, kid: &str, algorithm: Algorithm) -> anyhow::Result<DecodingKey> {
        let state = self.keys.read().await;
        ensure_cache_age(&self.config, state.obtained_at)?;
        let jwk = state
            .set
            .find(kid)
            .ok_or_else(|| anyhow!("JWT signing key was not found"))?;
        if let Some(usage) = &jwk.common.public_key_use {
            ensure!(
                *usage == PublicKeyUse::Signature,
                "JWK is not a signing key"
            );
        }
        if let Some(key_algorithm) = jwk.common.key_algorithm {
            ensure!(
                Algorithm::try_from(key_algorithm).ok() == Some(algorithm),
                "JWK algorithm does not match JWT header"
            );
        }
        DecodingKey::from_jwk(jwk).context("construct JWT verification key")
    }

    async fn refresh_if_due(&self, force: bool) -> anyhow::Result<()> {
        let mut last_attempt = self.refresh.lock().await;
        let minimum_interval = if force {
            Duration::from_secs(10)
        } else {
            Duration::from_secs(self.config.jwks_refresh_seconds)
        };
        if last_attempt.elapsed() < minimum_interval {
            return Ok(());
        }
        *last_attempt = Instant::now();
        match fetch_jwks(&self.http, &self.config).await {
            Ok(set) => {
                persist_jwks(Path::new(&self.config.jwks_cache_file), &set)?;
                *self.keys.write().await = KeyState {
                    set,
                    obtained_at: SystemTime::now(),
                };
                debug!("refreshed JWT verification keys");
                Ok(())
            }
            Err(error) => {
                let obtained_at = self.keys.read().await.obtained_at;
                ensure_cache_age(&self.config, obtained_at)?;
                warn!(?error, "JWKS refresh failed; retaining cached keys");
                Ok(())
            }
        }
    }
}

async fn fetch_jwks(http: &Client, config: &ClientAuthorizationConfig) -> anyhow::Result<JwkSet> {
    let jwks_uri = if let Some(uri) = &config.jwks_uri {
        uri.clone()
    } else {
        let discovery_uri = format!(
            "{}/.well-known/openid-configuration",
            config.issuer.trim_end_matches('/')
        );
        let discovery = http
            .get(discovery_uri)
            .send()
            .await
            .context("fetch OIDC discovery document")?
            .error_for_status()
            .context("OIDC discovery endpoint returned an error")?
            .json::<DiscoveryDocument>()
            .await
            .context("decode OIDC discovery document")?;
        ensure!(
            discovery.issuer == config.issuer,
            "OIDC discovery issuer does not exactly match configuration"
        );
        discovery.jwks_uri
    };
    let set = http
        .get(jwks_uri)
        .send()
        .await
        .context("fetch JWKS")?
        .error_for_status()
        .context("JWKS endpoint returned an error")?
        .json::<JwkSet>()
        .await
        .context("decode JWKS")?;
    ensure!(!set.keys.is_empty(), "JWKS contains no keys");
    Ok(set)
}

fn load_cached_jwks(config: &ClientAuthorizationConfig) -> anyhow::Result<KeyState> {
    let path = Path::new(&config.jwks_cache_file);
    let metadata = fs::metadata(path)
        .with_context(|| format!("read JWKS cache metadata {}", path.display()))?;
    let obtained_at = metadata
        .modified()
        .context("read JWKS cache modification time")?;
    ensure_cache_age(config, obtained_at)?;
    let bytes = fs::read(path).with_context(|| format!("read JWKS cache {}", path.display()))?;
    let set: JwkSet = serde_json::from_slice(&bytes).context("decode cached JWKS")?;
    ensure!(!set.keys.is_empty(), "cached JWKS contains no keys");
    Ok(KeyState { set, obtained_at })
}

fn ensure_cache_age(
    config: &ClientAuthorizationConfig,
    obtained_at: SystemTime,
) -> anyhow::Result<()> {
    if config.jwks_max_stale_seconds == 0 {
        return Ok(());
    }
    let age = SystemTime::now()
        .duration_since(obtained_at)
        .unwrap_or_default();
    ensure!(
        age <= Duration::from_secs(config.jwks_max_stale_seconds),
        "cached JWKS exceeds jwks_max_stale_seconds"
    );
    Ok(())
}

fn persist_jwks(path: &Path, set: &JwkSet) -> anyhow::Result<()> {
    let parent = path.parent().filter(|value| !value.as_os_str().is_empty());
    if let Some(parent) = parent {
        fs::create_dir_all(parent)
            .with_context(|| format!("create JWKS cache directory {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec(set).context("encode JWKS cache")?;
    let mut file = AtomicWriteFile::open(path)
        .with_context(|| format!("open atomic JWKS cache {}", path.display()))?;
    file.write_all(&bytes)
        .with_context(|| format!("write JWKS cache {}", path.display()))?;
    file.commit()
        .with_context(|| format!("replace JWKS cache {}", path.display()))?;
    Ok(())
}

fn parse_algorithm(value: &str) -> anyhow::Result<Algorithm> {
    let algorithm =
        Algorithm::from_str(value).with_context(|| format!("unsupported JWT algorithm {value}"))?;
    ensure!(
        !matches!(
            algorithm,
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
        ),
        "symmetric JWT algorithms are not accepted for JWKS authorization"
    );
    Ok(algorithm)
}

pub(crate) async fn read_request_header<S>(
    stream: &mut S,
    maximum: usize,
    duration: Duration,
) -> anyhow::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    timeout(duration, async {
        let mut bytes = Vec::with_capacity(maximum.min(4096));
        let mut chunk = [0_u8; 2048];
        loop {
            let read = stream
                .read(&mut chunk)
                .await
                .context("read HTTP request header")?;
            ensure!(read != 0, "connection closed before HTTP request headers");
            bytes.extend_from_slice(&chunk[..read]);
            if let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                ensure!(
                    header_end + 4 <= maximum,
                    "HTTP request headers exceed configured limit"
                );
                return Ok(bytes);
            }
            ensure!(
                bytes.len() <= maximum,
                "HTTP request headers exceed configured limit"
            );
        }
    })
    .await
    .context("timed out reading HTTP request headers")?
}

pub(crate) fn request_path(bytes: &[u8]) -> anyhow::Result<&str> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HTTP_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    ensure!(
        request
            .parse(bytes)
            .context("parse HTTP request")?
            .is_complete(),
        "incomplete HTTP request headers"
    );
    let target = request
        .path
        .ok_or_else(|| anyhow!("HTTP request target is missing"))?;
    let path = target.split('?').next().unwrap_or(target);
    ensure!(
        path.starts_with('/'),
        "HTTP request target must use origin form"
    );
    Ok(path)
}

pub(crate) fn strip_request_path_prefix(bytes: Vec<u8>, prefix: &str) -> anyhow::Result<Vec<u8>> {
    let line_end = bytes
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or_else(|| anyhow!("HTTP request line is incomplete"))?;
    let request_line =
        std::str::from_utf8(&bytes[..line_end]).context("HTTP request line is not UTF-8")?;
    let first_space = request_line
        .find(' ')
        .ok_or_else(|| anyhow!("HTTP method is malformed"))?;
    let target_start = first_space + 1;
    let target_end = request_line[target_start..]
        .find(' ')
        .map(|offset| target_start + offset)
        .ok_or_else(|| anyhow!("HTTP request target is malformed"))?;
    let target = &request_line[target_start..target_end];
    let query_start = target.find('?').unwrap_or(target.len());
    let path = &target[..query_start];
    let prefix = prefix.trim_end_matches('/');
    let remainder = path
        .strip_prefix(prefix)
        .filter(|value| value.is_empty() || value.starts_with('/'))
        .ok_or_else(|| anyhow!("HTTP request path does not match configured prefix"))?;
    let rewritten_path = if remainder.is_empty() { "/" } else { remainder };
    let mut output = Vec::with_capacity(bytes.len());
    output.extend_from_slice(&bytes[..target_start]);
    output.extend_from_slice(rewritten_path.as_bytes());
    output.extend_from_slice(&target.as_bytes()[query_start..]);
    output.extend_from_slice(&bytes[target_end..]);
    Ok(output)
}

pub(crate) fn set_host_header(bytes: Vec<u8>, host: &str) -> anyhow::Result<Vec<u8>> {
    ensure!(
        !host.is_empty() && !host.contains(['\r', '\n']),
        "backend_host must be a non-empty HTTP Host value"
    );
    let header_end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("incomplete HTTP request headers"))?;
    let mut output = Vec::with_capacity(bytes.len() + host.len());
    let mut host_count = 0;
    for (index, line) in bytes[..header_end].split(|byte| *byte == b'\n').enumerate() {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let is_host = index > 0
            && line
                .splitn(2, |byte| *byte == b':')
                .next()
                .is_some_and(|name| name.eq_ignore_ascii_case(b"host"));
        if is_host {
            host_count += 1;
            output.extend_from_slice(b"Host: ");
            output.extend_from_slice(host.as_bytes());
        } else {
            output.extend_from_slice(line);
        }
        output.extend_from_slice(b"\r\n");
    }
    ensure!(
        host_count == 1,
        "HTTP request must contain exactly one Host header"
    );
    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(&bytes[header_end + 4..]);
    Ok(output)
}

/// Apply standard reverse-proxy headers using trusted tunnel metadata.
pub(crate) fn set_proxy_headers(
    bytes: Vec<u8>,
    client_ip: Option<&str>,
    scheme: &str,
) -> anyhow::Result<Vec<u8>> {
    ensure!(
        matches!(scheme, "http" | "https"),
        "forwarded scheme must be http or https"
    );
    let header_end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("incomplete HTTP request headers"))?;
    let mut output = Vec::with_capacity(bytes.len() + 160);
    let mut original_host = None;
    let mut has_accept_encoding = false;

    for (index, line) in bytes[..header_end].split(|byte| *byte == b'\n').enumerate() {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if index == 0 {
            output.extend_from_slice(line);
            output.extend_from_slice(b"\r\n");
            continue;
        }
        let Some(separator) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let name = &line[..separator];
        let value = line[separator + 1..]
            .strip_prefix(b" ")
            .unwrap_or(&line[separator + 1..]);
        if name.eq_ignore_ascii_case(b"host") {
            ensure!(
                original_host.is_none(),
                "HTTP request must contain exactly one Host header"
            );
            original_host = Some(value.to_vec());
        }
        if name.eq_ignore_ascii_case(b"accept-encoding") {
            has_accept_encoding = true;
        }
        if name.eq_ignore_ascii_case(b"x-forwarded-for")
            || name.eq_ignore_ascii_case(b"x-forwarded-proto")
            || name.eq_ignore_ascii_case(b"x-forwarded-host")
        {
            continue;
        }
        output.extend_from_slice(line);
        output.extend_from_slice(b"\r\n");
    }

    let original_host =
        original_host.context("HTTP request must contain exactly one Host header")?;
    if let Some(client_ip) = client_ip.filter(|value| !value.trim().is_empty()) {
        ensure!(
            !client_ip.contains(['\r', '\n']),
            "client IP contains invalid characters"
        );
        output.extend_from_slice(b"X-Forwarded-For: ");
        output.extend_from_slice(client_ip.as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(b"X-Forwarded-Proto: ");
    output.extend_from_slice(scheme.as_bytes());
    output.extend_from_slice(b"\r\nX-Forwarded-Host: ");
    output.extend_from_slice(&original_host);
    output.extend_from_slice(b"\r\n");
    if !has_accept_encoding {
        output.extend_from_slice(b"Accept-Encoding: gzip\r\n");
    }
    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(&bytes[header_end + 4..]);
    Ok(output)
}

fn bearer_token(bytes: &[u8]) -> anyhow::Result<&str> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HTTP_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    ensure!(
        request
            .parse(bytes)
            .context("parse HTTP request")?
            .is_complete(),
        "incomplete HTTP request headers"
    );
    let mut value = None;
    for header in request.headers.iter() {
        if header.name.eq_ignore_ascii_case("authorization") {
            ensure!(
                value.is_none(),
                "multiple Authorization headers are not accepted"
            );
            value = Some(
                std::str::from_utf8(header.value).context("Authorization header is not UTF-8")?,
            );
        }
    }
    let value = value.ok_or_else(|| anyhow!("Authorization header is required"))?;
    let (scheme, token) = value
        .trim()
        .split_once(' ')
        .ok_or_else(|| anyhow!("Authorization header must use Bearer"))?;
    ensure!(
        scheme.eq_ignore_ascii_case("Bearer") && !token.trim().is_empty(),
        "Authorization header must use Bearer"
    );
    Ok(token.trim())
}

fn strip_authorization_header(bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    let header_end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("incomplete HTTP request headers"))?;
    let mut output = Vec::with_capacity(bytes.len());
    for (index, line) in bytes[..header_end].split(|byte| *byte == b'\n').enumerate() {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let is_authorization = index > 0
            && line
                .splitn(2, |byte| *byte == b':')
                .next()
                .is_some_and(|name| name.eq_ignore_ascii_case(b"authorization"));
        if !is_authorization {
            output.extend_from_slice(line);
            output.extend_from_slice(b"\r\n");
        }
    }
    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(&bytes[header_end + 4..]);
    Ok(output)
}

fn claim_strings<'a>(
    claims: &'a Value,
    path: &str,
) -> anyhow::Result<std::collections::HashSet<&'a str>> {
    let mut value = claims;
    for component in path.split('.') {
        ensure!(
            !component.is_empty(),
            "roles_claim contains an empty path component"
        );
        value = value
            .get(component)
            .ok_or_else(|| anyhow!("JWT role claim is missing"))?;
    }
    let mut values = std::collections::HashSet::new();
    match value {
        Value::String(role) => {
            values.insert(role.as_str());
        }
        Value::Array(roles) => {
            for role in roles {
                values.insert(
                    role.as_str()
                        .ok_or_else(|| anyhow!("JWT role claim array must contain strings"))?,
                );
            }
        }
        _ => bail!("JWT role claim must be a string or string array"),
    }
    Ok(values)
}

async fn write_denial<S>(stream: &mut S, denial: &Denial) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let response = match denial {
        Denial::Unauthorized(_) => b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"lfp-pipe\"\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: 25\r\n\r\n{\"error\":\"unauthorized\"}\n".as_slice(),
        Denial::Forbidden(_) => b"HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: 22\r\n\r\n{\"error\":\"forbidden\"}\n".as_slice(),
    };
    stream
        .write_all(response)
        .await
        .context("write authorization denial")?;
    stream
        .shutdown()
        .await
        .context("close unauthorized connection")
}

#[cfg(test)]
mod tests {
    use super::{
        bearer_token, claim_strings, request_path, set_host_header, set_proxy_headers,
        strip_authorization_header, strip_request_path_prefix,
    };
    use serde_json::json;

    #[test]
    fn parses_bearer_header_case_insensitively() {
        let request = b"POST /api/jobs HTTP/1.1\r\nHost: service.example\r\nauthorization: bearer abc.def.ghi\r\n\r\n";
        assert_eq!(bearer_token(request).expect("bearer"), "abc.def.ghi");
    }

    #[test]
    fn reads_nested_string_role_claims() {
        let claims = json!({"realm_access": {"roles": ["service-user", "admin"]}});
        let roles = claim_strings(&claims, "realm_access.roles").expect("roles");
        assert!(roles.contains("service-user"));
    }

    #[test]
    fn rewrites_host_header_and_preserves_body() {
        let request =
            b"POST /api/generate HTTP/1.1\r\nhost: public.example\r\nContent-Length: 2\r\n\r\n{}"
                .to_vec();
        let rewritten = set_host_header(request, "127.0.0.1:11434").expect("host rewrite");
        assert_eq!(
            rewritten,
            b"POST /api/generate HTTP/1.1\r\nHost: 127.0.0.1:11434\r\nContent-Length: 2\r\n\r\n{}"
        );
    }

    #[test]
    fn removes_bearer_token_before_forwarding() {
        let request = b"POST /api/jobs HTTP/1.1\r\nHost: service.example\r\nAuthorization: Bearer secret\r\nContent-Length: 2\r\n\r\n{}";
        let stripped = strip_authorization_header(request).expect("stripped request");
        assert!(
            !stripped
                .windows(b"secret".len())
                .any(|value| value == b"secret")
        );
        assert!(stripped.ends_with(b"\r\n\r\n{}"));
    }

    #[test]
    fn strips_routing_prefix_and_preserves_query_and_body() {
        let request = b"POST /gateway/api/jobs?stream=false HTTP/1.1\r\nHost: service.example\r\nContent-Length: 2\r\n\r\n{}".to_vec();
        assert_eq!(request_path(&request).expect("path"), "/gateway/api/jobs");
        let rewritten = strip_request_path_prefix(request, "/gateway").expect("rewritten");
        assert!(rewritten.starts_with(b"POST /api/jobs?stream=false HTTP/1.1\r\n"));
        assert!(rewritten.ends_with(b"\r\n\r\n{}"));
    }

    #[test]
    fn proxy_headers_replace_spoofed_values_and_preserve_public_host() {
        let request = b"POST /xyz/api?stream=false HTTP/1.1\r\nHost: public.example:443\r\nX-Forwarded-For: 203.0.113.99\r\nX-Forwarded-Proto: ftp\r\nX-Forwarded-Host: attacker.example\r\nContent-Length: 2\r\n\r\n{}".to_vec();
        let rewritten =
            set_proxy_headers(request, Some("198.51.100.24"), "https").expect("proxy headers");
        let text = String::from_utf8(rewritten).expect("UTF-8 request");
        assert!(text.starts_with("POST /xyz/api?stream=false HTTP/1.1\r\n"));
        assert!(text.contains("Host: public.example:443\r\n"));
        assert!(text.contains("X-Forwarded-For: 198.51.100.24\r\n"));
        assert!(text.contains("X-Forwarded-Proto: https\r\n"));
        assert!(text.contains("X-Forwarded-Host: public.example:443\r\n"));
        assert!(text.contains("Accept-Encoding: gzip\r\n"));
        assert!(!text.contains("attacker.example"));
        assert!(!text.contains("203.0.113.99"));
        assert!(text.ends_with("\r\n\r\n{}"));
    }

    #[test]
    fn proxy_headers_preserve_existing_accept_encoding() {
        let request =
            b"GET / HTTP/1.1\r\nHost: public.example\r\nAccept-Encoding: br\r\n\r\n".to_vec();
        let rewritten = set_proxy_headers(request, None, "http").expect("proxy headers");
        let text = String::from_utf8(rewritten).expect("UTF-8 request");
        assert_eq!(text.matches("Accept-Encoding:").count(), 1);
        assert!(text.contains("Accept-Encoding: br\r\n"));
    }

    #[test]
    fn host_override_keeps_original_host_in_forwarding_header() {
        let request = b"GET / HTTP/1.1\r\nHost: public.example\r\n\r\n".to_vec();
        let forwarded =
            set_proxy_headers(request, Some("198.51.100.24"), "https").expect("proxy headers");
        let rewritten = set_host_header(forwarded, "127.0.0.1:8080").expect("host override");
        let text = String::from_utf8(rewritten).expect("UTF-8 request");
        assert!(text.contains("Host: 127.0.0.1:8080\r\n"));
        assert!(text.contains("X-Forwarded-Host: public.example\r\n"));
    }
}
