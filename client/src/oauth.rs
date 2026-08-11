//! Authentik service-account exchange for renewable route-scoped NATS tickets.

use std::fs;

use anyhow::{Context, anyhow, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use shared::config::ClientOAuthConfig;

#[derive(Debug, Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
}

#[derive(Debug, Serialize)]
struct TicketRequest<'a> {
    hostname: &'a str,
    client_name: &'a str,
}

/// A short-lived NATS connection configuration returned by the control plane.
#[derive(Debug, Deserialize)]
pub struct OAuthTicket {
    /// NATS bearer ticket.
    pub token: String,
    /// Unix expiry used to schedule renewal.
    pub expires_unix: i64,
    /// Normalized client ID embedded in the ticket.
    pub client_id: String,
    /// Exact route request subject.
    pub request_subject: String,
    /// Public NATS endpoints in preference order.
    pub nats_urls: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct TicketResponse {
    token: String,
    #[serde(default)]
    expires_unix: Option<i64>,
    client_id: String,
    request_subject: String,
    nats_urls: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct JwtClaims {
    exp: i64,
}

/// Exchange a service-account app password for an OIDC token and then a NATS ticket.
pub async fn obtain_ticket(
    config: &ClientOAuthConfig,
    client_name: &str,
) -> anyhow::Result<OAuthTicket> {
    let secret = fs::read_to_string(&config.client_secret_file).with_context(|| {
        format!(
            "failed to read OAuth client secret file {}",
            config.client_secret_file
        )
    })?;
    ensure!(
        !secret.trim().is_empty(),
        "OAuth client secret file is empty"
    );
    let http = Client::builder()
        .build()
        .context("construct OAuth HTTP client")?;
    let scope = config.scopes.join(" ");
    let token_response = http
        .post(&config.token_url)
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", config.provider_client_id.as_str()),
            ("username", config.username.as_str()),
            ("password", secret.trim()),
            ("scope", scope.as_str()),
        ])
        .send()
        .await
        .context("request Authentik OAuth token")?;
    if !token_response.status().is_success() {
        return Err(anyhow!(
            "Authentik OAuth token request returned {}",
            token_response.status()
        ));
    }
    let access: OAuthTokenResponse = token_response
        .json()
        .await
        .context("decode Authentik OAuth token response")?;

    let ticket_response = http
        .post(format!(
            "{}/api/tunnel-tokens",
            config.control_plane_url.trim_end_matches('/')
        ))
        .bearer_auth(access.access_token)
        .json(&TicketRequest {
            hostname: &config.hostname,
            client_name,
        })
        .send()
        .await
        .context("request route-scoped tunnel ticket")?;
    if !ticket_response.status().is_success() {
        return Err(anyhow!(
            "LFP Pipe ticket request returned {}",
            ticket_response.status()
        ));
    }
    let response: TicketResponse = ticket_response
        .json()
        .await
        .context("decode LFP Pipe ticket response")?;
    let expires_unix = match response.expires_unix {
        Some(expiry) => expiry,
        None => jwt_expiry(&response.token)?,
    };
    let ticket = OAuthTicket {
        token: response.token,
        expires_unix,
        client_id: response.client_id,
        request_subject: response.request_subject,
        nats_urls: response.nats_urls,
    };
    ensure!(
        !ticket.token.is_empty(),
        "LFP Pipe returned an empty ticket"
    );
    ensure!(
        !ticket.nats_urls.is_empty(),
        "LFP Pipe returned no NATS endpoints"
    );
    Ok(ticket)
}

fn jwt_expiry(token: &str) -> anyhow::Result<i64> {
    let payload = token
        .split('.')
        .nth(1)
        .context("LFP Pipe ticket is not a JWT")?;
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .context("decode LFP Pipe ticket JWT payload")?;
    let claims: JwtClaims =
        serde_json::from_slice(&decoded).context("decode LFP Pipe ticket JWT claims")?;
    Ok(claims.exp)
}
