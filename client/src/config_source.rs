//! Local and centrally managed client configuration sources.

use std::{sync::Arc, time::Duration};

use anyhow::Context;
use eventsource_stream::Eventsource;
use futures::StreamExt;
use reqwest::Client;
use serde::Deserialize;
use shared::config::{CentralClientBootstrap, ClientConfig, parse_client_config_document};
use tokio::{
    sync::mpsc,
    time::{MissedTickBehavior, interval, sleep},
};

const INITIAL_RETRY_DELAY: Duration = Duration::from_secs(1);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);
const CONFIG_POLL_INTERVAL: Duration = Duration::from_secs(30);
const APPLIED_CONFIG_HEADER: &str = "X-LFP-Pipe-Config-Revision";

#[derive(Debug, Deserialize)]
struct CentralResponse {
    config_toml: String,
    #[serde(default)]
    config_revision: Option<String>,
    username: String,
}

struct CentralSnapshot {
    configs: Vec<ClientConfig>,
    revision: String,
}

#[derive(Debug, Deserialize)]
struct CentralSettings {
    token_url: String,
    provider_client_id: String,
    scopes: Vec<String>,
}

fn device_headers(
    request: reqwest::RequestBuilder,
    applied_revision: Option<&str>,
) -> reqwest::RequestBuilder {
    let request = request
        .header(
            "X-LFP-Pipe-Device",
            std::env::var("COMPUTERNAME")
                .or_else(|_| std::env::var("HOSTNAME"))
                .unwrap_or_else(|_| "lfp-pipe-client".into()),
        )
        .header("X-LFP-Pipe-Version", env!("CARGO_PKG_VERSION"))
        .header("X-LFP-Pipe-Platform", std::env::consts::OS);
    match applied_revision {
        Some(revision) => request.header(APPLIED_CONFIG_HEADER, revision),
        None => request,
    }
}

async fn central_access(
    bootstrap: &CentralClientBootstrap,
) -> anyhow::Result<(Client, CentralSettings, String)> {
    // Central configuration authenticates before route startup, so Rustls must
    // have the same process-wide provider that run_all installs for NATS/TLS.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let username = bootstrap
        .username
        .as_deref()
        .context("central config requires username or LFP_PIPE_OAUTH_USERNAME")?;
    let secret_file = bootstrap.client_secret_file.as_deref().context(
        "central config requires client_secret_file or LFP_PIPE_OAUTH_CLIENT_SECRET_FILE",
    )?;
    let http = Client::new();
    let base_url = bootstrap.control_plane_url.trim_end_matches('/');
    let settings = http
        .get(format!("{base_url}/api/client-settings"))
        .send()
        .await?
        .error_for_status()?
        .json::<CentralSettings>()
        .await?;
    let token = crate::oauth::obtain_access_token(
        &settings.token_url,
        &settings.provider_client_id,
        username,
        secret_file,
        &settings.scopes,
    )
    .await?;
    Ok((http, settings, token))
}

/// Fetch, validate, and hydrate the configuration assigned to this machine.
pub async fn fetch_central(
    bootstrap: &CentralClientBootstrap,
) -> anyhow::Result<Vec<ClientConfig>> {
    Ok(fetch_central_snapshot(bootstrap, None).await?.configs)
}

async fn fetch_central_snapshot(
    bootstrap: &CentralClientBootstrap,
    applied_revision: Option<&str>,
) -> anyhow::Result<CentralSnapshot> {
    let secret_file = bootstrap.client_secret_file.as_deref().context(
        "central config requires client_secret_file or LFP_PIPE_OAUTH_CLIENT_SECRET_FILE",
    )?;
    let base_url = bootstrap.control_plane_url.trim_end_matches('/');
    let (http, settings, access_token) = central_access(bootstrap)
        .await
        .context("authenticate central client")?;
    let response = device_headers(
        http.get(format!("{base_url}/api/client-config")),
        applied_revision,
    )
    .bearer_auth(access_token)
    .send()
    .await
    .context("fetch central client configuration")?
    .error_for_status()
    .context("central client configuration was rejected")?
    .json::<CentralResponse>()
    .await
    .context("decode central client configuration")?;
    let mut configs = parse_client_config_document(&response.config_toml)?;
    for config in &mut configs {
        let oauth = config
            .oauth
            .as_mut()
            .context("every centrally managed route requires OAuth")?;
        oauth.username.clone_from(&response.username);
        oauth.client_secret_file = secret_file.to_string();
        oauth.token_url.clone_from(&settings.token_url);
        oauth
            .provider_client_id
            .clone_from(&settings.provider_client_id);
        oauth
            .control_plane_url
            .clone_from(&bootstrap.control_plane_url);
        oauth.scopes.clone_from(&settings.scopes);
    }
    Ok(CentralSnapshot {
        configs,
        // Older control planes do not return a revision. The sentinel keeps
        // mixed-version rollouts running until the upgraded server is visible.
        revision: response
            .config_revision
            .unwrap_or_else(|| "unreported".to_string()),
    })
}

async fn push_updates(
    bootstrap: CentralClientBootstrap,
    applied_revision: String,
    updates: mpsc::Sender<()>,
) {
    loop {
        let result: anyhow::Result<()> = async {
            let (http, _, token) = central_access(&bootstrap).await?;
            let response = device_headers(
                http.get(format!(
                    "{}/api/client-events",
                    bootstrap.control_plane_url.trim_end_matches('/')
                )),
                Some(&applied_revision),
            )
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
            let mut stream = response.bytes_stream().eventsource();
            while let Some(event) = stream.next().await {
                if event?.event == "config" {
                    let _ = updates.send(()).await;
                }
            }
            Ok(())
        }
        .await;
        if let Err(error) = result {
            tracing::warn!(
                ?error,
                "central config push stream disconnected; reconnecting"
            );
        }
        sleep(Duration::from_secs(3)).await;
    }
}

async fn poll_updates(updates: mpsc::Sender<()>) {
    let mut poll = interval(CONFIG_POLL_INTERVAL);
    poll.set_missed_tick_behavior(MissedTickBehavior::Skip);
    poll.tick().await;
    loop {
        poll.tick().await;
        if updates.send(()).await.is_err() {
            return;
        }
    }
}

/// Run centrally managed routes and replace them when the assigned document changes.
pub async fn run_central(bootstrap: CentralClientBootstrap) -> anyhow::Result<()> {
    run_central_with_reporter(bootstrap, None).await
}

/// Run centrally managed routes while reporting rejected updates to a desktop UI.
pub async fn run_central_with_reporter(
    bootstrap: CentralClientBootstrap,
    reporter: Option<Arc<dyn Fn(Option<String>) + Send + Sync>>,
) -> anyhow::Result<()> {
    let mut retry_delay = INITIAL_RETRY_DELAY;
    let mut applied_revision: Option<String> = None;
    loop {
        let snapshot = match fetch_central_snapshot(&bootstrap, applied_revision.as_deref()).await {
            Ok(snapshot) => snapshot,
            Err(error) => {
                tracing::warn!(
                    ?error,
                    ?retry_delay,
                    "central client is not ready; retrying"
                );
                if let Some(reporter) = &reporter {
                    reporter(Some("Reconnecting…".into()));
                }
                sleep(retry_delay).await;
                retry_delay = next_retry_delay(retry_delay);
                continue;
            }
        };
        let fingerprint =
            match serde_json::to_vec(&snapshot.configs).context("fingerprint central config") {
                Ok(fingerprint) => fingerprint,
                Err(error) => {
                    tracing::warn!(
                        ?error,
                        ?retry_delay,
                        "central configuration is not ready; retrying"
                    );
                    if let Some(reporter) = &reporter {
                        reporter(Some("Configuration unavailable · retrying".into()));
                    }
                    sleep(retry_delay).await;
                    retry_delay = next_retry_delay(retry_delay);
                    continue;
                }
            };
        let active_status = applied_config_status(&snapshot.configs);
        applied_revision = Some(snapshot.revision.clone());
        if let Some(reporter) = &reporter {
            reporter(Some(active_status.clone()));
        }
        let (update_sender, mut update_receiver) = mpsc::channel(4);
        let push_task = tokio::spawn(push_updates(
            bootstrap.clone(),
            snapshot.revision.clone(),
            update_sender.clone(),
        ));
        let poll_task = tokio::spawn(poll_updates(update_sender));
        let runtime = crate::run_all(snapshot.configs);
        tokio::pin!(runtime);
        let mut replace_routes = false;
        loop {
            tokio::select! {
                result = &mut runtime => {
                    match result {
                        Ok(()) => tracing::warn!(?retry_delay, "tunnel runtime stopped; reconnecting"),
                        Err(error) => tracing::warn!(?error, ?retry_delay, "tunnel connection stopped; reconnecting"),
                    }
                    if let Some(reporter) = &reporter {
                        reporter(Some("Reconnecting…".into()));
                    }
                    break;
                },
                _ = update_receiver.recv() => {
                    match fetch_central_snapshot(&bootstrap, applied_revision.as_deref()).await {
                        Ok(next) if next.revision != snapshot.revision
                            || serde_json::to_vec(&next.configs).context("fingerprint central config")? != fingerprint => {
                            if let Some(reporter) = &reporter {
                                reporter(Some("Applying configuration…".into()));
                            }
                            replace_routes = true;
                            break
                        },
                        Ok(_) => {}
                        Err(error) => {
                            tracing::warn!(?error, "central config refresh rejected; retaining active routes");
                            if let Some(reporter) = &reporter {
                                reporter(Some(format!("Configuration warning · {active_status}")));
                            }
                        },
                    }
                }
            }
        }
        push_task.abort();
        poll_task.abort();
        if replace_routes {
            retry_delay = INITIAL_RETRY_DELAY;
            tracing::info!("central configuration changed; replacing active routes");
        } else {
            sleep(retry_delay).await;
            retry_delay = next_retry_delay(retry_delay);
        }
    }
}

fn applied_config_status(configs: &[ClientConfig]) -> String {
    let route_count = configs.len();
    if route_count == 0 {
        "Connected".to_string()
    } else if route_count == 1 {
        "Connected - 1 Route".to_string()
    } else {
        format!("Connected - {route_count} Routes")
    }
}

fn next_retry_delay(current: Duration) -> Duration {
    current.saturating_mul(2).min(MAX_RETRY_DELAY)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_delay_is_capped() {
        assert_eq!(
            next_retry_delay(Duration::from_secs(1)),
            Duration::from_secs(2)
        );
        assert_eq!(next_retry_delay(Duration::from_secs(20)), MAX_RETRY_DELAY);
        assert_eq!(next_retry_delay(MAX_RETRY_DELAY), MAX_RETRY_DELAY);
    }

    #[test]
    fn applied_status_reports_the_route_count() {
        let config = parse_client_config_document(
            r#"
client_id = "sports"
nats_url = "nats://localhost:4222"

[[backend_rules]]
pattern = "sports.example.com"
backend_addr = "127.0.0.1:6565"
"#,
        )
        .expect("config");
        assert_eq!(applied_config_status(&config), "Connected - 1 Route");
        assert_eq!(
            applied_config_status(&[config[0].clone(), config[0].clone()]),
            "Connected - 2 Routes"
        );
        assert_eq!(applied_config_status(&[]), "Connected");
    }
}
