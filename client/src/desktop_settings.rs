//! Desktop-first settings, enrollment, and operating-system integration.

use std::{fs, path::PathBuf, time::Duration};

use anyhow::{Context, ensure};
use auto_launcher::{AutoLaunch, AutoLaunchBuilder, WindowsEnableMode};
use serde::{Deserialize, Serialize};
use shared::config::CentralClientBootstrap;
use uuid::Uuid;

/// Default management origin used by first-run desktop clients.
pub const DEFAULT_CONTROL_PLANE: &str = "https://manage-pipe.lfpconnect.io";

/// Persisted preferences and enrollment identity for the desktop experience.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesktopSettings {
    /// Whether configuration is synchronized from the management server.
    #[serde(default = "default_true")]
    pub remote_managed: bool,
    /// Management origin used for enrollment and configuration.
    #[serde(default = "default_control_plane")]
    pub control_plane_url: String,
    /// Authentik service-account username assigned during enrollment.
    #[serde(default)]
    pub username: Option<String>,
    /// Stable anonymous device identifier used only during enrollment.
    #[serde(default)]
    pub device_id: String,
}

fn default_true() -> bool {
    true
}
fn default_control_plane() -> String {
    DEFAULT_CONTROL_PLANE.into()
}

impl Default for DesktopSettings {
    fn default() -> Self {
        Self {
            remote_managed: true,
            control_plane_url: default_control_plane(),
            username: None,
            device_id: Uuid::new_v4().to_string(),
        }
    }
}

/// Return the operating-system user configuration directory for lfp-pipe.
pub fn settings_dir() -> anyhow::Result<PathBuf> {
    dirs::config_dir()
        .context("locate user config directory")
        .map(|path| path.join("lfp-pipe"))
}

/// Load desktop preferences or create user-friendly remote-managed defaults.
pub fn load_or_create() -> anyhow::Result<DesktopSettings> {
    let path = settings_dir()?.join("desktop.json");
    if path.exists() {
        return serde_json::from_slice(&fs::read(&path)?).context("parse desktop settings");
    }
    let settings = DesktopSettings::default();
    save(&settings)?;
    // A desktop install is intended to behave like a background connectivity
    // agent; users can immediately opt out through the tray checkbox.
    if let Ok(auto) = auto_launch() {
        let _ = auto.enable();
    }
    Ok(settings)
}

/// Persist desktop preferences without placing them in a project directory.
pub fn save(settings: &DesktopSettings) -> anyhow::Result<()> {
    let directory = settings_dir()?;
    fs::create_dir_all(&directory)?;
    fs::write(
        directory.join("desktop.json"),
        serde_json::to_vec_pretty(settings)?,
    )
    .context("save desktop settings")
}

/// Return the private service-account secret path for this OS user.
pub fn secret_path() -> anyhow::Result<PathBuf> {
    Ok(settings_dir()?.join("client-secret"))
}

/// Convert enrolled desktop settings into the shared central bootstrap shape.
pub fn central_bootstrap(settings: &DesktopSettings) -> Option<CentralClientBootstrap> {
    (settings.remote_managed
        && settings.username.is_some()
        && secret_path().is_ok_and(|path| path.exists()))
    .then(|| CentralClientBootstrap {
        control_plane_url: settings.control_plane_url.clone(),
        control_plane_config: true,
        username: settings.username.clone(),
        client_secret_file: secret_path()
            .ok()
            .map(|path| path.to_string_lossy().into_owned()),
    })
}

#[derive(Serialize)]
struct EnrollmentRequest<'a> {
    device_id: &'a str,
    name: String,
    platform: &'static str,
    version: &'static str,
}
#[derive(Deserialize)]
struct EnrollmentCreated {
    code: String,
    poll_token: String,
    claim_url: String,
}
#[derive(Deserialize)]
struct EnrollmentStatus {
    status: String,
    username: Option<String>,
    client_secret: Option<String>,
}

/// Enroll a desktop through a short-lived browser approval and store credentials.
pub async fn enroll(settings: &mut DesktopSettings) -> anyhow::Result<()> {
    let http = reqwest::Client::new();
    let created = http
        .post(format!(
            "{}/api/enrollments",
            settings.control_plane_url.trim_end_matches('/')
        ))
        .json(&EnrollmentRequest {
            device_id: &settings.device_id,
            name: std::env::var("COMPUTERNAME")
                .or_else(|_| std::env::var("HOSTNAME"))
                .unwrap_or_else(|_| "managed-client".into()),
            platform: std::env::consts::OS,
            version: env!("CARGO_PKG_VERSION"),
        })
        .send()
        .await?
        .error_for_status()?
        .json::<EnrollmentCreated>()
        .await?;
    open::that_detached(&created.claim_url).context("open enrollment page")?;
    for _ in 0..120 {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let response = http
            .get(format!(
                "{}/api/enrollments/{}",
                settings.control_plane_url.trim_end_matches('/'),
                created.code
            ))
            .bearer_auth(&created.poll_token)
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::ACCEPTED {
            continue;
        }
        let status = response
            .error_for_status()?
            .json::<EnrollmentStatus>()
            .await?;
        if status.status == "claimed" {
            let username = status.username.context("enrollment omitted username")?;
            let secret = status.client_secret.context("enrollment omitted secret")?;
            ensure!(!secret.is_empty(), "enrollment returned empty secret");
            let path = secret_path()?;
            fs::create_dir_all(path.parent().context("secret directory")?)?;
            fs::write(path, secret)?;
            settings.username = Some(username);
            save(settings)?;
            return Ok(());
        }
    }
    anyhow::bail!("enrollment expired before it was approved")
}

/// Construct the native per-user start-at-boot integration.
pub fn auto_launch() -> anyhow::Result<AutoLaunch> {
    let executable = std::env::current_exe()?;
    let mut builder = AutoLaunchBuilder::new();
    builder
        .set_app_name("LFP Connect Pipe")
        .set_app_path(&executable.to_string_lossy())
        .set_windows_enable_mode(WindowsEnableMode::CurrentUser);
    builder.build().map_err(Into::into)
}
