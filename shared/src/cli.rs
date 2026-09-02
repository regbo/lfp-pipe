//! Command-line and environment configuration for both binaries.
//!
//! Clap resolves a value supplied by a command-line flag before the matching
//! environment variable. Optional values are then layered over the TOML file,
//! giving the project one explicit precedence order:
//!
//! `CLI flag > environment variable > environment variable file > TOML file > typed default`.

use std::{
    env,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
};

use anyhow::Context;
use clap::{Args, Parser};

use crate::{
    config::{
        CentralClientBootstrap, ClientConfig, ClientOverrides, RelayMode, ServerConfig,
        ServerOverrides, load_central_client_bootstrap, load_client_configs, load_server_config,
    },
    logging::DEFAULT_LOG_FILTER,
};

const FILE_BACKED_ENVIRONMENT: &[&str] = &[
    "LFP_PIPE_CONFIG",
    "RUST_LOG",
    "LFP_PIPE_PUBLIC_LISTEN",
    "LFP_PIPE_DATA_LISTEN",
    "LFP_PIPE_ADVERTISED_DATA_ADDR",
    "LFP_PIPE_NATS_URL",
    "LFP_PIPE_NATS_TOKEN_FILE",
    "LFP_PIPE_RELAY_MODE",
    "LFP_PIPE_REQUEST_SUBJECT",
    "LFP_PIPE_DOMAIN_SUBJECT_ROUTING",
    "LFP_PIPE_CLAIM_TIMEOUT_MS",
    "LFP_PIPE_PENDING_TIMEOUT_MS",
    "LFP_PIPE_CLIENT_ID",
    "LFP_PIPE_CLAIM_ACK_TIMEOUT_MS",
    "LFP_PIPE_TRAY",
    "LFP_PIPE_OAUTH_USERNAME",
    "LFP_PIPE_OAUTH_CLIENT_SECRET_FILE",
];

fn load_file_backed_value(
    name: &str,
    direct: Option<OsString>,
    file_path: Option<OsString>,
) -> anyhow::Result<Option<OsString>> {
    if direct.is_some() {
        return Ok(direct);
    }
    let Some(file_path) = file_path else {
        return Ok(None);
    };
    let path = Path::new(&file_path);
    let value = fs::read_to_string(path)
        .with_context(|| format!("read {name}_FILE from {}", path.display()))?;
    Ok(Some(OsString::from(value.trim_end_matches(['\r', '\n']))))
}

fn hydrate_file_backed_environment() -> anyhow::Result<()> {
    for name in FILE_BACKED_ENVIRONMENT {
        let file_name = format!("{name}_FILE");
        if let Some(value) =
            load_file_backed_value(name, env::var_os(name), env::var_os(&file_name))?
        {
            // Runtime parsing happens in main before any worker threads start,
            // so no other thread can concurrently read or mutate the process environment.
            unsafe { env::set_var(name, value) };
        }
    }
    Ok(())
}

/// Configuration and logging values needed to launch a component.
#[derive(Debug)]
pub struct RuntimeConfig<T> {
    /// Fully layered component configuration.
    pub config: T,
    /// Tracing filter selected by `--log-filter`, `RUST_LOG`, or its default.
    pub log_filter: String,
}

/// Controls whether the client creates a desktop system-tray interface.
#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
pub enum DesktopMode {
    /// Enable the tray only when the process appears to have a desktop session.
    #[default]
    Auto,
    /// Require the tray interface and fail if it cannot be initialized.
    Always,
    /// Run as a purely headless process.
    Never,
}

/// Configuration and source metadata needed to launch the tunnel client.
#[derive(Debug)]
pub struct ClientRuntimeConfig {
    /// Fully layered route configurations.
    pub config: Vec<ClientConfig>,
    /// Tracing filter selected by CLI, environment, or default.
    pub log_filter: String,
    /// TOML path exposed through the desktop tray's Open Config action.
    pub config_path: PathBuf,
    /// Requested desktop integration mode.
    pub desktop_mode: DesktopMode,
    /// Optional centrally managed bootstrap settings.
    pub central: Option<CentralClientBootstrap>,
}

#[derive(Debug, Args)]
struct CommonOptions {
    /// Path to the component's TOML configuration file.
    #[arg(long, env = "LFP_PIPE_CONFIG", value_name = "PATH")]
    config: Option<PathBuf>,

    /// Tracing directives, for example `info,server=debug`.
    #[arg(
        long,
        env = "RUST_LOG",
        value_name = "DIRECTIVES",
        default_value = DEFAULT_LOG_FILTER
    )]
    log_filter: String,
}

/// CLI accepted by `lfp-pipe-server`.
#[derive(Debug, Parser)]
#[command(
    name = "lfp-pipe-server",
    version,
    about = "Expose private TCP services through a public lfp-pipe ingress"
)]
struct ServerCli {
    #[command(flatten)]
    common: CommonOptions,

    /// Override the public ingress listen address.
    #[arg(long, env = "LFP_PIPE_PUBLIC_LISTEN", value_name = "ADDR")]
    public_listen: Option<String>,

    /// Override the callback/data listen address.
    #[arg(long, env = "LFP_PIPE_DATA_LISTEN", value_name = "ADDR")]
    data_listen: Option<String>,

    /// Address advertised to clients; an empty value uses `data-listen`.
    #[arg(long, env = "LFP_PIPE_ADVERTISED_DATA_ADDR", value_name = "ADDR")]
    advertised_data_addr: Option<String>,

    /// Override the NATS control-plane URL.
    #[arg(long, env = "LFP_PIPE_NATS_URL", value_name = "URL")]
    nats_url: Option<String>,

    /// File containing a NATS bearer token.
    #[arg(long, env = "LFP_PIPE_NATS_TOKEN_FILE", value_name = "PATH")]
    nats_token_file: Option<String>,

    /// Select automatic, splice, or buffered stream forwarding.
    #[arg(long, env = "LFP_PIPE_RELAY_MODE", value_enum)]
    relay_mode: Option<RelayMode>,

    /// Override the NATS connection-request subject.
    #[arg(long, env = "LFP_PIPE_REQUEST_SUBJECT", value_name = "SUBJECT")]
    request_subject: Option<String>,

    /// Publish requests on subjects suffixed with reversed hostname labels.
    #[arg(long, env = "LFP_PIPE_DOMAIN_SUBJECT_ROUTING", value_name = "BOOL")]
    domain_subject_routing: Option<bool>,

    /// Milliseconds to wait for the first matching client claim.
    #[arg(long, env = "LFP_PIPE_CLAIM_TIMEOUT_MS", value_name = "MS")]
    claim_timeout_ms: Option<u64>,

    /// Milliseconds to retain an ingress while awaiting its callback socket.
    #[arg(long, env = "LFP_PIPE_PENDING_TIMEOUT_MS", value_name = "MS")]
    pending_timeout_ms: Option<u64>,
}

impl ServerCli {
    fn load(self) -> anyhow::Result<RuntimeConfig<ServerConfig>> {
        let config_path = self
            .common
            .config
            .context("server requires --config or LFP_PIPE_CONFIG")?;
        let config = load_server_config(&config_path)?.with_overrides(ServerOverrides {
            public_listen: self.public_listen,
            data_listen: self.data_listen,
            advertised_data_addr: self.advertised_data_addr,
            nats_url: self.nats_url,
            nats_token_file: self.nats_token_file,
            relay_mode: self.relay_mode,
            request_subject: self.request_subject,
            domain_subject_routing: self.domain_subject_routing,
            claim_timeout_ms: self.claim_timeout_ms,
            pending_timeout_ms: self.pending_timeout_ms,
        });
        Ok(RuntimeConfig {
            config,
            log_filter: self.common.log_filter,
        })
    }
}

/// CLI accepted by `lfp-pipe-client`.
#[derive(Debug, Parser)]
#[command(
    name = "lfp-pipe-client",
    version,
    about = "Connect private TCP backends to an lfp-pipe public server"
)]
struct ClientCli {
    #[command(flatten)]
    common: CommonOptions,

    /// Override the stable identifier used when claiming tunnel requests.
    #[arg(long, env = "LFP_PIPE_CLIENT_ID", value_name = "ID")]
    client_id: Option<String>,

    /// Override the NATS control-plane URL.
    #[arg(long, env = "LFP_PIPE_NATS_URL", value_name = "URL")]
    nats_url: Option<String>,

    /// File containing a NATS bearer token.
    #[arg(long, env = "LFP_PIPE_NATS_TOKEN_FILE", value_name = "PATH")]
    nats_token_file: Option<String>,

    /// Select automatic, splice, or buffered stream forwarding.
    #[arg(long, env = "LFP_PIPE_RELAY_MODE", value_enum)]
    relay_mode: Option<RelayMode>,

    /// Override the NATS connection-request subject.
    #[arg(long, env = "LFP_PIPE_REQUEST_SUBJECT", value_name = "SUBJECT")]
    request_subject: Option<String>,

    /// Milliseconds to wait for the server's claim decision.
    #[arg(long, env = "LFP_PIPE_CLAIM_ACK_TIMEOUT_MS", value_name = "MS")]
    claim_ack_timeout_ms: Option<u64>,

    /// Show a system-tray interface when a desktop session is available.
    #[arg(
        long,
        env = "LFP_PIPE_TRAY",
        value_enum,
        default_value_t = DesktopMode::Auto
    )]
    tray: DesktopMode,

    /// Authentik service-account username for central configuration.
    #[arg(long, env = "LFP_PIPE_OAUTH_USERNAME", value_name = "USERNAME")]
    oauth_username: Option<String>,

    /// Secret file for central configuration authentication.
    #[arg(long, env = "LFP_PIPE_OAUTH_CLIENT_SECRET_FILE", value_name = "PATH")]
    oauth_client_secret_file: Option<String>,
}

impl ClientCli {
    fn load(self) -> anyhow::Result<ClientRuntimeConfig> {
        let config_path = self
            .common
            .config
            .unwrap_or_else(|| PathBuf::from("client.toml"));
        let overrides = ClientOverrides {
            client_id: self.client_id,
            nats_url: self.nats_url,
            nats_token_file: self.nats_token_file,
            relay_mode: self.relay_mode,
            request_subject: self.request_subject,
            claim_ack_timeout_ms: self.claim_ack_timeout_ms,
        };
        let mut central = if config_path.exists() {
            load_central_client_bootstrap(&config_path)?
        } else {
            None
        };
        if let Some(bootstrap) = &mut central {
            bootstrap.username = self.oauth_username.or_else(|| bootstrap.username.clone());
            bootstrap.client_secret_file = self
                .oauth_client_secret_file
                .or_else(|| bootstrap.client_secret_file.clone());
        }
        let loaded = if central.is_some() {
            Vec::new()
        } else {
            if config_path.exists() {
                load_client_configs(&config_path)?
            } else {
                Vec::new()
            }
        };
        anyhow::ensure!(
            loaded.len() == 1 || overrides.client_id.is_none(),
            "--client-id/LFP_PIPE_CLIENT_ID cannot override a multi-route config"
        );
        let config = loaded
            .into_iter()
            .map(|config| config.with_overrides(overrides.clone()))
            .collect();
        Ok(ClientRuntimeConfig {
            config,
            log_filter: self.common.log_filter,
            config_path,
            desktop_mode: self.tray,
            central,
        })
    }
}

/// Parse and layer server configuration from CLI flags, environment, and TOML.
pub fn parse_server_runtime() -> anyhow::Result<RuntimeConfig<ServerConfig>> {
    hydrate_file_backed_environment()?;
    ServerCli::parse().load()
}

/// Parse and layer client configuration from CLI flags, environment, and TOML.
pub fn parse_client_runtime() -> anyhow::Result<ClientRuntimeConfig> {
    hydrate_file_backed_environment()?;
    ClientCli::parse().load()
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::{OsStr, OsString},
        fs,
    };

    use clap::CommandFactory;

    use super::{ClientCli, ServerCli, load_file_backed_value};

    #[test]
    fn server_help_exposes_flags_and_environment_variables() {
        let command = ServerCli::command();
        let config = command
            .get_arguments()
            .find(|argument| argument.get_id() == "config")
            .expect("config argument");
        assert_eq!(config.get_env(), Some(OsStr::new("LFP_PIPE_CONFIG")));

        let help = ServerCli::command().render_long_help().to_string();
        assert!(help.contains("--public-listen"));
        assert!(help.contains("LFP_PIPE_PUBLIC_LISTEN"));
        assert!(help.contains("--log-filter"));
    }

    #[test]
    fn client_help_exposes_flags_and_environment_variables() {
        let help = ClientCli::command().render_long_help().to_string();
        assert!(help.contains("--client-id"));
        assert!(help.contains("LFP_PIPE_CLIENT_ID"));
        assert!(help.contains("LFP_PIPE_RELAY_MODE"));
        assert!(help.contains("--tray"));
        assert!(help.contains("LFP_PIPE_TRAY"));
    }

    #[test]
    fn direct_environment_value_precedes_file_value() {
        let value = load_file_backed_value(
            "LFP_PIPE_CLIENT_ID",
            Some(OsString::from("direct")),
            Some(OsString::from("missing-file")),
        )
        .expect("direct value");
        assert_eq!(value, Some(OsString::from("direct")));
    }

    #[test]
    fn file_backed_environment_trims_only_line_endings() {
        let path = std::env::temp_dir().join(format!(
            "lfp-pipe-env-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::write(&path, " value with spaces \r\n").expect("write environment file");
        let value = load_file_backed_value(
            "LFP_PIPE_CLIENT_ID",
            None,
            Some(path.clone().into_os_string()),
        )
        .expect("file value");
        let _ = fs::remove_file(path);
        assert_eq!(value, Some(OsString::from(" value with spaces ")));
    }
}
