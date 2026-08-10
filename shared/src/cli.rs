//! Command-line and environment configuration for both binaries.
//!
//! Clap resolves a value supplied by a command-line flag before the matching
//! environment variable. Optional values are then layered over the TOML file,
//! giving the project one explicit precedence order:
//!
//! `CLI flag > environment variable > TOML file > typed default`.

use std::path::PathBuf;

use clap::{Args, Parser};

use crate::{
    config::{
        ClientConfig, ClientOverrides, RelayMode, ServerConfig, ServerOverrides,
        load_client_config, load_server_config,
    },
    logging::DEFAULT_LOG_FILTER,
};

/// Configuration and logging values needed to launch a component.
#[derive(Debug)]
pub struct RuntimeConfig<T> {
    /// Fully layered component configuration.
    pub config: T,
    /// Tracing filter selected by `--log-filter`, `RUST_LOG`, or its default.
    pub log_filter: String,
}

#[derive(Debug, Args)]
struct CommonOptions {
    /// Path to the component's TOML configuration file.
    #[arg(long, env = "LFP_PIPE_CONFIG", value_name = "PATH")]
    config: PathBuf,

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

    /// Select automatic, splice, or buffered stream forwarding.
    #[arg(long, env = "LFP_PIPE_RELAY_MODE", value_enum)]
    relay_mode: Option<RelayMode>,

    /// Override the NATS connection-request subject.
    #[arg(long, env = "LFP_PIPE_REQUEST_SUBJECT", value_name = "SUBJECT")]
    request_subject: Option<String>,

    /// Milliseconds to wait for the first matching client claim.
    #[arg(long, env = "LFP_PIPE_CLAIM_TIMEOUT_MS", value_name = "MS")]
    claim_timeout_ms: Option<u64>,

    /// Milliseconds to retain an ingress while awaiting its callback socket.
    #[arg(long, env = "LFP_PIPE_PENDING_TIMEOUT_MS", value_name = "MS")]
    pending_timeout_ms: Option<u64>,
}

impl ServerCli {
    fn load(self) -> anyhow::Result<RuntimeConfig<ServerConfig>> {
        let config = load_server_config(&self.common.config)?.with_overrides(ServerOverrides {
            public_listen: self.public_listen,
            data_listen: self.data_listen,
            advertised_data_addr: self.advertised_data_addr,
            nats_url: self.nats_url,
            relay_mode: self.relay_mode,
            request_subject: self.request_subject,
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

    /// Select automatic, splice, or buffered stream forwarding.
    #[arg(long, env = "LFP_PIPE_RELAY_MODE", value_enum)]
    relay_mode: Option<RelayMode>,

    /// Override the NATS connection-request subject.
    #[arg(long, env = "LFP_PIPE_REQUEST_SUBJECT", value_name = "SUBJECT")]
    request_subject: Option<String>,

    /// Milliseconds to wait for the server's claim decision.
    #[arg(long, env = "LFP_PIPE_CLAIM_ACK_TIMEOUT_MS", value_name = "MS")]
    claim_ack_timeout_ms: Option<u64>,
}

impl ClientCli {
    fn load(self) -> anyhow::Result<RuntimeConfig<ClientConfig>> {
        let config = load_client_config(&self.common.config)?.with_overrides(ClientOverrides {
            client_id: self.client_id,
            nats_url: self.nats_url,
            relay_mode: self.relay_mode,
            request_subject: self.request_subject,
            claim_ack_timeout_ms: self.claim_ack_timeout_ms,
        });
        Ok(RuntimeConfig {
            config,
            log_filter: self.common.log_filter,
        })
    }
}

/// Parse and layer server configuration from CLI flags, environment, and TOML.
pub fn parse_server_runtime() -> anyhow::Result<RuntimeConfig<ServerConfig>> {
    ServerCli::parse().load()
}

/// Parse and layer client configuration from CLI flags, environment, and TOML.
pub fn parse_client_runtime() -> anyhow::Result<RuntimeConfig<ClientConfig>> {
    ClientCli::parse().load()
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use clap::CommandFactory;

    use super::{ClientCli, ServerCli};

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
    }
}
