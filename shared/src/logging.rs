//! Low-noise tracing initialization and connection-error classification.

use std::io::ErrorKind;

use anyhow::Context;
use tracing_subscriber::EnvFilter;

/// Default filter keeps lifecycle events while suppressing dependency chatter.
pub const DEFAULT_LOG_FILTER: &str = "info,async_nats=warn";

/// Install the process-wide tracing subscriber using the supplied directives.
///
/// `tracing` performs callsite filtering before recording disabled events, so
/// debug fields are not formatted or emitted unless the filter enables them.
pub fn init(log_filter: &str) -> anyhow::Result<()> {
    let filter = EnvFilter::try_new(log_filter).context("invalid tracing filter")?;
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .try_init()
        .map_err(|error| anyhow::anyhow!("failed to initialize tracing subscriber: {error}"))
}

/// Return true when a relay ended because a peer closed an established socket.
///
/// Timed clients such as iperf and browser speed tests commonly close parallel
/// workers with a reset after collecting enough data. Those terminal events are
/// useful at debug level but should not flood normal warning output.
pub fn is_expected_disconnect(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io_error| {
                matches!(
                    io_error.kind(),
                    ErrorKind::BrokenPipe
                        | ErrorKind::ConnectionReset
                        | ErrorKind::ConnectionAborted
                )
            })
    })
}

#[cfg(test)]
mod tests {
    use std::io::{Error, ErrorKind};

    use super::is_expected_disconnect;

    #[test]
    fn recognizes_wrapped_peer_disconnects() {
        let error =
            anyhow::Error::new(Error::from(ErrorKind::ConnectionReset)).context("relay failed");
        assert!(is_expected_disconnect(&error));
    }

    #[test]
    fn preserves_actionable_errors() {
        let error = anyhow::Error::new(Error::from(ErrorKind::PermissionDenied));
        assert!(!is_expected_disconnect(&error));
    }
}
