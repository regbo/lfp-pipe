//! JSON messages exchanged over the NATS control plane.

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// Server broadcast announcing one new public ingress connection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectionRequest {
    /// Unique identifier later repeated in the callback prefix.
    pub connection_id: String,
    /// HTTP Host or TLS SNI, or `None` for default/raw TCP routing.
    pub hostname: Option<String>,
    /// Per-request NATS inbox on which clients submit claims.
    pub reply_subject: String,
    /// Public callback/data address the winning client must dial.
    pub server_data_addr: String,
    /// Claim deadline expressed as Unix epoch milliseconds.
    pub deadline_unix_ms: u64,
}

/// Client response indicating that one configured backend matches a request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectionClaim {
    /// Stable identifier of the claiming client process.
    pub client_id: String,
    /// Connection being claimed.
    pub connection_id: String,
}

/// Server decision returned to every claimant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectionClaimAck {
    /// Whether this client should open the callback and backend sockets.
    pub accepted: bool,
    /// Client to which this acknowledgement applies.
    pub client_id: String,
    /// Connection to which this acknowledgement applies.
    pub connection_id: String,
    /// Human-readable rejection reason when not accepted.
    pub reason: Option<String>,
}

/// Encode one control-plane value as compact JSON.
pub fn encode_json<T: Serialize>(value: &T) -> anyhow::Result<Vec<u8>> {
    serde_json::to_vec(value).context("failed to serialize JSON payload")
}

/// Decode one control-plane value from JSON.
pub fn decode_json<T: for<'de> Deserialize<'de>>(payload: &[u8]) -> anyhow::Result<T> {
    serde_json::from_slice(payload).context("failed to parse JSON payload")
}
