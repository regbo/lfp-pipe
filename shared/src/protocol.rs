use anyhow::Context;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectionRequest {
    pub connection_id: String,
    pub hostname: Option<String>,
    pub reply_subject: String,
    pub server_data_addr: String,
    pub deadline_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectionClaim {
    pub client_id: String,
    pub connection_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectionClaimAck {
    pub accepted: bool,
    pub client_id: String,
    pub connection_id: String,
    pub reason: Option<String>,
}

pub fn encode_json<T: Serialize>(value: &T) -> anyhow::Result<Vec<u8>> {
    serde_json::to_vec(value).context("failed to serialize JSON payload")
}

pub fn decode_json<T: for<'de> Deserialize<'de>>(payload: &[u8]) -> anyhow::Result<T> {
    serde_json::from_slice(payload).context("failed to parse JSON payload")
}
