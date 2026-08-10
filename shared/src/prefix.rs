//! Versioned callback prefix used to pair a socket with pending ingress.

use anyhow::{Context, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

/// First line sent by a client on a callback/data connection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrefixEnvelope {
    /// Wire-format version.
    pub version: u16,
    /// Client that won the server's claim selection.
    pub client_id: String,
    /// Public ingress connection to which this callback belongs.
    pub connection_id: String,
}

impl PrefixEnvelope {
    /// Wire version emitted and accepted by this build.
    pub const CURRENT_VERSION: u16 = 1;

    /// Construct a prefix for a claimed connection.
    pub fn new(client_id: impl Into<String>, connection_id: impl Into<String>) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            client_id: client_id.into(),
            connection_id: connection_id.into(),
        }
    }

    /// Serialize the envelope as base64-encoded JSON terminated by a newline.
    pub fn encode_line(&self) -> anyhow::Result<Vec<u8>> {
        let json = serde_json::to_vec(self).context("failed to serialize prefix envelope")?;
        let mut encoded = STANDARD.encode(json).into_bytes();
        encoded.push(b'\n');
        Ok(encoded)
    }

    /// Decode and validate one newline-terminated prefix.
    pub fn decode_line(line: &[u8]) -> anyhow::Result<Self> {
        let line = std::str::from_utf8(line).context("prefix must be valid utf-8")?;
        let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
        if trimmed.is_empty() {
            bail!("prefix line is empty");
        }

        let decoded = STANDARD
            .decode(trimmed)
            .context("prefix must be valid base64")?;
        let envelope: Self = serde_json::from_slice(&decoded).context("prefix JSON is invalid")?;
        if envelope.version != Self::CURRENT_VERSION {
            bail!("unsupported prefix version {}", envelope.version);
        }
        Ok(envelope)
    }
}

#[cfg(test)]
mod tests {
    use super::PrefixEnvelope;

    #[test]
    fn round_trip_prefix_line() {
        let envelope = PrefixEnvelope::new("client-a", "conn-1");
        let encoded = envelope.encode_line().expect("encode");
        let decoded = PrefixEnvelope::decode_line(&encoded).expect("decode");
        assert_eq!(decoded, envelope);
    }

    #[test]
    fn rejects_invalid_base64() {
        assert!(PrefixEnvelope::decode_line(b"not-base64\n").is_err());
    }
}
