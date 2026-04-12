use anyhow::{Context, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrefixEnvelope {
    pub version: u16,
    pub client_id: String,
    pub connection_id: String,
}

impl PrefixEnvelope {
    pub const CURRENT_VERSION: u16 = 1;

    pub fn new(client_id: impl Into<String>, connection_id: impl Into<String>) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            client_id: client_id.into(),
            connection_id: connection_id.into(),
        }
    }

    pub fn encode_line(&self) -> anyhow::Result<Vec<u8>> {
        let json = serde_json::to_vec(self).context("failed to serialize prefix envelope")?;
        let mut encoded = STANDARD.encode(json).into_bytes();
        encoded.push(b'\n');
        Ok(encoded)
    }

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
