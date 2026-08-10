//! TLS record validation and Server Name Indication extraction.

use anyhow::{Context, bail};

/// Parse a ClientHello record and return its optional SNI hostname.
pub fn extract_sni(record_bytes: &[u8]) -> anyhow::Result<Option<String>> {
    let hello =
        clienthello::parse_from_record(record_bytes).context("failed to parse ClientHello")?;
    Ok(hello.server_name().map(ToOwned::to_owned))
}

/// Check that buffered bytes begin with a TLS handshake record header.
pub fn validate_tls_record_header(record_bytes: &[u8]) -> anyhow::Result<()> {
    if record_bytes.len() < 5 {
        bail!("TLS record is too short");
    }
    if record_bytes[0] != 0x16 {
        bail!("expected TLS handshake record");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{extract_sni, validate_tls_record_header};

    const CLIENT_HELLO_HEX: &str = "1603010200010001fc030313c41da51d52aeb7dcb6bdd69b4d9e781444c315b8a21a284a70147123873d2d201286093e9ee592085a0347d2a253a26d7b9dfe2f3f8e7dec0d4d9631b404169d0024130213031301c02cc030c02bc02fcca9cca8c024c028c023c027009f009e006b006700ff0100018f00000010000e00000b6578616d706c652e636f6d000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000016000000170000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b00050403040303002d00020101003300260024001d0020de92b88f6ab6d2d5fab6ff9111308b96545e37e176778b776858f984e980207b001500e200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    fn decode_hex(input: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len() / 2);
        let bytes = input.as_bytes();
        for i in (0..bytes.len()).step_by(2) {
            let hi = (bytes[i] as char).to_digit(16).expect("hex");
            let lo = (bytes[i + 1] as char).to_digit(16).expect("hex");
            out.push(((hi << 4) | lo) as u8);
        }
        out
    }

    #[test]
    fn validates_tls_header() {
        let bytes = decode_hex(CLIENT_HELLO_HEX);
        validate_tls_record_header(&bytes).expect("valid record");
    }

    #[test]
    fn extracts_example_com_from_captured_client_hello() {
        let bytes = decode_hex(CLIENT_HELLO_HEX);
        let sni = extract_sni(&bytes).expect("parse");
        assert_eq!(sni.as_deref(), Some("example.com"));
    }
}
