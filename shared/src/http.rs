pub fn extract_http_host(payload: &[u8]) -> Option<String> {
    if !looks_like_http(payload) {
        return None;
    }

    let headers_end = payload
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)?;
    let headers = std::str::from_utf8(&payload[..headers_end]).ok()?;

    for line in headers.lines().skip(1) {
        let line = line.trim_end_matches('\r');
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("host") {
            let host = value.trim();
            if host.is_empty() {
                return None;
            }
            return Some(strip_port(host).to_string());
        }
    }

    None
}

fn looks_like_http(payload: &[u8]) -> bool {
    const METHODS: [&[u8]; 10] = [
        b"GET ",
        b"POST ",
        b"HEAD ",
        b"PUT ",
        b"PATCH ",
        b"DELETE ",
        b"OPTIONS ",
        b"TRACE ",
        b"CONNECT ",
        b"PRI * HTTP/2.0",
    ];

    METHODS.iter().any(|method| payload.starts_with(method))
}

fn strip_port(host: &str) -> &str {
    if let Some(stripped) = host.strip_prefix('[') {
        return stripped.split(']').next().unwrap_or(host);
    }

    host.split(':').next().unwrap_or(host)
}

#[cfg(test)]
mod tests {
    use super::extract_http_host;

    #[test]
    fn extracts_host_header_without_port() {
        let request = b"GET / HTTP/1.1\r\nHost: Example.com:8443\r\nConnection: close\r\n\r\n";
        assert_eq!(extract_http_host(request).as_deref(), Some("Example.com"));
    }

    #[test]
    fn ignores_non_http_payloads() {
        assert_eq!(extract_http_host(b"\x16\x03\x01\x00\x10"), None);
    }
}
