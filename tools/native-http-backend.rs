//! Minimal HTTP backend used for native tunnel throughput smoke tests.
//!
//! Compile with Rust 2024 and pass an optional listen address. The process
//! supports bounded upload/download bodies so measurements focus on the tunnel.

use std::{
    env,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread,
};

const MARKER: &[u8] = b"lfp-pipe-native-smoke\n";
const MAX_TRANSFER_BYTES: usize = 512 * 1024 * 1024;

fn main() -> std::io::Result<()> {
    let listen = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:0".to_owned());
    let listener = TcpListener::bind(listen)?;
    println!("LISTEN_ADDR={}", listener.local_addr()?);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    if let Err(error) = serve(stream) {
                        eprintln!("request failed: {error}");
                    }
                });
            }
            Err(error) => eprintln!("accept failed: {error}"),
        }
    }
    Ok(())
}

fn serve(mut stream: TcpStream) -> std::io::Result<()> {
    let mut request = [0_u8; 8192];
    let size = stream.read(&mut request)?;
    let headers = &request[..size];
    let first_line = headers
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    eprintln!("{}", String::from_utf8_lossy(first_line).trim());

    let request_line = String::from_utf8_lossy(first_line);
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().unwrap_or_default();
    let path = request_parts.next().unwrap_or("/");

    if method == "GET"
        && let Some(bytes) = transfer_size(path, "/download/")
    {
        return send_download(&mut stream, bytes);
    }
    if method == "POST" && path == "/upload" {
        return receive_upload(&mut stream, headers);
    }

    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        MARKER.len()
    )?;
    stream.write_all(MARKER)
}

fn transfer_size(path: &str, prefix: &str) -> Option<usize> {
    path.strip_prefix(prefix)?
        .parse::<usize>()
        .ok()
        .filter(|bytes| *bytes <= MAX_TRANSFER_BYTES)
}

fn send_download(stream: &mut TcpStream, bytes: usize) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {bytes}\r\nConnection: close\r\n\r\n"
    )?;
    let chunk = [0_u8; 64 * 1024];
    let mut remaining = bytes;
    while remaining > 0 {
        let size = remaining.min(chunk.len());
        stream.write_all(&chunk[..size])?;
        remaining -= size;
    }
    Ok(())
}

fn receive_upload(stream: &mut TcpStream, initial: &[u8]) -> std::io::Result<()> {
    let header_end = initial
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .unwrap_or(initial.len());
    let content_length = String::from_utf8_lossy(&initial[..header_end])
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or_default()
        .min(MAX_TRANSFER_BYTES);
    let mut received = initial.len().saturating_sub(header_end).min(content_length);
    let mut buffer = [0_u8; 64 * 1024];
    while received < content_length {
        let chunk_size = (content_length - received).min(buffer.len());
        let size = stream.read(&mut buffer[..chunk_size])?;
        if size == 0 {
            break;
        }
        received += size;
    }
    let body = format!("{received}\n");
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}
