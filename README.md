# regbo-tunnel

Rust reverse-proxy prototype with:

- `server`: accepts inbound TCP, routes by TLS SNI when present, falls back to HTTP `Host`, and coordinates claims over NATS
- `client`: subscribes on NATS, claims matching requests, dials the backend, and connects back to the server
- `shared`: protocol, config, prefix envelope, hostname helpers, and routing logic
- `Caddy`: local TLS backend for development, reverse proxying to LibreSpeed running on the client side

## Flow

1. A TCP client connects to `server`.
2. `server` tries TLS SNI first, then falls back to the HTTP `Host` header; if neither is present it routes as a default request.
3. `server` publishes a `ConnectionRequest` on NATS.
4. Matching clients send `ConnectionClaim`s.
5. `server` round-robins accepted claims across matching clients for the same route, then the winning client opens a TCP connection back to the server data port.
6. The client sends a base64-encoded prefix line containing `client_id` and `connection_id`.
7. The server validates the prefix and binds the socket to the pending ingress connection.
8. Both sides use `tokio::io::copy_bidirectional` for transparent stream forwarding.

## Local Dev Stack

- `mise run server-dev` starts NATS and the Rust server
- `mise run client-dev` starts LibreSpeed, Caddy, and the Rust client
- Caddy listens on `9443` with an internal cert and proxies `wsl.regbodesktop.local` to LibreSpeed on `localhost:8080`
- LibreSpeed is published as `127.0.0.1:8080` only, to simulate a backend that is private to the client side
- The server binds its data listener on `0.0.0.0:7001` and publishes `localhost:7001` as the client connect-back address to make mixed PowerShell/WSL local development easier

## Example

Run a local NATS server, then:

```powershell
$HOME\.cargo\bin\cargo.exe run -p server -- --config .\server.example.toml
$HOME\.cargo\bin\cargo.exe run -p client -- --config .\client.example.toml
```

The example server config listens on `8443` so it can run without root/admin privileges during development.

For an end-to-end curl test after starting `server-dev` and `client-dev`, run curl from WSL:

```sh
wsl curl -k --resolve wsl.regbodesktop.local:8443:127.0.0.1 https://wsl.regbodesktop.local:8443/
```
