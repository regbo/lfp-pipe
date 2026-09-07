# Security hardening plan

This plan records the reviewed findings while keeping data-plane ingress instances independent. A
callback returns to the ingress instance advertised in its connection request; ingress instances do
not share accepted sockets, pending maps, counters, or callback secrets.

## Trust model

- The central manager and its Authentik integration are trusted administrators.
- Centrally managed route, backend, authorization, and local-path configuration is therefore an
  intentional capability rather than a vulnerability.
- Public peers, unclaimed devices, and route clients other than the selected winner remain
  untrusted.

## Implemented

### Total handshake deadlines and optional local limits

- Apply a 15-second total deadline to ingress protocol detection and callback-prefix receipt.
- Buffer and replay fragmented TLS ClientHello or HTTP header bytes so the deadline permits slow
  handshakes without losing application data.
- Keep optional per-ingress public-connection and callback-handshake limit logic available, but
  disable both limits by default (`0`) until production capacity is measured.
- Transfer the public-connection permit into pending state and retain it for the entire relay.
- Release the callback-handshake permit after successful pairing, because the public-connection
  permit then bounds the established tunnel.
- Keep every counter and permit local to the ingress process so scaling managers adds capacity
  without synchronization.

### Go dependency remediation

- Update the vulnerable `golang.org/x/net` and `golang.org/x/text` dependency graph.
- Run `govulncheck` after the update and retain resolved versions in `go.mod` and `go.sum`.

## Deferred work

### P1: Atomic callback validation and one-time authentication

1. Generate a random 256-bit callback key on the ingress instance for each accepted claim.
2. Return the key only in the selected client's claim acknowledgement.
3. Have the selected client authenticate the prefix with HMAC-SHA-256 over the protocol version,
   client ID, connection ID, and accepting-ingress identity.
4. Perform constant-time client-ID and MAC comparisons while the pending entry remains present.
5. Remove the pending entry only after every comparison succeeds.
6. Add replay, wrong-client, wrong-MAC, expiry, and concurrent-callback tests.

The key remains local to the accepting ingress and the selected client. This adds no
ingress-to-ingress communication, payload encryption, multiplexing, or network round trip.

### P1: Enrollment capability separation and atomic claims

1. Give each enrollment a browser claim code and a separate client retrieval token; store only
   hashes server-side.
2. Never return full claim codes from enrollment-list endpoints. Ordinary users see only their own
   redacted enrollment metadata; administrators may receive a separately authorized redacted view.
3. Change claiming to one atomic `pending -> claimed` compare-and-set operation that rejects
   claimed and expired records.
4. Bind credential retrieval to the private client token and consume the returned secret once.
5. Put enrollment state in the control plane's shared durable store before increasing control-plane
   replicas; this is management-plane consistency and does not couple ingress instances.
6. Add concurrency tests proving that exactly one claimant and one credential retrieval succeed.

### P1: Control-plane transport validation

1. Parse and normalize the configured control-plane URL once in the local bootstrap layer.
2. Require HTTPS for non-loopback origins; permit HTTP only for explicit loopback development.
3. Reject embedded credentials, fragments, and unexpected URL schemes.
4. Derive configuration, enrollment, event-stream, and ticket requests from the validated origin
   instead of accepting absolute endpoint replacements.
5. Require external OAuth token endpoints to use HTTPS and pin their origin at enrollment so later
   configuration cannot silently redirect a stored credential.
6. Add URL-confusion, downgrade, redirect, and origin-change tests.

### P2: Device credential storage and rotation

1. Store desktop secrets in Windows Credential Manager, macOS Keychain, or Linux Secret Service.
2. Preserve explicit secret-file support for headless deployments and Docker/Swarm secrets, with
   restrictive permission checks where the operating system exposes them.
3. Issue finite-lived device credentials and rotate them during a broad renewal window with random
   jitter to prevent synchronized refresh traffic.
4. Use overlapping old/new credentials until the client proves the replacement works, then revoke
   the old credential.
5. Keep route-scoped NATS tickets short-lived so revocation converges without ingress coordination.
6. Add interrupted-rotation, rollback, vault-unavailable, and large-fleet jitter tests.

Credential rotation is control-plane traffic only. It does not change established relays or require
ingress servers to synchronize.
