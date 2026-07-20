# KyClash Network Runtime Implementation v1

Status: Approved and locked for P1 implementation

Date: 2026-07-21

Supersedes: no prior runtime implementation decision

Protocol amendment: `../roadmap/kyclash-runtime-protocol-review-20260721.md`

Datagram-size amendment:
`../roadmap/kyclash-runtime-datagram-size-review-20260721.md`

QUIC ordering amendment:
`../roadmap/kyclash-runtime-quic-order-review-20260721.md`

## Decision scope

This record selects concrete components for the data path already locked in
`kyclash-networking-v1.md`. It does not change the product semantics: WireGuard
remains the encrypted layer-3 tunnel, QUIC remains the preferred carrier,
WSS/TCP remain ordered availability fallbacks, fallback remains
break-before-make, and P1 remains single-site and does not modify DNS.

## Decision

KyClash will ship a dedicated Go network sidecar. The sidecar will embed:

- the upstream `golang.zx2c4.com/wireguard` packages from `wireguard-go` for the
  WireGuard device, peer state, and macOS utun integration;
- a KyClash-owned implementation of the upstream replaceable `conn.Bind`
  boundary so encrypted WireGuard packets use the selected carrier rather than
  the default UDP socket;
- `github.com/quic-go/quic-go` for the preferred QUIC carrier;
- `github.com/coder/websocket` for the WSS fallback;
- Go's standard `crypto/tls` and `net` packages for TLS and framed TCP fallback.

The Rust Tauri backend remains the lifecycle, policy, route-transaction, and
credential coordinator. It starts the sidecar without secrets in arguments or
environment variables, authenticates versioned local IPC, supplies credentials
through an inherited private channel, and owns every route transaction.

## Evidence

- Upstream `wireguard-go` documents macOS utun support and exposes a replaceable
  `conn.Bind` interface with open, receive, send, close, endpoint, and batching
  operations: <https://git.zx2c4.com/wireguard-go/tree/README.md> and
  <https://git.zx2c4.com/wireguard-go/tree/conn/conn.go>.
- `quic-go` implements IETF QUIC, including unreliable datagrams, and uses the
  MIT license: <https://github.com/quic-go/quic-go>.
- `coder/websocket` provides a maintained, context-aware WebSocket client with
  TLS through Go's HTTP stack and uses the ISC license:
  <https://github.com/coder/websocket>.
- `wireguard-go`, `quic-go`, and `coder/websocket` licenses are compatible with
  distribution in the GPL-3.0-only KyClash application when their notices are
  retained. Dependency versions and hashes must be pinned in `go.mod`/`go.sum`.

## KyClash carrier protocol

QUIC datagrams carry an encrypted WireGuard packet using the bounded
fragmentation amendment when required by the negotiated datagram size. WSS and
TCP carry the same base packet envelope over an ordered byte stream:

```text
magic[4] = "KYNP"
version[1] = 1
kind[1] = 1 (wireguard_packet) | 2 (ping) | 3 (pong) | 4 (close)
flags[2] = 0, or bit 0 for reviewed QUIC fragmentation
payload_length[4] = unsigned network byte order
sequence[8] = unsigned network byte order, monotonic per carrier connection
payload[payload_length]
```

The maximum payload is 65,535 bytes. Unknown versions, kinds, unknown flags,
oversized payloads, truncated frames, replayed/non-monotonic sequences, invalid
fragments, and extra bytes after a complete datagram frame fail closed. QUIC
datagrams use the same envelope so packet validation and diagnostics remain
transport-independent. Carrier TLS authenticates the KyClash endpoint; the
inner WireGuard protocol continues to authenticate peers and encrypt packets.

This framing is a KyClash client/server contract. A compatible, independently
reviewed server implementation is required before real endpoint testing. It is
not presented as standard WireGuard interoperability over arbitrary QUIC or
WebSocket servers.

## Privilege and secret boundary

- The sidecar receives private keys and local IPC authentication material only
  over inherited standard input or an inherited descriptor and zeroes owned
  buffers after configuration.
- No private key, token, endpoint credential, or IPC proof may appear in process
  arguments, environment variables, configuration files, diagnostics, panic
  output, or normal logs.
- macOS utun creation and route mutation remain separate capabilities. The
  sidecar cannot mutate routes; the Rust route orchestrator cannot read tunnel
  private keys.
- Any privileged launcher must allow only a version-pinned, KyClash-signed
  sidecar and a fixed command surface. General shell execution is prohibited.
- Production builds must verify the bundled sidecar hash/signature before
  launch. Sidecar download and self-update remain disabled.

## Lifecycle rules

1. Validate signed policy and obtain credential material.
2. Start and mutually authenticate local IPC.
3. Configure the WireGuard device while carrier output is closed.
4. Connect QUIC and pass a health gate.
5. Transactionally apply private routes.
6. On carrier failure, roll back/close the old carrier before opening WSS or
   TCP; established flows are not migrated in v1.
7. On total failure or disconnect, roll back routes before stopping utun and
   clearing secrets.

The existing Rust data-plane controller remains authoritative for this order.
The sidecar reports facts and performs requested device/carrier operations; it
does not independently choose policy or install routes.

## Rejected alternatives

### BoringTun embedded in the Rust application

Rejected for P1 because its latest published release line has been dormant
since 2022 and KyClash would need to own more of the macOS device and privileged
integration. It remains a contingency only after a new security/maintenance
review.

### Standalone unmodified `wireguard-go`

Rejected because its default bind sends WireGuard directly over UDP and cannot
implement the locked QUIC/WSS/TCP carrier semantics without the custom Bind.

### Network Extension in the first macOS release

Deferred because it changes signing, entitlement, installation, and lifecycle
boundaries. Adopting it requires a separate ADR and Apple entitlement evidence.

### Seamless multipath or make-before-break

Rejected because it changes the locked fallback semantics and creates ambiguous
packet and route ownership.

## Implementation gates

The real sidecar may replace mocks only after all of these pass:

- deterministic frame codec, fuzz, truncation, replay, and size-bound tests;
- carrier-independent Bind conformance and cancellation tests;
- loopback QUIC, WSS, and TCP tests with ephemeral test certificates;
- secret-leak tests for arguments, environment, logs, diagnostics, and crash
  output;
- sidecar build reproducibility, dependency license inventory, SBOM, and binary
  hash verification;
- macOS utun, route, forced-exit, sleep/wake, and network-switch tests on a
  disposable authorized host;
- compatible server endpoint review and isolated packet-loss/jitter/throughput
  measurements.

Local source, codecs, mocks, loopback carriers, and unprivileged tests may be
implemented autonomously. Creating utun interfaces, mutating routes, accessing
real credentials, or contacting real KyClash endpoints requires explicit user
authorization.

Changes to the selected WireGuard engine, carrier libraries, packet envelope,
privilege split, or fallback ordering require a new review record.
