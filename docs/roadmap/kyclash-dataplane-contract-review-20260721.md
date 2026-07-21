# KyClash data-plane session contract review

Status: approved and locked for N1

Date: 2026-07-21

Amends implementation details of:

- `../architecture/kyclash-network-runtime-v1.md`
- `kyclash-production-networking-work-program-20260721.md`

## Findings resolved

The v1 profile previously required only a non-empty WireGuard peer key, so a
profile could pass Rust and Go validation but remain impossible to configure in
wireguard-go. Endpoint strings also had no single normalized dial form, and
health sampling had no cross-language response contract. These were blocking
N1B because backend success and state transition could not be tested against
stable inputs and facts.

## Locked profile details

- `peer_public_key` is canonical padded RFC 4648 Base64 decoding to exactly 32
  bytes. Private material remains bootstrap-only and is never part of a profile.
- `identity_ref` must use the `keychain:` scheme and a safe opaque identifier.
- QUIC uses `https://`, WSS uses `wss://`, and TCP uses `tcp://` with an
  explicit port. User information, query strings, and fragments are forbidden.
- HTTPS/WSS default to port 443. The normalized dial address is `host:port` and
  TLS `ServerName` is the URL hostname. Non-WSS endpoint paths are forbidden.
- Every configured transport has exactly one endpoint; QUIC is primary and
  only WSS/TCP may appear once in the ordered fallback list.
- Private CIDRs are canonical network prefixes. Tunnel local addresses retain
  their host prefix (`/32` or `/128` in the first profile).
- The N1 userspace WireGuard MTU is 1420. A different real-utun MTU requires
  measured evidence and review rather than silent platform divergence.

Production carrier TLS uses normal platform certificate validation and the
normalized server name. Ephemeral lab roots may be injected only through an
in-memory test/backend constructor; they are not serialized into the production
profile, environment, diagnostics, or retained evidence.

## Locked backend and health details

The IPC session invokes a data-plane backend for prepare, named connect, health,
disconnect, stop, cancel, and close. Profile/tunnel/carrier state changes only
after the corresponding backend call succeeds. A failure returns a stable,
redacted structured error and retains the last confirmed state.

Health facts contain only:

```text
reachable: boolean
latency_ms: unsigned 32-bit integer
jitter_ms: unsigned 32-bit integer
loss_percent: unsigned integer in 0..100
```

Health facts do not select fallback. Rust applies the signed policy threshold
and issues explicit disconnect/connect requests. N1B must replace the inert
contract backend with the real userspace implementation before N1 can close.

Changing key encoding, endpoint normalization, MTU, trust injection, health
fields, or the “backend success before state transition” rule requires another
review record.
