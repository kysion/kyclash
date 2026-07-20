# KyClash Networking Architecture v1

Status: Locked for P0/P1 implementation

Date: 2026-07-21

## Decision

KyClash keeps Mihomo as the owner of proxy subscriptions, policy groups, DNS
proxying, system proxy, and the existing TUN feature. Private networking is a
separate product domain coordinated by the Tauri Rust backend and executed by a
dedicated, least-privilege network sidecar.

The first supported data path is:

1. WireGuard provides the encrypted layer-3 tunnel and private addressing.
2. QUIC is the preferred transport for carrying tunnel traffic.
3. WSS/TCP is an availability fallback when UDP or QUIC is unavailable.
4. One KyClash route orchestrator owns all private CIDRs installed for the
   networking domain.

No two components may independently edit the same route or DNS state.

## Scope of v1

The first release supports one active site, an explicit list of private CIDRs,
connect/disconnect/retry, connection health, transactional route application,
transport fallback, and redacted diagnostics.

Multi-site concurrency, peer-to-peer traversal, dynamic routing protocols,
user-provided shell commands, mobile clients, and seamless migration of
established flows between transports are out of scope.

## Runtime boundaries

```text
React UI
  -> versioned Tauri commands and events
Rust networking controller
  -> authenticated local IPC
KyClash network sidecar
  -> WireGuard adapter
  -> QUIC transport
  -> WSS/TCP fallback
  -> health and metrics

Rust route orchestrator
  -> route ownership journal
  -> platform route/DNS adapters
  -> rollback and stale-state recovery
```

The UI never executes system commands or constructs platform routes. The
sidecar never changes routes without a transaction issued by the controller.
Platform elevation must be narrow and auditable.

## Route and DNS ownership

- Mihomo continues to own proxy/default-traffic behavior.
- The networking controller exclusively owns configured private CIDRs.
- A connect transaction records pre-existing state before applying changes.
- Route conflicts fail closed; KyClash does not silently replace routes owned
  by another VPN or an administrator.
- Disconnect, failed connect, process restart, and crash recovery consume the
  same ownership journal and are idempotent.
- P0 does not modify system DNS. Private DNS requires a later ADR.

Running Mihomo TUN and private networking together is supported only after the
route-conflict test matrix passes on the target platform.

## Configuration contract

Networking configuration is versioned independently from `IVerge` and must not
be embedded into `verge.yaml`.

```text
schema_version
profile_id
control_plane
identity_ref
site
  id
  display_name
  private_cidrs[]
tunnel
  local_addresses[]
  peer_public_key
  keepalive_seconds
transports
  primary: quic
  fallbacks[]: wss | tcp
  endpoints[]
policy
  connect_timeout
  health_interval
  fallback_threshold
```

Passwords, API tokens, WireGuard private keys, and long-lived device secrets are
never serialized into this file. They are generated locally where possible and
stored in an operating-system credential store. Logs contain only opaque
identifiers and redacted endpoints.

## State machine

```text
Disconnected
  -> Authenticating
  -> FetchingConfig
  -> PreparingTunnel
  -> ConnectingPrimary
  -> ConnectedPrimary
  -> DegradedFallback
  -> Reconnecting
  -> Disconnecting
  -> Disconnected
```

Every transition has a timeout, cancellation path, structured reason code, and
observable event. Failed setup transitions roll back routes and tunnel state.

Fallback is break-before-make in v1. Automatic return to QUIC is deferred until
the next reconnect to avoid route flapping and ambiguous flow ownership.

## Security requirements

- Local IPC authenticates both endpoint and protocol version.
- The controller rejects unknown schema versions and unsigned remote policy.
- Secrets are never accepted through command-line arguments.
- Diagnostic export is allowlist-based and redacted by default.
- Sidecar downloads and updates require KyClash-owned signatures.
- Production infrastructure access requires explicit user authorization.

## Update and compatibility policy

KyClash must not consume Clash Verge Rev application releases. Application and
network-sidecar updates remain disabled until KyClash owns an endpoint, signing
key, rollback metadata, and release procedure.

Internal names such as `clash-verge-service`, the service IPC crate, Mihomo
sidecar names, and the Rust package name remain unchanged until a dedicated
migration proves installation, elevation, IPC, and uninstall compatibility.
Visible product identity is KyClash with bundle identifier
`net.kysion.kyclash`.

Legacy Clash Verge Rev data is not imported silently. A future explicit import
flow may copy selected profiles after preview, validation, and backup.

## Architecture gates

Implementation may move from P0 to P1 only when all of the following exist:

- JSON Schema and matching Rust/TypeScript contract tests.
- Mock sidecar with versioned authenticated IPC.
- Route transaction and crash-recovery tests without production infrastructure.
- Mihomo TUN coexistence test matrix for the target platform.
- Secret-storage adapter and redacted diagnostic tests.
- A rollback demonstration for every system mutation.

Any change to route ownership, secret storage, transport semantics, or the
single-site boundary requires a new ADR and re-review.
