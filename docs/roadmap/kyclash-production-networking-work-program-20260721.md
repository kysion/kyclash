# KyClash production networking long-range work program

Status: approved and locked for continuous execution

Date: 2026-07-21

Parent plan: `kyclash-production-networking-plan-20260721.md`

Review record: `kyclash-production-networking-review-20260721.md`

## Outcome

Complete N1 through N5 as one dependency-ordered program that ends with a
Developer ID-signed macOS arm64 candidate proving single-site private
networking, QUIC -> WSS -> TCP fallback, transactional private routes, Mihomo
TUN coexistence, crash recovery, and redacted operational evidence.

This program does not authorize production infrastructure mutation, a GitHub
Release, updater activation, or contact with a staging endpoint. N6 remains a
separate release-activation transaction.

## Continuous execution rules

1. Work starts at the first incomplete item and continues without requesting a
   routine “next step”.
2. Each merge unit below is independently reviewable, updates progress in this
   document, passes its applicable gates, is committed, and is pushed to
   `origin/main` before the next unit starts.
3. A later work package cannot compensate for a failed earlier exit gate.
4. Host mutation is forbidden outside the confirmed disposable macOS VM.
   Physical-Mac tests are limited to N5 cases that virtualization cannot model
   and require explicit execution authorization at that point.
5. Tests use synthetic credentials, loopback endpoints, TEST-NET/private test
   addresses, and allowlisted evidence. Passwords, tokens, private keys, raw
   endpoint credentials, and Keychain values are never retained.
6. A failure leaves the relevant state disconnected and proves final absence
   of owned child, carrier, utun, route, journal lease, and synthetic Keychain
   entry before work continues.

## Program dependency chain

```text
N1A contracts
 -> N1B carrier/device runtime
 -> N1C lab server
 -> N1D actual-child matrix
 -> N2A production gate/controller
 -> N2B policy v2/credential boundary
 -> N2C Tauri/UI/lifecycle order
 -> N3A reproducible trusted bundle
 -> N3B real utun
 -> N3C VM termination matrix
 -> N4A signed helper/XPC
 -> N4B route lease transaction
 -> N4C Mihomo coexistence VM matrix
 -> N5A impairment/reliability
 -> N5B performance/lifecycle
 -> N5C physical/staging approval gates
```

## N1: real userspace data plane

### N1A — lock executable data-plane contracts

Status (2026-07-21): complete. The reviewed amendment locks strict shared Go/
Rust profile validation, Base64 WireGuard public keys, endpoint normalization,
platform trust plus in-memory-only lab trust, MTU 1420, bounded health facts,
and backend-success-before-state-transition. Shared fixtures and injected
backend failures verify the executable contract.

Deliverables:

- Move the validated Go profile into a reusable, strict package with parity
  fixtures shared with Rust.
- Lock WireGuard key encoding, endpoint normalization, TLS server identity, lab
  trust injection, MTU, health facts, and non-secret status fields.
- Add a data-plane backend interface used by the IPC session; state changes
  occur only after backend success.
- Preserve single-flight IPC and Rust-only fallback selection.

Tests and evidence:

- Unknown fields/version, malformed key/address/endpoint, duplicate transport,
  missing endpoint, and secret-formatting tests.
- Rust/Go byte-for-byte fixtures for every new request and response.

Merge unit: `networking(n1a): lock data-plane session contracts`.

### N1B — bind WireGuard to explicit carriers

Status (2026-07-21): complete. A reusable switchboard keeps one wireguard-go
Bind stable while refusing make-before-break and never choosing fallback. The
production child now builds a userspace-netstack WireGuard device from the
bootstrap private key, clears its owned key after configuration, explicitly
dials QUIC/WSS/TLS-TCP, supports down/reopen cycles, bounded carrier health and
dial cancellation, and closes the backend on EOF or malformed IPC. Injected
dial, cancellation, repeated-carrier, and cleanup tests use no host interface.

Deliverables:

- Add a switchable carrier boundary so the WireGuard device can be prepared
  before a carrier is attached without independently selecting fallback.
- Build the userspace-netstack WireGuard device from bootstrap private material
  and the validated profile; clear transient key buffers after configuration.
- Implement explicit connect/disconnect for QUIC, WSS, and TLS/TCP through the
  existing carrier implementations.
- Implement bounded health snapshots, cancellation, idempotent stop, and
  cleanup after partial initialization.

Tests and evidence:

- Device/carrier failure injection at every construction and cleanup boundary.
- No argv, environment, log, diagnostic, panic, or retained fixture contains
  runtime private material.
- Break-before-make call ordering is asserted, not inferred from final state.

Merge unit: `feat(networking): bind userspace WireGuard to named carriers`.

### N1C — compatible loopback lab server

Deliverables:

- Add a repository-owned lab server that accepts the KYNP QUIC, WSS, and
  TLS/TCP contracts and terminates a userspace WireGuard peer.
- Bind to loopback and ephemeral ports by default. Any non-loopback address
  requires an exact lab-only confirmation and remains excluded from CI.
- Generate ephemeral certificates and WireGuard keys per run; pass trust only
  through an in-memory test boundary.
- Provide deterministic impairment controls for UDP refusal, delay, loss,
  disconnect, and server abort without requiring root networking changes.

Tests and evidence:

- Refusal of non-loopback bind, TLS identity mismatch, malformed frames,
  replay, oversized packets, and unknown protocol versions.
- Bidirectional multi-packet traffic through each carrier.

Merge unit: `test(networking): add compatible loopback lab server`.

### N1D — actual-child end-to-end matrix

Deliverables:

- Drive the real Go executable from the Rust stdio runtime through apply,
  prepare, QUIC connect, health, disconnect, WSS connect, TCP connect, cancel,
  stop, and session disconnect.
- Cover UDP-blocked fallback commands, reconnect, repeated cycles, premature
  server exit, sidecar exit, controller timeout, and crash-loop backoff.

Exit evidence:

- Encrypted bidirectional WireGuard traffic passes over all three carriers.
- Every case ends with no child and no host interface, route, DNS, Keychain, or
  external-network change.

Merge unit: `test(networking): close actual-child userspace data-plane gate`.

N1 is complete only after N1A–N1D pass together.

## N2: production Rust controller and credential path

### N2A — default-off production controller

Deliverables:

- Add `networking-production`, absent from default and release feature sets
  until N4 closes.
- Add one async controller task that exclusively owns the child and serializes
  requests, deadlines, cancellation, health polling, restart, and crash-loop
  state.
- Emit redacted, monotonic application events and retain a bounded diagnostic
  ring with no raw profile or secret fields.
- Keep development mock commands and production commands in separate modules.

Tests and evidence:

- Request correlation, timeout race, cancellation race, stale response,
  malformed child output, restart, and controller-drop tests.

Merge unit: `feat(networking): add gated production controller`.

### N2B — signed policy v2 and Keychain boundary

Deliverables:

- Define signed envelope v2 with signed `issued_at`, `expires_at`, unique
  revision, profile payload, key ID, and algorithm.
- Pin a test trust root and reject v1, unsigned, expired, future-dated,
  replayed, unknown-key, malformed, or tampered production policy.
- Persist only the latest accepted revision metadata needed for replay refusal.
- Resolve only `keychain:` references in
  `net.kysion.kyclash.networking`; generate missing WireGuard material locally
  and send it once through bootstrap stdin.
- Keep destructive Keychain lifecycle tests manual/ignored and scoped to
  `net.kysion.kyclash.test` in a disposable account.

Tests and evidence:

- Clock-boundary and revision-store fault injection.
- In-memory credential adapter tests prove create/read/update/delete semantics,
  redaction, and zeroization without touching the login Keychain.

Merge unit: `feat(networking): enforce policy v2 and credential boundary`.

### N2C — production API, UI, and lifecycle transaction

Deliverables:

- Add typed site/status/connect/cancel/disconnect/diagnostic Tauri commands;
  never return keys, raw policy, credential references, or unredacted endpoints.
- Wire production UI states for authenticating, preparing, primary connect,
  fallback, cancelling, recovering, disconnecting, and structured failure.
- Replace the POC order with validate -> authenticate -> prepare fake tunnel ->
  connect Rust-selected carrier -> health gate -> durable fake route apply.
- Cleanup order is fake route rollback -> tunnel stop -> secret clear.

Exit evidence:

- A production-feature app build drives the actual child and lab server while
  fake adapters assert exact mutation and cleanup order.
- Default/release builds cannot invoke the production command surface.

Merge unit: `feat(networking): wire gated production UI and lifecycle`.

N2 is complete only after N2A–N2C pass together.

## N3: trusted bundle and real macOS utun

### N3A — reproducible nested sidecar and launch trust

Deliverables:

- Build the arm64 Go sidecar reproducibly with pinned Go and module hashes.
- Generate license inventory, SBOM, binary SHA-256, architecture metadata, and
  build provenance from the same commit.
- Bundle and sign the sidecar as a nested executable before signing the app.
- Immediately before launch, verify regular-file ownership/permissions,
  architecture, expected hash, Team ID, and designated requirement.
- Refuse symlink, replacement, unsigned, wrong-team, wrong-architecture, or
  hash-mismatched binaries.

Merge unit: `build(macos): bundle and verify signed network sidecar`.

### N3B — real utun device lifecycle

Deliverables:

- Add wireguard-go macOS utun creation with validated local addresses and
  reviewed MTU; routes and DNS remain untouched.
- Return only the validated interface name and non-secret device facts.
- Bind device ownership to child instance plus operation ID; an arbitrary
  `utun*` name never proves ownership.
- Treat stdin EOF and controller disconnect as bounded cleanup triggers.

Tests and evidence:

- Pure validation and injected device tests run everywhere.
- Real create/up/encrypted traffic/down tests run only in the disposable VM.

Merge unit: `feat(macos): add owned WireGuard utun lifecycle`.

### N3C — disposable-VM termination matrix

Scenarios:

- Normal repeated connect/disconnect.
- Carrier failure during setup and after health.
- Sidecar kill, app kill, stdin EOF, login/logout, and guest reboot.
- Stale interface observation and refusal to claim an unowned utun.

Exit evidence:

- Signed app launches only the signed sidecar and carries lab traffic through
  real utun.
- Every scenario proves final absence of the exact owned utun and child.
- No private route or DNS mutation occurs.

Merge unit: `test(macos): close signed sidecar and utun VM gate`.

N3 is complete only after N3A–N3C pass together.

## N4: privileged routes and Mihomo coexistence

### N4A — signed SMAppService helper and typed XPC

Deliverables:

- Add a dedicated least-privilege helper target registered through
  `SMAppService` with a typed XPC protocol.
- Authenticate the app using audit token, Team ID, bundle identity, and
  designated requirement.
- Expose only typed discovery, begin/apply/rollback/recover, lease heartbeat,
  and status calls. No shell, command text, arbitrary executable, path, or
  environment input is accepted.
- Define install/upgrade/uninstall ownership without changing the inherited
  Mihomo service IPC.

Merge unit: `feat(macos): add authenticated typed route helper`.

### N4B — route transaction lease and crash recovery

Deliverables:

- Move the tested normalized route planner behind XPC.
- Bind a transaction to app identity, sidecar instance, operation ID, owned
  utun record, profile revision, and exact CIDRs.
- Persist pending journal state before each mutation and preserve conflict
  refusal, idempotent rollback, corruption refusal, and restart recovery.
- Roll back in the helper on XPC invalidation/lease expiry; reconcile from the
  Rust journal after restart.
- Enforce health -> utun ready -> journal durable -> route apply; cleanup routes
  before utun and secrets.

Tests and evidence:

- Pure/injected tests cover failure before and after every durable write and
  mutation, helper/controller death, duplicate messages, replayed lease,
  malformed identity, and rollback failure.

Merge unit: `feat(macos): lease transactional private routes`.

### N4C — disposable-VM system and Mihomo matrix

Scenarios:

- IPv4 and IPv6 normal connect/disconnect and private-service reachability.
- Sidecar, app, and helper abort; helper restart; guest reboot; journal
  corruption; pre-existing exact/more-specific/unknown-VPN conflicts.
- Packaged Mihomo TUN active with allowed less-specific coverage.
- Refusal of default-route takeover and any route not owned by the transaction.

Exit evidence:

- The private test service is reachable only while connected.
- Final absence checks cover routes, journal, XPC lease, utun, child, helper
  transaction, and synthetic credential state.

Merge unit: `test(macos): close route and Mihomo coexistence VM gate`.

N4 is complete only after N4A–N4C pass together. Only then may a separately
reviewed candidate include the production feature in normal builds.

## N5: reliability, lifecycle, and staged endpoint readiness

### N5A — deterministic impairment and recovery matrix

Matrix:

- Loss, duplication, reordering, jitter, latency, rate limit, UDP refusal,
  abrupt server close, TLS expiry/identity failure, frame limits, fragment
  expiry, replay, and malformed traffic.
- QUIC -> WSS -> TCP commands, break-before-make, retry ceilings, cancellation
  deadlines, network-change recovery, and clean disconnected convergence.
- Short CI matrix on every change and extended soak matrix on scheduled/manual
  isolated runs; neither publishes artifacts externally.

Acceptance:

- Every failure has a stable structured reason and bounded cleanup time.
- No fallback occurs inside Go without an explicit Rust command.

Merge unit: `test(networking): add deterministic reliability matrix`.

### N5B — performance and package lifecycle

Deliverables:

- Record CPU, resident memory, battery/energy, latency, throughput, loss, utun
  queue behavior, reconnect time, cancellation time, and diagnostic size.
- Define supported limits and regression thresholds from repeatable baselines.
- Run fresh install, upgrade, rollback, uninstall, crash, reboot, app relaunch,
  helper lifecycle, and cleanup with the exact signed candidate PKG.
- Notarization/stapling remains public-distribution hardening; if selected for
  the candidate, evidence must correspond to the exact tested bytes.

Merge unit: `test(release): close networking performance and PKG lifecycle`.

### N5C — physical-Mac and staging authorization gates

Physical-Mac-only cases:

- Sleep/wake, Wi-Fi/Ethernet switching, captive/offline transitions, energy
  behavior, and long-running interactive use that Virtualization.framework
  cannot faithfully represent.

Staging readiness review:

- Record endpoint ownership, TLS identity, policy-signing ownership, tenancy,
  authentication, rate limits, observability, revocation, and rollback.
- Do not contact the endpoint until the user explicitly authorizes that exact
  staging target.

Exit evidence:

- Isolated and physical matrices pass with no retained secret.
- The client returns to a clean disconnected state after every scenario.

Merge unit: `docs(networking): lock staged endpoint readiness evidence`.

N5 is complete only after N5A–N5C pass together.

## Common merge gates

Every merge unit runs the repository gates from the project skill. Go changes
also run formatting diff, module verification, race tests, vet, reproducible
build checks, and secret scans. Packaging/helper changes additionally validate
workflow/config syntax, nested signatures, entitlements, PKG signatures, SBOM,
and provenance. System work additionally stores redacted VM evidence and final
absence checks.

## Explicit authorization checkpoints

No additional authorization is needed for source, fixtures, in-memory tests,
loopback servers, builds, documentation, commits, or pushes.

Fresh authorization is required before:

- executing real utun or route mutation outside the already-designated
  disposable VM;
- using a real login Keychain account outside the scoped synthetic VM test;
- physical-Mac sleep/network-switch testing;
- contacting a staging or production endpoint;
- changing production PVE, ROS, K3s, DNS, routes, certificates, or credentials;
- publishing a GitHub Release or activating the updater.

## Program completion definition

N1–N5 are complete only when the exact signed candidate proves, from one clean
commit, that the production UI can establish one-site encrypted private
networking over QUIC with WSS/TCP fallback, apply only owned private routes,
coexist with Mihomo TUN, recover from every tested failure, expose only redacted
state, and leave no owned system state after disconnect or recovery.
