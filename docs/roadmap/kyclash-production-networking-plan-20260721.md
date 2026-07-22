# KyClash production networking implementation plan

Status: approved and locked after production-networking review

Planning amendment: the former Batch N1–N5 headings are historical workstream
groupings inside the single S1 production-networking delivery stage defined by
`kyclash-production-networking-single-stage-review-20260721.md`. They are not
independent stages or stopping points.

Date: 2026-07-21

Stdio protocol amendment: `kyclash-sidecar-stdio-review-20260721.md`

Long-range execution backlog:
`kyclash-production-networking-work-program-20260721.md`

Data-plane contract amendment:
`kyclash-dataplane-contract-review-20260721.md`

## Objective

Deliver the locked macOS arm64 single-site private-networking path:

```text
KyClash UI
  -> production Tauri controller
  -> authenticated Go sidecar IPC
  -> wireguard-go utun
  -> QUIC primary / WSS then TCP fallback
  -> Rust-owned route transaction through a signed macOS helper
```

The result must connect to a compatible KyClash server, expose health and
recovery state, coexist with Mihomo TUN, and restore every owned route and
tunnel resource after disconnect, failure, application restart, or forced
termination. DNS mutation, multi-site concurrency, peer-to-peer traversal,
dynamic routing, and production deployment are not part of this plan.

## Audit result

The repository contains substantial reusable POC code, but it is not a wired
production path:

- the UI commands instantiate only `MockNetworkSidecar`;
- the Go sidecar accepts authenticated bootstrap but deliberately returns
  `sidecar_unavailable` for profile, connect, and cancel;
- the Rust Unix process adapter is `networking-dev`-only and launches the mock
  binary with socket and instance arguments;
- the Go production sidecar refuses all command-line arguments and uses
  stdin/stdout for bootstrap and IPC, so the current Rust adapter cannot launch
  it;
- wireguard-go encryption, the custom carrier Bind, QUIC fragmentation, WSS,
  and TCP are proven only with userspace netstack or loopback tests;
- no production code creates macOS utun or reports its interface to Rust;
- the macOS route executor is lab-only and cannot be enabled in the app;
- signed policy and Keychain adapters exist, but no production controller
  fetches policy, resolves a credential, or supplies a private key to the
  sidecar;
- no compatible KyClash server is packaged or deployed for end-to-end staging.

The first implementation batch must therefore converge the Rust/Go process
contract. Starting with utun or UI wiring would build on incompatible runtime
assumptions.

## Locked safety boundaries

- The sidecar receives no secret in argv, environment variables, files, logs,
  panic output, or diagnostics.
- UI code never receives private keys and never constructs system commands.
- The sidecar owns WireGuard and carriers but never edits host routes or DNS.
- Rust owns the route journal and transaction order.
- A privileged component may execute only typed, normalized route operations;
  it may not expose a general command or shell surface.
- Production commands remain compile-time/default-off until the VM system gate
  passes. Mock development commands remain separate.
- No production endpoint, server, PVE, ROS, K3s, or release is touched without
  separate explicit authorization.

## Batch N0: Rust/Go runtime contract convergence

Goal: start and control the real Go executable without networking effects.

Status (2026-07-21): complete. The reviewed stdio contract, zeroizing Rust
launch context, bounded production runtime, shared bootstrap fixture, granular
stub command surface, and actual Go-child authentication/status/shutdown gates
are implemented. No system or external-network effect was used.

Tasks:

1. Write a protocol amendment defining one bootstrap record followed by
   newline-delimited, size-bounded request/response records over inherited
   stdin/stdout. Define EOF, malformed input, concurrent request, cancellation,
   event ordering, and shutdown behavior. The command surface is granular:
   prepare/stop tunnel, connect/disconnect a specified transport, sample health,
   and query status. The sidecar never chooses fallback policy.
2. Replace the dev-only socket assumptions with a production
   `StdioSidecarRuntime` that starts the binary with no arguments, pipes both
   directions, suppresses uncontrolled stderr, enforces timeouts, and kills the
   exact child on authentication failure.
3. Replace secret-bearing Rust `String` storage with zeroing byte material and
   generate the expected HMAC proof from the same canonical input as Go.
4. Add shared JSON fixtures and byte-for-byte Rust/Go contract tests for
   bootstrap, handshake, status, errors, request IDs, unknown fields, size
   limits, malformed frames, premature exit, and graceful disconnect.
5. Add actual-child tests using the built Go sidecar, including proof mismatch,
   crash/backoff, no argv/env leak, and constant failure output.

Exit gate:

- Rust launches the real Go sidecar and completes authenticated status and
  shutdown round trips with no socket, route, Keychain, utun, or external I/O.

## S1 workstream: Stateful sidecar and compatible lab server (formerly Batch N1)

Goal: turn the Go process from a protocol stub into a real userspace data plane.

Progress (2026-07-21): the actual Go child now owns a strict, persistent IPC
session that validates the shared profile, enforces profile -> tunnel -> one
explicit Rust-selected carrier, refuses make-before-break, reports bounded
redacted status, and cleans session state on disconnect. Independently, the
real userspace WireGuard integration carries bidirectional encrypted traffic
over loopback QUIC, WSS, and TLS/TCP servers through the actual child IPC
session.

N1A through N1D were complete at this historical checkpoint: strict shared
data-plane contracts, the real userspace backend driving wireguard-go through
an explicit single-carrier switchboard, the compatible loopback peer,
fallback, timeout cleanup, crash/backoff, and repeated actual-child cycles had
passed their gates. The concurrent-cancellation subclaim is reopened by the
locked `kyclash-sidecar-stdio-v2-control-review-20260722.md` amendment because
protocol v1 could not legally carry that control exception. Later N2 source
work remains valid while this atomic protocol remediation executes first.

Tasks:

1. Implement strict profile, tunnel, named-transport, health, status, cancel,
   and disconnect handling; reject invalid ordering and concurrent operations.
2. Convert the validated profile into carrier and WireGuard device settings
   without logging endpoint credentials, peer keys, or private material.
3. Instantiate QUIC first and ordered WSS/TCP fallbacks through the existing
   carrier factory and custom WireGuard Bind.
4. Add bounded health facts and structured error/status events. Rust owns the
   fallback threshold and issues explicit break-before-make commands; the
   sidecar does not select the next carrier.
5. Add a repository-owned compatible lab server implementing the reverse KYNP
   carrier contract and a WireGuard peer. It must default to loopback, use
   ephemeral test credentials, and refuse non-lab binding without confirmation.
6. Exercise real encrypted bidirectional traffic, cancellation, UDP blocking,
   fallback, reconnect, repeated connect/disconnect, and sidecar crashes using
   userspace netstack only.

Exit gate:

- The real sidecar and lab server carry bidirectional WireGuard traffic over
  QUIC and both ordered fallbacks, while all host interfaces and routes remain
  unchanged.

## S1 workstream: Production Rust controller and credential path (formerly Batch N2)

Goal: replace the in-process mock behind a still-default-off production API.

Tasks:

1. Add a `networking-production` feature separate from `networking-dev` and
   keep it absent from default/release builds until Batch N4 closes.
2. Implement an async controller owning sidecar lifecycle, request correlation,
   operation timeouts, cancellation, health polling, crash recovery, and
   redacted state events.
3. Fetch or import only a signed network-policy envelope v2, verify it against a
   pinned KyClash policy key, validate signed `issued_at`, `expires_at`, and
   unique policy revision fields, and reject unsigned, expired, replayed, or v1
   production configuration. Existing v1 fixtures remain test-only.
4. Resolve only a fixed `keychain:` reference from
   `net.kysion.kyclash.networking`, generate device WireGuard material locally
   when absent, and send it once through the inherited bootstrap channel.
5. Add typed production Tauri commands for site list/status/connect/cancel/
   disconnect and allowlisted diagnostic export. Do not reuse the dev command
   names or expose endpoint/credential fields.
6. Wire the existing networking UI model to a production adapter behind the
   compile-time gate, with explicit connecting, fallback, cancelling, recovery,
   and error states.
7. Replace the POC transaction order with the locked order: validate and
   authenticate, prepare utun, connect the Rust-selected carrier, pass its
   health gate, durably journal and apply routes. Cleanup always rolls routes
   back before stopping utun and clearing secrets.

Exit gate:

- A production-gated app build controls the real userspace sidecar and lab
  server end to end, while route and utun adapters remain fake and test-asserted.

## S1 workstream: Bundling, binary trust, and macOS utun (formerly Batch N3)

Goal: create and supervise a real macOS tunnel without applying private routes.

Tasks:

1. Reproducibly build the arm64 Go sidecar, generate SBOM/license inventory,
   bundle it as a signed nested executable, and verify its expected hash,
   architecture, Team ID, and designated requirement immediately before launch.
2. Implement wireguard-go macOS utun creation, configured MTU and local
   addresses, deterministic device teardown, and an IPC result containing only
   the validated interface name and non-secret facts.
3. Harden interface-name validation; never infer ownership from an arbitrary
   `utun*` name. Bind ownership to the live child instance and operation ID.
4. Cover create/configure/up/down, repeated cycles, sidecar kill, app kill,
   login/logout, and stale-device observation in the disposable VM.
5. Treat inherited stdin EOF as parent death: cancel carriers, close the
   wireguard-go device/utun, zero secrets, and exit within a bounded deadline.

Exit gate:

- The signed app launches only its signed sidecar, establishes encrypted lab
  traffic through a real utun, and leaves no owned device after every tested
  termination path. No private route is installed yet.

## S1 workstream: Privileged transactional routes and Mihomo coexistence (formerly Batch N4)

Goal: route configured private CIDRs through the owned utun and always restore
the previous system state.

Tasks:

1. Add a dedicated signed macOS helper registered with `SMAppService` and a
   typed XPC protocol. The helper validates the connecting application's audit
   token/designated requirement and exposes no command string or executable
   path. General shell execution is rejected.
2. Move the tested macOS route planner behind that typed privileged boundary;
   preserve pre-mutation discovery, conflict refusal, durable pending journal,
   idempotent rollback, and root-owned state-directory checks.
3. Bind every route request to the authenticated app, sidecar instance,
   operation ID, exact utun ownership record, and validated profile CIDRs.
   Each applied transaction also holds an XPC lease; invalidation or controller
   death triggers helper-side rollback while Rust retains the durable journal
   for restart reconciliation.
4. Enforce lifecycle order: sidecar carrier health, utun ready, journal durable,
   routes apply; on failure, routes rollback before utun stop and secret clear.
5. Run fixed isolated VM scenarios for normal disconnect, failure at every
   boundary, sidecar abort, app abort, helper restart, machine reboot, route
   conflict, and journal corruption.
6. After the typed active-Mihomo-interface ownership amendment, start the
   packaged Mihomo TUN in the disposable VM and prove allowed less-specific
   coverage, rejection of unknown VPN ownership, no default-route takeover,
   and complete cleanup for IPv4 and IPv6.

Exit gate:

- A private test service is reachable only while connected; every owned route,
  journal entry, utun, child process, and synthetic credential state is absent
  after disconnect or recovery, including with Mihomo TUN active.

## S1 workstream: Reliability and staged endpoint gate (formerly Batch N5)

Goal: close production-quality client behavior before enabling it by default.

Tasks:

1. Run loss, jitter, rate limit, UDP block, TLS failure, packet-size boundary,
   replay, long-duration throughput, suspend/resume, and network-interface
   switching matrices against the isolated compatible server.
2. Prove fallback order QUIC -> WSS -> TCP, break-before-make, bounded retry,
   cancellation latency, and recovery to a clean disconnected state.
3. Measure CPU, memory, battery, latency, throughput, packet loss, utun queue
   behavior, and diagnostic size; document supported limits.
4. Run fresh install, upgrade, rollback, uninstall, crash, and reboot lifecycle
   tests with the signed/notarized PKG in disposable VMs, then perform the
   physical-Mac-only sleep and network-switch checks.
5. Review a compatible staging endpoint and its certificate/policy ownership.
   External contact begins only after explicit endpoint authorization.

Exit gate:

- All isolated matrices pass, no secret appears in retained evidence, and the
  physical Mac confirms the cases Virtualization.framework cannot represent.

## Batch N6: Release activation

Goal: enable the already-tested production path without enabling publication or
updates implicitly.

Tasks:

1. Remove the temporary production compile gate only in the reviewed release
   candidate and retain an operator kill switch.
2. Replace development fixtures with the pinned production policy key and
   authorized endpoint configuration; no private signing key enters the app.
3. Rebuild, sign, notarize, staple, and re-run the complete client/sidecar test
   matrix from one clean commit.
4. Keep GitHub updater activation and Release publication as separate explicit
   transactions governed by the updater plan.

Exit gate:

- The notarized macOS arm64 candidate provides one-site private networking and
  recovery through the production UI, with release approval evidence. No GitHub
  Release is created by completing this batch alone.

## Locked implementation decisions

1. **IPC amendment:** adopt stdio as the single production sidecar transport and
   use the reviewed protocol-v1 single-flight request/response contract, with
   status/health polling and correlated cancellation. This matches the already-
   hardened Go bootstrap, avoids ambiguous response/event multiplexing, avoids
   filesystem socket ownership, and keeps secrets off argv and env.
2. **Privileged route executor:** use a dedicated signed KyClash route helper
   registered by `SMAppService` and reached through typed XPC.
   The inherited service IPC exposes Mihomo core lifecycle rather than a typed
   route transaction API; expanding that external dependency would couple
   private-route authority to unrelated proxy-service behavior. The helper must
   expose only normalized discover/apply/rollback/recover operations and remain
   independently uninstallable.

The compatible server is included as a lab implementation in N1. Its production
deployment, tenancy, authentication, policy issuance, and operations require a
separate server architecture and authorization; client completion must not be
equated with production infrastructure deployment.

## Merge gates for every batch

```bash
corepack pnpm run typecheck
corepack pnpm run web:build
corepack pnpm run lint
corepack pnpm run i18n:check
cargo fmt --all --check
cargo test -p clash-verge --all-features --lib
cargo clippy -p clash-verge --all-features --all-targets -- -D warnings
(cd network-sidecar && gofmt -w . && go mod verify && go test -race ./... && go vet ./...)
git diff --check
```

System-mutation batches additionally retain redacted VM evidence and prove final
absence of the exact owned interface, route, journal, child process, and test
Keychain account.
