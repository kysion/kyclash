# KyClash Implementation Plan

Status: Locked for execution

Review record: `docs/roadmap/kyclash-plan-review-20260721.md`

Distribution amendment: `docs/roadmap/kyclash-github-updater-review-20260721.md`

Architecture baseline: `docs/architecture/kyclash-networking-v1.md`

Runtime implementation: `docs/architecture/kyclash-network-runtime-v1.md`

## Iteration 0: Safe product baseline

Goal: produce a reproducible KyClash build that cannot replace itself with an
upstream Clash Verge Rev release.

Progress (2026-07-21): development baseline complete. The locally reproducible
PKG now has valid Developer ID Application and Installer signatures after
explicit authorization. Notarization and stapling are optional
public-distribution enhancements; installation lifecycle tests remain release
gates.

- Disable application update endpoints until KyClash signing is available.
- Correct portable archive branding without renaming compatibility binaries.
- Classify visible branding versus compatibility identifiers.
- Keep legacy configuration import explicit rather than silent.
- Run frontend, Rust, formatting, and configuration validation gates.
- Rebuild and smoke-test the macOS arm64 application from this workspace.

Completed in the current workspace:

- Application endpoints are empty and frontend/backend update gates are off.
- Removed the inherited updater verification key together with the updater
  configuration block; KyClash will add a new endpoint and public key only as
  one reviewed release-ownership change.
- Updater artifacts are not generated without a KyClash signing procedure.
- Removed the independently triggerable inherited updater workflow and updater
  jobs from the release workflow, disabled updater JSON generation and updater
  signing inputs, and removed inherited updater keys from fixed-WebView2 Tauri
  overrides.
- Added a fail-closed release-ownership verifier to CI and the project Skill.
  Standard updater-generation commands now refuse to run until the endpoint,
  key, rollback metadata, gates, and workflow are enabled in one reviewed
  change.
- Removed inherited scheduled autobuild, deploy-test release, asset deletion,
  and Telegram publishing workflows. They could mutate external releases or
  notify upstream channels without satisfying the macOS-first release gates.
- Replaced the inherited multi-platform tag workflow with a least-privilege,
  macOS-arm64-only draft pipeline. It is inert unless the repository variable
  `KYCLASH_MACOS_RELEASE_ENABLED` is explicitly set to `true`, requires the
  protected `kyclash-production-release` environment, and verifies Application
  and Installer signatures, checksum, and provenance before creating a draft.
  Optional notarization additionally gates stapling and Gatekeeper assessment.
- Portable archives use KyClash branding while retaining `clash-verge.exe`.
- Release, autobuild, download, and Telegram workflow links and visible release
  names target `kysion/kyclash` and display KyClash rather than publishing
  upstream Clash Verge Rev branding.
- Removed inherited upstream download channels, AutoBuild instructions,
  promotions, funding metadata, and support routing from the maintained Chinese
  and English README and KyClash issue templates. Historical untranslated
  upstream README copies were removed instead of presenting upstream packages
  as KyClash releases.
- Update-detail links and contributor documentation identify KyClash, while
  README documents the deliberately retained executable, service, crate, IPC,
  and legacy-registry cleanup identifiers required for compatibility.
- Typecheck, web build, ESLint, Rustfmt, unit tests, and Clippy pass.
- `KyClash_2.5.3_aarch64.pkg` is the macOS installation artifact, built from
  the Tauri application bundle with bundle identifier
  `net.kysion.kyclash`.
- Rebuilt the arm64 App and PKG from commit `30ef92f1` after explicit signing
  authorization. The evidence record confirms KyClash display identity, arm64
  architecture, valid Application and Installer signatures, trusted timestamp,
  size, SHA-256, and the expected Gatekeeper/stapler refusal for the deliberately
  unnotarized internal artifact. No install, notary, upload, or release action
  occurred.
- Revalidated the CI packaging path with
  `KYCLASH_NOTARIZATION_ENABLED=false`: Developer ID Application and Installer
  signatures remained mandatory and valid, while the expected unnotarized
  Gatekeeper warning did not stop internal package production.
- Rebuilt and visibly launched the signed arm64 KyClash bundle in the
  disposable Apple Virtualization.framework guest. The startup blocker was an
  unconditional Tauri updater-plugin registration against the intentionally
  absent base updater configuration; registration is now gated by the existing
  `APP_UPDATES_ENABLED` flag, while updater endpoints, keys, permissions, and
  release activation remain disabled.

Exit criteria:

- No configured Clash Verge Rev application updater endpoint.
- Typecheck, web build, Rust unit tests, and `git diff --check` pass.
- A macOS arm64 artifact can be reproduced from the current workspace.
- Remaining compatibility identifiers have documented reasons.

## Iteration 1: Versioned networking contract

Goal: establish compile-time contracts without changing host networking.

Progress (2026-07-21): complete.

- Add `kyclash-network.schema.json` with fixtures and validation tests.
- Add matching Rust and TypeScript types with parity tests.
- Add the locked state machine and structured error codes.
- Define IPC envelopes, protocol negotiation, cancellation, and event ordering.
- Add a mock control plane and mock sidecar.

Completed in the current workspace:

- Added JSON Schema v1 plus valid and unsupported-version fixtures.
- Added strict Rust validation and matching TypeScript contracts.
- Added an explicit state machine and stable structured error codes.
- Added versioned IPC request, response, status, and ordered-event contracts.
- Added a runtime-neutral operation tracker that validates operation IDs,
  emits every state change with a per-operation monotonic sequence, and applies
  deterministic, idempotent timeout and cancellation cleanup with structured
  reasons. Cancellation for a different operation cannot mutate state.
- Added in-memory mock control-plane and sidecar implementations with no
  process, route, DNS, tunnel, or external network effects.
- Added coverage for round trips, unknown versions, invalid configuration,
  invalid transitions, cancellation, timeout, reconnect baseline, and restart.

Exit criteria:

- Invalid and unknown schema versions fail closed.
- Rust and TypeScript fixtures round-trip identically.
- State transition tests cover cancellation, timeout, and restart.

## Iteration 2: Sidecar lifecycle and diagnostics

Goal: prove process isolation and observability without WireGuard or routes.

Progress (2026-07-21): complete for the locked macOS-first scope.

- Start, authenticate, monitor, restart, and stop the mock sidecar.
- Add bounded restart backoff and crash-loop protection.
- Persist no secrets in arguments or logs.
- Export an allowlist-based redacted diagnostic bundle.
- Add a read-only networking status page behind a development feature flag.

Completed in the current workspace:

- Added a runtime-neutral sidecar lifecycle controller.
- Added protocol/instance/authentication handshake validation.
- Added bounded exponential backoff and crash-loop protection.
- Added explicit stop and failed-start recovery behavior.
- Added an allowlist-only diagnostic snapshot with secret-leak tests.
- Added the `networking-dev` compile-time boundary and read-only status model.
- Added a standalone `networking-dev` mock-sidecar binary and Unix process
  adapter using a private local socket.
- Authentication material is delivered through inherited standard input and is
  absent from process arguments, environment variables, and diagnostics.
- Added actual-child integration tests for authenticated startup, liveness,
  shutdown, stale-socket recovery, and refusal to replace a regular file.
- Wired the read-only development status model to a feature-gated Tauri
  command. No network interface, route, DNS setting, or external endpoint is
  touched by this command or the mock process.

Remaining before Iteration 2 can close:

- None for the macOS-first scope. Run `pnpm dev:networking` to expose the
  read-only development status page and matching Tauri command.

Windows named-pipe/process support is intentionally deferred to the Windows
platform phase after the macOS MVP.

Exit criteria:

- Sidecar crashes cannot crash the Tauri application.
- Stale IPC and process state recover after application restart.
- Automated tests demonstrate secret redaction.

## Iteration 3: Route transaction POC

Goal: safely apply and roll back private CIDRs in an isolated lab.

Progress (2026-07-21): transaction persistence, macOS read-only discovery, and
a feature-gated fixed-scope route lab executor are complete. Its fixed TEST-NET
normal and forced-exit recovery cycles passed on a disposable GitHub-hosted
macOS runner. A local Apple Virtualization.framework lab is being prepared for
package lifecycle and broader isolated coexistence work.

- Implement platform route discovery and conflict detection.
- Add an ownership journal and idempotent transaction API.
- Exercise connect failure, forced termination, restart, and rollback.
- Test coexistence with Mihomo TUN.
- Keep DNS mutation out of scope.

Completed in the current workspace:

- Added runtime-neutral route discovery, mutation, and journal traits.
- Added CIDR normalization and overlap conflict refusal while allowing default
  underlay routes.
- Added idempotent apply/rollback, per-route ownership recording, stale-state
  recovery, and explicit rollback-failure propagation.
- Added in-memory fault tests without route, DNS, interface, tunnel, or
  external network effects.
- Added a versioned file journal with atomic replacement, private Unix
  permissions, deterministic serialization, and fail-closed handling for
  corruption, unknown versions, symlinks, and unavailable storage.
- Persisted each pending mutation before invoking the platform adapter so a
  forced termination can recover the route whose outcome was not confirmed.
- Added strict parsers for macOS IPv4 and IPv6 `netstat` route tables,
  including abbreviated split-default destinations used by TUN interfaces.
- Added a macOS read-only discovery adapter and verified it against the local
  route table. Its mutation methods always refuse with `PermissionDenied`.
- Added fault coverage for journal failure before mutation, journal failure
  after mutation, durable pending-route recovery, corruption, and restart.
- Locked and implemented the v2 Mihomo TUN coexistence boundary: only a
  configured active Mihomo interface may contribute a less-specific covering
  route. The typed owner, family facts, protocol reply, journal, Rust source,
  Objective-C bridge, and Swift helper are version-pinned; unknown VPN
  interfaces and exact or more-specific routes always fail closed, and `utun*`
  names never imply ownership by themselves. The packaged live-Mihomo VM gate
  remains separate and is not claimed by the synthetic fixture matrix.
- Added the IPv4/IPv6 coexistence matrix for Mihomo split routes, unknown VPN
  routes, exact conflicts, more-specific conflicts, and default underlay
  routes, with all mutation effects confined to the in-memory adapter.
- Added a shell-free macOS route-command planner for normalized IPv4/IPv6
  add/delete arguments, including option-injection and malformed-interface
  refusal. The planner returns data only and never starts `/sbin/route`.
- After explicit route-lab authorization, added a `networking-route-lab`
  compile-time adapter that executes only planner-produced `/sbin/route` argv,
  with no shell, stdin, captured diagnostics, retry, or application command
  wiring. Injected-executor tests prove exact add/delete ordering and fail-closed
  error propagation without touching the host route table.
- Added a fixed-scope lab executable for the authorized disposable-host gate.
  It accepts only cycle, abort-after-apply, leave-for-recovery, and recover
  modes; can mutate only RFC 5737 test route `192.0.2.0/24` through `lo0`;
  requires an exact explicit confirmation environment value plus root;
  serializes runs with a kernel-held lock that is released on process death;
  and uses the durable route journal for normal and forced-exit recovery. Its
  private `/var/tmp` directory must be a real root-owned directory.
- Hardened the journal directory boundary before privileged lab use: the final
  state directory must be a real directory rather than a symlink, preventing a
  pre-created `/var/tmp` link from redirecting journal writes or permission
  changes. A Unix regression test proves the linked target remains untouched.

Remaining system validation:

- The installed packaged-Mihomo coexistence matrix now passes in the local
  disposable macOS VM. Iteration 3 is not release-closed until the production
  Rust live-source/app path, private-service reachability, abort/reboot, and
  complete final-absence cases pass with the production-feature candidate.

Exit criteria:

- KyClash never overwrites an unowned conflicting route.
- Every injected failure restores the recorded pre-connect state.
- No production host or network is used without explicit authorization.

## Iteration 4: WireGuard and transport POC

Goal: validate the data plane in an isolated environment.

Progress (2026-07-21): complete for the isolated POC scope. Real WireGuard
encryption runs through authenticated loopback QUIC and the KyClash custom Bind;
no host tunnel, route, DNS mutation, credential store, or external endpoint is
used.

- Integrate the selected WireGuard adapter behind a stable trait.
- Implement QUIC primary transport and measured health checks.
- Implement WSS/TCP fallback with break-before-make behavior.
- Test UDP blocking, packet loss, jitter, suspend/resume, and network changes.

Completed in the current workspace:

- Added stable WireGuard and transport adapter traits without selecting or
  invoking a privileged implementation.
- Added a data-plane controller that starts and stops the tunnel, selects QUIC
  first, measures reachability/latency/jitter/loss, and applies a configurable
  consecutive-failure threshold.
- Enforced break-before-make by clearing the active transport only after its
  disconnect succeeds and before attempting WSS/TCP or a QUIC recovery.
- Added deterministic simulations for primary failure, ordered fallback,
  health-threshold fallback, network-change recovery, total transport failure,
  and tunnel cleanup.
- Integrated a private-route transaction boundary into the data-plane
  lifecycle. Route-apply failure, total transport failure, failed health
  fallback, and explicit disconnect all roll routes back before stopping the
  WireGuard adapter, with best-effort cleanup covered by ordered event tests.
- Added a versioned Ed25519-signed remote-policy envelope and pinned trust
  store. Unsigned profiles, unknown key IDs, unknown algorithms, malformed
  envelopes, tampered payloads, invalid signatures, and invalid decoded
  profiles all fail closed before a profile reaches the data plane.
- Locked the real data-plane implementation as a dedicated Go sidecar embedding
  upstream `wireguard-go`, a KyClash custom Bind, `quic-go`, and
  `coder/websocket`, with one common bounded packet envelope for QUIC, WSS, and
  TCP. The review also locks the privilege split, secret channel, lifecycle,
  rejected alternatives, and isolated validation gates.
- Added the standalone sidecar module and its transport-independent v1 frame
  codec. Tests cover canonical round trips, control-frame constraints, unknown
  fields, payload bounds, every truncation point, trailing datagram bytes,
  monotonic sequence enforcement, and fuzz-safe decoding without network or
  system effects.
- Added a carrier-neutral reliable-stream adapter for WSS and TCP with
  serialized writes, bounded packets, replay refusal, context cancellation,
  deadline cleanup, and idempotent close behavior, verified entirely over
  in-memory connections.
- Added the TCP fallback dialer with mandatory TLS 1.3, bounded connection
  setup, standard certificate-chain and server-name verification, and loopback
  tests proving authenticated packet exchange and wrong-identity refusal.
- Added the WSS fallback with a pinned WebSocket dependency, mandatory
  `wss://` and TLS 1.3, certificate/hostname verification, disabled compression,
  and refusal of URL credentials, queries, and fragments. Loopback tests use an
  ephemeral TLS WebSocket server and prove packet exchange and identity refusal.
- Reviewed and corrected the QUIC datagram size assumption before implementation.
  The locked amendment adds bounded, expiring, replay-resistant QUIC
  fragmentation while retaining the common frame header and all existing
  transport and fallback semantics.
- Implemented the reviewed fragment header and bounded in-memory reassembler.
  Tests cover canonical encoding, out-of-order completion, invalid counts,
  duplicates, completed-message replay, inconsistent metadata, expiry,
  concurrent assembly limits, and reconstructed-size limits.
- Locked a conservative 1,024-byte QUIC fragment payload after verifying that
  the selected library exposes path-size changes only as send errors. KyClash
  fragments before sending and fails into normal fallback if the path shrinks.
- Locked a 64-sequence QUIC replay window so valid datagram reordering is
  accepted once while duplicates and stale sequences fail closed. Ordered
  WSS/TCP carriers retain strict monotonic receive validation.
- Implemented the authenticated QUIC datagram carrier with pre-send
  fragmentation, bounded reassembly, a per-connection replay window, TLS 1.3
  and ALPN identity, cancellation, and idempotent cleanup. Loopback tests prove
  large-packet fragmentation/echo and wrong-certificate refusal.
- Added the KyClash `wireguard-go` custom Bind adapter without creating a TUN
  device. It maps one opaque peer endpoint onto the selected packet carrier,
  implements bounded receive/send and close cancellation, rejects wrong
  endpoints and undersized buffers, and passes in-memory conformance tests.
- Added an isolated end-to-end WireGuard test using `wireguard-go`'s userspace
  netstack on both ends. A TCP ping/pong crosses real WireGuard encryption and
  the KyClash custom Bind entirely in memory, proving data-plane integration
  without creating a host interface, route, DNS entry, or external connection.
- Added the production sidecar executable bootstrap boundary. It refuses all
  command-line arguments, accepts one bounded and strict stdin message, validates
  protocol/instance/auth/private-key fields, emits only an HMAC authentication
  proof, redacts formatting and errors, and clears owned secret buffers.
- Added entrypoint-level leak tests covering rejected secret-bearing arguments,
  inherited secret-bearing environment state, malformed bootstrap input, and
  malformed post-authentication IPC. Failure diagnostics stay constant and do
  not format attacker-controlled errors or crash output.
- Added a path-scoped macOS sidecar CI gate pinned to Go 1.26.5. It verifies
  module hashes and formatting, runs race tests and vet, proves two builds are
  byte-identical, records SHA-256 and embedded module metadata, generates a
  license-aware CycloneDX SBOM with a pinned tool, and retains evidence without
  publishing or bundling the sidecar.
- At the historical N0 checkpoint, kept the production sidecar alive after
  authentication with the exact Rust v1 request/response envelope. Status and
  disconnect worked, malformed or unknown requests failed closed, and
  profile/connect/cancel returned a structured `sidecar_unavailable` error
  until real networking gates were explicitly enabled. The locked protocol-v2
  control review now supersedes that wire version without rewriting the
  historical evidence.
- Added a shared status-response fixture asserted by both Rust and Go tests so
  changes to result tagging, state spelling, nullability, or field names cannot
  silently break controller/sidecar compatibility.
- Added the full isolated composition test: a multi-packet TCP payload traverses
  userspace WireGuard encryption, the custom Bind, bounded KyClash
  fragmentation, authenticated QUIC datagrams, reassembly, peer decryption, and
  the reverse path. All addresses and certificates are ephemeral loopback or
  userspace-netstack values.
- Added a reproducible fragmented-QUIC loopback benchmark and measurement
  record. Three Apple M5 runs measured a 401–407 microsecond 4 KiB round trip
  and 10.07–10.20 MB/s reported payload rate; the record explicitly limits this
  to local carrier evidence and lists all remaining impaired-link and host tests.

Remaining:

- Release validation still requires controlled packet-loss/jitter/UDP-blocking,
  sustained throughput, suspend/resume, and network-switch measurements on
  disposable authorized macOS hosts and compatible isolated server endpoints.
  This does not reopen the completed source-level isolated POC.

Exit criteria:

- QUIC and fallback behavior match the locked state machine.
- Tunnel and route cleanup remain transactional under fault injection.
- Performance measurements and limitations are documented.

## Iteration 5: macOS MVP

Goal: deliver one-site private access with user-facing recovery and diagnostics.

Progress: the 2026-07-21 source-level baseline passed, and subsequent signed
disposable-VM work closed S1.12. The aggregate S1 stage remains in progress at
S1.13; safe source and VM work is not complete. Production connection controls
and real credential access remain default-off pending the system, server, and
activation gates recorded in `kyclash-completion-audit-20260721.md`.

- Add site selection, connect/disconnect, health, routes, and diagnostics UI.
- Integrate system credential storage.
- Complete signing, GitHub updater ownership, and rollback procedures.
- Execute fresh install, upgrade, uninstall, sleep, network switch, and crash tests.

Completed in the current workspace:

- Expanded the development-only networking page with one-site identity,
  connect/disconnect controls, state, sidecar lifecycle, active transport,
  planned private routes, health metrics, and last-error diagnostics.
- Backed the controls with an in-process `MockNetworkSidecar` and embedded
  validated fixture. The page and commands remain compile-time gated and do
  not create a process, socket, tunnel, route, DNS mutation, credential lookup,
  or external request.
- Added a Rust lifecycle test for mock connect, status projection, route
  display, transport display, and disconnect.
- Added user-initiated JSON diagnostic export containing only the displayed
  allowlist fields; it omits control-plane and transport endpoints, identity
  references, peer keys, authentication material, and credential values.
- Added a credential-store boundary with strict `keychain:` references,
  non-serializable secret material, fixed redacted debug output, memory clearing
  on drop, and an in-memory test adapter.
- Added a macOS Keychain adapter scoped to the fixed
  `net.kysion.kyclash.networking` service namespace. Automated tests validate
  construction and redaction only; they do not write, read, or delete host
  Keychain entries.
- After explicit credential-lab authorization, added a feature-gated Keychain
  lifecycle executable with a fixed KyClash service and synthetic account. It
  generates a random value internally, refuses to overwrite a pre-existing
  item, verifies the exact read, clears memory, deletes the item,
  verifies absence, and provides fixed-scope interrupted-run cleanup. It has no
  application command wiring and remains unexecuted on the daily-use account.
- Hardened macOS release packaging so CI requires an Installer signing
  identity. Optional notarization material is isolated to the protected release
  environment and never passed as a command argument or stored in the repository.
- Locked the macOS release and rollback procedure. It separates Application and
  Installer signatures, records optional notarization/stapling and required
  lifecycle evidence, defines immutable rollback artifacts and stop triggers,
  and permits updater re-enablement only as one reviewed KyClash-owned
  endpoint/key/manifest/test transaction.
- Locked GitHub Releases as the KyClash-owned updater origin and added an inert
  Tauri configuration template, strict metadata schema/sample/validator,
  deterministic metadata builder, streaming minisign verifier, rollback policy,
  and CI variable/secret contract. Base builds and runtime update gates remain
  disabled; no Release or endpoint activation is performed by this preparation.
- Added a fail-closed runtime metadata policy ahead of any future activation.
  Both background download and cached-install refresh reject non-KyClash URLs,
  unknown/extra fields, sample or invalid source metadata, mismatched
  version/URL/signature, invalid artifact facts, and non-older rollback targets.
- Added install-time re-verification for the silent updater's on-disk cache.
  Cached bytes are checked again with the pinned Tauri public key and freshly
  fetched owned signature; missing key or altered bytes delete the cache and
  refuse installation.
- Applied the owned metadata policy to the frontend manual-check wrapper as
  well, so future JavaScript updater permissions cannot bypass the Rust silent
  updater's GitHub, platform, rollback, and strict-field checks.

Remaining:

- The production command boundary is now explicitly composed and lazy, but the
  normal/release build remains default-off until the packaged live-Mihomo,
  route, and lifecycle gates close. A bundle without an authorized signed
  policy/trust resource fails closed during initialization rather than falling
  back to a mock or guessed endpoint.
- Complete GitHub updater ownership and macOS installation lifecycle validation
  with authorized hosts. A historical arm64 candidate was notarized and
  stapled, but the current internal candidate is Developer ID signed and
  intentionally unnotarized. Notarization/stapling is optional public-
  distribution hardening; if selected for a later candidate, its exact bytes
  must repeat that optional gate.
- Re-enable updater capabilities only in the same separately authorized change
  that injects the KyClash public verification key, publishes signed immutable
  GitHub assets and rollback metadata, enables permissions and runtime gates,
  and passes lifecycle tests. Current builds remain disabled.
- Execute the production networking work packages below as one stage before replacing the mock or
  enabling a release build.

## Single-stage production networking execution plan — 2026-07-21

Production networking continuation is decomposed and ordered in
`kyclash-production-networking-plan-20260721.md`; its single S1 stage and
dependency-ordered work packages (historically labelled N1–N5),
dependencies, evidence, and authorization checkpoints are locked in
`kyclash-production-networking-work-program-20260721.md`. The original first
work package was Rust/Go runtime contract convergence: the Rust Unix adapter
had launched the argument-based mock protocol while the Go production sidecar
accepted only stdin/stdout. That real-child protocol gate has since passed;
current status is recorded in the S1 continuation below.

N0 progress (2026-07-21): complete. The locked stdio successor now defines a
64-KiB-bounded protocol-v2 bootstrap/handshake/request/response contract,
ordinary single-flight requests, and the one exact-target Cancel exception for
an active Connect or Health request. EOF and shutdown semantics and Rust-owned
granular transport selection remain unchanged. The production
`StdioSidecarRuntime` launches the actual Go executable with empty argv and
inherited environment, supplies zeroizing byte secrets through stdin, checks
the canonical v2 HMAC proof, correlates and fully drains both race responses,
terminates ambiguous or unauthenticated sessions, and performs graceful
disconnect. Shared bootstrap and handshake/HMAC fixtures are decoded by both
languages. Actual-child tests prove authenticated status/shutdown and
proof-mismatch termination without socket, route, Keychain, utun, or external
network I/O.

N1 data-plane progress is complete, including the locked stdio protocol-v2
cancellation amendment. The real child validates profiles, enforces granular
tunnel/carrier state order and explicit break-before-make, and carries
encrypted payload traffic over QUIC, WSS, and TLS/TCP. Shared v2 fixtures,
strict JSON and downgrade refusal, exact Connect/Health cancellation races,
both response orders, bounded timeout/child reap, crash-loop backoff, and
post-cancel carrier reuse pass across Rust and Go. The aggregate system
criterion remains in progress at S1.13. The exact policy-identity portion of
the locked production restart/rematerialization implementation is complete;
the helper accepted-connection barrier and Objective-C first-wins terminal
generation boundary are now closed source gates in the XPC
generation/rematerialization chain. Rust XPC-C is also locally closed: it owns
one bounded replacement, performs read-only discovery reconciliation on the
same generation, retains frozen ownership on failed recovery, and never
replays route mutations on a fresh generation. The first typed service-lifecycle
slice is also closed at the controller boundary: positive never-spawned/exact-
reap receipts, permanent old-handle mutation refusal, and immediate secret
destruction are enforced. The route-boundary retirement slice is now locally
closed as well: exact idle ownership, native-call absence, synchronous
generation destruction, a sealed non-copyable receipt bound to a process-unique
boundary incarnation, and retained-old-boundary mutation refusal are covered
by focused and full-library tests. The service mutation gate, queued/unjoined
task ownership, generation-bound Connect reservation, and command CAS
rematerialization have since closed locally. The current source chain also
binds each freshly prepared broker session dynamically to the Rust runtime
generation and composes the production v3 route boundary; S1.13 remains open
for the exact-candidate disposable-VM aggregate, not for an unwired factory.

The plan then advances through a stateful userspace sidecar and compatible lab
server, the production Rust/Keychain controller, signed sidecar bundling and
real macOS utun, privileged transactional routes plus Mihomo coexistence,
reliability/staging validation, and a separately reviewed release activation.

## Current S1 continuation — 2026-07-22

The locked single-stage work program is authoritative for current status. The
production composition gap is now closed at the source boundary: production
app setup registers a fixed-resource provider, an explicit initialization
command verifies the app-owned signed policy/trust resources, and Connect is
the only path that lazily materializes the Keychain, typed XPC route boundary,
trusted Go sidecar runtime, and live Mihomo source. Missing policy resources
fail closed and do not guess an endpoint, key, credential, or route.

The restart hardening now commits a strict v2 identity containing only the
revision, exact signed-envelope SHA-256, and key ID under a bounded
descriptor-relative cross-process transaction. Exact restart is zero-write;
same-revision byte changes, expiry, lower revisions, metadata/path swaps,
concurrent writers, publication faults, and unprovable rollback fail closed.
Legacy revision-only records migrate only on a higher authenticated revision.
Initialization remains single-flight and installs only a deferred factory, so
this source evidence does not claim an App launch, XPC connection, Keychain
read, sidecar, utun, or route mutation. The Swift helper accepted-connection
barrier, Objective-C XPC-B terminal-generation/transport-status boundary, and
Rust XPC-C replacement/reconciliation boundary are now closed source units.
XPC-C has local focused and full-library test, Clippy, formatting, and diff
evidence; it does not claim a live production endpoint. The controller's exact
child-absence retirement receipt and the route boundary's exact native-
generation retirement receipt are now implemented and locally tested. The
service mutation gate, generation-bound reservation, queued/joined route-task
ownership, and command-layer rematerialization CAS are now implemented and
locally tested. Connect reserves before task publication; replacement
compare-removes only the selected Arc/generation, builds off-slot, and retains
bounded redacted old-generation evidence when replacement fails.
The sidecar cancellation amendment is committed as `8811dda9` with local
full-race and 20-round soak evidence. GitHub Actions run `29932701242` (#69)
then passed the complete macOS verification: per-package `-race -count=5`
(10m19s), benchmark, actual-child, vet, reproducible build, SBOM, and signed
bundle checks all succeeded, as did both Linux impaired-network/loopback jobs.
The retained race evidence artifact is `8535377645` with digest
`sha256:04441aecb2f2d21bd32d8e27ae0ca8ab010f7e71e9b3cce30602134cc6f82f98`.
The hosted CI gate is closed; the production-feature VM aggregate remains
independent and incomplete.

The route-helper v2 lease/journal implementation and signed disposable-VM
matrix are complete for S1.12. Evidence covers dual-stack apply/rollback,
exact/more-specific/unknown-interface conflict refusal, explicit synthetic
Mihomo covering classification, helper restart, corrupt-journal recovery, and
final route/journal/lease absence. S1.13 is the first incomplete VM aggregate.
Its packaged-Mihomo/live-control matrix and a separate signed App-managed
`utun4093` GUI/lifecycle matrix pass in the disposable VM. The remaining gate
is the production-feature Rust live-source path, private-service reachability,
app/sidecar/helper abort, reboot/retry, typed service retirement, and aggregate
foreign-state cleanup; ordinary App evidence is not represented as
production-controller evidence.

The S1.13 production-feature candidate review is design-approved and locked in
`kyclash-production-vm-lab-candidate-review-20260722.md`. Its final recheck
closed the Keychain ownership and guest-to-host pull findings: creation is
atomic/create-only with duplicate and foreign-item fail-closed handling,
temporary generated buffers are wiped on error/duplicate paths, and cleanup
requires durable ownership plus a public witness. The pull transfers only
public descriptor/preflight/expiry evidence into a new private host root.
Construction is authorized only in
`kyclash-macos-lab-work`; runtime acceptance remains pending. Ordinary builds
remain default-off and no release/updater publication is authorized.

### 2026-07-23 broker session binding continuation

The first implementation slice of the locked broker-session amendment is now
source-complete: a fixed Mach-service bridge, typed descriptor ownership,
broker/runtime generation separation, exact stop/reap handling, and
recovery-only quarantine for stale or ambiguous broker replies. Swift closes
late XPC pipe descriptors before returning from an obsolete callback. These
changes are covered by focused Rust tests, Objective-C contract checks, and
the Swift broker self-test.

The route-helper v3 owner/journal contract now has its native XPC client,
root-broker bridge, durable filesystem integration, and production no-argument
listener. The production factory has replaced the local launcher with the
one-shot broker-bound launcher and rematerializes a fresh exact session for
each start. These are source gates only; they do not replace the remaining
production-feature VM aggregate. The distinct no-sign VM App uses the fixed
root-harness socket for lab real-utun evidence and installs no private routes.

### 2026-07-23 broker-bound route authority and v3 wire source slice

The locked S1.13 continuation now has a source/test boundary from the broker
start through route ownership. A controller built from a broker-assigned
session reference can be started only through a one-shot bound command. The
accepted handshake produces a non-copyable receipt carrying distinct runtime
and broker generations; failed or abandoned attempts are reaped or quarantined
and never restart with stale material.

`ControllerStartReceipt::authorize_routes` consumes that receipt with verified
tunnel facts and exact lease/operation identifiers to create a sealed
`BrokerRouteAuthorization`. The pure-Rust route v3 session retains it while
durably enforcing hold-before-route and route-before-release ordering,
including the `HoldPending -> RetirementPending` recovery path. Its fake
adapters cover wrong tuple, replay, partial/failed cleanup, release retry, and
v2 recovery-only behavior.

The native source seam now includes a broker v3 full-tuple XPC service/bridge
and a separate route-helper v3 wire/journal schema with strict top-level version
dispatch and an unprivileged contract self-test. The root bridge is ARC-linked
into the route-helper target, while the v3 interface is exposed only through
the production helper's no-argument v3 listener; the legacy v2 and v3 lab
listeners remain behind explicit CLI/environment gates. The ordinary App still
cannot select a helper endpoint or command, while the production factory
constructs the fixed v3 client only after Connect. The injected coordinator
self-test proves hold-before-route, rollback-before-release, exact release
retry, and connection invalidation without contacting the broker or mutating
host routes. The production and explicit lab listeners use a root-owned atomic
v3 plist store
with strict permissions and exact-owner startup recovery.

### 2026-07-23 production v3 composition and no-sign VM lab slice

The default-off production factory is now source-wired from Connect through a
fresh fixed tunnel-broker preparation, broker-assigned sidecar identity,
one-shot dynamic Rust-generation bind, authenticated protocol-v2 runtime, and
deferred route-helper v3 boundary. Broker and Rust generations remain
independent. Dropped preparation, failed exact reap, or ambiguous transport
state stays non-reusable and cannot mint positive absence.

The fixed route-helper v3 and root-broker clients reconnect only after a
transient transport failure and allocate a new connection epoch. They do not
replay the ambiguous call, and callbacks from an obsolete epoch cannot
terminalize the replacement. The v3 helper and broker both have bounded
heartbeat watchdog behavior: route-helper expiry enters the exact rollback /
prove-absence / release path, while broker expiry raises a recovery signal but
retains the held child until the helper releases the same tuple. A failed or
missing post-delete inspection is not route-absence proof. Broker results now
separate definitive rejection from ambiguous timeout/interruption/invalidation
so a possibly committed hold retains durable recovery authority.

Production Connect also requires both fixed SMAppService daemons to be enabled
and verifies their bundled identifiers, Team ID code requirements, and exact
launchd manifests before any production materialization. This is a source and
contract gate; no newly signed candidate or release is claimed here.

The current unsigned App build is intentionally separate. The smaller
`networking-vm-utun-lab-app` fixture remains route-free. Its reviewed sibling
`networking-vm-network-lab-app` has now passed visible acceptance in
`kyclash-macos-lab-work`: exact executable SHA-256
`39866bf893106aeaa9c567cc33e0c1394a820177df794b1785841166846822a2`
created real `utun4`, installed only `10.88.0.2/32` after carrier health,
reached `10.88.0.2:8080` over QUIC, WSS, and TCP with break-before-make, and
coexisted with the lab Mihomo `utun4094`. App EOF and the visible Disconnect
control each removed the harness, lab Mihomo, sockets, utuns, and routes while
leaving the default route unchanged.

That peer and all carrier listeners still live inside the same VM/root harness
and bind `127.0.0.1`. The result therefore closes only the no-sign single-VM
core-network lab; it does not prove an independent device/server, production
XPC, signing, publication, or S1.13. The next core lab criterion is a separately
reviewed second-VM Peer. SSH is key-based; password injection through
`sshpass`, `sudo -S`, scripts, logs, or evidence remains prohibited.

S1.13 therefore remains the first incomplete aggregate criterion. It closes
only after the exact production candidate passes VM Connect, real utun,
private reachability and routes, packaged Mihomo coexistence, fallback,
abort/reboot, and final-absence evidence.

## Later platform order

1. macOS x64
2. Windows x64
3. Windows arm64
4. Linux x64/arm64
5. Mobile after a separate product and architecture review

## Merge gates

Every iteration runs, as applicable:

```bash
corepack pnpm run typecheck
corepack pnpm run web:build
corepack pnpm run lint
corepack pnpm run i18n:check
cargo fmt --all --check
cargo test -p clash-verge --lib
cargo clippy -p clash-verge --all-targets
git diff --check
```

Platform mutations additionally require install, upgrade, uninstall, service,
TUN, system-proxy restoration, forced-exit cleanup, and update-signature tests.

### 2026-07-23 Linux Peer live-runtime contract lock and config-v2 slice

The Linux Peer live-runtime design is locked for source implementation and
isolated Linux acceptance by
`kyclash-linux-peer-live-runtime-review-20260723.md`. The approved review
content SHA-256 is
`e68c5938fe26b4729f4f4404c7ce222a1b6eed18e671c327e384e3ff5e57c998`;
the final protocol, Linux, and security reviews each reported C0/H0/M0.

The first dependency-ordered source slice is complete. The fixed
`/etc/kyclash/network-peer-v2.json` decoder and schema require schema v2,
carrier-auth v1, exactly one configured client, brokered Linux TUN-FD mode,
canonical WireGuard keys, DNS names, listeners, tunnel addresses, and private
prefixes, plus exact end-to-end address-family agreement. The v1 schema and
fixture remain negative historical evidence and the command exposes only the
fixed-path `--check-config` operation. Focused non-cached tests, race tests,
vet, Linux amd64/arm64 test-binary builds, and the full Go test/vet suite pass.

This slice does not close S1.13 and does not enable a live Peer. The public
credential loader remains deliberately fail-closed until the reviewed
invocation-bound `$CREDENTIALS_DIRECTORY` and ACL-v2 contract is implemented.
Profile-v2 pairing, credential materialization, TUN brokerage, TLS possession
proof, QUIC/WSS/TCP listeners, route WAL/lease recovery, systemd hardening, and
isolated live acceptance remain subsequent locked units. Live deployment and
contact with a staging or production site remain unauthorized.

### 2026-07-23 production profile-v2 and Linux Peer-v2 pairing slice

The next dependency-ordered public-contract unit is source-complete. A
separate production profile v2 now exists in JSON Schema, Go, Rust, and
TypeScript without changing or auto-upgrading the v1 lab profile. The shared
fixture pins schema version 2, carrier-auth version 1, both WireGuard public
keys, the client tunnel addresses, exact private CIDRs, one lowercase DNS
server name, ordered QUIC -> WSS -> TCP URLs, `/kynp`, ALPN
`kyclash-network/1`, and MTU 1420.

The Go pairing API returns an opaque, revalidated, deep-copied capability only
when the profile exactly matches one validated Linux Peer v2 configuration.
The shared contract rejects unknown/case-aliased/duplicate fields, lone
UTF-16 surrogates, ambiguous control-plane hosts and ports, noncanonical
Base64, high-bit aliases, and the remaining field-coordinate aliases at or
above `2^255-19`; the Go and Rust backend gates additionally reject X25519
low-order points. The cross-language Schema/TypeScript corpus is an explicit
package command and a path-complete sidecar CI gate.

Focused Go, race, vet, Rust, clippy, TypeScript, formatting, and 168
Schema/TypeScript contract checks pass. The final protocol, security, and
cross-language reviews each reported C0/H0/M0. This unit reads no Keychain
material, opens no listener, creates no TUN, and installs no route. S1.13
therefore remains open; the next locked source unit is the invocation-bound
`$CREDENTIALS_DIRECTORY` and ACL-v2 boundary, followed by TUN brokerage and
live carrier ownership.

### 2026-07-24 Linux Peer credential filesystem/ACL-v2 foundation

The first non-activating credential-boundary slice removes the superseded
Peer-writable `0700`/`0600` helper and adds a Linux-only transaction over one
continuously held directory descriptor. It accepts only the two locked
systemd materialization profiles: UID/GID-0 objects with the one exact named
Peer ACL, or Peer-owned mode-`0500`/`0400` objects on a read-only mount with
no access/default ACL. Fixed-basename `openat2`, `statx` mount IDs,
filesystem facts, single-link files, exact directory entries, bounded reads,
NUL rejection, context cut points, final path re-resolution and complete
failure/close zeroization are all covered by synthetic race seams.

A dedicated Ubuntu 24.04 workflow additionally constructs both profiles with
real ACL and read-only-mount operations, then repeats the positive path through
a real nonzero `User=kyclash` transient service with three encrypted
`LoadCredentialEncrypted=` sources. It proves the Peer can read but cannot
write, chmod, unlink, rename or create, while unrelated and shared-group
identities cannot read. Promotion to `main` requires that native gate to pass.

This foundation is deliberately not the live credential provider. The public
loader remains fixed fail-closed, the command remains `--check-config` only,
and neither `CREDENTIALS_DIRECTORY` nor a real credential location is read.
The aggregate invocation-bound boundary remains in progress until the
binary/identity manifest, exact self-pidfd systemd invocation proof,
dumpable/NoNewPrivs/TSYNC-seccomp bootstrap and opaque one-use identity lease
are implemented and pass native Linux acceptance.
