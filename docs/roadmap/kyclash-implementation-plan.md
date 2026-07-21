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
- Added an explicit Mihomo TUN coexistence policy: only a configured active
  Mihomo interface may contribute a less-specific covering route. Unknown VPN
  interfaces and exact or more-specific routes always fail closed; `utun*`
  names never imply ownership by themselves.
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

Remaining authorization-dependent validation:

- Execute Mihomo coexistence scenarios in the local disposable macOS VM. The
  production adapter remains read-only and Iteration 3 is not release-closed
  until that separate integration evidence exists.

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
- Kept the production sidecar alive after authentication with the exact Rust v1
  request/response envelope. Status and disconnect work, malformed or unknown
  requests fail closed, and profile/connect/cancel return a structured
  `sidecar_unavailable` error until real networking gates are explicitly enabled.
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

Progress (2026-07-21): all source-level and isolated work permitted by the
continuous-delivery authorization boundary is complete. Production connection
controls and real credential access remain disabled pending the authorized
host, server, and release gates recorded in
`kyclash-completion-audit-20260721.md`.

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

- Replace the mock command boundary only after the real sidecar, route lab,
  and system credential adapters pass their isolated validation gates.
- Complete GitHub updater ownership and macOS installation lifecycle validation
  with authorized hosts. The current arm64 candidate is notarized and stapled;
  every later release candidate must repeat that gate for its exact bytes.
- Re-enable updater capabilities only in the same separately authorized change
  that injects the KyClash public verification key, publishes signed immutable
  GitHub assets and rollback metadata, enables permissions and runtime gates,
  and passes lifecycle tests. Current builds remain disabled.
- Execute the production networking batches below before replacing the mock or
  enabling a release build.

## Production networking execution plan — 2026-07-21

Production networking continuation is decomposed and ordered in
`kyclash-production-networking-plan-20260721.md`. The first required batch is
Rust/Go runtime contract convergence: the current Rust Unix adapter launches
the argument-based mock protocol, while the Go production sidecar rejects all
arguments and uses stdin/stdout. utun, route, credential, and UI production
wiring must not proceed until the real child protocol gate passes.

N0 progress (2026-07-21): complete. The locked stdio amendment now defines a
64-KiB-bounded, single-flight bootstrap/handshake/request/response contract,
EOF and shutdown semantics, and Rust-owned granular transport selection. The
production `StdioSidecarRuntime` launches the actual Go executable with empty
argv and inherited environment, supplies zeroizing byte secrets through stdin,
checks the canonical HMAC proof, correlates request IDs, terminates ambiguous
or unauthenticated sessions, and performs graceful disconnect. A shared
bootstrap fixture is decoded by both languages. Actual-child tests prove
authenticated status/shutdown and proof-mismatch termination without socket,
route, Keychain, utun, or external network I/O. N1 is now the first incomplete
production-networking batch.

The plan then advances through a stateful userspace sidecar and compatible lab
server, the production Rust/Keychain controller, signed sidecar bundling and
real macOS utun, privileged transactional routes plus Mihomo coexistence,
reliability/staging validation, and a separately reviewed release activation.

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
