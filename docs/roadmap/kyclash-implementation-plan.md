# KyClash Implementation Plan

Status: Locked for execution

Review record: `docs/roadmap/kyclash-plan-review-20260721.md`

Architecture baseline: `docs/architecture/kyclash-networking-v1.md`

## Iteration 0: Safe product baseline

Goal: produce a reproducible KyClash build that cannot replace itself with an
upstream Clash Verge Rev release.

Progress (2026-07-21): development baseline complete. The locally reproducible
PKG is an unsigned development artifact; signing, notarization, stapling, and
installation lifecycle tests remain release gates.

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
- Portable archives use KyClash branding while retaining `clash-verge.exe`.
- Release, autobuild, download, and Telegram workflow links and visible release
  names target `kysion/kyclash` and display KyClash rather than publishing
  upstream Clash Verge Rev branding.
- Update-detail links and contributor documentation identify KyClash, while
  README documents the deliberately retained executable, service, crate, IPC,
  and legacy-registry cleanup identifiers required for compatibility.
- Typecheck, web build, ESLint, Rustfmt, unit tests, and Clippy pass.
- `KyClash_2.5.3_aarch64.pkg` is the macOS installation artifact, built from
  the Tauri application bundle with bundle identifier
  `net.kysion.kyclash`.

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

Progress (2026-07-21): transaction persistence and macOS read-only discovery
are complete; no platform route mutation command is implemented or executed.

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

Remaining authorization-dependent validation:

- Execute the planned route mutations and forced-exit cleanup in a disposable
  macOS lab host after explicit system-route authorization. Until then the
  production adapter remains read-only and Iteration 3 is not release-closed.

Exit criteria:

- KyClash never overwrites an unowned conflicting route.
- Every injected failure restores the recorded pre-connect state.
- No production host or network is used without explicit authorization.

## Iteration 4: WireGuard and transport POC

Goal: validate the data plane in an isolated environment.

Progress (2026-07-21): runtime-neutral control layer and deterministic fault
simulation in progress; no tunnel, transport socket, or external endpoint is
created.

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

Remaining:

- Integrate selected WireGuard, QUIC, WSS, and TCP implementations in an
  isolated environment and record real packet-loss, jitter, suspend/resume,
  and throughput measurements.

Exit criteria:

- QUIC and fallback behavior match the locked state machine.
- Tunnel and route cleanup remain transactional under fault injection.
- Performance measurements and limitations are documented.

## Iteration 5: macOS MVP

Goal: deliver one-site private access with user-facing recovery and diagnostics.

Progress (2026-07-21): feature-gated mock operations UI in progress; production
connection controls and credential access remain disabled.

- Add site selection, connect/disconnect, health, routes, and diagnostics UI.
- Integrate system credential storage.
- Complete signing, notarization, updater ownership, and rollback procedures.
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
- Hardened macOS release packaging so CI requires an Installer signing
  identity plus an App Store Connect notary API key, submits the final PKG to
  `notarytool`, staples the ticket, and validates it before upload. The private
  key is materialized as a mode-0600 runner file and only its path is passed to
  tools; credentials are never command arguments.

Remaining:

- Replace the mock command boundary only after the real sidecar, route lab,
  and system credential adapters pass their isolated validation gates.
- Complete signing, notarization, stapling, updater ownership, and macOS
  installation lifecycle validation with authorized credentials and hosts.
- Re-enable updater capabilities only in the same reviewed change that adds
  KyClash-owned endpoints, verification keys, rollback metadata, and tests;
  current builds have no updater configuration or frontend updater permission.

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
