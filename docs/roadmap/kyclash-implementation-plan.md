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
- Updater artifacts are not generated without a KyClash signing procedure.
- Portable archives use KyClash branding while retaining `clash-verge.exe`.
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

Progress (2026-07-21): macOS/Unix development process and IPC proof complete;
the development status page remains pending.

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

- Wire the feature-gated Tauri command into a read-only development status
  page.

Windows named-pipe/process support is intentionally deferred to the Windows
platform phase after the macOS MVP.

Exit criteria:

- Sidecar crashes cannot crash the Tauri application.
- Stale IPC and process state recover after application restart.
- Automated tests demonstrate secret redaction.

## Iteration 3: Route transaction POC

Goal: safely apply and roll back private CIDRs in an isolated lab.

- Implement platform route discovery and conflict detection.
- Add an ownership journal and idempotent transaction API.
- Exercise connect failure, forced termination, restart, and rollback.
- Test coexistence with Mihomo TUN.
- Keep DNS mutation out of scope.

Exit criteria:

- KyClash never overwrites an unowned conflicting route.
- Every injected failure restores the recorded pre-connect state.
- No production host or network is used without explicit authorization.

## Iteration 4: WireGuard and transport POC

Goal: validate the data plane in an isolated environment.

- Integrate the selected WireGuard adapter behind a stable trait.
- Implement QUIC primary transport and measured health checks.
- Implement WSS/TCP fallback with break-before-make behavior.
- Test UDP blocking, packet loss, jitter, suspend/resume, and network changes.

Exit criteria:

- QUIC and fallback behavior match the locked state machine.
- Tunnel and route cleanup remain transactional under fault injection.
- Performance measurements and limitations are documented.

## Iteration 5: macOS MVP

Goal: deliver one-site private access with user-facing recovery and diagnostics.

- Add site selection, connect/disconnect, health, routes, and diagnostics UI.
- Integrate system credential storage.
- Complete signing, notarization, updater ownership, and rollback procedures.
- Execute fresh install, upgrade, uninstall, sleep, network switch, and crash tests.

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
