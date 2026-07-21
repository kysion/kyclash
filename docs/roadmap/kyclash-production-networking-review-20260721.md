# KyClash production networking plan review

Status: approved and locked

Date: 2026-07-21

Reviewed inputs:

- `../architecture/kyclash-networking-v1.md`
- `../architecture/kyclash-network-runtime-v1.md`
- `kyclash-runtime-protocol-review-20260721.md`
- `kyclash-runtime-datagram-size-review-20260721.md`
- `kyclash-runtime-quic-order-review-20260721.md`
- `kyclash-production-networking-plan-20260721.md`
- `kyclash-sidecar-stdio-review-20260721.md`
- current Rust networking modules, Go sidecar, tests, package configuration,
  and disposable-macOS evidence

## Review method

The plan was checked against current source facts, locked ownership boundaries,
cross-language wire compatibility, privilege minimization, secret lifetime,
transaction ordering, crash recovery, testability without production systems,
release isolation, and explicit exit evidence for each batch.

## Blocking findings resolved before lock

1. **Rust and Go could not launch each other.** The Rust Unix runtime passed a
   socket path and instance ID as arguments, while the hardened Go sidecar
   rejects every argument and consumes bootstrap plus IPC on stdin/stdout. N0
   now makes stdio the sole production process transport and requires an actual
   cross-language child test before any system work.
2. **Fallback ownership was ambiguous.** The draft assigned stateful fallback
   selection to Go, contradicting the locked rule that Rust owns lifecycle and
   policy. The sidecar command surface is now granular; it reports carrier
   health and executes the transport explicitly selected by Rust.
3. **The current POC applies routes too early.** `DataPlaneController` currently
   applies routes before connecting the carrier, whereas the locked runtime
   requires a carrier health gate before route mutation. N2 now replaces this
   order and requires fault tests at every boundary.
4. **A journal alone cannot clean routes immediately after controller death.**
   A dead Rust process cannot consume its journal. N4 now uses a dedicated
   `SMAppService` helper with typed XPC, code-identity validation, and a route
   lease that rolls back on connection invalidation. The Rust journal remains
   the durable restart reconciliation source.
5. **Policy freshness was unspecified.** Adding unsigned local timestamps would
   not prevent replay. Production policy is now a versioned signed envelope v2
   containing issuance, expiry, and unique revision data; v1 remains test-only.
6. **Parent/sidecar orphan behavior was incomplete.** macOS lacks Linux-style
   parent-death signals. N3 now treats inherited stdin EOF as the authoritative
   parent-death signal and requires bounded carrier, WireGuard, utun, and secret
   cleanup.
7. **The compatible server boundary was easy to overstate.** N1 includes only a
   loopback/isolated lab server for client proof. Production tenancy,
   authentication, policy issuance, deployment, and operations require a
   separate server architecture and authorization.

## Locked execution order

1. N0: cross-language stdio runtime contract.
2. N1: stateful userspace sidecar and compatible lab server.
3. N2: production Rust controller, policy v2, Keychain, and gated UI.
4. N3: signed sidecar bundle and real macOS utun.
5. N4: SMAppService route helper and Mihomo coexistence.
6. N5: reliability, lifecycle, physical-host, and authorized staging gates.
7. N6: clean-commit release activation; updater/publication remain separate.

No later batch may be used to bypass an earlier exit gate. In particular, no
route/helper/UI production activation may compensate for a missing real-child
IPC gate.

## Non-negotiable lock conditions

- Rust selects transport and owns route transaction ordering.
- The Go sidecar owns WireGuard/utun/carrier execution and never host routes.
- The helper owns only typed route execution and lease rollback, never secrets
  or carrier policy.
- Secrets never enter argv, environment variables, persistent profile files,
  diagnostics, retained evidence, or uncontrolled error output.
- Production remains default-off through N4.
- Every system mutation has normal, injected-failure, forced-exit, restart, and
  final-absence evidence in a disposable VM.
- Production endpoint access, infrastructure mutation, GitHub Release,
  updater activation, and release publication require separate authorization.

Changes to transport ownership, stdio framing, route-helper authority, policy
v2 freshness, single-site scope, fallback order, or DNS scope require a new
review record before implementation.
