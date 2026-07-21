# KyClash production networking long-range work program

Status: approved and locked for continuous execution

Date: 2026-07-21

Parent plan: `kyclash-production-networking-plan-20260721.md`

Review record: `kyclash-production-networking-review-20260721.md`

Stage-consolidation review:
`kyclash-production-networking-single-stage-review-20260721.md`

## Outcome

Complete one indivisible stage, S1, as a dependency-ordered program that ends with a
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
   Physical-Mac tests are limited to S1.16 cases that virtualization cannot model
   and require explicit execution authorization at that point.
5. Tests use synthetic credentials, loopback endpoints, TEST-NET/private test
   addresses, and allowlisted evidence. Passwords, tokens, private keys, raw
   endpoint credentials, and Keychain values are never retained.
6. A failure leaves the relevant state disconnected and proves final absence
   of owned child, carrier, utun, route, journal lease, and synthetic Keychain
   entry before work continues.

## Single stage S1 — production networking delivery

Stage status: in progress. Completed work packages are evidence only; S1 is
not complete until every package and the final aggregate gate pass against one
exact signed candidate.

Historical N1–N5 labels below are evidence aliases only and are not stages or
stopping points.

### Current S1 status

| Work packages | Scope | Evidence status |
| --- | --- | --- |
| S1.01–S1.04 | contracts, carriers, lab server, actual child | complete |
| S1.05–S1.07 | production controller, policy/credentials, API/UI lifecycle | complete |
| S1.08 | reproducible signed nested sidecar and launch trust | complete; local authorized Developer ID evidence; notarization remains optional hardening |
| S1.09 | owned real utun lifecycle | complete; signed disposable-VM evidence and encrypted traffic cleanup passed |
| S1.10 | disposable-VM termination matrix | in progress; signed GUI launch now passes; distinct killed app/controller and GUI login/logout observations remain |
| S1.11 | signed helper and typed XPC | complete; ServiceManagement registration and signed client/helper round trip passed in the VM |
| S1.12 | route lease/recovery | in progress; signed VM begin/apply/status/rollback and helper restart pass, injected failure/full matrix remains |
| S1.13 | Mihomo coexistence VM matrix | pending; depends on real helper/XPC route execution |
| S1.14–S1.15 | impairment, performance/package lifecycle | in progress; CI matrices and package audit are active, lifecycle/soak evidence remains |
| S1.16 | physical/staging gates | pending; physical Mac and explicitly authorized staging observations remain |

First incomplete criterion: S1.10. Overall S1 status: in progress.

### Work-package dependency chain

```text
S1.01 contracts (formerly N1A)
 -> S1.02 carrier/device runtime (formerly N1B)
 -> S1.03 lab server (formerly N1C)
 -> S1.04 actual-child matrix (formerly N1D)
 -> S1.05 production gate/controller (formerly N2A)
 -> S1.06 policy v2/credential boundary (formerly N2B)
 -> S1.07 Tauri/UI/lifecycle order (formerly N2C)
 -> S1.08 reproducible trusted bundle (formerly N3A)
 -> S1.09 real utun (formerly N3B)
 -> S1.10 VM termination matrix (formerly N3C)
 -> S1.11 signed helper/XPC (formerly N4A)
 -> S1.12 route lease transaction (formerly N4B)
 -> S1.13 Mihomo coexistence VM matrix (formerly N4C)
 -> S1.14 impairment/reliability (formerly N5A)
 -> S1.15 performance/lifecycle (formerly N5B)
 -> S1.16 physical/staging approval gates (formerly N5C)
```

### S1 work packages: real userspace data plane

#### S1.01 — lock executable data-plane contracts (formerly N1A)

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

#### S1.02 — bind WireGuard to explicit carriers (formerly N1B)

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

#### S1.03 — compatible loopback lab server (formerly N1C)

Status (2026-07-21): complete. The repository-owned in-process lab peer binds
only explicit loopback addresses and ephemeral ports, generates a fresh TLS
certificate and WireGuard identity per run, and exposes trust only as an
in-memory certificate pool. It terminates a userspace WireGuard peer over KYNP
QUIC, WSS, or TLS/TCP. Automated tests pass four bidirectional, varied-size
traffic cycles on every carrier and cover non-loopback refusal, untrusted TLS,
UDP refusal, delay, deterministic loss, forced disconnect, and server abort.
Shared frame/carrier tests remain the single enforcement point for malformed,
replayed, oversized, control-kind, and unknown-version frames.

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

#### S1.04 — actual-child end-to-end matrix (formerly N1D)

Review amendment: `kyclash-actual-child-lab-review-20260721.md` locks a
`networking-dev`-only lab executable that shares the production data plane but
injects ephemeral trust directly in memory. The production bootstrap and
handshake remain unchanged and reject lab fields.

Status (2026-07-21): complete. The Rust stdio runtime drives the real lab child
through apply, prepare, QUIC/WSS/TCP connect, encrypted payload health,
break-before-make disconnect, concurrent cancel, tunnel stop, EOF/process
shutdown, and a UDP-blackhole timeout. Cancellation responses are correlated
by request ID even when they arrive before the canceled operation. The timeout
path kills and reaps the child within its deadline, and deterministic
controller tests cover restart/crash-loop backoff. CI repeats the complete lab
child cycle three times. Combined lab-server abort and actual-child tests leave
no host interface, route, DNS, Keychain, external connection, or live child.
N1A through N1D now pass together.

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

S1.01–S1.04 evidence status: complete. S1 remains in progress.

### S1 work packages: production Rust controller and credential path

#### S1.05 — default-off production controller (formerly N2A)

Status (2026-07-21): complete. `networking-production` is default-off and
separate from `networking-dev`. A single bounded Tokio actor exclusively owns
its runtime, authenticates the child, correlates response IDs, enforces request
deadlines, exposes cancellation tokens only for the matching in-flight
operation, performs typed health polling, applies bounded restart/crash-loop
state, and stops the child when the final handle drops. Its 128-entry monotonic
diagnostic ring contains only operation IDs, structured states, and error codes.
Tests cover cancellation/timeout races, stale responses, runtime failure,
health request typing, repeated crashes, bounded diagnostics, and actor drop.
No production Tauri command is exposed before N2C.

Deliverables:

- Add `networking-production`, absent from default and release feature sets
  until S1.11–S1.13 close.
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

#### S1.06 — signed policy v2 and Keychain boundary (formerly N2B)

Status (2026-07-21): complete. Envelope v2 signs the domain separator, key ID,
algorithm, and strict payload containing `issued_at`, `expires_at`, monotonic
revision, and the validated profile. A pinned synthetic Ed25519 test root and
clock/revision tests reject v1, unsigned/malformed, future, expired, replayed,
unknown-key, and tampered policies. The fail-closed revision store persists
only schema version plus the latest revision using a private atomic file and
refuses corruption/symlinks; injected persistence failure prevents acceptance.
Credential resolution accepts only `keychain:` references. The production
macOS store has the fixed `net.kysion.kyclash.networking` service, while the
test service is available only to tests/keychain-lab. Missing 32-byte
WireGuard material is generated locally, persisted once, copied only into the
zeroizing stdin bootstrap context, and redacted from Debug. Destructive
create/update/delete remains an ignored manual test scoped to
`net.kysion.kyclash.test` and a disposable account.

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

#### S1.07 — production API, UI, and lifecycle transaction (formerly N2C)

Status (2026-07-21): complete. The default-off production command module now
exposes only typed site summaries, redacted status, connect/cancel/disconnect,
and bounded diagnostic events. Its separately gated UI renders authenticating,
preparing, primary, fallback, cancelling, recovering, disconnecting, and
structured failure states without endpoints, credential references, policy
documents, or keys. The production service owns one operation at a time and
enforces authenticate/apply-profile -> prepare tunnel -> Rust-selected carrier
-> typed health gate -> route apply. Failure and disconnect converge through
route rollback -> carrier close -> tunnel stop -> controller shutdown/secret
release. Tests assert the exact order and QUIC break-before-make fallback. The
all-feature Rust suite continues to drive the actual Go child/lab server from
the same IPC/runtime boundary, while the production service uses injected fake
route adapters to prove mutation order. Production-feature Rust and web builds
pass; ordinary builds register neither the production Tauri commands nor its
navigation entry. Runtime configuration remains intentionally uninstalled
until the S1.08 trusted-bundle and S1.11–S1.13 route-helper gates close.

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

S1.05–S1.07 evidence status: complete; the feature remains default-off. S1
remains in progress.

### S1 work packages: trusted bundle and real macOS utun

#### S1.08 — reproducible nested sidecar and launch trust (formerly N3A)

Status (2026-07-21): complete. A
macOS-only builder now produces a thin target-specific Go executable with
`-trimpath`, no VCS record or Go build ID, signs it as the nested KyClash
network sidecar, and emits SHA-256, dependency, commit/Go-version provenance,
and a strict trust manifest. The release workflow imports the Developer ID
certificate before building the sidecar and route helper, supplies an inert
networking bundle overlay, verifies both nested signatures/Team IDs plus the
sidecar hash, and keeps updater
activation unchanged. Immediately before process creation, the Rust runtime
can require the strict manifest and rejects non-regular files, symlinks,
foreign ownership, writable permissions, non-thin/wrong Mach-O architecture,
hash mismatch, invalid Team ID, failed strict signature, or failed designated
requirement. Pure trust tests pass on every platform. An authorized local
Developer ID build proves that outer application signing preserves the arm64
sidecar identifier, Team ID, designated requirement, and manifest SHA-256.
The helper is present once at its locked path with its own identifier, Team ID,
and designated requirement. Gatekeeper correctly reports `Unnotarized
Developer ID`; that is an expected limitation of this internal no-store build,
not an S1.08 stop condition. No release was published.

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

#### S1.09 — real utun device lifecycle (formerly N3B)

Contract amendment: `kyclash-utun-contract-review-20260721.md` locks the
instance/request ownership record and redacted `tunnel_prepared` response.

Status (2026-07-22): complete. The contract and source implementation are
complete: the production-only macOS build tag creates the device, validates
its returned name, configures only local addresses and MTU, retains the exact
device object, and reports the bootstrap/request owner tuple. Default and lab
builds remain on netstack. Go unit, tagged macOS compile, vet, Rust contract,
production-controller, frontend, and repository gates pass locally. A
Developer ID-signed, VM-confirmation-gated arm64 test executable ran inside the
authorized `VirtualMac2,1` guest. Three repeated create/ownership/stop cycles,
direct backend-close cleanup, and real QUIC-carried WireGuard handshake plus
bidirectional encrypted-byte counters passed. Each case independently verified
the exact returned `utunN` disappeared, with no retained 10.88/10.89 address,
route, or lab process. The redacted lifecycle evidence SHA-256 is
`de2fafe5a5e1b012caa56ad82b9d9835f2752646ba59b4ec81025b10f7556c26`.

CI note: run `29840092883` captured the previously invisible race log and
proved the failure was the fixed eight-second loopback handshake budget under
race instrumentation, not a reported data race. Ordinary tests retain eight
seconds; race builds use a reviewed twenty-second operation budget and a
five-minute suite ceiling. Run `29840681961` then passed that race matrix and
the tagged utun compile; its later actual-child step exposed that
`networking-dev` library validation still invoked Tauri application packaging
without CI's intentionally absent Mihomo binaries. The build script now skips
Tauri packaging only for this non-application test feature, matching the
existing clippy/system-lab boundary. The exact local actual-child matrix passes;
replacement macOS-runner evidence remains pending.

Local Developer ID evidence (2026-07-21): the authorized Keychain identity
`Developer ID Application: Huang Chapping (RQUQ8Y3S9H)` signed the arm64
sidecar and route helper with trusted timestamps and the locked Team ID. A full
KyClash.app build then exposed that Tauri re-signed an `externalBin`, changing
both its identifier and hash after trust-manifest generation. The networking
overlay now places the already signed sidecar directly in
`Contents/Resources/kyclash-network-sidecar`, and release verification uses
that immutable path. The replacement bundle passes deep strict verification;
its sidecar SHA-256 is
`27e49f04434bd19a5460cb885cc0ed30498ff51d6b77f6849627aa7923e922d5` and
matches the bundled trust manifest. The helper is no longer duplicated through
the generic resources directory. No install, registration, utun, route,
notarization, upload, or release occurred.

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

#### S1.10 — disposable-VM termination matrix (formerly N3C)

Status (2026-07-22): in progress. A separately gated hold fixture created an
owned real utun in the disposable guest, published only its validated name to
a fixed `/var/tmp/kyclash-utun-lab-*` evidence path, and was then killed with
SIGKILL. The kernel released the exact device and an independent `ifconfig`
poll proved final absence. Normal repeated close and backend-close paths are
also covered by S1.09. The signed real-sidecar test boundary then proved both
stdin EOF and malformed IPC close the exact prepared device. Additional real
utun cases prove failed carrier setup cleans up and cleanup never claims or
closes a separately created unowned `utunN`. After the work guest stopped and
was restarted through Virtualization.framework, independent address, route,
process, and interface checks again proved final absence. The encrypted-traffic
case now also closes its authenticated QUIC peer after health before tearing
down the owned device. A distinct killed-app/controller process and actual GUI
login/logout remain open; their source-equivalent EOF and process-kill paths
are covered but do not replace those two VM observations. A freshly rebuilt
signed arm64 KyClash bundle has since launched through LaunchServices in the
same disposable guest and kept its GUI process, Mihomo child, and singleton
listener alive; the redacted window evidence is recorded in
`docs/testing/kyclash-macos-virtualization-lab.md`.

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

### S1 work packages: privileged routes and Mihomo coexistence

#### S1.11 — signed SMAppService helper and typed XPC (formerly N4A)

Contract review: `kyclash-route-helper-contract-review-20260721.md` locks the
bundle layout, fixed identities, code requirement, typed method surface,
single-connection lease, and fail-closed S1.11/S1.12 boundary.

Status (2026-07-22): complete. The cross-platform route-owner and lease
contract is implemented with strict serialization, exact utun owner matching,
bounded canonical private CIDRs, replay mismatch refusal, and no generic
command/path/environment fields. A macOS 13 Swift LaunchDaemon now implements
the fixed typed NSSecureCoding method surface, rejects root/unsigned or
wrong-team app connections through the locked code requirement, owns at most
one lease per XPC connection, and delegates mutations to a fixed journaled
coordinator.
Its strict plist, arm64 compile, nested signing builder, Tauri bundle placement,
and CI checks are implemented. Every typed request and reply position now has
an explicit NSXPC class allowlist, including the nested owner/reference and
bounded CIDR collection classes. Each connection owns a separately locked
service instance, and both XPC interruption and invalidation synchronously
discard its in-memory lease through the same idempotent cleanup boundary. A
production-feature-only Objective-C bridge now
links Apple's ServiceManagement framework and exposes only fixed status,
register, unregister, and open-settings operations to Rust; unsupported
platforms fail closed. The app-side typed XPC client is now complete: it keeps
one persistent privileged NSXPC connection, mirrors the fixed NSSecureCoding
classes and class allowlists, bounds every synchronous reply, exposes only the
locked discover/begin/apply/rollback/recover/heartbeat/status selectors, and
maps unknown states/errors fail-closed. Rust validates every owner/reference
before constructing C strings and serializes the one-lease connection. The
production UI explains the narrow private-route capability and requires an
explicit Enable action; it exposes registration state, approval settings, and
unregistration, and disables Connect until the helper is enabled. The signed
disposable-VM registration harness registers the daemon through `SMAppService`
and reports status `1` (enabled). After removing a stale legacy test plist and
resetting the disposable guest's Background Task Management database through
its interactive administrator session, launchd submitted the bundle-owned job.
A Developer ID-signed lab client then completed the real privileged Mach-
service `discover` round trip with idle state and no error; launchd reported
the helper running with one successful exec. S1.12 executor and VM lifecycle
evidence remain open.

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

#### S1.12 — route transaction lease and crash recovery (formerly N4B)

Status (2026-07-22): in progress. The production lifecycle now retains the
exact `TunnelDeviceFacts` returned by prepare and supplies those facts plus the
accepted policy revision to the route boundary only after the encrypted health
gate. The XPC production boundary constructs the exact owner tuple, begins one
lease, requires an exact prepared reply, applies only that reference, and
rolls it back on any embedded error, unexpected state, disconnect, or drop.
The helper now persists a private journal before each fixed `/sbin/route`
mutation, tracks pending/applied CIDRs, expires leases after bounded heartbeat
silence, and rolls back on XPC invalidation. VM mutation/restart evidence and
rejects destinations returned by the fixed read-only `route -n get` lookup,
while explicitly allowing the ordinary default underlay route and an absent
IPv6 table, before writing the first mutation. The helper's read-only self-test
is now part of the macOS CI compile gate. A read-only VM probe confirmed
macOS reports an uninstalled private IPv4 route as `destination: default` and
an absent IPv6 route as `not in table`; both now pass the availability guard.
The resumed interactive disposable VM has now re-run the scoped route
transaction lab: normal cycle, abort-after-apply (exit 134), and journal
recovery all passed, with no final `192.0.2.0/24` route. The redacted journal
evidence is retained under the ignored VM evidence directory with SHA-256
`50bf02a0536344ad46d398c759f2770daea16f1a2638568b769625396f3e657a`.
The signed VM client has now completed `begin/apply/status/rollback` on an
owned `utun4`, and the exact private route was absent after rollback. A
subsequent forced helper termination caused launchd to start a new instance
for the next discover call.

The injected failure gate is now covered in both Rust and the helper's
macOS-only self-test. The Rust matrix fails each durable journal save (before
and after each IPv4/IPv6 mutation) and each route mutation, asserting that no
owned route remains. `kyclash-route-helper --route-coordinator-self-test`
uses an in-memory executor and temporary private journal to cover dual-stack
normal/duplicate/replay/invalidation, exact conflict refusal, add failure,
rollback failure and retry, helper restart reconciliation, and corrupt-journal
fail-closed behavior; it never invokes `/sbin/route`. The CI compile gate runs
both the read-only route probe and this injected coordinator matrix. The
privileged VM's complete IPv4/IPv6/conflict/journal-corruption/restart matrix
and packaged Mihomo coexistence scenarios remain open for S1.13.

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

#### S1.13 — disposable-VM system and Mihomo matrix (formerly N4C)

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

Only after S1.11–S1.13 pass may a separately
reviewed candidate include the production feature in normal builds.

### S1 work packages: reliability, lifecycle, and staged endpoint readiness

#### S1.14 — deterministic impairment and recovery matrix (formerly N5A)

Status (2026-07-21): in progress. The loopback lab carrier now provides
deterministic latency, stepped jitter, byte-rate limiting, nth-packet loss,
nth-packet duplication, pair reordering, UDP refusal, and bounded forced
disconnect. Unit and race tests assert exact delivery order and cancellation-
aware delays without external networking. TLS identity refusal, frame bounds,
fragment expiry, replay refusal, abrupt server close, and Rust-commanded
QUIC/WSS/TCP fallback already have focused coverage. The consolidated short CI
matrix, stable reason-code assertions for every impairment, extended soak, and
network-change recovery evidence remain open.

The Linux isolated-network workflow now runs the netem matrix on every change,
retains environment and command logs as artifacts, and the macOS verification
workflow runs repeated race-enabled sidecar tests. These are CI evidence paths;
they do not replace the remaining scheduled soak and physical network-change
observations.

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

#### S1.15 — performance and package lifecycle (formerly N5B)

Status (2026-07-22): in progress. The release workflow now calls the shared
`scripts/verify-macos-package.mjs` audit, which checks the exact app bundle,
Developer ID signatures, Team ID, helper plist, sidecar trust hash, duplicate
helper absence, PKG signature, and emits a byte hash. Performance baselines,
rollback/uninstall evidence, and the remaining current-byte lifecycle matrix
remain open. The resumed disposable VM installed the current signed arm64
package over the existing KyClash installation and verified the receipt, deep
signature, nested sidecar, and route helper. The tested PKG SHA-256 is
`760cd22bb2fcaf1062417d88cb2fa4e0989176e6f873bece5bada01f008ad38e`.

The sidecar verification workflow now retains a repeated QUIC fragmented-round-
trip benchmark with CPU/runtime and allocation metadata. A local Apple M5 run
produced 14.00 MB/s, 292599 ns/op, and 67260 B/op at the current source; this
is a baseline only, not yet a release threshold.

Deliverables:

- Record CPU, resident memory, battery/energy, latency, throughput, loss, utun
  queue behavior, reconnect time, cancellation time, and diagnostic size.
- Define supported limits and regression thresholds from repeatable baselines.
- Run fresh install, upgrade, rollback, uninstall, crash, reboot, app relaunch,
  helper lifecycle, and cleanup with the exact signed candidate PKG.
- Notarization/stapling remains public-distribution hardening; if selected for
  the candidate, evidence must correspond to the exact tested bytes.

Merge unit: `test(release): close networking performance and PKG lifecycle`.

#### S1.16 — physical-Mac and staging authorization gates (formerly N5C)

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

The single S1 stage is complete only when the exact signed candidate proves, from one clean
commit, that the production UI can establish one-site encrypted private
networking over QUIC with WSS/TCP fallback, apply only owned private routes,
coexist with Mihomo TUN, recover from every tested failure, expose only redacted
state, and leave no owned system state after disconnect or recovery.
