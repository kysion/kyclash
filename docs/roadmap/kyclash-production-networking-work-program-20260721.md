# KyClash production networking long-range work program

Status: approved and locked for continuous execution

Date: 2026-07-21

Parent plan: `kyclash-production-networking-plan-20260721.md`

Review record: `kyclash-production-networking-review-20260721.md`

Stage-consolidation review:
`kyclash-production-networking-single-stage-review-20260721.md`

Route-helper Mihomo ownership amendment review:
`kyclash-route-helper-mihomo-interface-review-20260722.md`

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
| S1.01–S1.04 | contracts, carriers, lab server, actual child | complete; the atomic stdio protocol-v2 cancellation amendment passes Rust/Go fixture, race, lifecycle, strict-wire, and actual-child gates |
| S1.05–S1.07 | production controller, policy/credentials, API/UI lifecycle | complete; the exact-envelope identity/restart amendment now also passes durable zero-write, migration, concurrency, publication, rollback, resource-boundary, and deferred-materialization gates |
| S1.08 | reproducible signed nested sidecar and launch trust | complete; local authorized Developer ID evidence; notarization remains optional hardening |
| S1.09 | owned real utun lifecycle | complete; signed disposable-VM evidence and encrypted traffic cleanup passed |
| S1.10 | disposable-VM termination matrix | complete; signed GUI/logout/re-login, Go sidecar controller-kill/EOF plus parent-reparent cleanup, and the combined production-sidecar-owned real-utun controller-kill matrix passed; the ordinary inherited Mihomo child orphan remains a separately tracked non-production cleanup limitation |
| S1.11 | signed helper and typed XPC | complete; ServiceManagement registration and signed client/helper round trip passed in the VM |
| S1.12 | route lease/recovery | complete; v2 wire/journal migration, injected failure coverage, signed dual-stack VM transaction, conflict refusal, helper restart, journal-corruption fail-closed, and final-absence evidence passed |
| S1.13 | Mihomo coexistence VM matrix | in progress; typed live-source boundary, signed synthetic and packaged-Mihomo matrices, the signed App-managed `utun4093` GUI/lifecycle matrix, and the separate unsigned same-VM core-network lab pass in the disposable VM; the production broker-bound/v3 exact-candidate live execution, independent peer/server, abort/reboot, and aggregate cleanup remain |
| S1.14–S1.15 | impairment, performance/package lifecycle | in progress; CI matrices and package audit are active, lifecycle/soak evidence remains |
| S1.16 | physical/staging gates | pending; physical Mac and explicitly authorized staging observations remain |

The exact policy-identity portion of the locked production restart and
rematerialization amendment is complete at the source boundary. The helper
accepted-connection barrier (XPC-A) is implemented and locally closed:
registration happens before `resume`, every request is bound to a registered
generation, and invalidation rolls back under the same coordinator lock before
the replacement generation may observe authoritative `idle`. The Objective-C
first-wins terminal-generation and precise transport-status boundary (XPC-B)
is now locally closed in `96064f84`; strict arm64/x86_64 builds, analyzer,
ABI-layout checks, deterministic self-tests, and independent review passed.
XPC-C is locally closed in the current source unit: Rust owns one bounded
replacement, performs same-generation read-only reconciliation, preserves a
frozen owner on failed recovery, and never replays a mutation on a fresh
generation. Focused and full Rust library tests, Clippy, formatting, and diff
checks pass. The first typed-service cleanup slice is also locally closed: the
controller now issues an unforgeable generation-bound receipt only for a
never-spawned or exactly reaped child, permanently rejects mutations through
retained handles after retirement, and destroys retained launch secrets at the
retirement boundary. The route-boundary retirement slice is now locally closed
as well: only an idle, reconciled native generation with no route owner or
in-flight call may be synchronously destroyed, and its sealed generation-bound
receipt cannot be copied or issued by `Drop`; recovery-only, busy, and retained
old boundaries fail closed. Each receipt also binds a process-unique boundary
incarnation, so equal native generation counters on separate boundaries cannot
alias. The service-level boundary is now locally closed as well: an
Open/Retiring/RecoveryOnly/Retired gate owns exact service generations,
reservations, mutation leases, and queued/running/unjoined route tasks. Only
the non-copyable aggregate route-plus-controller receipt can authorize
retirement. The command layer reserves before spawn and performs exact
Arc/generation retirement, compare-remove, off-slot build, and empty-slot
install while retaining bounded redacted evidence if replacement fails. The
first incomplete source/build criterion is now the explicit production-feature
disposable-VM candidate and its fail-closed package classification. The first
incomplete aggregate criterion remains S1.13.
Overall S1 status: in progress.

Guest App checkpoint (2026-07-23): the explicit no-sign
`networking-userspace-lab-app` candidate was visibly launched in the selected
`VirtualMac2,1` guest and its Connect action completed the actual bundled
userspace sidecar sequence QUIC -> WSS -> TCP with break-before-make checks.
This closes the App-visible userspace evidence slice only; it intentionally
does not claim Darwin `utun`, private-route installation, tunnel-broker/XPC, or
production endpoint readiness. The redacted record is
`docs/testing/kyclash-userspace-lab-app-vm-20260723.md`.

Core-network App checkpoint (2026-07-23): the separately reviewed no-sign
`networking-vm-network-lab-app` candidate then passed visibly in the same
selected guest. Exact App executable SHA-256
`39866bf893106aeaa9c567cc33e0c1394a820177df794b1785841166846822a2`
created real `utun4`, installed only `10.88.0.2/32`, reached the private echo
over QUIC, WSS, and TCP with break-before-make, and coexisted with the fixed
Mihomo `utun4094`/covering route. App EOF and the visible Disconnect control
each removed the lab harness, Mihomo, sockets, utuns, and routes while leaving
the default route unchanged. This proves the requested core behavior only
against a peer inside the same VM/harness whose carrier listeners are on
`127.0.0.1`; it is not independent-device, production XPC, or S1.13 evidence.
The redacted evidence is under
`target/macos-vm-lab/evidence/vm-network-final-postfix-connected-20260723T025619Z/`.

Production broker/v3 checkpoint (2026-07-23): the fixed Mach-service client,
typed stdio descriptor handoff, independent broker/runtime generations,
one-shot dynamic generation bind, exact stop/reap boundary, and
stale-generation recovery quarantine are implemented. The production factory
now prepares fresh broker material and constructs the deferred v3 route
boundary after Connect. The native v3 helper and root-broker clients reconnect
with a fresh XPC epoch after transient transport loss without replaying the
ambiguous request; old-epoch callbacks cannot terminalize the replacement.
The production no-argument helper listener, root-owned v3 journal recovery,
helper/broker heartbeat watchdogs, positive post-delete route-absence proof,
distinct ambiguous/rejected outcomes, and fixed bundled code-requirement /
launchd-manifest Connect gate are present in the current source and contract
tests. These are source-level safety slices only. They do not claim production
Connect in the VM, App-owned real utun, private-route installation, or Mihomo
coexistence.

Hosted CI continuation (2026-07-22): the replacement macOS verify run
`29932701242` (GitHub Actions run #69) is fully successful. It keeps the
shipped one-second userspace probe deadline, applies a separate
`race && kyclash_race_lab` test-only budget to the isolated labserver package,
retains all reachability/loss/order assertions, and uses per-package
`-race -count=5` logs with bounded workers. macOS verify, race (10m19s),
actual-child, benchmark, vet, reproducible-build, SBOM, signed-bundle, and
both Linux impaired-network/loopback jobs all passed. The race evidence
artifact is `8535377645` with digest
`sha256:04441aecb2f2d21bd32d8e27ae0ca8ab010f7e71e9b3cce30602134cc6f82f98`.
This closes the hosted CI gate; it does not close the remaining production
feature VM aggregate.

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

Status (2026-07-22): complete. The atomic v2 implementation uses protocol 2
for bootstrap, HMAC, handshake, requests, and responses in Rust and Go, with
matching TypeScript ownership and shared bootstrap/status/health/Cancel/race
fixtures. Strict nested JSON and v1 mismatch refusal, exact-target Cancel,
cancel-wins and completion-wins in both response orders, contradictory and
missing-response fail-stop, bounded exact-child reap, controller registration
cleanup, EOF/parent/writer cleanup, and non-cancellable request isolation pass.
The freshly built production and lab children pass the 14-test Rust process
matrix, including prepare/stop, encrypted QUIC/WSS/TCP health traffic,
blackhole cancellation, timeout cleanup, post-cancel WSS/TCP reuse, and
authentication failure. The full Rust all-feature library gate passed 245
tests with the one scoped disposable-account Keychain lifecycle test ignored;
the Go normal, race, vet, formatting, and module gates also passed.
The `kyclash_utun` arm64 nested sidecar was then rebuilt and Developer ID
signed; strict code-sign verification passed and its regenerated public trust
manifest matched the exact signed-binary SHA-256.

Merge unit: `test(networking): close actual-child userspace data-plane gate`.

S1.01–S1.04 evidence status: complete. Aggregate S1 remains in progress at
S1.13; its locked restart/rematerialization source amendment is next.

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

Status (2026-07-22): complete. Envelope v2 signs the domain separator, key ID,
algorithm, and strict payload containing `issued_at`, `expires_at`, monotonic
revision, and the validated profile. A pinned synthetic Ed25519 test root and
clock/revision tests reject v1, unsigned/malformed, future, expired, replayed,
unknown-key, and tampered policies. The fail-closed identity store now persists
only schema version, revision, exact signed-envelope SHA-256, and key ID using
a private descriptor-relative transaction. Same-revision acceptance requires
the exact envelope identity; v1 records remain a lower-bound floor and migrate
only on a higher valid revision. Cross-process locking, commit-time expiry,
zero-write restart, `NOREPLACE`/`EXCHANGE` publication, conservative rollback,
directory/lock replacement, corruption, metadata-only change, and filesystem
fault tests all fail closed without persisting a profile or secret.
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
navigation entry.

The application composition gap is now closed with an explicit two-phase
boundary. App setup registers only a fixed-resource provider; the
`initialize_networking` command opens the durable identity transaction, reads
and verifies the code-signed
`resources/kyclash-networking-policy-keys.json` trust bundle and
`resources/kyclash-networking-policy-v2.json` envelope, validates every bounded
composition resource, commits the exact accepted policy identity, and installs
a deferred service factory. Concurrent initialization is single-flight, and an
exact app restart neither rewrites the identity record nor materializes runtime.
Initialization never reads
Keychain, opens route-helper XPC, starts the Go sidecar, creates utun, or
mutates routes. `connect_networking` is the only path that materializes that
factory; on macOS it then resolves the fixed KyClash Keychain service, creates
the typed XPC boundary, and starts the manifest-verified sidecar. Status and
site-list calls remain side-effect free before materialization. Missing policy
or trust resources fail closed as `invalid_configuration`; no endpoint or
public key is guessed or accepted from the frontend. A production bundle
therefore has a real initialization/connection path without silently enabling
the feature or shipping a development trust root.

Runtime configuration remains intentionally uninstalled until an authorized
production policy/trust bundle and the S1.08/S1.11–S1.13 route-helper gates
close.

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

S1.05–S1.07 evidence status: complete, including the exact-envelope durable
identity/restart amendment; the feature remains default-off. S1 remains in
progress at the XPC generation/rematerialization source gate required by
S1.13.

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

Status (2026-07-22): complete. A separately gated hold fixture created an
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
down the owned device. The signed Go sidecar controller-kill/EOF process
boundary and the actual GUI login/logout are now observed. The privileged
hold-fixture subcase was also run in the authorized Virtualization.framework
guest: PID 1983 owned `utun4`, the interface was present before an exact
SIGKILL, and an independent privileged `ifconfig` check returned exit status 1
after the kill. Redacted evidence is retained at
`target/macos-vm-lab/evidence/app-launch-20260722/utun-controller-kill-v3-20260722.txt`.
This closes standalone kernel/device release after forced termination. The
combined production-sidecar-owned utun controller case was then executed with
the signed production `run()` boundary: a controller spawned the actual sidecar
child, the child prepared `utun4`, and only the exact controller PID was
SIGKILLed. Within the first one-second poll both the child PID and `utun4` were
absent. Redacted evidence is retained at
`target/macos-vm-lab/evidence/app-launch-20260722/utun-combined-controller-20260722.txt`.
A freshly rebuilt
signed arm64 KyClash bundle has since launched through LaunchServices in the
same disposable guest and kept its GUI process, Mihomo child, and singleton
listener alive; the redacted window evidence is recorded in
`docs/testing/kyclash-macos-virtualization-lab.md`. A fresh exact-PID SIGKILL
observation then showed the app and singleton listener disappearing while the
ordinary bundled `verge-mihomo` proxy core was adopted by PID 1. That process
is not the production Go `kyclash-network-sidecar` (the default GUI build keeps
`networking-production` disabled), so it is recorded as a separate cleanup
limitation rather than a production-sidecar pass. The exact orphan was cleaned
only in the disposable guest and a signed relaunch restored the listener.
System Events/loginwindow logout removed the console session and all three
observed KyClash/Mihomo/listener processes; a Tart guest restart auto-logged the
test user back in and auto-started the signed bundle. GUI logout/re-login,
standalone privileged utun forced-termination cleanup, and the combined
production-sidecar-owned utun controller case are therefore observed. The
ordinary bundled Mihomo proxy core surviving an app SIGKILL remains a separate
cleanup limitation because it is not the production Go sidecar.

The signed Go `kyclash-network-sidecar` was also launched by an isolated
controller in the guest with ephemeral in-memory bootstrap material. After
exact command-path validation, SIGKILLing only that controller closed stdin and
the sidecar was absent within the 10-second poll window. This closes the
production sidecar's controller/EOF process boundary, but does not close the
privileged utun or route cleanup portion of S1.10.

A freshly rebuilt and Developer ID-signed sidecar was then tested with a
separate inherited writer process holding stdin open after the controller was
killed. The exact controller and sidecar paths were validated, the controller
was SIGKILLed, and the sidecar detected re-parenting and exited within 100 ms
while the writer remained alive. The redacted evidence is retained at
`target/macos-vm-lab/evidence/app-launch-20260722/production-sidecar-parent-watch-v3.txt`
and records sidecar SHA-256
`fd041fc1b5e3d7b7b3498cc7714161a6c0047510c492f734b60659c11f20689b`. This
closes the signed Go process-boundary hard-kill observation. The separately
executed privileged hold fixture and the exact production-sidecar controller
fixture close the real-utun forced-termination portions of S1.10.

The combined controller fixture used the signed production `run()` entrypoint,
kept the bootstrap/IPC writer open while the child owned `utun4`, then killed
only controller PID 1416. Child PID 1418 and `utun4` were both absent on the
first one-second poll. The redacted record is
`target/macos-vm-lab/evidence/app-launch-20260722/utun-combined-controller-20260722.txt`.

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
single-connection lease, and fail-closed S1.11/S1.12 boundary. The narrow
less-specific Mihomo exception is separately governed by
`kyclash-route-helper-mihomo-interface-review-20260722.md`. It was not present
in the v1 helper covered by this contract; the v2 boundary is implemented and
recorded under S1.12 below.

Status (2026-07-22): complete for the previously locked typed helper/XPC
surface; the XPC-A accepted-connection barrier amendment is now also locally
closed. The cross-platform route-owner and lease contract is implemented with
strict serialization, exact utun owner matching,
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
the helper running with one successful exec. The v2 executor, lease, and
crash-recovery evidence are recorded under S1.12 below; packaged-Mihomo
evidence is recorded under S1.13. The XPC-A evidence includes
warnings-as-errors Swift/Objective-C builds, injected coordinator self-tests,
same-generation typed `not_ready` to `idle` retry coverage, and static VM
safety checks. Its remaining production live-source,
reachability, abort/reboot, and aggregate-cleanup cases remain the first
incomplete VM system criterion.

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

Status (2026-07-22): complete for the v2 route-lease and crash-recovery gate.
The production lifecycle now retains the
exact `TunnelDeviceFacts` returned by prepare and supplies those facts plus the
accepted policy revision to the route boundary only after the encrypted health
gate. The XPC production boundary constructs the exact owner tuple, begins one
lease, requires an exact prepared reply, applies only that reference, and
rolls it back on any embedded error, unexpected state, disconnect, or drop.
The helper now persists a private journal before each fixed `/sbin/route`
mutation, tracks pending/applied CIDRs, expires leases after bounded heartbeat
silence, and rolls back on XPC invalidation. The availability guard now uses a
normalized explicit IPv4 netmask/IPv6 lookup plus a read-only routing-table
overlap scan. The v2 candidate fails closed on exact, more-specific, unknown-
interface, or unclassified non-default overlap; it permits a less-specific
covering route only on the exact typed active-Mihomo interface, while the
ordinary default underlay remains ignored. The signed synthetic fixture proves
that protocol boundary, but packaged-Mihomo acceptance remains an S1.13 gate.
The helper's read-only parser/overlap self-test is now part of the macOS CI
compile gate. A signed VM
probe confirmed dual-stack normal apply/rollback, exact IPv4/IPv6 conflict
refusal, and a more-specific `/25` refusal without writing a journal.
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
rollback failure and retry, heartbeat/lease expiry, helper restart
reconciliation, and corrupt-journal fail-closed behavior; it never invokes
`/sbin/route`. The CI compile gate runs both the read-only route probe and this
injected coordinator matrix. The
redacted dual-stack/conflict evidence is retained at
`target/macos-vm-lab/evidence/app-launch-20260722/route-helper-dual-conflict-20260722.txt`.
The privileged VM's complete v2 journal-corruption/restart matrix passed with
the signed client. Evidence is retained at
`target/macos-vm-lab/evidence/route-helper-v2-20260722/route-helper-v2-matrix.log`
(SHA-256
`7054e0c0cf66b73e969ea880cd8a901eb4a71f68419feb205b8587b4b8645661`). The
synthetic-Mihomo owner evidence is retained beside it (SHA-256
`9df6a2394737ae626c1effcacc7452a8403e0f4eb1630e007decb2fbba3de7dc`). The
matrix proved dual-stack normal apply/rollback, exact and more-specific
trusted-interface refusal, unknown-interface covering refusal, explicit
empty/wrong/matching Mihomo classification, helper kill/restart recovery,
journal corruption error 8, and final route/journal/lease absence. No
production route, DNS, endpoint, or credential was used.

The typed Mihomo amendment is now implemented through the v2 Rust/Objective-C/
Swift wire and journal boundary. Its live-source and packaged-Mihomo checks
remain an S1.13 gate; the synthetic fixture evidence does not authorize a
less-specific route on a real app build by itself.

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

Status (2026-07-22): in progress. The signed VM helper/XPC client and v2 typed
boundary pass the synthetic-Mihomo matrix: a less-specific covering route is
accepted only for the exact frozen synthetic interface, while empty/wrong,
unknown-interface, exact, and more-specific cases fail closed. The complete
run also passed helper restart and journal-corruption recovery.

The separate installed-package executor has now passed both static validation
and `live-run` in the authorized `VirtualMac2,1` guest. It pinned the 2.5.3
receipt, intact app seal, Team ID/identifiers, byte-identical packaged helper,
packaged Mihomo SHA-256
`31e2e5a15c0e1df760f98525de6fc0e92e0112c475fb5c1fdc91c9100d76ef9b`,
root-private control socket, live `/configs` values, and signed-client
`if_nametoindex` evidence for `utun4094`. The matrix passed matching IPv4/IPv6
less-specific coverage, empty/wrong/unknown/exact/more-specific refusal,
Mihomo stop/restart with a changed PID and live resampling, default-route
refusal, and final process/socket/utun/route/journal/lease absence. The
redacted 69-line guest log has SHA-256
`a504fbe6c017b0719bca258b21a6f1a05fce1268d9c487d85245c8873b2fa317`.
The first run also exposed that Mihomo leaves an unbound Unix socket path after
exit; the harness now removes only that exact root-owned, single-link socket
after proving the launchd job, exact process, utun, routes, and socket holders
are absent. The complete matrix then passed from a clean preflight.

This advances but does not close S1.13. Production Rust live-source execution,
private-service reachability, app/sidecar/helper abort, guest reboot/retry, and
complete synthetic-credential/foreign-state cleanup remain required; the
packaged lab-client path is not production-controller evidence.

#### Current no-sign App-first VM probe — 2026-07-23

The user-authorized deliverable for this run is an `.app` only, without a
Developer ID signing step. The
candidate `KyClash-Lab-05516b7d.app` was launched visibly in the selected
`kyclash-macos-lab-work` guest (`VirtualMac2,1`, arm64, console user `supen`).
The KyClash Network page rendered the fixed single-site profile, and the
bundled Mihomo child stayed healthy. The main executable reports only an
ad-hoc/linker signature with no Team ID, so this is not a Developer ID-signed
candidate; no installer transaction was performed for this probe.

The UI's explicit Enable action returned `sidecar_unavailable` and kept the
helper status at `not_found`. The ad-hoc candidate cannot satisfy the helper's
fixed Developer ID and code-signing requirement, so registration/enablement
failed closed.
The production sidecar was then driven directly through its normal stdin IPC
inside the same guest as uid 501. Bootstrap and `apply_profile` were accepted,
but `prepare_tunnel` failed before the carrier or route phases; the independent
utun probe reports the underlying `tun.CreateTUN` error as `operation not
permitted`. The subsequent disconnect performed bounded cleanup. The interface
inventory remained unchanged and the sidecar exited cleanly, with no owned
utun left behind. The redacted probe record is retained locally at
`target/macos-vm-lab/evidence/prepare-utun-nonroot-20260723.md`.

The non-privileged actual-child VM run did pass independently against the
repository's loopback userspace lab: QUIC, WSS, and TCP each connected and
returned healthy samples; an attempted overlap was rejected with
`invalid_state_transition`; every transport was explicitly disconnected before
the next one; and the child exited cleanly. This closes only the userspace
carrier/IPC evidence slice, not the production utun/helper gate.

A separate user-owned Mihomo probe also failed closed at the OS boundary with
`configure tun interface: Connect: operation not permitted`; no interface or
route remained. The run root/leaf files pass local chain/key checks, but the
current System Keychain has zero matching root fingerprints, so the
system-trust probe failed. Trust import remains a separate later carrier
prerequisite. These observations are current evidence, not completion of S1.13.
No password automation, Keychain mutation, route mutation, signing, release,
or production endpoint was used.

A separately reviewed no-sign path compiles only
`networking-vm-utun-lab-app` and connects to the fixed VM socket
`/var/run/net.kysion.kyclash.vm-utun-lab.sock`. That smaller profile remains
the explicit `VM LAB · REAL UTUN · NO ROUTES` fixture.

The newer sibling `networking-vm-network-lab-app` profile has now passed its
visible disposable-VM acceptance. It connects only to
`/var/run/net.kysion.kyclash.vm-network-lab.sock`; the manually authorized
root harness created `utun4`, installed `10.88.0.2/32` after carrier health,
proved the fixed private echo over QUIC, WSS, and TCP, and coexisted with the
lab Mihomo on `utun4094`. Both App EOF and UI Disconnect cleanup passed. The
peer and all three carrier listeners were nevertheless inside the same VM and
bound to loopback, so this closes only the no-sign single-VM core-network lab,
not an independent peer, production helper/XPC, signing, or S1.13.

VM SSH uses the dedicated key. `sshpass`, `sudo -S`, scripted password stdin,
Keychain retrieval, and UI password injection remain forbidden; no password is
stored in source, commands, logs, or evidence.

The uid-501 failure exposed an unimplemented privilege boundary rather than a
carrier defect. The corrective architecture is now approved and locked in
`kyclash-privileged-tunnel-broker-review-20260723.md`: a second, independently
authenticated tunnel broker owns only the fixed sidecar/utun session, while
the existing helper remains route-only. The required route-before-tunnel crash
ordering is locked separately in
`kyclash-tunnel-route-retirement-interlock-review-20260723.md`. Source work has
since advanced through the broker-bound production factory and v3 route
composition recorded in the current source slice below. These reviews and
source gates do not convert the historical no-sign userspace probe into a
production pass. The distinct VM-utun lab App described above can add lab-only
real-interface evidence while retaining `routes_installed=false`.

The independent App-managed Mihomo matrix now also passes against a freshly
installed Developer ID-signed internal PKG in the same `VirtualMac2,1` guest.
LaunchServices produced a visible frontmost guest window, the exact installed
App and root-owned packaged Mihomo processes were proven, and live `/configs`
reported enabled `utun4093` with auto-route disabled. A continuous invariant
monitor proved system DNS, proxy state, default routes, and existing private
routes unchanged; cleanup removed the process/socket/utun and restored the
original App-data directory identity. Its redacted evidence SHA-256 is
`1e06355753e3856e01ac3e1aaf6f18687b8a6a6cb96d41e9f84c124abd6095bd`.
This closes the ordinary signed-App managed-TUN subcase, but deliberately does
not substitute for invoking `MacosActiveMihomoTunSource` through the
production-feature control path.

Scenarios:

- IPv4 and IPv6 normal connect/disconnect and private-service reachability.
- Sidecar, app, and helper abort; helper restart; guest reboot; journal
  corruption; pre-existing exact/more-specific/unknown-VPN conflicts.
- Packaged Mihomo TUN active; after the locked v2 amendment and live Rust
  observation source, prove allowed less-specific coverage, unknown-VPN
  refusal, and complete cleanup.
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

Status (2026-07-22): in progress. The loopback lab carrier now provides
deterministic latency, stepped jitter, byte-rate limiting, nth-packet loss,
nth-packet duplication, pair reordering, UDP refusal, and bounded forced
disconnect. Unit and race tests assert exact delivery order and cancellation-
aware delays without external networking. TLS identity refusal, frame bounds,
fragment expiry, replay refusal, abrupt server close, and Rust-commanded
QUIC/WSS/TCP fallback already have focused coverage. Additional bounded tests
now cover blocked stream writes, cancelled QUIC receives, abrupt authenticated
QUIC peer close, and twelve repeated userspace connect/disconnect cycles. The
prior full Go suite and CI-equivalent race suite passed at `-count=5`; a
loopback soak driver is available at
`network-sidecar/lab/linux/reliability-soak.sh` and completed ten rounds. The
Rust process-level actual-child traffic, explicit QUIC/WSS/TCP sequencing, and
the locked stdio protocol-v2 cancellation matrix now pass. Evidence scope is
recorded in `docs/testing/kyclash-network-reliability-20260722.md`.

The production service monitor now also performs the locked runtime fallback
instead of tearing the entire connection down at the first health threshold.
It retains the owned utun and route lease, heartbeats that lease, explicitly
disconnects and observes the failed carrier absent, and then attempts only the
remaining ordered fallbacks. Focused tests prove QUIC failure followed by WSS
failure reaches TCP only after two disconnects, with no route reapply or
rollback during the successful switch. Exhausting all carriers converges
through route rollback, tunnel stop, and secret release with the stable
`fallback_transport_unavailable` reason. Because the monitor cannot join its
own heartbeat task, it remains in fail-closed `Error` after automatic resource
cleanup; an explicit Disconnect performs the exact external join before
publishing `Disconnected`. The production-code Go health path and actual-child
Connect/Health cancellation now pass against
repository-owned encrypted loopback peers; this is not an external
production-endpoint claim.

The cancellation amendment is now committed as `8811dda9`. It closes three
independent carrier races exposed by the hosted protocol-v2 run: a completed
frame write whose cancellation result won locally (sequence advancement), a
late `context.AfterFunc` deadline callback (callback join before reset), and a
cancelled probe racing a buffered Pong (cancellation wins while consuming the
matching Pong). Deterministic unit tests, ordinary and race stress, the full
Go race suite (`-count=5`), and a 20-round loopback reliability soak passed.
Hosted run `29932701242` subsequently passed the full macOS verification,
including the cancellation/race and actual-child steps; its evidence is
recorded in the hosted continuation above.

The consolidated short CI matrix is configured in the macOS sidecar workflow;
stable reason-code assertions for the exercised impairments are covered locally
and in the longer race matrix. Extended Linux VM soak and network-change
recovery evidence remain open. No fallback is introduced implicitly inside Go.

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
helper absence, PKG signature, installed-app-readable trust-manifest mode, and
emits a byte hash. A disposable-VM upgrade exposed that the public sidecar
trust manifest had inherited source mode `0600`; after `pkgbuild` changed its
owner to `root:wheel`, the normal app user could not read the sealed resource
or complete deep signature verification. Commit `8bd179d1` fixes the producer
to enforce `0644` after every write and makes package verification fail on any
other mode. The previous corrected Developer ID-signed internal candidate had
SHA-256 `b06d0c64bce8b50459875bf905ade2a244d17537f8a22e34ca270b008ed434f1`.
After commit `be3c9f39` was pushed, the latest exact internal candidate was
rebuilt and has PKG SHA-256
`0a95bb3933eb19625e555a9005b852a4c6511d4dd7d6aee1b67fa0dae0c17fb4`.
Its app executable, sidecar, and helper hashes are recorded in
`docs/testing/kyclash-macos-arm64-pkg-20260721.md`. The previous candidate
upgraded successfully in the disposable guest; as the non-admin test user,
the receipt, `0644` manifest, exact sidecar hash match, nested Team ID, and
deep strict app signature all passed. LaunchServices then ran the installed
`/Applications/KyClash.app`, its Mihomo child, and singleton listener while
the previous lab-copy process was absent. Redacted evidence and the visible
installed-app capture are retained under
`target/macos-vm-lab/evidence/app-launch-20260722/`. Performance baselines,
fresh-install/rollback/uninstall/reboot evidence, and the latest exact-byte VM
lifecycle matrix remain open. The latest candidate passed the host package
audit and visible LaunchServices smoke. Notarization was intentionally not
required for either internal candidate.

The subsequently rebuilt internal candidate after `04c4e4d9` is the exact
installed package used by the packaged-Mihomo VM matrix. Its PKG SHA-256 is
`ff6aa01b005550a78869ee7a94b63b8acc1840da553290e63901760605f98bac`;
the app executable, sidecar, and helper SHA-256 values are respectively
`d1e02264ef21a1ad94bcdf2f653ccbd8fbb21a7c5960b999ca8d96e424416a8f`,
`f50e402be47f3c15196807784b46f6ec141234a929b401613f07fe3e59dbe557`,
and `aa6816decd845e167747adf953fd4406da12674860383b3b4d3573057e3d8280`.
It is Developer ID signed with a trusted Installer timestamp and intentionally
unnotarized. It remains an internal subsystem candidate, not the final
production-feature S1 candidate.

The retained historical notarized package was then exercised as a rollback
artifact. Its installer transaction succeeded, but its application did not
remain running or restore the singleton listener within the bounded poll and
it predates the production sidecar trust resource. It is therefore recorded as
negative compatibility evidence, not an acceptable rollback candidate. The
corrected current candidate was immediately reinstalled; non-admin deep
signature verification, manifest mode, installed-app launch, Mihomo child, and
listener all returned to the passing state. Redacted evidence is
`target/macos-vm-lab/evidence/app-launch-20260722/pkg-rollback-restore-20260722.txt`.
A compatible retained rollback artifact is still required.

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

#### S1.13 current source slice — 2026-07-23 production broker/v3 chain

The production source chain is now wired but does not close the S1.13 VM
aggregate. A fresh tunnel-broker session is prepared without a Rust runtime
generation. After the controller allocates its generation, the prepared stdio
launcher binds it exactly once at the launch edge. The accepted handshake
issues a non-copyable receipt containing the independent Rust generation,
broker generation, and exact broker-assigned sidecar identity. Restart
prepares new broker material; abandoned, stale, ambiguous, or not-exactly-
reaped sessions cannot be reused or represented as positive absence.

The receipt and matching `TunnelDeviceFacts` produce one sealed route
authority. The production v3 route lifecycle preserves the exact
broker/sidecar/lease/operation tuple and enforces:

`hold_pending (durable) -> exact broker hold -> held -> route apply -> applied`

and, on teardown,

`route rollback -> successful post-delete absence inspection ->
retirement_pending (durable) -> exact broker release -> released`.

The Objective-C root bridge is linked only into the route-helper target. The
helper's no-argument path selects the production v3 listener; explicit v3 and
legacy v2 lab listeners require their fixed CLI/environment gates. Production
and explicit v3 lab listeners use the root-owned atomic v3 plist store with
strict schema, ownership, permission, symlink, and same-owner startup-recovery
checks.

Both the route-helper v3 App client and the helper-to-broker root client now
allocate a fresh XPC connection epoch after timeout, interruption,
invalidation, or remote transport failure. They never replay the failed
ambiguous call, and a callback from an older epoch cannot terminalize the
replacement. Definitive broker rejection is distinct from ambiguous transport
outcome. A possibly committed hold therefore retains `HoldPending` recovery
authority and refuses new work; it is never erased as though no hold existed.

The helper heartbeat watchdog sends an expired active lease through the same
rollback/prove-absence/release path. A nil or failed post-delete route
inspection is not positive absence and retains the durable journal in
recovery-only state. The tunnel-broker heartbeat watchdog marks the held tuple
as recovery-required but deliberately keeps the exact child/utun and hold
until the helper proves routes absent and releases that tuple. A bounded exact
tombstone supports a lost-release-reply retry without converting an unknown or
stale generation into reap evidence.

Production Connect requires both fixed SMAppService daemons to report enabled
and independently verifies the bundled route-helper and tunnel-broker
identifier/Team-ID requirements plus their exact launchd labels, Mach services,
and bundle programs. This readiness gate accepts no caller-selected path or
requirement. The production feature remains default-off outside the reviewed
candidate.

These are source and contract-test results only. No new signing, helper
registration, broker contact, production route mutation, or release
publication is claimed by this slice. S1.13 remains the first incomplete
aggregate criterion: the exact production candidate must still pass the
disposable-VM Connect, real-utun, private-service reachability, private-route,
packaged-Mihomo coexistence, QUIC -> WSS -> TCP, abort/reboot, and final-
absence matrix.

The separately reviewed unsigned App is deliberately not that candidate. Its
newer `networking-vm-network-lab-app` sibling has passed real-utun, fixed
private-route/reachability, Mihomo coexistence, QUIC -> WSS -> TCP, App-EOF,
and visible-Disconnect acceptance in `kyclash-macos-lab-work`. The exact App
executable SHA-256 is
`39866bf893106aeaa9c567cc33e0c1394a820177df794b1785841166846822a2`.
Its compatible peer and carrier listeners still run inside the same root
harness and bind loopback, so it cannot claim a second device, external/site
server, production XPC, signing, publication, or S1.13 completion. The next
core lab gate is a separately reviewed independent Peer VM; production and
staging endpoints remain outside this program's authorization. SSH already
uses the VM-only key; `sshpass`, `sudo -S`, and all password injection or
retention are forbidden.

#### S1.13 Linux Peer live-runtime contract and config-v2 continuation

The Linux Peer live-runtime contract has passed the required three independent
review tracks and is locked for source implementation and isolated Linux
acceptance. The reviewed-content SHA-256 is
`e68c5938fe26b4729f4f4404c7ce222a1b6eed18e671c327e384e3ff5e57c998`;
all final verdicts are C0/H0/M0.

The first merge unit implements only the public config/schema boundary:
schema v2, carrier-auth v1, one configured client, one brokered Linux TUN-FD
mode, fixed check path, canonical keys and endpoints, bounded nonoverlapping
private prefixes, and exact IPv4/IPv6 family-set agreement across server,
client, and forwarding policy. The superseded v1 artifacts remain negative
evidence. Non-cached focused tests, race tests, vet, Linux cross-build checks,
and the full Go test/vet gates pass.

The Peer remains fail-closed: no live command exists and the old fixed
credential-directory skeleton cannot be reached through the public loader.
The next units must implement profile-v2 pairing and the exact
invocation-bound credential/ACL-v2 boundary before TUN brokerage, TLS
possession proof, QUIC/WSS/TCP listeners, route WAL/lease recovery, hardened
systemd activation, and isolated live-runtime acceptance. This source unit
does not authorize deployment, site contact, PVE/ROS/K3s changes, or S1.13
closure.
