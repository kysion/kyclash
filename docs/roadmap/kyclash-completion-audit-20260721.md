# KyClash completion audit — 2026-07-21

## Decision

The locked single S1 stage remains in progress. Its architecture, isolated
runtime proof, development UI, credential boundary, release procedure,
branding, documentation, CI, signed-but-unnotarized arm64 development PKG, and
route-helper v2 evidence have passed their applicable gates through S1.12.
S1.04 is complete again after the atomic stdio protocol-v2 Rust/Go/TypeScript,
strict-wire, race, actual-child, and lifecycle gates passed. The exact
policy-identity portion of the locked production restart/rematerialization
implementation is complete, and XPC-A (the helper accepted-connection
barrier) is now locally closed. Registration occurs before XPC resume, all
requests require a live registered generation, and invalidation performs the
owned rollback before a replacement can certify idle. XPC-B (the Objective-C
first-wins terminal-generation and precise transport-status boundary) is now
locally closed in `96064f84`, with deterministic self-tests and independent
review. XPC-C (Rust-owned replacement and same-generation read-only
reconciliation) is locally closed in the current source unit: the bounded
replacement, frozen-owner retention, no-mutation-replay rule, and injected
failure tests pass. The broker-bound/v3 production source prerequisites are
now implemented behind the default-off feature and covered by their local
contract gates. The first incomplete criterion is the S1.13 disposable-VM
runtime aggregate. Its controller-absence prerequisite is locally
closed: only a never-spawned or exact stop/reap generation can retire, retained
handles become mutation-inert, and launch secrets are destroyed immediately.
The route-boundary terminal receipt is now locally closed: a receipt requires
an idle reconciled generation, no owner/reference or in-flight native call, and
synchronous destruction of that exact native client; busy and recovery-only
boundaries cannot retire, `Drop` cannot mint proof, and retained retired
boundaries reject mutation. The receipt binds a process-unique boundary
incarnation as well as its native generation, but remains route-local evidence:
it does not prove absence of queued service tasks or make an old service `Arc`
inert. The service mutation gate, generation-bound Connect reservation,
queued/joined route-task ownership, aggregate retirement receipt, and command
CAS are now locally closed. Connect reserves before task publication;
replacement compare-removes only the exact Arc/generation and retains bounded
redacted evidence on failure. This audit is not a terminal completion or
permission to stop continuous delivery while safe work remains.

The 2026-07-23 source chain has advanced beyond the earlier unwired broker/v3
checkpoint. The default-off macOS production factory now prepares one fixed
broker session, binds the independently allocated Rust runtime generation only
at the one-shot stdio launch edge, derives bootstrap and route authority from
the broker-assigned reference, and constructs the fixed route-helper v3 client.
The helper's no-argument path selects the production v3 listener. Transient v3
helper and root-broker client failures create a fresh XPC connection epoch
without replaying the failed request or allowing an obsolete callback to
terminalize the replacement. Helper and broker heartbeat watchdogs retain
recovery authority, positive route absence requires a successful post-delete
inspection, and rejected operations are distinguished from ambiguous remote
outcomes. Production Connect also verifies the fixed bundled helper/broker
code requirements and exact launchd manifests in addition to their enabled
service status. These are source and contract-test results, not disposable-VM
production acceptance.

This is not a production-release declaration. Continuation is authorized. Real
route and lifecycle gates still require disposable hosts, and impaired-network
validation requires a compatible isolated endpoint. Notarization is an optional
public-distribution enhancement rather than a current development blocker.

The separate unsigned core-network App lab has now passed against exact
executable SHA-256
`39866bf893106aeaa9c567cc33e0c1394a820177df794b1785841166846822a2`.
It proves a visible real utun, fixed private route/reachability, Mihomo
coexistence, QUIC -> WSS -> TCP, App-EOF cleanup, and visible-Disconnect
cleanup in `kyclash-macos-lab-work`. Its Peer and carrier listeners remain in
the same VM/root harness and bind loopback. It is therefore not a compatible
independent endpoint and does not close S1.13.

## Completed evidence

- The route transaction engine covers conflict refusal, rollback, restart
  recovery, idempotence, and fault injection without changing host routes.
- XPC-A's helper connection barrier is locally closed: accepted IDs register
  before `resume`; every request requires a live registered generation; sole
  generation discovery is the only authoritative `idle`; stale IDs fail
  closed; and invalidation rollback retains the journal and recovery tombstone
  on failure. The native lab client retries only typed v2 `not_ready` on that
  same connection generation.
- The production controller now distinguishes reusable shutdown from permanent
  retirement. A private generation-bound receipt requires positive child
  absence, stop timeout/CrashLoop cannot produce it, retained handles reject
  every later mutation, diagnostics remain read-only, and launch context plus
  authentication proof are destroyed before the receipt is returned.
- The production route boundary now distinguishes reusable, busy,
  recovery-only, and retired generations. Its one sealed retirement receipt is
  issued only after exact idle ownership and native-call absence are proved and
  the exact boundary incarnation/native generation is synchronously destroyed;
  retained retired boundaries cannot reconnect or mutate routes. This is one
  required service-retirement fact, not standalone replacement authority.
- Production initialization now persists only revision, exact signed-envelope
  SHA-256, and key ID under a bounded cross-process transaction. Exact restart
  is zero-write; v1 migration, expiry, same-revision identity changes,
  concurrent writers, directory/lock replacement, atomic publication,
  rollback, and resource TOCTOU/fault boundaries have deterministic coverage.
  Initialization still cannot read Keychain, open XPC, start a sidecar, create
  utun, or mutate routes.
- The Go sidecar implements authenticated bootstrap and IPC, WireGuard carrier
  adaptation, QUIC fragmentation/reassembly/replay protection, and authenticated
  WSS/TCP fallback boundaries.
- Entrypoint tests prove that rejected arguments, inherited environment state,
  malformed bootstrap input, and malformed IPC cannot enter process diagnostics;
  failure output is constant and attacker-controlled error chains are not
  formatted.
- An isolated userspace test proves WireGuard through fragmented QUIC in both
  directions without creating interfaces, routes, DNS changes, or external
  connections.
- The development-only macOS UI exposes lifecycle, health, routes, transport,
  errors, cancellation, and allowlisted diagnostic export through a mock
  command boundary. The production command boundary is now explicitly
  composed through the broker-bound/v3 route chain and remains lazy and
  default-off in ordinary/release builds. It fails closed when its signed
  policy/trust resources, privileged-service readiness, bundled code
  requirements, or exact launchd manifests are not satisfied.
- The production broker session is prepared without a Rust generation and is
  bound exactly once when `StdioSidecarRuntime` allocates the launch
  generation. Broker and Rust generations remain independent, and abandoned
  preparation, stale generation, ambiguous transport loss, or failed exact
  reap cannot be converted into reusable absence evidence.
- Route-helper v3 now has a production no-argument listener, exact-generation
  reconnecting native clients, root-owned durable journal recovery, positive
  post-delete absence checks, distinct rejected/ambiguous broker outcomes, and
  helper/broker heartbeat watchdog coverage. An ambiguous hold or failed
  absence proof retains the exact tuple and blocks a fresh Connect.
- The credential boundary uses fixed Keychain references and redacted,
  clear-on-drop secret material. Automated tests do not touch the host Keychain.
- The release workflow requires separate Application and Installer identities,
  optional notarization/stapling, SBOM/provenance evidence, and rollback
  controls. Updater permissions remain disabled pending the GitHub updater
  activation transaction.
- The release pipeline cannot generate updater JSON or invoke updater publishing,
  the manual inherited updater workflow is absent, fixed-WebView2 overrides do
  not restore an inherited verification key, and a CI verifier locks these
  conditions together with both runtime update gates.
- Inherited scheduled/multi-platform publication and notification workflows are
  absent. The remaining release workflow is macOS arm64 only, defaults closed
  behind an explicit repository authorization variable and protected
  environment, and can create only a draft after all signing, notarization,
  signature, checksum, and provenance checks succeed. Optional notarization and
  stapling evidence is required only when that enhancement is enabled.
- Maintained README and issue intake surfaces identify KyClash, link only to the
  KyClash repository for releases and support, preserve explicit upstream
  attribution, and no longer advertise upstream packages, AutoBuild channels,
  funding, Telegram, or third-party promotions as KyClash resources.
- The current arm64 development PKG evidence is recorded in
  `docs/testing/kyclash-macos-arm64-pkg-20260721.md`. Its Application and
  Installer signatures are valid, but it is unnotarized, unstapled, rejected by
  Gatekeeper, and must not be represented as a release artifact.
- GitHub Releases updater preparation is source-complete: its owned endpoint,
  inert build template, metadata schema/sample/validator, metadata builder,
  streaming signature verifier, rollback policy, and CI configuration names are
  documented in `../release/kyclash-github-updater-v1.md`. Runtime gates remain
  off and no Release has been created or endpoint activated.
- Dormant runtime update paths now validate the owned GitHub URL and strict
  KyClash metadata policy before download and cached-install refresh. Rejected
  metadata fails closed without being echoed into logs.
- Cached updater bytes are cryptographically verified again immediately before
  installation. Missing public-key configuration, malformed encoding, altered
  cache bytes, or signature mismatch deletes the cache and refuses installation.
- The frontend manual-check wrapper independently rejects and closes metadata
  that violates the same KyClash GitHub/platform/source/rollback contract,
  preventing a future JavaScript capability from bypassing the Rust policy.
- A newly rebuilt Developer ID arm64 bundle now launches visibly in the
  disposable macOS VM. The GUI smoke proved a live KyClash window, bundled
  Mihomo child, and singleton listener; evidence and the updater-plugin startup
  fix are recorded in `docs/testing/kyclash-macos-virtualization-lab.md`. The
  latest foreground run uses `~/kyclash-lab/app-run-20260722-3/KyClash.app`;
  its clean Home-page capture is
  `target/macos-vm-lab/evidence/app-launch-20260722/kyclash-live-vm-home2-20260722.png`
  (SHA-256 `37a762972cee3f067c7e0eb977a22bb3af40f772b910ffb06d246855f2d15377`).
- The same disposable guest then recorded a real GUI logout/re-login cycle:
  logout removed the console session, KyClash process, bundled Mihomo process,
  and singleton listener; a Tart guest restart restored the console and the
  signed login-item launch. An exact app SIGKILL also showed the ordinary
  `verge-mihomo` proxy core surviving as an adopted process. That binary is not
  the production Go sidecar, so the observation remains a separately tracked
  non-production cleanup limitation; the production-sidecar child-absence
  gate is closed by the combined controller/utun evidence below.
- A signed `kyclash-network-sidecar` controller-boundary run in the same
  disposable guest generated only ephemeral in-memory bootstrap material,
  read the handshake, and then SIGKILLed the exact controller PID. The Go
  sidecar disappeared within the 10-second poll window after stdin EOF; the
  redacted result is retained in the VM evidence directory. A rebuilt signed
  sidecar was then tested with stdin held open by an inherited writer; after
  the exact controller was SIGKILLed, the sidecar detected re-parenting and
  exited within 100 ms while the writer remained alive. This closes the signed
  Go process-boundary observation. A separately gated privileged hold fixture
  then created `utun4` in the authorized Virtualization.framework guest, was
  terminated by exact PID SIGKILL, and was independently verified absent by
  `ifconfig`; the redacted record is
  `target/macos-vm-lab/evidence/app-launch-20260722/utun-controller-kill-v3-20260722.txt`.
  This closes standalone kernel/device release after forced termination. The
  signed production `run()` boundary was then exercised in the same guest: a
  controller spawned the actual sidecar child, the child owned `utun4`, and an
  exact controller SIGKILL was followed by child and interface absence on the
  first one-second poll. The redacted record is
  `target/macos-vm-lab/evidence/app-launch-20260722/utun-combined-controller-20260722.txt`.
  S1.10's real-utun termination gate is complete; the ordinary inherited
  Mihomo proxy orphan after app SIGKILL remains a separate non-production
  cleanup limitation.
- The complete local gate passed on 2026-07-21: frontend typecheck/build/lint,
  localization and dead-code checks; 142 Rust all-feature library tests; two
  process-level sidecar tests; Clippy with all features and warnings denied; Go module
  verification, formatting, repeated race tests, and vet.
- The protocol-v2 source closure gate passed on 2026-07-22: 245 Rust
  all-feature library tests passed with the one scoped disposable-account
  Keychain lifecycle test ignored; the 14-test stdio matrix plus the production
  controller's blocked-cancellation case passed against freshly built
  production and lab Go children; and Go module, formatting, normal, race,
  vet, and shared-fixture parity gates passed. This evidence is loopback/local
  and is not a production-endpoint claim.
- The protocol-v2 sidecar workflow is active on every relevant change. GitHub
  Actions run `29932701242` (#69) passed all four jobs: macOS verify (including
  per-package `-race -count=5`, actual-child, benchmark, vet, reproducible
  build, and SBOM), signed macOS bundle, Linux loopback reliability soak, and
  Linux impaired-network matrix. The race evidence artifact is `8535377645`
  with digest
  `sha256:04441aecb2f2d21bd32d8e27ae0ca8ab010f7e71e9b3cce30602134cc6f82f98`.
  The hosted CI gate is now green; it does not substitute for the still-open
  production-feature VM/live-source aggregate gate.

## Remaining system, external, and activation gates

The following work remains after S1.12. Safe repository work and the already
authorized disposable-VM matrix continue without another routine prompt;
production infrastructure, updater publication, and release activation remain
separate authorization boundaries:

1. Exercise the explicit production-feature, lab-marked Rust live-source path
   against the packaged
   Mihomo control API in the disposable VM, including private-service
   reachability, app/sidecar/helper abort, reboot/retry, aggregate foreign-route
   cleanup, and typed service retirement. The broker-bound dynamic-generation,
   v3 listener/client, heartbeat watchdog, positive-absence, ambiguity, and
   bundled-code-requirement source prerequisites are closed; the ordinary
   signed-App managed-TUN subcase has passed and is not substituted for this
   production boundary.
2. Move the compatible Peer out of the client VM under a separately reviewed
   two-VM lab boundary, then test it under loss, jitter, UDP blocking,
   sustained load, suspend/resume, and network switching. The completed
   same-VM `127.0.0.1` Peer is only the preceding core-network fixture.
3. Enable the already composed production command boundary only after the
   required S1 route/lifecycle evidence passes and activation is separately
   authorized; ordinary/release builds remain default-off meanwhile.
4. Optionally exercise the manual destructive Keychain lifecycle test on a
   disposable account using only `net.kysion.kyclash.test`; this does not block
   other development.
5. Optionally notarize and staple a public-distribution candidate when the
   operator chooses to provide Apple notary credentials.
6. Run authorized fresh-install, upgrade, rollback, uninstall, forced-exit,
   service, system-proxy, TUN, and cleanup validation.
7. Provide the generated public verification key, signed immutable GitHub
   artifacts, retained rollback version, disposable-host lifecycle evidence,
   and separate authorization before atomic updater activation and publication.
8. Begin macOS x64 and later platforms only after the macOS arm64 MVP release
   gates above are closed.

## Current execution matrix

| Work item | Current state | Stops current source work? | Required external input |
| --- | --- | --- | --- |
| GitHub updater contract, templates, metadata and verification tools | Complete and default-off | No | None |
| GitHub updater activation and first metadata publication | Prepared, not authorized or enabled | Yes, for live updates only | Generated public key, protected private signing secret, retained rollback artifact, lifecycle evidence, and explicit publication/activation authorization |
| Developer ID internal arm64 PKG | Signed; unnotarized with Gatekeeper warning | No | None |
| Apple notarization and stapling | Optional enhancement | No | Notary credentials only if selected |
| Keychain destructive lifecycle | Scoped manual/ignored test only; `.test` namespace contract and non-destructive source gates pass | No | Disposable account/VM only when the manual lifecycle run is selected |
| Real route mutation and crash recovery | v2 typed lease/journal, dual-stack VM transaction, conflict/restart/journal-corruption, packaged-Mihomo, ordinary signed-App managed-TUN, and unsigned same-VM core-network App matrices passed; the broker-bound/v3 production live-source/reachability/abort/reboot aggregate remains | Yes, for production route adapter | Exact production candidate VM evidence and independent private-service fixture |
| Impaired-network and sustained transport validation | Deterministic loopback + race count=5 + ten-round soak and Linux netem CI passed; visible same-VM real-utun/fallback/private-route evidence passed; independent-Peer matrix pending | Yes, for production data plane | Reviewed independent Peer VM and disposable client VM |
| Install/upgrade/rollback/uninstall cleanup | Procedure prepared; signed GUI smoke passed; full installed-byte matrix pending | Yes, for general distribution | Disposable macOS lifecycle host and retained candidate/rollback artifacts |
| macOS x64 and later platforms | Deferred by locked platform order | Yes, for those platforms only | macOS arm64 MVP gates closed |

## Resume rule

The project skill treats a request to continue through all stages as standing
authority for safe repository work. Future execution resumes automatically at
the first authorized item above; it does not require repeated “next step”
prompts. Credentials and real host or external-system mutations remain explicit
authorization boundaries.

## Authorization update — 2026-07-21

The user authorized continuation after this audit. The repository now contains
the feature-gated real route executor and fixed-scope lab harness documented in
`../testing/kyclash-macos-route-lab.md`. Read-only preflight rejected the current
development Mac as the mutation environment because it carries active split
routes and multiple tunnels and has no non-interactive elevation. At that
checkpoint item 1 remained open for a disposable macOS host. The subsequent
signed v2 route matrix closed S1.12, and the packaged-Mihomo plus ordinary
signed-App managed-TUN matrices advanced S1.13. The production Rust
live-source, reachability, abort/reboot, and aggregate cleanup cases remain the
S1.13 continuation recorded below.

The authorized credential-lab source preparation is also complete. The
feature-gated fixed-service lifecycle harness and disposable-account procedure
are documented in `../testing/kyclash-macos-keychain-lab.md`. Its destructive
cycle remains manual on the daily-use development account. The separately
scoped `net.kysion.kyclash.test` cycle passed on a disposable GitHub macOS
runner; neither case blocks updater or other source work.

## Linux VM network-lab preparation — 2026-07-21

The Linux-capable portion of item 2 now has a repository-owned Ubuntu ARM64
`tc netem`/nftables harness and runbook. It validates authenticated baseline
transports, bounded loss/jitter/rate impairment, UDP blocking with WSS/TCP still
available, and sustained fragmented-QUIC benchmarking without production
endpoints or credentials. The harness refuses non-Linux hosts, requires root
only inside the disposable VM, defaults to loopback, and removes its isolated
traffic-control state on exit.

The matrix passed on the isolated GitHub-hosted Ubuntu ARM64 runner in workflow
run `29802494990` for commit `f73f822b6025e36d4af63e3578bbeab2d4aa337f`.
Both `linux-impaired-network` and the ordinary sidecar verification job
succeeded, and the Linux evidence artifact is retained through 2026-08-04.
This closes the reproducible isolated Linux server/network subset without
requiring a local Fusion VM. Linux execution cannot close the macOS utun,
route, lifecycle, sleep/wake, or network-switch gates, and a separately reviewed
compatible server remains necessary before production-endpoint claims.

## Deterministic reliability continuation — 2026-07-22

The sidecar reliability suite now records bounded cancellation and recovery
edges in addition to the existing impairment, framing, replay, and fallback
tests. The full Go suite and the CI-equivalent race gate passed at `-count=5`;
a repository-owned loopback soak driver completed ten rounds and retains one
log per round for longer disposable-VM runs. The exact commands, scope, and
remaining production boundary are recorded in
`../testing/kyclash-network-reliability-20260722.md`. This advances the
reproducible source/loopback subset but does not close external sustained-load,
sleep/wake, or physical network-change gates.

## GitHub-hosted macOS system gate preparation — 2026-07-21

The fixed-scope Keychain lifecycle and TEST-NET route transaction now have a
dedicated `macos-15` workflow. It runs only on GitHub-hosted disposable VMs,
requires passwordless elevation, captures redacted fixed-scope evidence, and
uses an exit trap to recover the route journal, delete the synthetic Keychain
item, and remove only the dedicated lab files.

Workflow run `29804311056` passed on `macos-15` ARM64 for commit
`bdb0feeae4e3a0c93924cb64b6fe2dec86192dd2`. It closes the fixed Keychain
lifecycle plus normal and forced-exit route recovery sub-gates. Redacted
artifact `8484981045` is retained through 2026-08-04. PKG lifecycle, Mihomo
coexistence, utun, sleep/wake, and physical network switching remain outside
this initial gate.

## Local Apple Virtualization.framework lab — 2026-07-21

The local disposable-host route is now locked to Apple Virtualization.framework
on the Apple Silicon development Mac. The repository uses Tart as a thin CLI
over that framework, pins the last host-compatible release (`2.32.1`), and
creates the base guest from Apple's latest supported IPSW rather than a prepared
third-party image. Tart `2.33.0` was signature-valid but exited with status 137
before command dispatch on this M5/macOS 26.5.1 host, so it is not accepted
until its compatibility is re-evaluated.

The controller and runbook are `scripts/macos-vm-lab.sh` and
`../testing/kyclash-macos-virtualization-lab.md`. The existing system lab now
accepts either its established GitHub-hosted runner or a confirmed local guest,
and independently requires a `VirtualMac*` hardware model in local mode. A
physical Mac therefore remains protected even if its caller copies all lab
environment variables. Setup Assistant has been completed, the base was stopped
cleanly, and a `kyclash-macos-lab-work` clone was created and booted. The guest
obtained a NAT address; SSH automation was still pending at that checkpoint
until Remote Login was explicitly enabled for the dedicated guest account. No
guest password is stored or passed to host automation.

Remote Login and a VM-only SSH public key were subsequently configured. The
local fixed Keychain lifecycle and route normal/forced-exit recovery lab passed,
and independent cleanup checks found no synthetic Keychain item, TEST-NET
route, or journal. The signed, unnotarized PKG then passed guest-side hash,
Installer signature, strict app signature, identity, architecture, and fresh
installation checks. Gatekeeper rejection as `Unnotarized Developer ID` was
confirmed; user-visible launch override and the remaining lifecycle checks
were still pending at that checkpoint, without weakening Gatekeeper globally.

The operator then selected notarization for direct GitHub distribution and
configured a local `notarytool` Keychain profile. Submission
`e568f45f-5b55-4dac-b068-89096d9949c1` was accepted with no issues, the ticket
was stapled and validated, and the final PKG hash became
`760cd22bb2fcaf1062417d88cb2fa4e0989176e6f873bece5bada01f008ad38e`.
Host and guest Gatekeeper now accept the PKG and installed app as `Notarized
Developer ID`; guest upgrade installation passed. This was notarization only:
no App Store record, GitHub Release, or updater activation was created.

A later current-source internal rebuild found and fixed an installed-resource
permission defect: the public sidecar trust manifest had been packaged as
`root:wheel 0600`. Commit `8bd179d1` enforces `0644` and makes the package audit
reject any other mode. The corrected, intentionally unnotarized signed PKG has
SHA-256
`b06d0c64bce8b50459875bf905ade2a244d17537f8a22e34ca270b008ed434f1`.
It upgraded successfully in the disposable guest; the non-admin test user
passed deep strict signature verification, read the manifest, matched its hash
to the nested sidecar, and launched `/Applications/KyClash.app` with its Mihomo
child and singleton listener. The earlier notarized bytes remain historical
evidence and are not claimed for this current candidate.

## Visible App and production route overlap continuation — 2026-07-22

The corrected signed PKG is installed in the disposable macOS guest, where
`/Applications/KyClash.app` has visibly run with the KyClash brand, Mihomo
child, and singleton listener. An earlier host-side diagnostic launch is not
acceptance evidence and is superseded by the guest-only matrices. The current
candidate and exact VM evidence are recorded in
`docs/testing/kyclash-macos-arm64-pkg-20260721.md`; this closes the ordinary
signed-App launch and managed-TUN subcase, but does not imply that the
default-off production networking feature has been enabled in the release
candidate.

The signed route helper now normalizes IPv4 CIDRs into explicit netmask
lookups and scans the read-only route table. Its v2 boundary fails closed on
exact, more-specific, unknown-interface, or unclassified non-default overlap;
only a less-specific covering route on the exact typed active-Mihomo interface
is eligible, while the ordinary default underlay is ignored. Its parser/overlap
self-test and injected coordinator matrix cover that policy. In the disposable
VM, a typed dual-stack
transaction passed on owned `utun4`; exact IPv4/IPv6 and more-specific IPv4
conflicts failed closed without a journal. The historical
`128.0.0.0/1`/`fd00::/8` coexistence probe is superseded and is not current
acceptance evidence. The typed active-Mihomo-interface ownership amendment is
implemented through the v2 source/wire/journal boundary, while its packaged
Mihomo live-source gate is still pending before less-specific coexistence can
be accepted through the production-feature Rust path. An earlier scoped
cleanup found no test route, journal, helper, or test utun. Later VM matrices
removed their synthetic devices, routes, sockets, journal, and lease state.
The production live-source, abort/reboot, private-service, physical sleep/wake,
and real network-switch gates remain open. Helper journal-corruption/restart
recovery itself is already covered by the signed v2 fixture matrix below.

## S1 v2 route-helper continuation — 2026-07-22

The signed v2 route-helper/client boundary and the disposable VM matrix have
now been executed, not merely prepared. `stage`, `bootstrap`, `preflight`, and
`run` all passed in the authorized `VirtualMac2,1` guest. The matrix evidence
is retained at
`target/macos-vm-lab/evidence/route-helper-v2-20260722/route-helper-v2-matrix.log`
(SHA-256
`7054e0c0cf66b73e969ea880cd8a901eb4a71f68419feb205b8587b4b8645661`). It
records dual-stack apply/rollback, exact/more-specific/unknown-interface
conflict refusal, explicit empty/wrong/matching Mihomo classification, helper
restart, corrupt-journal fail-closed, and final route/journal/lease absence.

This closes the S1.12 v2 route-lease/crash-recovery criterion. Since that run,
the packaged-Mihomo/live-control matrix and a separate signed App-managed
`utun4093` GUI/lifecycle matrix have also passed in the disposable VM. The
latter proves unchanged DNS/proxy/default/private routes, visible guest UI,
live managed TUN, final runtime absence, and original App-data restoration;
its evidence SHA-256 is
`1e06355753e3856e01ac3e1aaf6f18687b8a6a6cb96d41e9f84c124abd6095bd`.

S1.13 remains the first incomplete VM aggregate criterion for production Rust
live-source invocation, private-service reachability, app/sidecar/helper abort,
reboot/retry, and the aggregate foreign-state/credential cleanup gate. The
ordinary App matrix does not substitute for the default-off production
control path. Its exact policy-identity/restart, XPC-A helper-barrier, XPC-B
Objective-C terminal-generation, and XPC-C Rust replacement/reconciliation
source prerequisites are now complete. No endpoint, release, updater activation, production
infrastructure, or real login-Keychain lifecycle was touched.

## S1.13 production-feature candidate design lock — 2026-07-22

The independent recheck closed the candidate-review findings. Keychain
creation is atomic and create-only, duplicate/foreign items fail closed, and
destructive cleanup requires both the durable `created=1` marker and the exact
public-key witness under the scoped `net.kysion.kyclash.test` namespace. The
resolver also wipes the temporary generated buffer on generation, duplicate,
and error paths. The
guest-to-host boundary now transfers only the descriptor, policy-revision
preflight, and expiry-ceiling scalar, with same-session VirtualMac proof,
TOCTOU validation, and create-only private host publication. The candidate
design is locked and construction in `kyclash-macos-lab-work` is authorized;
runtime acceptance remains the first incomplete S1.13 gate. Ordinary builds
remain default-off, and no release/updater publication is authorized.

## S1.13 broker/session safety continuation — 2026-07-23

The first source construction slice after the design lock is now present. The
fixed tunnel-broker Mach-service client transfers only typed stdin/stdout
descriptors and a broker-assigned session reference; the Rust runtime keeps
that broker generation distinct from its own runtime generation. Exact idle
stop/reap is the only positive child-absence result. A stale generation,
transport failure, interruption, or invalidation is quarantined as
recovery-only and can never be converted into a `Reaped` receipt. Swift closes
late XPC pipe replies explicitly. Focused Rust, Objective-C, Swift self-test,
and contract gates pass. The companion pure-Rust route-helper v3 contract now
binds broker protocol/generation/sidecar ID to the lease and operation tuple,
models the hold/route/retirement journal order, and classifies v2 records as
recovery-only.

This does not close S1.13. The production composition now binds the broker
reference into bootstrap/handshake/tunnel facts, orders the v3 durable
hold/route/retirement lifecycle, and rematerializes fresh broker material for
each start. Its current source wiring is recorded below. The separate no-sign
App path is the fixed-socket VM real-utun lab with no routes; it is not a
production helper path. No password automation, signing, route mutation,
release, or production endpoint was used for that lab preparation.

## S1.13 broker-bound route authority and v3 wire continuation — 2026-07-23

The source-only continuation now closes the next identity boundary without
claiming a live production connection. A broker-bound controller start consumes
one fresh launch material and returns a non-copyable receipt only after the
exact sidecar handshake is accepted. Ordinary `start()` cannot bypass that
boundary; cancellation, failed authentication, and broker-bound child exit
remain exact-reap/recovery-only outcomes and cannot reuse a generation.

The receipt-to-route seam is now sealed in pure Rust. It verifies the same
sidecar instance in the tunnel facts, derives the complete broker/generation/
lease/operation tuple, and drives a testable durable order of
`hold_pending -> hold -> held -> apply -> applied` followed by
`rollback/prove-absence -> retirement_pending -> release -> released`.
Ambiguous hold and cleanup failures never authorize a new route or a new
sidecar; v2/v1 state remains recovery-only. The broker v3 service and bridge
now echo the complete tuple, reject legacy/v3 mixing, support exact no-op
retirement, and retain one bounded retired tuple so a lost release reply can be
retried after the child is reaped. The route-helper v3 wire/journal schema,
strict version dispatch, and an unprivileged contract self-test are installed
in the helper target. The no-argument helper path selects the production v3
listener, while v2 and v3 lab listeners require their explicit CLI/environment
gates.

All focused Rust/Swift/Objective-C/Node and full Rust library/Clippy/format
checks for that slice passed. This is not S1.13 completion: the later source
slice closes native linking, durable v3 ordering, and production composition,
but private reachability, abort/reboot cleanup, and the exact production VM
aggregate remain open. No password was automated or stored; VM SSH is
key-based, while the local administrator prompt for the separate root lab
harness is intentionally visible.

## S1.13 native route-helper v3 interlock source continuation — 2026-07-23

The root broker route client is now linked into the route-helper target through
an ARC Objective-C object and an explicit C ABI header; it is not linked into
the ordinary App. A separate v3 XPC service/delegate and injected coordinator
prove the complete hold-before-route and route-before-release lifecycle,
including ambiguous HoldPending recovery, exact release tombstones, release
failure quarantine, and connection invalidation. The production helper target's
no-argument launch path now selects the production v3 listener. The v3 lab
CLI/environment gate remains an explicit alternate path; legacy v2 is
available only through its separate explicit v2 lab gate.

The linked unsigned helper passes bridge, strict v3 journal, injected
interlock, durable-store, existing coordinator, and read-only self-tests;
Objective-C, Node, workflow syntax, Swift warnings-as-errors, and diff checks
pass. Production and explicit lab v3 listeners use a root-owned atomic v3
store and same-owner startup recovery. Fresh production composition is now
wired in the current source slice below; VM private-route/Mihomo acceptance
and the production aggregate remain open. No signing, password automation,
broker contact, production route mutation, or release publication occurred.

## S1.13 production v3 composition hardening source slice — 2026-07-23

The default-off production factory now prepares the fixed tunnel-broker
session first, consumes its broker-assigned instance identity, and binds the
Rust runtime generation dynamically and exactly once at stdio launch. A
restart obtains a fresh prepared broker session; the broker generation is
never synthesized from, or assumed equal to, the Rust runtime generation.
The factory creates the deferred production v3 route boundary and the service
holds the sealed broker/route authority through heartbeat, rollback, release,
and exact retirement.

Both fixed native v3 clients now recover from timeout, interruption,
invalidation, or remote transport failure by creating a new XPC connection
epoch. The failed in-flight call remains ambiguous and is not replayed; a late
callback from the old epoch cannot invalidate the replacement. The helper's
no-argument target remains the production v3 listener. Legacy v2 and explicit
v3 lab listeners remain selectable only through their fixed lab flags.

The v3 helper watchdog retires an expired lease through rollback, a successful
post-delete inspection, durable retirement state, and exact broker release.
A missing inspection result is not positive route-absence proof and retains
recovery authority. Broker transport loss is classified as ambiguous rather
than definitive rejection, so a possibly committed hold is never erased or
followed by route mutation. The broker watchdog marks an expired route hold as
requiring recovery while retaining the exact held child until the helper
proves route absence and releases that tuple. Production Connect additionally
requires both privileged services to be enabled and verifies the fixed Team
ID/identifier code requirements plus exact bundled launchd manifests before
opening the production path.

This closes a source/contract slice only. S1.13 is still the first incomplete
aggregate gate: the production chain has not yet passed the exact-candidate VM
Connect, real-utun, private-service, private-route, packaged-Mihomo,
QUIC -> WSS -> TCP, abort/reboot, and final-absence matrix.

The separate unsigned `networking-vm-network-lab-app` has now passed its own
locked acceptance. In the selected `VirtualMac2,1` guest it created `utun4`,
installed `10.88.0.2/32` only after carrier health, reached the private echo
over all three carriers, and coexisted with Mihomo `utun4094`. App EOF and the
visible Disconnect control each left the harness, sockets, lab Mihomo, utuns,
and routes absent with the default route unchanged. Evidence is retained under
`target/macos-vm-lab/evidence/vm-network-final-postfix-connected-20260723T025619Z/`;
the screenshot SHA-256 is
`9b9b4435c95c1aa88a66e05a25da9b0c4e3922fb08406b6bf9b3f22ebcb7391a`.
The Peer and QUIC/WSS/TCP listeners were still inside the same VM and bound to
`127.0.0.1`, so this does not prove an independent device/server or production
XPC. The next core gate is the separately reviewed two-VM Peer lab. SSH is
already key-based; `sshpass`, `sudo -S`, and every other password-injection
path remain forbidden.

## Linux Peer live-runtime lock and first source unit — 2026-07-23

The independent Peer contract review is now administratively locked for source
implementation and isolated Linux acceptance. Its approved-content SHA-256 is
`e68c5938fe26b4729f4f4404c7ce222a1b6eed18e671c327e384e3ff5e57c998`,
with final protocol, Linux, and security verdicts of C0/H0/M0.

The config/schema-v2 unit is source-complete and verified. Runtime decoding,
the JSON Schema, fixtures, and the check-only command agree on schema v2,
carrier-auth v1, one client, brokered TUN-FD mode, canonical 32-byte WireGuard
public keys, canonical DNS/listener data, bounded private prefixes, and exact
server/client/private-prefix address-family equality. V1 is rejected by both
the decoder and command. Focused tests, race tests, vet, Linux amd64/arm64 test
cross-builds, and the full Go test/vet suite pass.

This is not a live-server completion claim. The command still has no live
mode, the credential API intentionally returns unavailable, and no listener,
TUN, route, staging endpoint, or production endpoint was touched. S1.13
remains open for profile-v2 pairing, invocation-bound credential/ACL handling,
brokered TUN ownership, carrier proof/listeners, route WAL and recovery,
systemd hardening, isolated Linux acceptance, and the later macOS production
aggregate.
