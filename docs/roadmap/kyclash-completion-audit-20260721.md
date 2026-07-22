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
failure tests pass. The first incomplete safe source criterion is now the
production-feature live-source and typed service-lifecycle path required by the
incomplete S1.13 VM aggregate. Its controller-absence prerequisite is locally
closed: only a never-spawned or exact stop/reap generation can retire, retained
handles become mutation-inert, and launch secrets are destroyed immediately.
The route-boundary terminal receipt remains the next source criterion. This
audit is not a terminal completion or permission to stop continuous delivery
while safe work remains.

This is not a production-release declaration. Continuation is authorized. Real
route and lifecycle gates still require disposable hosts, and impaired-network
validation requires a compatible isolated endpoint. Notarization is an optional
public-distribution enhancement rather than a current development blocker.

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
  composed and lazy, but remains default-off in ordinary/release builds and
  fails closed when its signed policy/trust resources are not provisioned.
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
- The protocol-v2 sidecar workflow is now active on every relevant change. Run
  `29921505966` for XPC-A completed its signing, impaired-network, and Linux
  reliability jobs, while its verification job exposed the three cancellation
  races corrected in commit `8811dda9`. Local ordinary/race stress, the full
  Go race suite (`-count=5`), and a 20-round loopback soak pass for that fix;
  The latest hosted run `29923178571` passed signing, Linux impaired-network,
  and loopback-soak jobs but its macOS verify job still failed in the hosted
  race step; the hosted gate remains red and is not represented as green here.

## Remaining system, external, and activation gates

The following work remains after S1.12. Safe repository work and the already
authorized disposable-VM matrix continue without another routine prompt;
production infrastructure, updater publication, and release activation remain
separate authorization boundaries:

1. Finish the route-boundary terminal receipt, service mutation gate, and
   command-layer CAS rematerialization, then exercise the production-feature
   Rust live-source path against the packaged
   Mihomo control API in the disposable VM, including private-service
   reachability, app/sidecar/helper abort, reboot/retry, aggregate foreign-route
   cleanup, and typed service retirement. XPC-C's bounded replacement and
   read-only reconciliation source prerequisite is closed; the ordinary
   signed-App managed-TUN subcase has passed and is not substituted for this
   production boundary.
2. Test a reviewed compatible server endpoint under loss, jitter, UDP blocking,
   sustained load, suspend/resume, and network switching.
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
| Keychain destructive lifecycle | Complete on disposable GitHub macOS runner; scoped to `net.kysion.kyclash.test` | No | None |
| Real route mutation and crash recovery | v2 typed lease/journal, dual-stack VM transaction, conflict/restart/journal-corruption, packaged-Mihomo, and ordinary signed-App managed-TUN VM matrices passed; production Rust live-source/reachability/abort/reboot aggregate remains | Yes, for production route adapter | Production-feature VM evidence and isolated private-service fixture |
| Impaired-network and sustained transport validation | Deterministic loopback + race count=5 + ten-round soak passed; Linux netem CI evidence retained; external matrix pending | Yes, for production data plane | Compatible isolated server and disposable client host |
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
