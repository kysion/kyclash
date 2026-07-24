---
name: kyclash-continuous-delivery
description: Review, lock, implement, visibly run in the selected disposable macOS VM, verify, commit, and push the KyClash roadmap continuously without stopping at partial milestones. Use whenever work under the KyClash workspace concerns architecture, networking, sidecars, routes, WireGuard, QUIC/WSS fallback, UI, packaging, releases, branding, tests, documentation, macOS VM App launch or acceptance, requests to continue/finish/all-complete, or any active roadmap whose safe tasks must proceed without repeated prompting.
---

# KyClash Continuous Delivery

## Load the authority chain

Read these files before changing scope or architecture:

1. `docs/roadmap/kyclash-plan-review-20260721.md`
2. `docs/roadmap/kyclash-github-updater-review-20260721.md` for no-store
   distribution, optional notarization, GitHub Releases updater ownership, and
   manual Keychain lifecycle scope
3. `docs/architecture/kyclash-networking-v1.md`
4. `docs/architecture/kyclash-network-runtime-v1.md` when implementing the real
   data plane or sidecar
5. `docs/roadmap/kyclash-runtime-protocol-review-20260721.md` when implementing
   QUIC framing or reassembly
6. `docs/roadmap/kyclash-runtime-datagram-size-review-20260721.md` when
   implementing QUIC datagram sends
7. `docs/roadmap/kyclash-runtime-quic-order-review-20260721.md` when implementing
   QUIC receive ordering or replay protection
8. `docs/roadmap/kyclash-implementation-plan.md`
9. `docs/roadmap/kyclash-production-networking-work-program-20260721.md`
   when continuing the single S1 delivery stage; execute its first incomplete
   work package and retain its evidence and authorization checkpoints
10. `docs/roadmap/kyclash-privileged-tunnel-broker-review-20260723.md`,
    `docs/roadmap/kyclash-broker-session-binding-review-20260723.md`, and
    `docs/roadmap/kyclash-tunnel-route-retirement-interlock-review-20260723.md`
    when implementing real utun or the privileged broker/route interlock
11. `docs/roadmap/kyclash-vm-utun-lab-app-review-20260723.md` when the current
    deliverable is a no-sign App using the disposable-VM real-utun lab path;
    keep its explicit no-routes and non-production claims intact
12. `docs/roadmap/kyclash-vm-network-lab-app-review-20260723.md` when the
    current no-sign App deliverable must prove the core private-network result
    in the disposable VM: real utun, fixed private route/reachability, Mihomo
    coexistence, and QUIC -> WSS -> TCP break-before-make; keep its fixed
    sibling-harness authority and non-production claim boundary intact
13. `docs/roadmap/kyclash-vm-external-peer-lab-review-20260723.md` when the
    core private-network result must cross two disposable VirtualMac guests;
    use its locked client/peer split, courier, listener, SSH, bridge,
    supervision, evidence, and cleanup contracts without silently falling
    back to the host or a loopback peer
14. `kyclash-handoff-20260721.md` only for historical context

Treat the review record and architecture as locked. If they conflict with the
handoff, follow the locked documents. Require a new review record before
changing route ownership, secret storage, transport semantics, macOS-first
ordering, or single-site scope.

## Continue without repeated prompts

After the user authorizes execution through the complete delivery stage:

- Continue from the first incomplete roadmap exit criterion.
- Break work into reviewable commits and push each commit to `origin/main` only
  after its applicable gates pass.
- Update roadmap progress in the same commit as the implementation.
- Move directly to the next safe task after a milestone passes.
- Do not stop merely to announce a next step or request routine confirmation.
- Stop only for a genuine hard blocker, a required credential or external
  dependency, or an action outside the authorization boundary below.
- Keep the working tree clean between completed milestones.
- Treat requests such as “continue through all stages” or “complete S1” as standing authority for
  every safe action in this file. Do not wait for another “next step” between
  batches; keep advancing until all safe gates are complete or a defined
  authorization boundary is the only remaining work.

## Enforce terminal conditions

Treat continuous execution as a terminal-condition loop, not as a request to
finish one convenient batch:

```text
load first incomplete exit criterion
review/lock if required
implement
verify
commit and push the completed reviewable unit
update the roadmap
immediately load the next incomplete criterion
repeat
```

A passed test, commit, push, milestone, batch, status explanation, token cost,
elapsed time, or a clean worktree is not a terminal condition. Do not send a
final response merely because one of these occurred. Use commentary for
progress and continue making tool calls.

The production-networking roadmap has exactly one delivery stage, S1. Its work
packages and historical N1–N5 aliases are evidence units only. Never describe
one work package, one former N-group, or one CI matrix as a completed stage.
Only the aggregate S1 completion definition is a stage terminal condition.

Before every final response during an authorized execution run, perform this
stop audit:

1. Read the authoritative roadmap and identify its first incomplete criterion.
2. Check whether every remaining safe criterion is complete.
3. If safe work remains, do not finalize; continue with that criterion.
4. If an external boundary blocks one criterion, continue every independent
   source, mock, test, documentation, build, CI, and isolated-VM criterion that
   does not require crossing that boundary.
5. Finalize only when all authorized criteria are complete, or when the only
   remaining work requires a specific credential, external-state change, or
   authorization that is not already granted.

Do not label design work, a failing test, an implementation defect, or a need
for another review amendment as a blocker. Resolve it locally and continue.
Do not downgrade a user's “finish all” instruction into “finish the next
merge unit.” If the user asks for status while execution is active, answer in
commentary and resume execution in the same turn.

If execution is forcibly interrupted by the environment rather than reaching a
terminal condition, leave the roadmap truthful, keep completed commits pushed,
record the exact active criterion as `in progress`, and state explicitly that
the program is not complete. Never describe that interruption as task
completion.

## Authorization boundary

May proceed autonomously with source edits, local mocks, tests, builds, local
development processes, Git commits, and pushes to the configured KyClash
repository.

Do not mutate production PVE, ROS, K3s, routes, DNS, interfaces, tunnels,
credentials, signing identities, releases, or external infrastructure without
explicit authorization. Use in-memory or isolated local adapters until that
authorization exists. Never weaken a gate to make it pass.

## Enforce the macOS execution target

Treat the host Mac as build and orchestration infrastructure, not as the macOS
acceptance target. When a disposable Apple Virtualization.framework guest has
been selected for the work:

- Before every runtime-affecting command, classify its target as `host-build`
  or `guest-runtime`. Commands that invoke `open`, `installer`, an App
  executable, Mihomo, the sidecar, the helper, `launchctl`, routes, DNS,
  Keychain, or lifecycle tests are forbidden in a `host-build` shell. Execute
  them only through the confirmed guest console or guest SSH session.
- Resolve the work-guest address from `scripts/macos-vm-lab.sh ip`; do not trust
  a remembered address. At the start of each new guest session, verify
  `VirtualMac*` from inside that same session before invoking a runtime command.
  Prefer the ignored VM-only SSH key; never embed a password in a command,
  script, log, evidence file, or skill.
- Treat every executable compiled with `kyclash_utun` as guest-runtime capable.
  The host may cross-compile it but must not execute it, including through
  `go test` on the same Darwin/arm64 architecture. Use compile-only gates on the
  host and run the binary or tagged test only after re-proving the selected
  `VirtualMac*` guest.
- Interpret “run/open/verify the App” as running `/Applications/KyClash.app`
  inside that guest. Do not substitute a host launch because it is easier to
  observe or automate.
- Do not run the KyClash App, PKG installer, Mihomo TUN, sidecar, route helper,
  Keychain lifecycle, `launchctl` jobs, route commands, DNS commands, or
  lifecycle acceptance cases on the host unless the user explicitly authorizes
  that exact host action in the current request.
- If the guest is stopped, start or recover it and continue there. A stopped or
  temporarily unreachable guest is not permission to fall back to the host.
- Before any guest system test, independently require `sysctl -n hw.model` to
  begin with `VirtualMac`, record the guest OS and architecture, and confirm the
  expected package receipt, bundle path, and signature. Fail closed on a
  mismatch.
- Keep the guest UI visible for GUI acceptance. Launch the installed bundle
  through guest LaunchServices, foreground it in the guest, and prove its guest
  PID, executable path, bundled Mihomo health, and visible window. Host PIDs,
  host screenshots, and host sockets are not guest evidence.
- Label every runtime artifact and log with its execution target. Never combine
  host build provenance with guest runtime provenance into a claim that the App
  ran in the guest.
- If KyClash is accidentally launched on the host, stop that host instance
  immediately, verify that its child processes and owned system state are gone,
  disclose the correction, and resume in the guest.

For the current local lab, use the explicitly selected disposable
`kyclash-macos-lab-work` guest. Never mutate or use the clean
`kyclash-macos-lab-base` image for acceptance tests.

### Enforce the current two-VM core-networking checkpoint

When the external-peer review is active, the only runtime targets are
`kyclash-macos-lab-work` for the client and `kyclash-macos-lab-peer` for the
peer. The host remains build/courier/orchestration-only, and
`kyclash-macos-lab-base` remains stopped and immutable. Never replace the peer
with an in-process, loopback, container, host, or production endpoint and call
the cross-VM gate complete.

Keep disposable guests stopped while the active work is limited to source
review, host-only compilation, documentation, or artifact preparation. Start
`kyclash-macos-lab-work` and `kyclash-macos-lab-peer` only immediately before a
guest staging or two-VM runtime step that needs them, and stop both again after
the evidence has been exported. Never leave an idle guest running merely to
signal progress; preserve host CPU and memory without weakening the two-VM
acceptance gate.

The current user deliverable is one unsigned `KyClash.app`. Do not spend this
checkpoint on signing, notarization, PKG, DMG, installer, updater, release, or
unrelated product work. Cross-compile App/helper binaries on the host, copy
only the reviewed artifacts into the selected guests, and execute all utun,
route, Mihomo, carrier, SSH, lifecycle, and App runtime work inside those
guests.

Keep the SSH meanings explicit:

- `10.88.0.2:22` is the run-bound, public-key-only fixed proof service. It
  intentionally has no interactive shell.
- `10.88.0.2:2222` is the fixed proxy to the peer's system
  `127.0.0.1:22`. Normal interactive SSH is possible only when that peer
  account's effective sshd/authorized-key policy permits it; the locked
  automated acceptance uses the restricted `kyclashlabssh` forced command.
- Both endpoints count only when traffic crosses the client KyClash utun and
  exact `10.88.0.2/32` route. Management SSH over guest `en0` is only an
  orchestration channel and never overlay evidence.

Default-NAT VM creation/bootstrap is separate from bridged-LAN attachment.
Before every `tart run ... --net-bridged=en0`, require a fresh explicit
authorization for that exact run and re-prove both VM identities, unique MACs,
unique SSH host keys, listener baselines, and the reviewed user-owned lab LAN.
An earlier clone/start authorization does not authorize a later bridge.

Administrator actions in either guest must remain visibly user-authorized.
Never place a password in `sshpass`, `sudo -S`, AppleScript/UI automation,
stdin, argv, environment, source, logs, evidence, or commentary. Continue all
independent source/build/test work first; request the minimum visible guest
action only when it is the sole remaining gate.

### Preserve the Shenzhen read-only boundary

When Shenzhen real-site acceptance is in scope, read and follow
`docs/testing/kyclash-shenzhen-readonly-acceptance-20260723.md`. Run those
probes only inside `kyclash-macos-lab-work` after KyClash owns a healthy utun;
the host must not substitute its own reachability. Install only the locked
split routes `10.68.72.0/21` and `10.20.81.0/24`, with the two optional VIP
`/32` routes only when selected. Never add a default route, use the obsolete
`10.68.72.1` path, log in to a remote management plane, deploy a remote peer,
or mutate PVE, ROS, K3s, databases, storage, IPMI, or hypervisors. A topology
or management address is not a KyClash server endpoint; require an already
reviewed peer endpoint and public trust material before attempting the real
site tunnel. Never request or expose remote passwords, tokens, or private
keys.

## Enforce the App-first visible checkpoint

When the user asks to run, open, show, or verify KyClash, or says they have not
seen the App running, make the visible guest App the first active acceptance
criterion. Pause unrelated backend, documentation, CI, and long test batches
until this checkpoint passes. Perform only work directly required to build,
package, install, or repair the candidate if it cannot launch yet.

Use this order without substituting host evidence:

1. Build the candidate; a host build is compile/package evidence only.
2. Copy the candidate into a guest-writable location in
   `kyclash-macos-lab-work` and install it there.
3. Re-prove `VirtualMac*`, guest OS/architecture, package receipt, installed
   path, candidate hash, Team ID, and deep signature from inside the guest.
4. Launch `/Applications/KyClash.app` through guest LaunchServices, bring its
   window to the foreground, and keep the VM console visible.
5. Prove the guest PID resolves to the installed executable, the window is
   visible, and every expected bundled child such as Mihomo is healthy.
6. Capture a screenshot from the guest session, copy it to the ignored
   `target/macos-vm-lab/evidence/<run-id>/` directory, and surface it to the
   user in the same run. Keep a redacted evidence manifest beside it.
7. Resume lower-level roadmap work only after this visible checkpoint passes.

The evidence manifest must distinguish `build_target` from
`runtime_target` and contain only non-secret facts: timestamp, VM name,
`hw.model`, OS, architecture, package/bundle version, artifact hash, Team ID,
guest PID, executable path, visible-window result, bundled-child health, and
screenshot path. Never store a password, token, private key, Keychain value, or
raw credential output.

No screenshot means GUI acceptance is incomplete. No `VirtualMac*` proof means
the execution target is unverified. A host process, successful build, passing
unit test, valid signature, installed PKG, or historical screenshot cannot
replace the current guest launch. If launch or evidence collection fails, keep
the criterion `in progress`, fix the failure, and retry in the guest.

### Preserve the guest screenshot trust boundary

An SSH process is not automatically in the logged-in Aqua bootstrap and a
plain SSH invocation of `screencapture` can fail even while the App has a real
window. Handle that boundary explicitly:

- Never replace a failed guest capture with a host screenshot of the VM window,
  a historical guest image, a build artifact, or an Accessibility-only window
  count.
- Use `scripts/macos-vm-capture-visible-app.command` from the work guest's
  `Terminal.app`. Copy it into a fresh mode-0700 evidence directory and launch
  that exact regular file through guest LaunchServices. The script must refuse
  non-`VirtualMac` hardware, a non-installed App path, multiple App PIDs,
  symlinked/pre-existing output, and non-PNG or empty output.
- Treat `launchctl bsexec` as privileged guest execution. Do not run it on the
  host and do not pass a password through SSH, a tool call, argv, stdin, logs,
  source, or evidence. A successful command still needs the same guest PNG
  validation and visual inspection.
- If macOS denies Terminal Screen Recording, open the corresponding Privacy &
  Security pane inside `kyclash-macos-lab-work` and request the user to enable
  only `Terminal`. Do not reset TCC, edit a TCC database, grant wider access,
  automate the password prompt, or infer consent from an older grant. Quit and
  reopen Terminal after the user confirms the setting, then retry into a new
  evidence path.
- After capture, require a newly created, guest-user-owned, mode-0600 regular
  PNG with nonzero dimensions and SHA-256. Copy it to ignored host evidence,
  inspect that exact file, and reject screenshots showing a TCC prompt, lock
  screen, Terminal obstruction, or a different App candidate.

The same honesty rule applies to installation. Expanding a verified PKG and
atomically placing its exact payload in `/Applications` is useful internal App
deployment evidence, but it is not a successful `installer(8)` transaction and
must not be reported as receipt/upgrade proof. If guest administrator
authorization is required, show the guest prompt for the user; never transmit
or reuse their password programmatically.

## Report outcomes instead of defending activity

- Lead every runtime update with the concrete artifact and execution target,
  for example `KyClash.app launched in kyclash-macos-lab-work`, followed by its
  evidence. Never present intent such as “I did not stop” or “I will continue”
  as progress or delivery.
- Do not use `running`, `verified`, `passed`, `delivered`, or `complete` for the
  App unless the current guest evidence satisfies the visible checkpoint.
- If the App is not yet visible, say `App not yet delivered` and identify the
  exact failing gate. Continue resolving it when the action remains authorized.
- Treat a user-visible runnable App as a product deliverable, not as an optional
  final smoke test after invisible implementation work.
- Before finalizing, surface the latest guest screenshot or its clickable local
  evidence path and state separately what ran on the host and what ran in the
  guest.

## Implementation order

1. Close the current iteration against its documented exit criteria.
2. Implement macOS route discovery and a pure transaction/journal engine before
   invoking platform route commands.
3. Prove rollback, conflict refusal, restart recovery, and idempotence with
   fault-injection tests.
4. Add platform mutation only behind an explicit development/test boundary.
5. Integrate WireGuard behind a stable adapter, then QUIC primary transport,
   then WSS/TCP break-before-make fallback.
6. Build the macOS MVP UI, credential storage, diagnostics, and lifecycle tests.
7. Complete Developer ID signing when authorized. Treat notarization/stapling
   as optional public-distribution hardening under the locked GitHub/no-store
   amendment.
8. Add platforms in the locked order: macOS x64, Windows x64, Windows arm64,
   then Linux.

Keep Mihomo responsible for proxy/default traffic and existing TUN behavior.
Keep KyClash private CIDRs under one transactional route orchestrator. Do not
modify system DNS in P0/P1.

## Required gates

Run applicable checks before each commit:

```bash
corepack pnpm run typecheck
corepack pnpm run web:build
corepack pnpm run lint
corepack pnpm run i18n:check
corepack pnpm run knip:check
corepack pnpm run release:ownership-check
cargo fmt --all --check
cargo test -p clash-verge --lib
cargo test -p clash-verge --features networking-dev,clippy --test networking_sidecar
cargo clippy -p clash-verge --all-targets --all-features -- -D warnings
git diff --check
```

The `networking_sidecar` integration target compiles the desktop library
without Rust's `cfg(test)`. Include the repository's `clippy` non-application
feature so it uses the mock Tauri context while `networking-dev` deliberately
skips application resource packaging. Do not replace this with a host App
launch or remove either feature to make the gate appear to pass.

Use a temporary Corepack shim in `PATH` when Git hooks cannot locate `pnpm`.
Preserve hooks; never bypass them. Validate any changed workflow YAML and run
platform-specific packaging checks when packaging changes.

## Completion rules

Mark an iteration complete only when its exit criteria and tests pass. Treat an
unsigned or unnotarized macOS PKG as a clearly labelled development/internal
test artifact, not a generally trusted package. Keep KyClash updates disabled
until KyClash owns its GitHub endpoint, signing keys, rollback metadata, and
release procedure.

At each handoff, report completed commits, validation evidence, remaining hard
blockers, and the exact next incomplete roadmap criterion.

The handoff rule does not authorize a voluntary handoff while safe roadmap work
remains. It applies only at an actual terminal condition or an unavoidable
environment interruption.
