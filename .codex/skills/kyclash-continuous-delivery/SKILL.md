---
name: kyclash-continuous-delivery
description: Review, lock, implement, verify, commit, and push the KyClash roadmap continuously without stopping at partial milestones. Use whenever work under the KyClash workspace concerns architecture, networking, sidecars, routes, WireGuard, QUIC/WSS fallback, UI, packaging, releases, branding, tests, documentation, requests to continue/finish/all-complete, or any active roadmap whose safe tasks must proceed without repeated prompting.
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
10. `kyclash-handoff-20260721.md` only for historical context

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
cargo test -p clash-verge --features networking-dev --test networking_sidecar
cargo clippy -p clash-verge --all-targets --all-features -- -D warnings
git diff --check
```

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
