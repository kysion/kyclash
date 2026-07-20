---
name: kyclash-continuous-delivery
description: Review, lock, implement, verify, commit, and push the KyClash roadmap continuously in the KyClash repository. Use whenever work under the KyClash workspace concerns architecture, networking, sidecars, routes, WireGuard, QUIC/WSS fallback, UI, packaging, releases, branding, tests, documentation, or requests to continue/finish the next batch without repeated prompting.
---

# KyClash Continuous Delivery

## Load the authority chain

Read these files before changing scope or architecture:

1. `docs/roadmap/kyclash-plan-review-20260721.md`
2. `docs/architecture/kyclash-networking-v1.md`
3. `docs/roadmap/kyclash-implementation-plan.md`
4. `kyclash-handoff-20260721.md` only for historical context

Treat the review record and architecture as locked. If they conflict with the
handoff, follow the locked documents. Require a new review record before
changing route ownership, secret storage, transport semantics, macOS-first
ordering, or single-site scope.

## Continue without repeated prompts

After the user authorizes execution through all stages:

- Continue from the first incomplete roadmap exit criterion.
- Break work into reviewable commits and push each commit to `origin/main` only
  after its applicable gates pass.
- Update roadmap progress in the same commit as the implementation.
- Move directly to the next safe task after a milestone passes.
- Do not stop merely to announce a next step or request routine confirmation.
- Stop only for a genuine hard blocker, a required credential or external
  dependency, or an action outside the authorization boundary below.
- Keep the working tree clean between completed milestones.

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
7. Complete signing/notarization only when credentials are authorized.
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
unsigned macOS PKG as a development artifact, not a release. Keep KyClash
updates disabled until KyClash owns its endpoint, signing keys, rollback
metadata, and release procedure.

At each handoff, report completed commits, validation evidence, remaining hard
blockers, and the exact next incomplete roadmap criterion.
