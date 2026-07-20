# KyClash Plan Review Record

Status: Approved and locked

Date: 2026-07-21

Reviewed inputs:

- `kyclash-handoff-20260721.md`
- `docs/architecture/kyclash-networking-v1.md`
- `docs/roadmap/kyclash-implementation-plan.md`
- Current source, tests, packaging configuration, and Git state

## Findings resolved before lock

1. The old handoff described DMG, README, and networking contracts as pending,
   but those statements were superseded by the current workspace.
2. Iteration 2 required a Windows adapter even though the platform order placed
   Windows after the macOS MVP. The macOS-first scope now closes Iteration 2 on
   Unix local IPC; Windows named-pipe work is deferred to its platform phase.
3. A locally reproducible package and a releasable package are different gates.
   Local unsigned PKG output proves packaging only. Public release additionally
   requires Developer ID signing, notarization, stapling, and install tests.
4. The workspace was detached and entirely uncommitted. A source-control
   baseline is therefore the first execution batch after plan lock.

## Locked execution order

1. Establish and publish a reviewed source-control baseline.
2. Close Iteration 2 with the feature-gated read-only development status page.
3. Implement the macOS route transaction POC without DNS mutation.
4. Implement WireGuard plus QUIC/WSS-TCP transport POC in an isolated lab.
5. Deliver the signed and notarized macOS arm64 MVP.
6. Add macOS x64, then Windows x64, Windows arm64, and Linux.

## Non-negotiable gates

- No production PVE, ROS, K3s, route, DNS, or tunnel mutation without explicit
  authorization.
- Unknown configuration and IPC versions fail closed.
- Secrets never enter command arguments, logs, diagnostics, or repository
  files.
- Every route mutation is journaled, ownership checked, idempotent, and covered
  by rollback fault tests.
- KyClash application updates remain disabled until its endpoint, signatures,
  rollback metadata, and release procedure exist.
- Public macOS artifacts must be signed, notarized, and stapled. Unsigned PKGs
  are development artifacts only.
- Each iteration must pass the repository merge gates before it is marked
  complete.

Changes to route ownership, secret storage, transport semantics, first-release
platform, or single-site scope require a new review record before execution.
