# KyClash production networking single-stage consolidation review

Status: approved and locked

Date: 2026-07-21

## Decision

The production networking program is one indivisible delivery stage:
`S1 — production networking delivery`.

The former N1 through N5 labels are retained only as historical evidence
aliases. They are not phases, milestones, release gates, handoff points, or
valid stopping conditions. Their deliverables are now dependency-ordered work
packages S1.01 through S1.16 inside the same stage.

This consolidation changes planning semantics only. It does not change the
locked architecture, route ownership, secret boundary, transport ordering,
single-site scope, platform order, test requirements, authorization boundary,
or release policy.

## Completion rule

S1 has only two program states: `in progress` and `complete`. Individual work
packages may record `complete`, `in progress`, or `pending` evidence, but their
completion never changes the stage state or authorizes a handoff.

S1 becomes complete only when one exact Developer ID-signed candidate from one
clean commit passes every S1.01–S1.16 criterion and demonstrates:

- one-site encrypted networking over QUIC with WSS/TCP break-before-make
  fallback;
- owned macOS utun and transactional private routes with Mihomo coexistence;
- crash, reboot, install, upgrade, rollback, uninstall, impairment, and
  lifecycle cleanup;
- redacted diagnostics and final absence of all owned system state.

External authorization checkpoints remain checkpoints inside S1, not separate
stages. When one checkpoint cannot run, all independent source, mock, CI, and
isolated-VM work elsewhere in S1 continues.

## Execution rule

Execution always resumes at the first incomplete S1 work package. Commits and
CI runs remain reviewable evidence units, but no response may describe a work
package, former N-group, batch, commit, or runner result as completion of the
stage. A final completion report is valid only after the S1 completion rule is
satisfied.
