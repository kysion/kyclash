# KyClash tunnel/route retirement interlock review

Status: approved and locked for implementation

Date: 2026-07-23

Depends on:

- `kyclash-privileged-tunnel-broker-review-20260723.md`
- `kyclash-route-helper-contract-review-20260721.md`
- `kyclash-production-restart-rematerialization-review-20260722.md`

## Finding

The production service already performs controlled cleanup in the correct
order: route rollback precedes tunnel stop. A new tunnel broker and the route
helper would, however, receive independent XPC invalidation callbacks after an
App crash. Without an interlock the broker could stop the sidecar/utun before
the route helper has durably removed its routes. The two privileged services
therefore need one narrow root-to-root lifecycle relationship without merging
their authorities.

## Locked decision

The route owner and durable journal gain one exact tunnel session generation in
addition to the existing sidecar instance ID. Before the first route mutation,
the route helper calls a second fixed broker Mach service and binds that exact
session generation to the exact route lease. The broker then marks the session
`route_held` and refuses App-originated stop while the hold exists.

After the route helper completes rollback, removes the exact journal, and
fsyncs the journal directory, it releases the exact hold. If the App connection
is still live, release only makes the session stoppable and the App completes
normal broker stop/reap. If the App connection is already absent, release
causes the broker to close stdin, perform bounded TERM/KILL fallback, and
`waitpid` the exact child before retiring the session generation.

Route-helper startup recovery and lease-expiry rollback use the same
rollback/fsync/release path. A release transport failure retains a bounded
retirement-pending record and is retried only for the exact same journal owner
and tunnel generation. It never replays route mutation and never releases a
different or newer tunnel session.

The root-to-root protocol exposes only:

```text
hold(tunnel_generation, sidecar_instance_id, route_lease_id)
release(tunnel_generation, sidecar_instance_id, route_lease_id)
status(tunnel_generation, sidecar_instance_id, route_lease_id)
```

It accepts only the fixed signed route-helper identity with effective uid 0.
There is no App access, generic dictionary, executable/path/argv/environment,
route/CIDR, secret, profile, shell, or file-operation input. The tunnel broker
still cannot mutate routes; the route helper still cannot launch a process,
create utun, or receive bootstrap secrets.

## Failure semantics

- App loss: broker retains the held sidecar/utun until helper rollback and
  exact release complete.
- Route-helper XPC invalidation: helper rollback runs before release.
- Route-helper crash: its journal remains authoritative; launchd restart
  recovers routes and releases only the recorded tunnel generation.
- Release failure: routes remain absent, the broker hold remains, and cleanup
  is `recovery_only`; a new Connect is forbidden.
- Broker-side stale/mismatched/duplicate hold or release: fail closed without
  changing either session.
- Unexpected sidecar or broker process death can make utun disappear before
  software can order cleanup. In that crash-only case the route helper must
  remove the exact journaled routes through its bounded invalidation,
  heartbeat-expiry, or startup-recovery path and prove final absence. It is not
  represented as an orderly retirement pass.
- Reboot: kernel-owned interface/process state disappears; helper startup
  reconciles any retained route journal before accepting a new lease.

## Required tests

- controlled disconnect and App SIGKILL prove rollback/fsync precede release
  and exact child reap;
- release racing a new session cannot affect the new generation;
- route rollback failure retains the broker hold and blocks Connect;
- release transport failure enters exact recovery-only state and succeeds only
  on same-owner retry;
- helper kill/restart recovers the journal and releases the exact held session;
- broker/sidecar abrupt death triggers bounded route cleanup and is labelled a
  crash recovery, not an ordered-retirement pass;
- duplicate, replayed, stale-generation, wrong-instance, wrong-lease,
  non-root, wrong-signer, and App-originated root-service calls are rejected;
- every case proves final child, utun, route, journal, lease, and hold absence.

## Non-goals

This amendment does not authorize arbitrary cross-helper commands, merge the
two daemons, change carrier fallback policy, automate a password, enable an
updater, publish a release, or touch production infrastructure. No-sign builds
cannot activate this production interlock; their root harness evidence remains
lab-only.
