# KyClash broker session and route-binding review

Status: approved and locked for implementation

Date: 2026-07-23

Amends:

- `kyclash-privileged-tunnel-broker-review-20260723.md`
- `kyclash-tunnel-route-retirement-interlock-review-20260723.md`
- `../architecture/kyclash-network-runtime-v1.md`
- `kyclash-production-networking-work-program-20260721.md`

## Trigger

The first tunnel-broker client seam exposed three identities that must not be
collapsed:

1. the Rust stdio runtime generation;
2. the broker session generation; and
3. the sidecar protocol-v2 `instance_id`.

The current production factory creates the protocol-v2 instance ID before the
broker starts, while the broker independently creates a different
`sidecarInstanceID`. Merely substituting a broker launcher for
`LocalProcessLauncher` would therefore compile but could not bind bootstrap,
handshake, tunnel facts, route journal, hold, release, and retirement to one
identity. The first prepared launcher was also single-use, so it could not
preserve the already locked sidecar restart behavior.

## Locked decision

The broker-assigned reference is authoritative for every production sidecar
attempt:

```text
TunnelBrokerSessionReference {
  protocol_version,
  generation,
  sidecar_instance_id
}
```

The App XPC method remains parameterless `start(reply:)`. It is not widened
with an instance ID, path, argv, environment, command, profile, route, DNS, or
secret. Every start or restart acquires a fresh broker reference and fresh
stdio descriptors. A broker reference is never derived from, or assumed equal
to, the Rust runtime generation.

### Prepare, bind, and start

The production controller gains a two-part start boundary:

1. `prepare_session` asks the fixed broker session provider for a fresh,
   single-use prepared session. It owns the exact reference, descriptors, and
   process-control handle but is not yet bound to a Rust runtime generation.
2. After the controller allocates its next runtime generation, it consumes the
   prepared session through `bind_runtime_generation`. Duplicate use, stale
   generation, dropped descriptors, or a mismatched reference fails closed and
   explicitly stops/reaps or quarantines that exact broker session.

`SidecarLaunchMaterial` owns only the zeroizing authentication token and
WireGuard private material. It creates an ephemeral `SidecarLaunchContext`
after preparation, using the broker reference's exact `sidecar_instance_id`,
and computes the matching HMAC proof for that attempt. A restart acquires a
new broker reference and rematerializes a new context/proof; it never reuses an
old prepared session or old reference. Retirement destroys the launch material
and every ephemeral context/proof.

The controller publishes one non-copyable start receipt at the same linearized
point at which the handshake is accepted:

```text
ControllerStartReceipt {
  runtime_generation,
  broker_reference
}
```

A later read of mutable launcher state is not a substitute for this receipt.
The service consumes the receipt for the exact active generation and pins it
until route rollback and tunnel retirement finish.

### Required identity invariants

Before any route mutation, all of the following must be equal:

```text
bootstrap.instance_id
  == handshake.instance_id
  == TunnelDeviceFacts.instance_id
  == ControllerStartReceipt.broker_reference.sidecar_instance_id
```

The route lease and durable journal bind the complete tuple:

```text
(
  broker protocol version,
  broker generation,
  sidecar instance ID,
  route lease ID,
  operation ID
)
```

Missing or mismatched fields prevent route mutation and leave the service
fail-closed. A sidecar-provided interface name or instance ID cannot create or
alter the broker reference.

### Exact absence and restart

`stale_generation` is not positive reap evidence. The broker retains a bounded
exact-session retirement tombstone, or an equivalent non-forgeable receipt,
after observing or forcing child termination. Only an exact broker stop/reap
reply or exact retired-session receipt may let the Rust controller issue
`ControllerAbsenceKind::Reaped`.

Broker interruption, invalidation, an unknown stale generation, or a bounded
reap timeout enters recovery-only state. It cannot be converted into orderly
retirement, and a new Connect remains blocked until route and process absence
are reconciled. A prepared session dropped before bootstrap must close both
stdio descriptors and perform bounded exact stop/reap; it must not rely on an
unobserved object drop as evidence.

An ordinary sidecar crash follows the same exact-reference rule. After its
route lease is rolled back and released, an in-service restart may acquire a
new broker session and rematerialize context only if the previous session has
positive retirement evidence. Otherwise the whole service remains
recovery-only and must be rematerialized after reconciliation.

## Route-helper protocol v3 interlock

Adding the broker reference changes the route-owner wire and journal contract,
so new requests use route-helper protocol v3. Historical v2 journals are
recovery-only input: they may be rolled back and removed, but cannot claim a
broker hold that did not exist in v2.

For a v3 lease the helper performs:

1. validate the exact owner tuple and read-only route/Mihomo conflicts;
2. durably write and fsync a `hold_pending` owner record;
3. call the fixed root-only broker `hold` with the exact broker reference and
   route lease ID;
4. durably record `held`; only this state may add a private route;
5. journal and apply only the already normalized private routes;
6. on cleanup, roll back every owned route and durably prove route absence;
7. atomically persist an exact bounded retirement-pending record, remove the
   active route journal, and fsync the journal directory;
8. call broker `release` for the exact tuple;
9. let the App stop/reap the now-unheld session, or accept the broker's exact
   stop/reap receipt when the App connection is already absent; and
10. remove the retirement-pending record only after exact release/retirement
    succeeds and fsync that removal.

An ambiguous hold call never permits route mutation. Recovery queries only the
same exact tuple and either releases that hold after proving routes absent or
proves that the exact broker session is already absent. Release transport
failure retains the retirement-pending record and freezes Connect; it never
replays a route mutation or releases a newer generation.

The broker root protocol remains exactly `hold`, `release`, and `status`. The
route helper still cannot launch a process, receive bootstrap secrets, create
utun, or send arbitrary commands. The broker still cannot inspect or mutate
routes.

## Production composition gate

Production composition may replace `LocalProcessLauncher` only after all of
the following are present in one source chain:

- broker session provider and non-copyable start receipt;
- dynamic context/proof binding to the broker-assigned instance ID;
- route-helper v3 owner, journal, hold/release client, and recovery states;
- exact broker reap/retirement evidence;
- fixed `SMAppService` registration/status for both broker and route helper;
- fixed broker/sidecar resource placement and package verification; and
- Connect disabled unless both privileged services satisfy their locked code
  requirements.

Until this gate closes, the broker client seam remains testable but is not a
production connection path.

## Rejected alternatives

- Passing an App-selected instance ID or generic dictionary to broker
  `start`; this widens the locked XPC surface and makes broker identity
  caller-controlled.
- Reusing one connection-scoped sidecar ID with only a first prelaunch; it
  does not by itself solve restart receipts, mutable-reference races, or stale
  prepared-session cleanup.
- Treating the Rust runtime counter as the broker generation.
- Reading the broker reference later from mutable launcher state instead of a
  controller start receipt.
- Treating `stale_generation`, XPC invalidation, missing PID lookup, or object
  drop as exact child reap.
- Letting broker invalidation release a route hold before helper rollback and
  fsync.
- Installing routes from sidecar facts before the exact broker reference and
  health gate are both validated.

## Required tests

- prepare/bind/start success, duplicate consumption, generation mismatch,
  dropped preparation, descriptor EOF, timeout, and late-XPC-reply cleanup;
- runtime generation and broker generation inequality without aliasing;
- bootstrap, handshake, tunnel facts, and start-receipt ID equality;
- restart obtains a new broker reference and rejects every old-reference
  status/stop/hold/release attempt without affecting the new session;
- child crash, broker crash, App loss, route-helper loss, and reap timeout
  distinguish orderly retirement from recovery-only cleanup;
- v3 hold-pending/held, route mutation, rollback, retirement-pending, release,
  and final-journal-absence ordering with fsync fault injection;
- ambiguous hold/release, replay, duplicate, wrong instance, wrong generation,
  wrong lease, wrong operation, non-root, and wrong-signer refusal;
- QUIC -> WSS -> TCP break-before-make while the same exact tunnel/route lease
  remains active;
- packaged Mihomo IPv4/IPv6 coexistence and final child, utun, route, journal,
  lease, hold, descriptor, and secret absence in the disposable macOS VM.

## Scope

This amendment authorizes source, pure tests, fixed loopback fixtures, and the
already selected disposable VM. It does not authorize password automation,
production endpoints or infrastructure, signing, packaging, release
publication, updater activation, or host-network mutation. The no-sign App
remains userspace-lab only and cannot claim production utun or routes.
