# KyClash privileged tunnel broker review

Status: approved and locked for S1 real-utun implementation

Date: 2026-07-23

Amends:

- `docs/architecture/kyclash-networking-v1.md`
- `docs/architecture/kyclash-network-runtime-v1.md`
- `docs/roadmap/kyclash-production-networking-work-program-20260721.md`
- `docs/roadmap/kyclash-route-helper-contract-review-20260721.md` (boundary
  reaffirmed; no route-helper API change)

## Trigger and observed failure

The no-sign `.app` was launched in the designated `kyclash-macos-lab-work`
guest and rendered the Networking page. Its normal Go production child accepted
bootstrap and `apply_profile`, but `tun.CreateTUN` returned `operation not
permitted` for uid 501. The existing route helper is intentionally route-only
and cannot create a tunnel, launch a sidecar, receive credentials, or execute
arbitrary commands. Signing the child alone does not grant ordinary-user utun
creation. This is an architectural privilege-boundary gap, not a carrier or
profile validation failure.

## Decision

Add a separate, least-privilege macOS `SMAppService` LaunchDaemon and Mach
service named `net.kysion.kyclash.tunnel-broker`. It owns only the fixed Go
sidecar process and its real-utun lifetime. The existing
`net.kysion.kyclash.route-helper` remains byte-for-byte route-only.

The broker creates a single authenticated session and returns a typed pair of
stdio file descriptors to the app. The existing protocol-v2 bootstrap,
handshake, request correlation, cancellation drain, deadlines, and cleanup are
reused unchanged over those descriptors. The Rust side abstracts only the
launch/process-control seam; the production controller and service ordering do
not change:

```text
health success -> route-helper journal/lease/apply
route rollback -> broker stop/reap -> tunnel/secret cleanup
```

The broker accepts no executable path, argv, environment, shell, route, DNS,
interface, or file-operation input. It derives the one allowed sidecar path
from its own bundle, and before every launch verifies regular-file/no-symlink,
arm64 architecture, exact SHA-256 manifest, Team ID, and designated
requirement. One app connection owns at most one generation-bound child/utun
lease. A stale generation, duplicate start, client invalidation, broker stop,
or child failure closes the pipes, terminates and reaps only that exact child,
and refuses reuse of the old generation. Bootstrap secrets travel only through
the typed session/stdio channel, are never placed in argv, environment, files,
or diagnostics, and are zeroized after handoff.

### Route/tunnel retirement interlock

The broker must not tear down a tunnel immediately on an app/XPC loss while a
route helper may still own a lease. Before the production aggregate gate can
close, the route helper must bind the first route mutation to the exact broker
`instance_id` and session generation. On app loss it journals and fsyncs route
rollback first, then sends a fixed, authenticated root-to-root `retire` message
to the broker. Only that exact retire, or a clean disconnected state with no
route lease, may release the sidecar/utun. A helper crash/reconcile follows the
same rollback -> retire order. The interlock is a separate reviewed source
amendment; this document does not silently widen the existing route-helper
method surface.

## Development VM profile (no-sign `.app`)

The user-requested deliverable remains an `.app` without signing, installer,
notarization, or release publication. An ad-hoc/no-sign build is restricted to
`networking-system-lab`/debug and userspace-netstack evidence. It cannot
register or activate either production privileged service and must not weaken
the broker or route-helper code requirement.

For the disposable VM only, a separately staged fixed lab launcher may be
started by a visible Terminal command after the user types `sudo` once. The
launcher has a fixed executable/hash and fixed private Unix socket, accepts
only the debug build's loopback session, and is compiled out of ordinary and
release builds. It is a root utun/stdio harness, not the production XPC or
route transaction; its evidence is explicitly labelled `lab-only` and cannot
close S1.13. The no-sign App may display the userspace Connect path, but it
must not silently route production commands through this harness. The harness
never runs on the host or a staging/production machine. No password is
automated, passed in arguments, or stored by the harness.

If the lab launcher is not manually authorized, the no-sign app must fail
closed at `sidecar_unavailable`; userspace QUIC/WSS/TCP evidence may still run.

## Rejected alternatives

### Extending route-helper

Rejected. Combining root route authority, sidecar secrets, process launch, and
utun ownership violates the locked typed method surface and enlarges the
failure/attack radius. It would require a new protocol and a complete review of
all route/restart evidence, not a small implementation shortcut.

### NetworkExtension / `NEPacketTunnelProvider`

Deferred as a separate post-S1 architecture. It requires a new appex target,
Network Extension entitlement/capability and VPN authorization, and a
packet-flow adapter replacing the current wireguard-go device boundary. It is
not needed to close the current minimal broker path.

### Password automation or `sshpass`

Rejected. Passwords must not appear in process arguments, shell history,
transcripts, logs, or saved files. Administrator authorization for a lab
launcher is an explicit, visible guest-terminal action.

## Locked implementation units

1. Abstract `StdioSidecarLauncher` and `SidecarProcessControl` in
   `stdio_runtime.rs`; preserve protocol-v2 behavior and add fake-pipe,
   timeout, cancellation, exact-reap, stale-generation, and descriptor-leak
   tests.
2. Add a production-only broker client bridge with a typed session-generation
   API and no generic command/path fields.
3. Add the macOS broker target, fixed plist/identity, signature/hash/arch
   self-tests, one-session lifecycle, invalidation cleanup, and build verifier.
4. Add a debug-only VM launcher script/fixture with a visible one-time `sudo`
   preflight; keep it out of release features and ordinary bundles. Its root
   utun evidence is separate from App/XPC evidence.
5. Review and implement the route/tunnel retirement interlock, then run the
   selected signed-candidate VM matrix: visible Connect, real utun ownership,
   private route after health, packaged Mihomo coexistence, QUIC -> WSS -> TCP
   break-before-make, cancellation, app/broker/sidecar/helper abort, logout,
   reboot, and final absence. Evidence is redacted and guest-scoped.

## Acceptance and non-claims

The broker design is locked for implementation, but this record does not claim
that its source, signed registration, or VM acceptance is complete. Current
no-sign evidence remains valid only for the userspace slice and the observed
fail-closed privilege boundary. A real-utun production claim requires the
Developer ID-signed broker/sidecar/App in the disposable VM; notarization is a
public-distribution enhancement, not a current no-store blocker.

No production endpoint, GitHub Release, updater activation, PVE/ROS/K3s,
physical-Mac network mutation, Keychain lifecycle mutation, password, token,
or private key is authorized by this review.
