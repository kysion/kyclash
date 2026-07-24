# KyClash no-sign VM core-network App lab review

Status: approved and locked for implementation

Date: 2026-07-23

This review creates a new disposable-VM acceptance profile. It does not
replace or widen `kyclash-vm-utun-lab-app-review-20260723.md`; that profile
remains the smaller `REAL UTUN · NO ROUTES` fixture. It also leaves the
production `SMAppService`, signed XPC, tunnel-broker, route-helper v3, policy,
Keychain, and retirement-interlock reviews unchanged.

## Trigger and current gap

The current requested artifact is an unsigned `KyClash.app`. The existing
VM-utun App can visibly create a real `utun` and exercise QUIC, WSS, and TCP,
but it deliberately reports `routes_installed=false`. It therefore cannot
prove the project's core user outcome: private-service reachability through a
KyClash-owned route while a real Mihomo TUN and its covering route coexist.

An unsigned App cannot activate the production signed helpers. A separate,
manually authorized root fixture is consequently the only permitted no-sign
acceptance path. Evidence from this profile is a product-function lab result,
not production-helper or S1 completion.

## Locked decision

Add a separate default-off feature named
`networking-vm-network-lab-app`. It implies the existing userspace-lab command
surface but is mutually exclusive with `networking-vm-utun-lab-app` and
`networking-production`. Ordinary, release, signed-production, and updater
builds never enable it.

The App connects only to:

```text
/var/run/net.kysion.kyclash.vm-network-lab.sock
```

The one-shot root executable is
`kyclash-vm-network-lab-harness`. It is a sibling of, not a replacement for,
the route-free utun harness. It accepts no arguments and fails closed unless:

- it is `darwin/arm64`, effective uid `0`, and `hw.model` begins with
  `VirtualMac`;
- the exact environment markers name the local
  Virtualization.framework runner and `kyclash-macos-lab-work`;
- `/dev/console` has one non-root interactive owner;
- its fixed root stage, journal, Mihomo executable, configuration, socket, and
  process identities satisfy the rules below; and
- no foreign exact or more-specific route overlaps the fixed private target.

Building and staging may be automated. Starting the root fixture requires one
visible guest-Terminal `sudo`. SSH itself uses the VM-only public key. Password
automation, `sshpass`, `sudo -S`, stdin injection, Keychain retrieval, and UI
scripting of a password are forbidden.

## Closed authority and fixed values

No path, command, interface, route, endpoint, DNS value, process identifier,
profile, secret, or failure mode is accepted from the App. The complete lab
authority is compiled or derived from authenticated runtime facts:

| Field | Fixed value |
| --- | --- |
| VM | `kyclash-macos-lab-work`, `VirtualMac*`, arm64 |
| socket | `/var/run/net.kysion.kyclash.vm-network-lab.sock` |
| root stage | `/private/var/tmp/kyclash-vm-network-lab-stage` |
| root state | `/private/var/tmp/kyclash-vm-network-lab-root` |
| route journal | `/private/var/tmp/kyclash-vm-network-lab-root/route-lease-v1.json` |
| Mihomo controller socket | `/private/var/tmp/kyclash-vm-network-lab-root/mihomo.sock` |
| Mihomo child stage | `/private/var/tmp/kyclash-vm-network-lab-stage/mihomo` |
| Mihomo config | `/private/var/tmp/kyclash-vm-network-lab-stage/mihomo-config.json` |
| repository Mihomo config | `macos/route-helper/vm-network-lab-mihomo-config.json` (SHA-256 `2ad62e399c953f5298d8de22ee7d762277968f18e186c97d281cfdb67b10df5d`) |
| profile | `lab.vm-network.actual-child` |
| site | `lab-vm-network` |
| client address | `10.88.0.1/32` |
| private route | `10.88.0.2/32` |
| private echo | `10.88.0.2:8080` |
| carriers | loopback QUIC, then WSS, then TCP |
| Mihomo interface | `utun4094` |
| Mihomo covering route | `10.88.0.0/24` |
| Mihomo controller | root-private fixed Unix socket under the lab root |
| DNS/default route/system proxy | read-only snapshots; mutation forbidden |

The build embeds the SHA-256 of the repository's fixed Apple-Silicon
`verge-mihomo` input. The root process opens the fixed staged file without
following links, checks regular-file identity, mode, owner, architecture, and
the embedded hash before executing a root-owned copy with fixed empty
environment and fixed arguments. The config contains only direct mode, the
fixed Unix controller, one TUN, the fixed covering route, and `MATCH,DIRECT`;
it contains no DNS, TCP controller, secret, provider, listener, or production
endpoint.

## Ownership and state order

One root process owns the Mihomo fixture, WireGuard backend, exact `utun`,
route journal, route mutation, App stream, and cleanup. Splitting these across
uncoordinated root processes is forbidden.

The accepted order is:

```text
preflight foreign-state absence
  -> persist Mihomo start intent
  -> start and authenticate exact Mihomo child/API/device/covering route
  -> accept one authenticated App uid on the fixed socket
  -> protocol-v2 bootstrap and profile
  -> create/configure real WireGuard utun
  -> connect QUIC and prove carrier health
  -> persist route add-pending
  -> add 10.88.0.2/32 to the exact KyClash utun
  -> inspect and persist route applied
  -> App TCP echo proves private reachability
  -> disconnect QUIC before connecting WSS
  -> repeat health and private echo on WSS
  -> disconnect WSS before connecting TCP
  -> repeat health and private echo on TCP
```

The App-to-harness stream keeps the existing protocol-v2 line bootstrap and
authenticated request envelopes.  The first server line is the fixed,
versioned `vm_network_lab_handshake_v1` object; unknown fields, versions,
profiles, or modes are rejected.  Its non-secret fields are exactly
`protocol_version`, `instance_id`, `auth_proof`, `lab_profile`,
`runtime_mode`, `tunnel_kind`, `tunnel_interface`, `mihomo_device`, and
`cancel_endpoint`.  Before `PrepareTunnel`, `tunnel_interface` is explicitly
`null`; the real `utunN` is returned only in the typed `TunnelPrepared` facts
and subsequent status snapshots.  Subsequent status responses use the
existing typed IPC responses with the additional allowlisted booleans below;
route/journal state is never accepted from the client.  A lab-only typed
`sample_private_reachability` request has empty data and returns only a
bounded `{reachable, latency_ms}` fact; production sidecars reject this
request as an unknown/invalid state operation.

The journal is a mode-0600, root-owned, version-1 JSON record written with a
create-only temporary file, `fsync`, and atomic rename followed by directory
`fsync`.  It contains only the fixed `route_lease_id`, authenticated sidecar
instance ID, exact tunnel generation/interface, fixed CIDR, fixed Mihomo
child identity, including PID, process start-time, executable dev/inode, and
SHA-256, and one of `start_pending`, `add_pending`, `applied`,
`delete_pending`, `teardown_pending`, `released`, or `recovery_only`.  A
corrupt, replaced,
symlinked, or owner/mode-mismatched journal is a fail-closed recovery state;
absence is accepted only after a fresh route/process/interface inspection.

Cleanup on Disconnect, App EOF, cancellation, TERM, carrier failure, or
bounded command failure is always:

```text
disconnect active carrier
  -> persist route delete-pending
  -> delete only the exact owned /32 route
  -> positively inspect !ownedExact && !foreignConflict
  -> persist teardown_pending (journal remains authoritative)
  -> stop/close WireGuard and its exact utun
  -> stop/reap the exact Mihomo child
  -> prove fixed controller/device/covering-route absence
  -> prove DNS/default-route/system-proxy snapshots unchanged
  -> remove only owned fixed lab files/socket
  -> persist released, fsync, and unlink the exact journal as the final step
```

The route must not be installed before the first selected carrier is healthy.
It remains bound to the same utun during break-before-make carrier switching;
no two carriers may be attached simultaneously.

If route rollback, child/device teardown, or positive absence is ambiguous, the harness enters
recovery-only, accepts no new App, retains the exact journal and ownership
facts, and does not claim cleanup. On restart it reconciles the exact journal
before starting Mihomo or listening. A missing inspection is never positive
absence. Unknown, symlinked, replaced, corrupt, wrong-owner, wrong-mode, or
wrong-version state is a fail-closed stop condition.

## Route and Mihomo proof

The route executor is not a general command service. Its only mutation plans
are fixed argv calls equivalent to:

```text
/sbin/route -n add -net 10.88.0.2/32 -interface <owned-utunN>
/sbin/route -n delete -net 10.88.0.2/32 -interface <owned-utunN>
```

`<owned-utunN>` is the exact `TunnelDeviceFacts` interface returned by the
same backend instance and operation; it is never supplied by the App. Before
add, read-only discovery must show exactly one less-specific
`10.88.0.0/24` route on the authenticated Mihomo `utun4094`, no exact or
more-specific conflict, and no default route on either lab interface. After
every mutation, a fresh read-only table inspection is mandatory.

Mihomo coexistence is true only when all of these agree during every private
echo sample: the owned child PID and executable bytes, root-private controller
socket, `/configs` `tun.enable=true` and `tun.device=utun4094`, kernel interface
index, one covering route on that interface, one KyClash `/32` on its different
owned utun, and unchanged default/DNS/proxy snapshots.

## App contract and visible result

The App reuses protocol v2 bootstrap, HMAC proof, request correlation,
cancellation, deadlines, and EOF semantics. The lab status adds only
allowlisted non-secret facts:

- `runtime_mode=vm_network_lab`;
- `tunnel_kind=darwin_utun`;
- exact `tunnel_interface=utunN` while connected;
- `routes_installed`, `private_reachable`, and `mihomo_coexisting` booleans;
- the three carrier samples and their private-echo result; and
- a closed typed error code.

The navigation/page label is
`VM LAB · REAL UTUN · PRIVATE ROUTE · MIHOMO`. It must also state visibly that
this is a disposable-VM root lab and not production XPC. Diagnostics contain
no endpoints, keys, tokens, raw config, command output, PID, filesystem path,
or credential value.

## Required source and contract tests

- mutually exclusive/default-off feature and production-boundary assertions;
- no-argument, VirtualMac/root/console-user/socket/peer-uid/single-connection
  harness tests;
- fixed Mihomo path/hash/config/API/device/process and foreign-state refusal;
- journal create-only/atomic/fsync/version/mode/symlink/replacement tests;
- pending-before-add, pending-before-delete, postflight positive absence,
  startup recovery, and nil-inspection failure tests;
- exact/more-specific/unknown-interface conflict refusal and only the exact
  authenticated Mihomo covering-route allowance;
- route-after-health and route-before-utun-stop ordering;
- the lab-only typed private-reachability request, with production-sidecar
  rejection and empty request data;
- private TCP echo on QUIC, WSS, and TCP with break-before-make assertions;
- EOF, cancellation, TERM, child crash, route-command failure, and duplicate
  Connect cleanup tests; and
- contract checks proving production composition, SMAppService, route helper,
  tunnel broker, release build, and ordinary App never reference this feature
  or socket.

## Disposable-VM acceptance

Acceptance requires one visible run of the exact unsigned App in the selected
VM and redacted evidence for:

1. the foreground KyClash network page and one Connect click;
2. a real owned `utunN` distinct from `utun4094`;
3. the exact Mihomo covering route plus KyClash `/32` route;
4. successful fixed private TCP echo over QUIC, WSS, and TCP;
5. break-before-make carrier order with the same utun and route;
6. Disconnect and App-EOF cleanup; and
7. final absence of the KyClash route, utun, fixed socket, journal, Mihomo
   child/device/controller/covering route, with DNS/default/proxy unchanged.

## Acceptance result — 2026-07-23

The locked profile passed against the exact unsigned arm64 App whose executable
SHA-256 is
`39866bf893106aeaa9c567cc33e0c1394a820177df794b1785841166846822a2`.
The App ran visibly in `kyclash-macos-lab-work` (`VirtualMac2,1`, macOS
26.5.2, arm64) and reported `vm_network_lab`, `darwin_utun`, `utun4`, the
installed `10.88.0.2/32` route, private echo reachability, and Mihomo
coexistence on `utun4094`. QUIC, WSS, and TCP each passed the private echo
while the final active carrier was TCP. The reviewed break-before-make
transition log retained the same KyClash utun and private route across carrier
changes.

Both required cleanup paths passed for those exact App bytes:

- App `SIGKILL` closed the App stream and removed the root harness, lab
  Mihomo, both lab utuns, fixed sockets, exact and covering routes, while the
  default route remained `192.168.64.1` through `en0`.
- A second visible run used the App's `DISCONNECT LAB` control. The App
  remained running while the same harness, Mihomo, sockets, utuns, and routes
  were removed and the default route remained unchanged.

The redacted connected evidence is retained under the ignored directory
`target/macos-vm-lab/evidence/vm-network-final-postfix-connected-20260723T025619Z/`.
Its screenshot SHA-256 is
`9b9b4435c95c1aa88a66e05a25da9b0c4e3922fb08406b6bf9b3f22ebcb7391a`.
The manifest explicitly records the topology as an isolated same-VM loopback
peer. This result is not evidence of a second device, an external server, a
site LAN gateway, a production endpoint, or production helper/XPC readiness.

## Non-goals and claim boundary

This review does not authorize host runtime, physical-Mac mutation, arbitrary
routes, production/staging endpoints, production credentials, a production
XPC bypass, signing-gate weakening, packaging, notarization, publishing, or
updater activation. It does not make the unsigned App independently
deployable without the manually authorized VM fixture.

Passing this lab proves the requested visible core behavior in the disposable
VM only. It cannot close the production signed-helper, production Keychain,
production endpoint, App/sidecar/helper restart, physical sleep/network
switch, or S1 aggregate gates.
