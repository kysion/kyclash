# KyClash no-sign VM utun App lab review

Status: approved and locked for implementation

Date: 2026-07-23

Amends only the development-VM profile in:

- `kyclash-privileged-tunnel-broker-review-20260723.md`
- `kyclash-broker-session-binding-review-20260723.md`
- `kyclash-tunnel-route-retirement-interlock-review-20260723.md`

The production `SMAppService`, XPC, code-signing, route-helper v3, broker
session, and retirement-interlock decisions are unchanged.

## Trigger

The requested current deliverable is an unsigned `.app`, not an installer or
release. An unsigned App cannot activate the locked production helpers. The
existing userspace App proves the carrier sequence but cannot create Darwin
`utun`, so it cannot provide the requested visible real-interface evidence.

The privileged-broker review already authorizes a separately staged, fixed
VM-only root harness after one visible guest-Terminal `sudo` authorization.
This amendment fixes the App-to-harness contract so the lab path cannot be
mistaken for, or silently replace, production composition.

## Locked decision

Add the default-off Cargo feature `networking-vm-utun-lab-app`. It implies the
existing `networking-userspace-lab-app` feature and changes only that lab
command's launcher. It never implies production authority and it is forbidden
from ordinary/release builds.

The App connects only to the fixed socket:

```text
/var/run/net.kysion.kyclash.vm-utun-lab.sock
```

The separately staged Go harness is compiled only for Darwin with
`kyclash_utun`, has no arguments, and must fail closed unless all of these are
true:

- effective uid is root;
- OS/architecture are `darwin/arm64`;
- `hw.model` begins with `VirtualMac`;
- the exact environment markers name the local Virtualization.framework
  runner and `kyclash-macos-lab-work` guest; and
- `/dev/console` is owned by one non-root interactive user.

The root process creates the socket under the root-owned `/var/run` directory
with a restrictive umask, verifies it is a new Unix socket, changes only that
socket to mode `0600` and the console user's uid/gid, and accepts exactly one
connection from that uid. The App independently requires a non-symlink Unix
socket owned by its own effective uid, mode `0600`, and a root peer before it
sends bootstrap material.

The connected stream reuses protocol v2 bootstrap, HMAC authentication,
request correlation, cancellation, deadlines, and bounded EOF cleanup. The
harness accepts no path, argv, environment, route, DNS, profile selection, or
arbitrary command from the App. It creates one fixed loopback QUIC/WSS/TCP
cluster and exposes one fixed profile. The profile creates a real wireguard-go
`utun` only when the App issues `PrepareTunnel`; all carrier switches remain
break-before-make. Closing the App stream cancels IPC, closes WireGuard and the
owned utun, clears secrets, closes the cluster, removes only the exact socket,
and exits.

The App status and navigation must say `VM LAB · REAL UTUN · NO ROUTES`, expose
`runtime_mode=vm_utun_lab`, retain `routes_installed=false`, and reject a
`userspace` interface name. The ordinary userspace lab retains its existing
labels and behavior.

## Route boundary

This slice deliberately does not install private routes. Adding a route to a
root harness would bypass the locked route journal, conflict discovery,
Mihomo ownership checks, and retirement interlock. Private CIDRs shown in the
VM-utun App are fixed profile metadata only. Route and Mihomo coexistence
acceptance remains on the signed production helper path.

The harness may configure only the fixed local address on the utun through the
existing wireguard-go adapter. It must not invoke `route`, change DNS, call the
route helper, or contact production infrastructure.

## Visible authorization and evidence

Building and staging the harness may be automated. Starting it is a
guest-runtime action: the selected disposable VM must be re-proved and the
user must type `sudo` visibly in its Terminal. A password may never enter
argv, environment, stdin automation, source, logs, or evidence. `sshpass`,
`sudo -S`, Keychain retrieval, and UI scripting of the password are forbidden.

Lab evidence can prove only the exact no-sign App, real utun, loopback carrier
sequence, EOF cleanup, and final interface/socket absence in
`kyclash-macos-lab-work`. It cannot close the production broker, route-helper,
Mihomo coexistence, signing, install, release, or S1 aggregate gates.

## Required tests

- feature/default-off and production-boundary contract checks;
- harness build with `darwin,arm64,kyclash_utun` and no accepted arguments;
- root, VirtualMac, exact-marker, console-user, socket-mode, peer-uid, and
  single-connection refusal tests;
- fixed profile and QUIC -> WSS -> TCP order checks;
- Rust fixed-socket metadata/root-peer/generation/EOF tests using only
  temporary sockets in unit tests;
- App status tests proving the distinct mode, real-utun interface validation,
  and `routes_installed=false`; and
- disposable-VM Connect/Disconnect and App-EOF evidence proving final utun and
  socket absence.

## Non-goals

This amendment does not authorize password automation, host runtime, physical
Mac mutation, production endpoints, private-route mutation, production XPC
bypass, signing-gate weakening, packaging, release publication, or updater
activation.
