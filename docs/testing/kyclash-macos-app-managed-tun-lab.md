# KyClash app-managed Mihomo TUN VM matrix

Status: signed disposable-VM matrix passed on 2026-07-22

Execution target: the disposable `kyclash-macos-lab-work` Apple
Virtualization.framework guest only. The host Mac is build and orchestration
infrastructure and is never an acceptance substitute.

## Purpose and evidence boundary

`scripts/macos-vm-app-managed-tun-matrix.sh` proves that the installed,
Developer ID-signed `/Applications/KyClash.app` launches through guest
LaunchServices, displays a guest window, and drives its managed Mihomo instance
to create the fixed `utun4093` device through the installed privileged service.
The matrix also proves that this fixture does not change system DNS, system
proxy state, default routes, or existing RFC1918/ULA private routes.

This is app-managed Mihomo evidence. It does **not** by itself prove that the
production Rust `MacosActiveMihomoTunSource` was invoked; closing that separate
S1.13 requirement still needs the production-feature App control path or a
reviewed VM-only probe at that exact boundary.

## Fixed safety contract

- `static-check` is the only mode intended to run on the host. It parses and
  hash-pins the repository fixtures and performs no mutation.
- `preflight`, `run`, and `restore` refuse anything except Darwin arm64 with an
  `hw.model` beginning `VirtualMac`, the exact local-VM runner marker, and the
  exact confirmation marker.
- The current user must also own the guest console session. Host PIDs, sockets,
  windows, or interfaces cannot satisfy the checks.
- The installed bundle must have package receipt `net.kysion.kyclash`, bundle
  identifier `net.kysion.kyclash`, intact deep signatures, and Team ID
  `RQUQ8Y3S9H`. The fixed service socket must already exist under its exact
  `root:staff` mode-`02770` parent, and the console user must belong to that
  group. The service's mode-`0777` socket is accepted only behind this
  non-world-traversable parent boundary.
- The fixtures are DIRECT-only, have no selected profile, use a clearly
  synthetic non-sensitive API token, disable DNS and system proxy integration,
  set `auto-route=false`, and cannot accept a path, command, interface, CIDR,
  endpoint, or credential from the caller.
- The script atomically moves the complete original App data directory into a
  unique mode-`0700` sibling backup. The lab directory carries a pinned marker.
  Cleanup removes only that verified lab directory and atomically restores the
  same original directory object and inode.
- An interrupted execution is recovered with `restore`; ambiguous ownership or
  an unknown path fails closed and preserves the backup.
- Route comparisons retain destination, gateway, flags, and interface while
  excluding only macOS's volatile ARP/ND expiry counter. A timer decrement is
  not reported as a route mutation; any material route-field change still
  fails closed.
- The live Mihomo API is parsed locally with macOS's system JSON library
  because its valid response contains JSON `null` values that `plutil` cannot
  represent. Only the fixed TUN/mode/version fields are checked; the full
  response and synthetic API token are never printed. Mihomo normalizes an
  explicit false `strict-route` to JSON `null`; the gate accepts only `false`
  or `null` while independently proving that no protected route appeared.

## Commands

From the repository checkout on the host, run only the non-mutating checks:

```bash
/bin/bash -n scripts/macos-vm-app-managed-tun-matrix.sh
env -u BASH_ENV -u ENV \
  scripts/macos-vm-app-managed-tun-matrix.sh static-check
```

Copy the current script and `macos/app-tun-lab/` fixtures into the disposable
work guest. Then run these commands **inside that guest's console-user
session**:

```bash
env -u BASH_ENV -u ENV \
  KYCLASH_RUNNER_ENVIRONMENT=local-virtualization-framework \
  KYCLASH_VM_LAB_CONFIRM=authorized-kyclash-virtualization-framework-vm \
  /bin/bash --noprofile --norc \
  scripts/macos-vm-app-managed-tun-matrix.sh preflight

env -u BASH_ENV -u ENV \
  KYCLASH_RUNNER_ENVIRONMENT=local-virtualization-framework \
  KYCLASH_VM_LAB_CONFIRM=authorized-kyclash-virtualization-framework-vm \
  /bin/bash --noprofile --norc \
  scripts/macos-vm-app-managed-tun-matrix.sh run
```

If the shell, SSH session, App, or VM interaction is interrupted after the
backup becomes active, rerun the same command with `restore`. Do not manually
move or delete the backup: `restore` revalidates its owner, mode, basename,
phase, original inode, lab marker, exact processes, socket, and `utun4093`
before making any destructive change.

## Passing result

A passing `run` records only allowlisted facts: guest model/OS/architecture,
package version, App and Mihomo hashes, guest PIDs, visible-window state,
`tun.enable=true`, `tun.device=utun4093`, invariant comparisons, cleanup, and
original-directory identity restoration. It never prints the full Mihomo
configuration, API token, original App configuration, profile contents, or
credentials.

The full `run` passed in the `VirtualMac2,1` guest on macOS 26.5.2. The
Developer ID-signed, intentionally unnotarized internal PKG was installed only
in that guest. Its exact hashes were:

- App executable:
  `acbd5b20a99dfd85115fb192dae184e773844b4d1e3724ae676c565761967e8f`
- packaged Mihomo:
  `3ead9b2b29854961100af3ef2c6bdce2764779b53e3177b4590bf34dd45b53ad`
- nested network sidecar:
  `f50e402be47f3c15196807784b46f6ec141234a929b401613f07fe3e59dbe557`
- nested route helper:
  `aa6816decd845e167747adf953fd4406da12674860383b3b4d3573057e3d8280`
- 68,501,192-byte PKG:
  `81de8dafe66eb8891210fdf52de669af058dbc099809cabfc9aa84e4ff58caff`

The guest launched the installed App through LaunchServices, proved PID 27759
at the exact bundle executable, proved root Mihomo PID 27821 at the exact
packaged executable, foregrounded a visible guest window, and observed live
`tun.enable=true` with `tun.device=utun4093`. DNS, system proxy, IPv4/IPv6
default routes, and existing RFC1918/ULA routes remained at the normalized
baseline. Cleanup proved the App, Mihomo, socket, and `utun4093` absent and
restored the original App-data directory identity.

The redacted 29-line evidence is retained at
`target/macos-vm-lab/evidence/app-managed-tun-v1-20260722/app-managed-tun-matrix.log`;
its SHA-256 is
`1e06355753e3856e01ac3e1aaf6f18687b8a6a6cb96d41e9f84c124abd6095bd`,
and the secret-pattern scan passed.

Fail-closed development findings were retained as fixes rather than passing
claims: macOS `netstat` exposes a volatile ARP expiry counter, Mihomo emits
JSON `null` for disabled `strict-route`, and the system-proxy library briefly
enabled HTTPS while redundantly applying an already-disabled state. Route
comparison now excludes only the expiry counter, the JSON gate accepts only
false/null for that one field, and KyClash now skips macOS proxy mutation when
both the requested and observed proxy states are already disabled. An
operator interrupt also restored the original directory and left no runtime
state.
