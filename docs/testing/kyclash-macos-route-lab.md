# KyClash macOS route lab

Status: ready for an explicitly authorized disposable macOS host

This runbook validates the real `/sbin/route` boundary added behind the
`networking-route-lab` feature. It must not be run on a daily-use workstation,
production host, remote-only host, or a host carrying unrelated VPN traffic.

## Fixed safety scope

- IPv4 route: `192.0.2.0/24`, reserved for documentation by RFC 5737
- Interface: `lo0`
- Journal: `/var/tmp/net.kysion.kyclash-route-lab/route-journal.json`
- No DNS, default-route, proxy, service, credential, or external-network change
- No caller-provided route, gateway, interface, executable, or shell fragment
- Requires root and the exact confirmation value
  `KYCLASH_ROUTE_LAB_CONFIRM=authorized-disposable-macos-host`
- A kernel-held file lock serializes processes and is released automatically by
  the operating system after normal exit, kill, or abort.

## Build and preflight

```bash
cargo build -p clash-verge \
  --features networking-route-lab \
  --bin kyclash-route-lab

test -x target/debug/kyclash-route-lab
test -z "$(netstat -rn -f inet | awk '$1 == "192.0.2" || $1 == "192.0.2.0/24"')"
```

Stop if the test route already exists, the host is not disposable, remote
console recovery is unavailable, or an unrelated VPN owns overlapping traffic.

## Normal transaction

```bash
sudo env KYCLASH_ROUTE_LAB_CONFIRM=authorized-disposable-macos-host \
  target/debug/kyclash-route-lab cycle

test -z "$(netstat -rn -f inet | awk '$1 == "192.0.2" || $1 == "192.0.2.0/24"')"
```

The command must add, observe, journal, remove, and re-observe the fixed route.
Any failure is a failed gate even if cleanup succeeds.

## Forced-exit recovery

The abort command is expected to terminate abnormally after the route and
journal entry are durable:

```bash
sudo env KYCLASH_ROUTE_LAB_CONFIRM=authorized-disposable-macos-host \
  target/debug/kyclash-route-lab abort-after-apply

netstat -rn -f inet | awk '$1 == "192.0.2" || $1 == "192.0.2.0/24"'

sudo env KYCLASH_ROUTE_LAB_CONFIRM=authorized-disposable-macos-host \
  target/debug/kyclash-route-lab recover

test -z "$(netstat -rn -f inet | awk '$1 == "192.0.2" || $1 == "192.0.2.0/24"')"
```

The middle query must show the route, and the final query must show none. Save
the redacted journal, command exit codes, OS build, and route-table excerpts as
test evidence. Do not include unrelated routes or addresses.

## Cleanup

Only after the fixed route is confirmed absent:

```bash
sudo rm /var/tmp/net.kysion.kyclash-route-lab/route-journal.json
sudo rm /var/tmp/net.kysion.kyclash-route-lab/lab.lock
sudo rmdir /var/tmp/net.kysion.kyclash-route-lab
```

Missing cleanup files are harmless. Do not broaden these paths or use recursive
deletion.

## Current-host preflight evidence — 2026-07-21

The development Mac passed read-only parser discovery and unprivileged refusal:
the candidate route was absent before and after execution, the lab directory was
not created, and the binary returned `PermissionDenied`. The host has an active
Mihomo-style split route plus several system tunnels and lacks non-interactive
sudo, so it is not accepted as the disposable-host mutation environment.

This runbook closes the executable preparation gate only. Iteration 3 remains
release-open until normal, forced-exit, and Mihomo-coexistence evidence is
captured on an authorized disposable host.
