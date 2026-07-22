# KyClash macOS route lab

Status: normal transaction and crash recovery passed on GitHub-hosted macOS

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

## GitHub-hosted runner gate

`scripts/macos-system-lab.sh` runs the normal cycle and forced-abort recovery on
an ephemeral `macos-15` GitHub-hosted runner. It refuses non-GitHub or
non-disposable environments, captures only the fixed TEST-NET route and journal,
and installs an exit trap that recovers the transaction and removes only the
fixed lab files. This gate can close route mutation and crash-recovery evidence;
Mihomo coexistence remains separate because the production integration is not
enabled.

The gate passed in workflow run `29804311056`, job `88551634740`, on the
`macos-15` ARM64 runner for commit
`bdb0feeae4e3a0c93924cb64b6fe2dec86192dd2`. The job completed in 5 minutes 7
seconds. Normal apply/rollback, expected abnormal termination after durable
apply, fixed-route observation, journal recovery, and final route absence all
passed. Evidence artifact `8484981045` has archive digest
`sha256:714881e9985440db636fb38589b5c3e32bb5665144047443f13e0b84bba5b043`
and is retained through 2026-08-04.

The same fixed-scope lab may also run in the confirmed local Apple
Virtualization.framework guest described in
`docs/testing/kyclash-macos-virtualization-lab.md`. The script verifies the
`VirtualMac` hardware model and refuses the physical development Mac.

This local guest cycle passed on 2026-07-21 on macOS 26.5.2 arm64. Normal
apply/rollback, expected exit 134 after durable apply, journal recovery, and
independent final route/journal absence all passed.

## Injected coordinator matrix (no privileges)

The signed helper source includes a separate deterministic self-test that does
not invoke `/sbin/route` or alter host state:

```bash
xcrun swiftc -parse-as-library -O -target arm64-apple-macos13.0 \
  -framework Foundation -o /tmp/kyclash-route-helper \
  macos/route-helper/main.swift
/tmp/kyclash-route-helper --route-coordinator-self-test
```

It uses an in-memory executor and a temporary private journal to cover normal
IPv4/IPv6 apply and cleanup, duplicate/replayed lease messages, exact route
conflicts, injected add and rollback failures, heartbeat/lease expiry,
connection invalidation, helper restart reconciliation, and corrupt-journal
fail-closed behavior. The signed privileged VM has now also passed dual-stack
normal apply/rollback, exact IPv4/IPv6 and more-specific IPv4 conflict refusal.
The current helper fails closed on every non-default overlap, so the historical
less-specific IPv4/IPv6 probe is superseded and is not accepted coexistence
evidence. A typed active-Mihomo-interface ownership amendment is required
before less-specific coverage may be allowed. The complete production-journal
corruption/restart matrix and packaged Mihomo coexistence remain separate
gates; see `kyclash-macos-virtualization-lab.md` for the evidence boundary.
