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

## Injected coordinator matrix (disposable VM, no route mutation)

The helper source includes separate deterministic self-tests that do not invoke
`/sbin/route` or alter route state. Compile-only checks may run on the build
host, but the linked helper executable and these self-tests run only after
re-proving the selected `VirtualMac*` guest; do not execute the helper on the
host:

```bash
bridge_obj="$(mktemp /tmp/kyclash-route-client.XXXXXX)"
xcrun clang -fobjc-arc -fblocks -Wall -Wextra -Werror \
  -target arm64-apple-macos13.0 -mmacosx-version-min=13.0 \
  -I macos/tunnel-broker -c macos/tunnel-broker/route-client.m \
  -o "$bridge_obj"
xcrun swiftc -parse-as-library -O -target arm64-apple-macos13.0 \
  -framework Foundation -framework OSLog \
  -import-objc-header macos/tunnel-broker/route-client.h \
  -o /tmp/kyclash-route-helper \
  macos/route-helper/main.swift "$bridge_obj"
/tmp/kyclash-route-helper --route-coordinator-self-test
/tmp/kyclash-route-helper --route-v3-bridge-self-test
/tmp/kyclash-route-helper --route-v3-contract-self-test
/tmp/kyclash-route-helper --route-v3-interlock-self-test
/tmp/kyclash-route-helper --route-v3-durable-store-self-test
```

The production helper's no-argument path now exposes the v3 listener. The
explicit `--route-v3-lab-listener` plus
`KYCLASH_ROUTE_HELPER_V3_LAB=1` path remains a separate deterministic lab
mode; legacy v2 is similarly available only through
`--route-v2-lab-listener` plus `KYCLASH_ROUTE_HELPER_V2_LAB=1`. Both v3 paths
use the root-owned atomic plist store and exact-owner startup recovery. The
injected v3 self-test uses an in-memory executor, broker, and temporary journal
seam to cover ordering without contacting the broker.

The two fixed v3 native clients use connection epochs to reconnect after a
transient timeout, interruption, invalidation, or remote failure. They do not
replay the ambiguous request, and an old connection callback cannot invalidate
the replacement. Distinct ambiguous/rejected broker results retain a possibly
committed hold, helper and broker watchdogs preserve the exact recovery tuple,
and route retirement requires a successful post-delete inspection; a missing
inspection result is not positive absence.

The v2 matrix uses an in-memory executor and a temporary private journal to
cover normal IPv4/IPv6 apply and cleanup, duplicate/replayed lease messages,
exact route conflicts, injected add and rollback failures, heartbeat/lease expiry,
connection invalidation, helper restart reconciliation, and corrupt-journal
fail-closed behavior. The signed privileged VM has now also passed dual-stack
normal apply/rollback, exact IPv4/IPv6 and more-specific IPv4 conflict refusal.
The historical untyped less-specific IPv4/IPv6 probe is superseded. The typed
v2 active-Mihomo-interface and packaged-Mihomo matrices have passed, but they
do not substitute for the still-open production broker/v3 exact-candidate VM
aggregate. See `kyclash-macos-virtualization-lab.md` for the evidence boundary.

The production Connect source gate also checks that both privileged services
are enabled and that the fixed bundled helper/broker executables satisfy the
expected identifier/Team-ID code requirements and exact launchd manifests.
This runbook does not claim that a new signed candidate, helper registration,
or production v3 VM transaction has been executed.
