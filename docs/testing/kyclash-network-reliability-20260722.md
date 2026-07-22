# KyClash deterministic network reliability evidence — 2026-07-22

Status: local loopback and repeated sidecar tests passed; production endpoint,
macOS sleep/wake, and physical network-change gates remain open.

## Scope

The tests in this record use only repository-owned in-process peers, ephemeral
TLS certificates, userspace WireGuard netstack devices, and loopback sockets.
They do not create host interfaces or routes, contact a production endpoint, or
read credentials.

The reliability additions exercise the cancellation and recovery edges that are
easy to miss in a short happy-path run:

- A blocked TLS/TCP or WSS stream write is released by its context deadline.
- A QUIC receive wait is released by cancellation within a bounded deadline.
- An abrupt authenticated QUIC peer close fails the receive operation rather
  than hanging.
- A prepared userspace backend completes twelve explicit connect/disconnect
  cycles without leaving an active carrier or operation cancellation handle.
- A live loopback lab cluster carries health probes through QUIC, then WSS,
  then TLS/TCP with an explicit disconnect before each next carrier.
- Injected prepare/connect/health/disconnect/stop failures retain the stable
  `sidecar_unavailable` reason and do not advance the IPC session state.
- An impairment delay honors cancellation and never delivers the cancelled
  packet.
- Existing deterministic loss, stepped jitter, rate limiting, duplication,
  pair reordering, UDP refusal, TLS identity refusal, replay, fragment expiry,
  packet-size bounds, IPC cancellation, and Rust break-before-make tests remain
  enabled.
- The production Rust monitor now advances only in the configured QUIC -> WSS
  -> TCP order after a consecutive-health threshold. Each old carrier is
  explicitly observed disconnected before the next connect, while the stable
  utun and owned route lease are retained and heartbeated.

## Commands and results

The host did not have a system Go installation. Go 1.26.5 was downloaded to a
temporary directory under `/tmp` for this validation only; it is not part of the
repository or the application bundle.

From `network-sidecar`:

```bash
go test -count=3 -timeout=300s ./...
go test -race -count=3 -timeout=300s ./...
```

Both commands passed on Apple Silicon macOS 25.5.0 with Go 1.26.5. The retained
ignored evidence log is:

```text
network-sidecar/target/s114-reliability-20260722/go-reliability.log
SHA-256: 2e89467b36f4e9b8ac287d9252878c5ba4ba5bc4b847b2f96380e99991a855ae
```

The local CI-equivalent race gate (`-count=5`) also passed after the
live-carrier and IPC matrices were added; the slowest `internal/labserver`
package completed in about 150 seconds. Hosted macOS runners have a slower
tail for this package after the live matrix was enabled, so the workflow keeps
the same five-run coverage with a bounded 600-second package timeout. This is
an execution-budget adjustment, not a reduction in assertions or per-operation
deadlines.

The focused cancellation/reconnect run also passed under the race detector:

```bash
go test -race -count=3 -timeout=180s \
  ./internal/carrier ./internal/userspace
```

The real userspace cluster break-before-make test passed three times normally
and three times under the race detector:

```bash
go test -race -count=3 -timeout=180s \
  ./internal/labserver -run TestClusterCarriesBreakBeforeMakeAcrossAllCarriers
```

The IPC reason/state matrix passed five normal and five race-enabled repeats:

```bash
go test -race -count=5 -timeout=180s \
  ./internal/ipc -run TestBackendFailureReasonCodeIsStableAndStateRemainsBounded
```

The Rust process-level integration also passed with freshly built temporary Go
children (the binaries were kept only under `/tmp`):

```bash
KYCLASH_NETWORK_SIDECAR_BIN=/tmp/kyclash-s114-child/kyclash-network-sidecar \
KYCLASH_NETWORK_LAB_SIDECAR_BIN=/tmp/kyclash-s114-child/kyclash-network-sidecar-lab \
  cargo test --manifest-path src-tauri/Cargo.toml --features networking-dev \
  --lib networking::stdio_runtime::unix::tests::actual_lab_child_carries_health_traffic_across_all_carriers -- --exact
```

The test passed in 1.84 seconds and remains traffic/sequencing evidence for the
actual IPC child, userspace WireGuard health traffic, and explicit
QUIC/WSS/TCP order. Its earlier concurrent-cancellation interpretation used the
superseded protocol-v1 framing and is not accepted as cancellation evidence;
the valid atomic protocol-v2 cancellation closure is recorded below.

The focused production-service monitor suite also passed:

```bash
cargo test -p clash-verge --all-features --lib \
  networking::production_service::tests
```

Nineteen tests passed. The runtime-health case injects three failed QUIC samples,
then a failed WSS health gate, and proves TCP is connected only after the QUIC
and WSS disconnect observations. Routes are applied only once and remain
active across the successful carrier switch. A separate all-carriers-failed
case proves final route rollback precedes tunnel stop and secret release. The
expanded lifecycle cases also prove final Connected publication and accepted
Cancel are a single either/or decision, fatal primary errors survive rollback
failure, and blocked heartbeat/rollback calls cannot detach or replay a route
mutation. A monitor that has cleaned routes and stopped the child remains
fail-closed in `Error` until an external Disconnect joins its exact heartbeat
task; only that completed join may publish `Disconnected` and clear the active
operation.

The atomic stdio protocol-v2 closure then passed with freshly built ignored
host artifacts. Rust executed 14 process-level tests against the production
and lab Go children; the matrix covers strict v2 bootstrap/HMAC, prepare/stop,
encrypted QUIC/WSS/TCP health traffic, exact-target cancellation, both race
outcomes and response orders, contradictory-response fail-stop, timeout
cleanup, post-cancel reuse, and exact-child reap. The production controller's
blocked-cancellation case also passed against the real lab child. The full
Rust all-feature library gate passed 245 tests with the one disposable-account
Keychain lifecycle test intentionally ignored. Go module, formatting, normal,
race, vet, and shared-fixture parity gates passed. The locally built children
are disposable test artifacts; no stale pre-commit binary hash is treated as
clean-source release evidence.

The Linux `tc netem`/nftables harness was inspected in non-mutating mode on the
same host:

```bash
bash lab/linux/netem-lab.sh dry-run
```

It emitted the expected loopback-only delay/jitter/loss/rate, UDP-block, and
benchmark commands. Actual queue/filter mutation remains restricted to the
disposable Linux VM or the existing isolated GitHub Actions runner evidence.

The new loopback soak driver completed the default ten-round run on Apple
Silicon macOS:

```bash
KYCLASH_SOAK_ROUNDS=10 \
  KYCLASH_SOAK_OUTPUT=/tmp/kyclash-s114-soak \
  bash lab/linux/reliability-soak.sh
```

All ten rounds passed (console-log SHA-256
`205bfce7bc7ed62c339de98a1201d9ba6e06ee6195d956a385d4b6d956a7c1cc`). A manual
or scheduled Linux VM run may raise
`KYCLASH_SOAK_ROUNDS` (maximum 1000); the script stops on the first failure and
retains per-round logs. No soak result is a production capacity claim.

The macOS sidecar workflow now also runs a short deterministic smoke matrix on
every change before the longer race gate. It covers the carrier, loopback
lab-server, userspace, and bind packages plus the stable IPC failure-reason
state assertion. The smoke command uses a 90-second package timeout and
retains its redacted log as the `network-sidecar-reliability-smoke-*` artifact;
it remains loopback-only and needs neither root nor an external endpoint. The
first hosted result for this newly added step is pending the next workflow run.

## Remaining S1.14 boundary

The deterministic source, short smoke gate, isolated Linux subset, production
Rust-to-Go command boundary, production-code Go health sampling, and blocked
actual-child cancellation are now repeatable locally; the existing hosted
race/netem results remain retained in CI. S1.14 remains open for a reviewed
compatible server under sustained impairment, macOS sleep/wake, and physical
network-interface changes after the S1.13 system gate closes. No fallback is
enabled implicitly inside Go.
