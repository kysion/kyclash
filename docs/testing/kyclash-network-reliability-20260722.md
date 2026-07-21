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

The test passed in 1.84 seconds and covered the actual IPC child, userspace
WireGuard health traffic, explicit QUIC/WSS/TCP sequencing, and cancellation.

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

## Remaining S1.14 boundary

The deterministic source and isolated Linux subset is now repeatable locally and
in CI. S1.14 remains open for a reviewed compatible server under sustained
impairment, macOS sleep/wake and physical network-interface changes, and the
production Rust-to-Go command boundary once the S1.10–S1.13 system gates are
closed. No fallback is enabled implicitly inside Go.
