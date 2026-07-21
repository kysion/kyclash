# KyClash Network Runtime Measurements 2026-07-21

Status: Reproducible local P1 evidence; not a production capacity claim

## Environment

- Apple M5, arm64
- macOS 26.5.1 (25F80)
- Go 1.26.5
- loopback UDP with an ephemeral TLS 1.3 certificate
- QUIC datagrams enabled, KyClash 1,024-byte fragmentation enabled
- 4,096-byte application payload echoed once per benchmark operation

Command:

```bash
cd network-sidecar
go test ./internal/carrier \
  -run '^$' \
  -bench '^BenchmarkQUICCarrierFragmentedRoundTrip$' \
  -benchtime=3s \
  -count=3 \
  -benchmem
```

## Result

| Run | Round trip | Reported payload rate | Heap/op | Allocations/op |
| --- | ---: | ---: | ---: | ---: |
| 1 | 406,657 ns | 10.07 MB/s | 67,238 B | 211 |
| 2 | 405,134 ns | 10.11 MB/s | 67,256 B | 212 |
| 3 | 401,664 ns | 10.20 MB/s | 67,242 B | 212 |

The median local 4 KiB round trip was 405 microseconds. The reported payload
rate is based on one 4 KiB payload per complete echo operation; it is not
full-duplex aggregate throughput.

## Functional composition evidence

`TestWireGuardEncryptsThroughFragmentedQUICCarrier` sends a multi-packet TCP
payload through both userspace WireGuard peers, the custom Bind, KyClash
fragmentation/reassembly, and authenticated QUIC in both directions. It runs
with the race detector and performs no host-interface, route, DNS, credential,
or external-network operation.

## Limitations and remaining measurements

- Loopback removes internet RTT, congestion, NAT, firewall, and radio effects.
- The benchmark measures the QUIC carrier and KyClash framing, while the full
  WireGuard composition is currently a correctness test rather than a
  throughput benchmark.
- No claim is made for production packet loss, jitter, CPU, battery, or memory.
- UDP blocking, controlled loss/jitter, sleep/wake, network switching, and
  sustained throughput must still be measured on disposable authorized macOS
  hosts and compatible isolated server endpoints.
- WSS/TCP fallback has authenticated loopback correctness coverage but still
  needs the same sustained and impaired-link measurement matrix.

These limitations prevent Iteration 4 from being release-closed even though the
safe local implementation and composition gates now pass.

## Linux VM matrix preparation

The reproducible Ubuntu ARM64 harness now lives at
`network-sidecar/lab/linux/netem-lab.sh`. It is loopback-scoped by default,
cleans its `tc` and nftables state on exit, needs no endpoint credential, and
covers baseline transports, controlled delay/jitter/loss/rate, UDP blocking
with WSS/TCP availability, and sustained QUIC benchmarking.

Its dry-run and source tests pass on the development Mac. The same matrix passed
on GitHub Actions run `29802494990`, job `linux-impaired-network`, using the
`ubuntu-24.04-arm` runner for commit `f73f822b6025e36d4af63e3578bbeab2d4aa337f`.
The impairment job completed in 1 minute 50 seconds and retained artifact
`network-sidecar-linux-netem-ARM64` (artifact `8484258177`, archive digest
`sha256:3179b7f99e5ae0f00ab5f1fab0586c4cdfc9cd5586fa31bb1ea3e68cb577b7d8`)
through 2026-08-04.

This closes the reproducible isolated Linux server/network subset. It does not
close macOS utun, routes, sleep/wake, network switching, installation lifecycle,
or testing against a separately reviewed KyClash server implementation.
