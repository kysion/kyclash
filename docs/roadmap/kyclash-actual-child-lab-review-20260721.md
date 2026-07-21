# KyClash N1D actual-child lab boundary review

Status: approved and locked for N1D

Date: 2026-07-21

Amends test-harness details of:

- `kyclash-dataplane-contract-review-20260721.md`
- `kyclash-production-networking-work-program-20260721.md`

## Decision

N1D uses a separate `kyclash-network-sidecar-lab` executable compiled only for
the `networking-dev` integration-test target. It shares the production
bootstrap authentication, IPC session, profile validation, userspace backend,
WireGuard device, switchboard, and carrier implementations. Its wrapper adds
only loopback peer orchestration and ephemeral trust injection.

The production `kyclash-network-sidecar` bootstrap and handshake remain byte
compatible and continue to reject unknown fields. Production code never reads
lab trust from argv, environment, a profile, persisted configuration, or a
diagnostic channel.

The lab executable:

- derives the synthetic client public key from the one-time bootstrap private
  key and starts repository-owned QUIC, WSS, and TLS/TCP loopback peers;
- combines their per-run certificate roots only in memory and passes that pool
  directly to `userspace.New`;
- returns an authenticated, bounded lab handshake containing only loopback
  endpoint URLs and the ephemeral peer public key;
- exposes the normal production IPC requests after the handshake and contains
  no lab-only request capable of bypassing validation or producing host I/O;
- closes every peer, WireGuard device, listener, and transient key buffer on
  stdin EOF, malformed IPC, cancellation, or process termination.

Rust recognizes the extended handshake only in the `networking-dev` stdio
runtime. A production controller rejects any lab handshake. This preserves a
closed production trust boundary while allowing the real child data path to be
tested without mutating a system trust store.

## Traffic evidence

Each lab peer owns an in-netstack echo service. Health sampling performs a
bounded backend probe over the active WireGuard netstack in the lab executable;
therefore a successful N1D health response proves encrypted bidirectional
payload traffic, not merely a carrier connection or WireGuard handshake.

Production health remains a backend fact contract. General production probe
destination selection is deferred to N2 policy v2 and is not inferred by Go.

## Failure and cleanup rules

- QUIC refusal, peer abort, response delay, and forced disconnect are selected
  before child launch from a typed test configuration, never from production
  policy.
- Rust remains the only fallback selector and must issue disconnect before the
  next named connect.
- Lab endpoints must normalize to loopback. Any other address aborts before an
  IPC profile is applied.
- The test retains no certificate, private key, raw bootstrap record, endpoint
  credential, or child output after the case ends.
- Every case asserts child exit and uses no host interface, route, DNS, system
  Keychain, or external network.

Changing the production bootstrap, accepting lab trust in the production
binary, adding an implicit Go fallback, or allowing a non-loopback lab endpoint
requires another review.
