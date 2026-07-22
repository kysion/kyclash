# KyClash sidecar stdio protocol review

Status: approved and locked for N0/N1

Date: 2026-07-21

Current implementation note: this document remains the immutable protocol v1
record. `kyclash-sidecar-stdio-v2-control-review-20260722.md` is the reviewed
and locked successor for the current App/sidecar implementation; v1 fixtures
are retained as historical and downgrade-rejection evidence.

Amends: `kyclash-production-networking-plan-20260721.md`

## Finding

The development mock and the production Go sidecar used incompatible process
contracts. The mock used command arguments, a Unix socket, and a one-line token;
the production executable rejects all arguments and already consumes a strict
bootstrap record from stdin. The production framing, concurrency, EOF, and
shutdown behavior therefore had to be fixed before implementing tunnel state.

## Locked wire contract

The child is started with no arguments and an empty inherited environment.
Stderr is not parsed or retained. Rust sends exactly one JSON bootstrap object,
terminated by LF, followed by JSON IPC request objects terminated by LF. Go
writes exactly one authenticated handshake object followed by one response for
each accepted request. Every record, including LF, is at most 64 KiB. Empty,
oversized, truncated, malformed, unknown-field, unknown-version, and trailing
JSON input fails closed and terminates the child with constant diagnostics.

Protocol v1 is strictly single-flight: Rust does not send another request until
the preceding response with the identical request ID arrives. Unsolicited
frames and concurrent requests are invalid in v1. Observable state is obtained
by bounded status/health polling; each returned operation event retains its
monotonic sequence. A future multiplexed event frame requires a new protocol
version and review rather than heuristic response/event parsing.

The command surface is granular: prepare/stop tunnel, connect/disconnect one
explicitly named transport, sample health, get status, cancel an operation, and
disconnect the complete sidecar session. Rust alone selects QUIC, WSS, or TCP
and enforces break-before-make. Unsupported N0 commands return structured
`sidecar_unavailable` responses without changing process or host state.

## Lifecycle and failure semantics

- Bootstrap material is base64-encoded only as required by Go JSON `[]byte`
  decoding; this is transport encoding, not persistence or encryption.
- Rust computes and compares the HMAC-SHA-256 proof over the canonical v1 input
  and kills the exact child on timeout, premature exit, malformed handshake,
  wrong version, instance mismatch, or proof mismatch.
- A request timeout makes the session unusable; the controller terminates the
  exact child rather than attempting to resynchronize an ambiguous stream.
- `cancel` is an ordinary correlated request and never bypasses single-flight;
  the controller may terminate the child when an in-flight operation cannot
  respond within its cancellation deadline.
- `disconnect` acknowledges only after cleanup is complete and then exits zero.
- EOF on inherited stdin means controller death or intentional channel close;
  the sidecar cancels work, clears owned secrets, closes carriers and tunnel,
  and exits within the bounded cleanup deadline.

Changing record framing, the single-flight rule, command ownership, bootstrap
secret channel, or EOF/shutdown semantics requires a new review record.
