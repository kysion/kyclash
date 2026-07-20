# KyClash Runtime Datagram Size Review 2026-07-21

Status: Approved and locked

Amends: `kyclash-runtime-protocol-review-20260721.md`

## Finding

The selected `quic-go` API reports `DatagramTooLargeError` and its current
maximum only after a send attempt. It does not expose the peer/path maximum as a
pre-send query. Therefore deriving fragment size from a query, as required by
the first fragmentation review, is not implementable without an optimistic
oversized send.

## Decision

P1 uses a fixed maximum QUIC fragment payload of 1,024 bytes. With the 20-byte
base header and 12-byte fragment header, each fragmented KyClash datagram is at
most 1,056 bytes. This stays conservatively below QUIC's required 1,200-byte
minimum UDP payload while leaving room for QUIC packet protection and datagram
framing. It also permits the 64-fragment limit to carry the full 65,535-byte
frame bound.

An unfragmented KyClash frame may use at most the same 1,024-byte payload.
Larger packets are fragmented before any send. If `quic-go` still returns
`DatagramTooLargeError` because the available size changed, the send fails and
the existing health/fallback policy handles it; KyClash does not retry partial
messages with a new fragment geometry.

Adaptive sizing may be added only after the chosen QUIC API can provide a
pre-send bound or a separately reviewed KyClash path-MTU negotiation exists.
