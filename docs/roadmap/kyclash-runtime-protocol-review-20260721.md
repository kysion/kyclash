# KyClash Runtime Protocol Review 2026-07-21

Status: Approved and locked

Reviewed baseline: `docs/architecture/kyclash-network-runtime-v1.md`

## Blocking finding

The original runtime record required one complete encrypted WireGuard packet in
one QUIC datagram while allowing payloads up to 65,535 bytes. QUIC datagrams are
bounded by the negotiated datagram size and path MTU. The original requirement
therefore cannot safely carry every accepted frame and would turn ordinary MTU
variation into a runtime failure.

Silently lowering the WireGuard interface MTU is not sufficient: it would make
correctness depend on one conservative platform value, reduce throughput, and
still provide no fail-closed behavior if a peer emits a larger encrypted packet.
Using one ordered QUIC stream would avoid the size limit but introduce
head-of-line blocking across tunnel packets.

## Approved resolution

The common frame header remains version 1. WSS and TCP remain unfragmented.
QUIC may set flags bit 0 (`fragmented`) and insert this 12-byte prefix before
each fragment payload:

```text
message_id[8] = unsigned network byte order, unique per connection
fragment_index[2] = unsigned network byte order, starts at zero
fragment_count[2] = unsigned network byte order
```

`payload_length` is the fragment payload length and excludes the prefix. Every
fragment retains its own monotonic frame sequence. A packet with one fragment
must use the unfragmented form.

The sender derives fragment payload size from the QUIC connection's supported
datagram size and subtracts both KyClash headers. It must never optimistically
send an oversized datagram. The receiver enforces:

- at most 64 fragments and 65,535 reconstructed bytes per message;
- one fixed fragment count and one frame kind for a message;
- no duplicate indices or message IDs recently completed;
- bounded concurrent assemblies and a fixed expiry;
- delivery only after every index is present;
- clearing all incomplete assemblies on carrier close or connection change.

Malformed, duplicate, inconsistent, expired, excessive, or replayed fragments
fail closed. There is no cross-carrier reassembly. Break-before-make remains
unchanged.

## Review result

The resolution preserves the locked WireGuard, QUIC-primary, WSS/TCP fallback,
single-site, route-ownership, privilege, and secret boundaries. It corrects an
implementation-level transport contract before deployment and requires no real
network or system mutation.

Changes to these fragmentation rules require another review record.
