# KyClash Runtime QUIC Ordering Review 2026-07-21

Status: Approved and locked

Amends: `kyclash-runtime-protocol-review-20260721.md`

## Finding

QUIC datagrams are unreliable and may arrive out of order. Applying the strict
monotonic receive check used by ordered WSS/TCP streams would reject legitimate
traffic and make packet reordering indistinguishable from replay.

## Decision

Senders still assign a strictly increasing frame sequence. WSS/TCP receivers
still require strict monotonic arrival. QUIC receivers use a 64-sequence sliding
window: a newly observed high sequence advances the window; an unseen sequence
within the window is accepted once; duplicates and sequences older than the
window fail closed.

Fragment message IDs remain independently protected by the bounded reassembler,
including completed-message replay refusal. The window resets on every new QUIC
connection and is never shared across carriers.

Changing the window size or replay behavior requires another review record.
