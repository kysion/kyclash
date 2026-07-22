# KyClash sidecar stdio protocol v2 control review

Status: approved and locked for S1.04–S1.05

Date: 2026-07-22

Amends:

- `kyclash-sidecar-stdio-review-20260721.md`
- `kyclash-actual-child-lab-review-20260721.md`
- `kyclash-production-networking-work-program-20260721.md`

## Decision

KyClash upgrades the sidecar bootstrap, handshake, request, and response
contract atomically to protocol v2. Protocol v2 retains ordinary single-flight
IPC and adds one narrow control exception: while one cancellable primary
request is active, Rust may send exactly one Cancel request that names that
primary request's exact wire `request_id`.

This is not general multiplexing. It exists so a blocked carrier connection or
health probe can be cancelled without discarding a healthy sidecar, userspace
WireGuard device, or already active fallback carrier. The former protocol v1
fail-stop rule remains historical evidence and is not silently reinterpreted.

## Version and authentication boundary

- Bootstrap, authenticated handshake, every IPC request, and every IPC
  response use `protocol_version: 2`.
- The HMAC input is the exact byte domain
  `kyclash-sidecar-bootstrap-v2\0` followed by the validated instance ID.
- Rust and Go accept v2 only. There is no negotiation, downgrade, dual-stack
  decoder, or mixed v1/v2 process session.
- The App and its nested sidecar are one signed package transaction. Rollback
  restores the complete older package; it never mixes a v2 App with a v1
  sidecar or the reverse.
- LF-delimited strict JSON, the 64 KiB record ceiling, unknown-field refusal,
  constant diagnostics, ignored stderr, EOF cleanup, and inherited-environment
  rules remain unchanged.
- KYNP carrier framing remains KYNP v1. WireGuard device configuration,
  policy-envelope v2, and route-helper v2 are separate protocols and are not
  renumbered by this review.

The existing v1 fixtures remain in the repository as historical/rejection
evidence. New v2 fixtures become authoritative for Rust/Go parity. Both mixed
version directions must fail before tunnel, carrier, route, or credential
state changes.

## Locked wire identity

Cancel uses the primary request's wire identity, not the controller/UI
operation identity:

```json
{
  "protocol_version": 2,
  "request_id": "cancel.0000000000000001",
  "payload": {
    "type": "cancel",
    "data": {
      "target_request_id": "request.health.123"
    }
  }
}
```

The Cancel request ID and target request ID must both satisfy the shared ID
grammar and must differ. `operation_id` remains a Rust controller, UI, and
redacted-diagnostic identifier; it is not a sidecar cancellation target.

A successful control response is typed rather than a generic acknowledgement:

```json
{
  "protocol_version": 2,
  "request_id": "cancel.0000000000000001",
  "result": {
    "Ok": {
      "type": "cancel_accepted",
      "data": {
        "target_request_id": "request.health.123"
      }
    }
  }
}
```

`cancel_accepted` means only that cancellation won the ordering race and the
matching operation context was signalled. It does not mean the operation has
joined or cleanup is complete.

## Locked concurrency state machine

```text
Idle
  -> Active(target_request_id)
  -> Cancelling(target_request_id, cancel_request_id)
  -> Idle
```

- There is at most one active primary request.
- The initial v2 control exception applies only to `connect_transport` and
  `sample_health`.
- While either request is active, the only accepted additional frame is one
  Cancel whose `target_request_id` exactly equals the active primary request
  ID.
- A second Cancel, mismatched or stale target, third frame, `disconnect`,
  `disconnect_transport`, status request, health request, or any other primary
  request during the active/cancelling state is a protocol violation. It must
  not be treated as cancellation and makes the session unusable.
- Disconnect and fallback sequencing is always: accept and fully drain Cancel,
  return to Idle, then send the ordinary disconnect request. Go never queues a
  future disconnect behind an active operation.
- EOF, parent death, malformed input, and process teardown remain independent
  strong cleanup signals and may cancel any active backend work.

## Linearization and response draining

Exactly one of these outcomes is valid:

1. Cancel wins.
   - Go precisely matches the active target, moves to Cancelling, signals that
     request's context, and returns `cancel_accepted`.
   - The primary request returns an `operation_cancelled` error without a
     persistent health error.
   - The two responses may arrive in either order. Rust validates and drains
     both exact IDs and payloads before declaring clean cancellation or reusing
     the stream.
2. Completion wins.
   - The validated primary response remains authoritative.
   - An exact Cancel already in transit receives a typed
     `invalid_state_transition` too-late response.
   - Rust drains both responses and returns the primary result; it does not
     relabel completed work as cancelled.

A cancelled connect returns to a prepared tunnel with no active transport. A
cancelled health probe preserves its existing tunnel and carrier and does not
set a permanent `last_error`. Cancel never changes profile, utun ownership,
routes, or the next operation. A cancellation flag with no matching active
controller operation must not contaminate a future Connect.

## Timeout, failure, and lifecycle rules

- A normal request timeout retains the v1 fail-stop rule: terminate and reap
  the exact child because the stream is ambiguous.
- After Rust flushes Cancel, a separate bounded drain deadline begins. It is
  not the nearly exhausted remainder of the primary request deadline.
- Clean cancellation requires both the typed `cancel_accepted` response and
  the matching primary `operation_cancelled` response.
- A missing, duplicate, malformed, wrong-version, wrong-ID, wrong-payload, or
  unsolicited response; an accepted Cancel followed by primary success; or a
  drain timeout terminates and reaps the exact child. The runtime returns a
  fatal sidecar error and the controller must leave `Running`; it must not
  report clean `OperationCancelled` while referring to a dead child.
- The Go reader-to-owner and operation-to-owner channel sends are
  context-aware. Every exit path cancels and boundedly joins active work before
  closing the backend. A writer error, parent cancellation, EOF, or invalid
  frame cannot leave a goroutine blocked on an abandoned channel.
- Rust remains the only fallback selector. Go cancellation cannot select or
  pre-connect QUIC, WSS, or TCP.

## Required implementation and test gate

The v2 change is one atomic merge unit across Rust, Go, fixtures, tests, trust
hashes, and documentation. It is not complete until all of these pass:

- shared v2 bootstrap, HMAC, status, health, Cancel, cancel-wins, and
  completion-wins fixtures in Rust and Go;
- v1/v2 mismatch refusal before any backend call;
- connect and health cancellation-wins plus completion-wins;
- both allowed response orders;
- mismatched target, duplicate Cancel, third frame, concurrent disconnect,
  unknown field/version, truncated/oversized input, and unsolicited response;
- each missing-response direction and a backend that ignores cancellation,
  proving bounded exact-child kill/reap and fatal controller lifecycle;
- cancelled Connect followed by WSS and TCP use, and cancelled Health followed
  by continued use of the existing carrier;
- actual Go child QUIC-blackhole and health-blackhole cancellation;
- EOF, parent death, repeated cancellation, goroutine/FD cleanup, Go race, Rust
  all-feature tests, Clippy, formatting, and shared-fixture parity.

No production endpoint, credential, route, release, or external infrastructure
is authorized by this protocol review.
