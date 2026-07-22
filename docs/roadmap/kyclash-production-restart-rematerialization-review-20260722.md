# KyClash production restart and rematerialization review

Status: approved and locked; policy-store publication amendment re-reviewed and
re-locked on 2026-07-22

Date: 2026-07-22

Amends:

- `kyclash-production-networking-review-20260721.md`
- `kyclash-route-helper-contract-review-20260721.md`
- `kyclash-production-networking-single-stage-review-20260721.md`

## Scope

This review closes two restart defects found while preparing the S1.13 exact
production VM matrix:

1. a previously accepted, still-valid policy resource is rejected when the
   same signed App initializes again because the durable store remembers only
   its revision; and
2. a route-helper interruption leaves Rust holding the invalid native XPC
   client, while the command layer can retain a terminal service indefinitely.

The change does not weaken policy freshness, add XPC retry of ambiguous route
mutations, change helper authority, or authorize production infrastructure.

## Policy identity decision

The replay store becomes an identity store. Its v2 record contains only:

```json
{
  "schema_version": 2,
  "revision": 42,
  "envelope_sha256": "<64 lowercase hexadecimal characters>",
  "key_id": "policy.production"
}
```

`envelope_sha256` is SHA-256 over the exact signed-envelope resource bytes
read through the existing owned-resource boundary. It is not a digest of a
reserialized payload or profile. The store never contains the profile,
endpoint credentials, private keys, Keychain material, signature bytes, or
decoded WireGuard key material.

The current split `latest()`/`store()` API and its staged pending revision are
removed. They cannot express an idempotent no-write result and have a
cross-process check/commit race. The replacement is one identity-store
transaction with explicit `new`, `advance`, `idempotent`, and `reject`
decisions.

On a clean install the fixed `networking` leaf may not exist. The transaction
first opens and pins the existing platform-resolved App-data directory with
`O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC` and validates directory type,
effective-user ownership, and refusal of group/world writes. It creates only
the literal `networking` child using `mkdirat(..., 0700)`. `EEXIST` is accepted
only after `openat(O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)` and `fstat` prove the
same safe leaf; a symlink, non-directory, wrong owner, or group/world-writable
leaf fails closed. A successful creation is followed by `fsync` of the pinned
App-data descriptor. There is no path-based `create_dir_all` and no recursive
creation of an untrusted ancestor.

The transaction then pins the revision-store parent leaf's device and inode.
Every lock, record, temporary, rename, and directory-sync operation is
descriptor-relative (`openat`, `renameat`, `fsync`) through that one leaf
descriptor. The path is re-opened relative to the pinned App-data
descriptor and compared to the pinned device/inode before classification and
before reporting commit, so parent replacement fails closed rather than
creating a second lock domain.

The transaction owns a persistent adjacent lock file opened relative to that
directory with `O_NOFOLLOW | O_CLOEXEC | O_CREAT | O_RDWR` and requested mode
`0600`, then uses `fstat` to require a regular file owned by the effective user,
link count one, and effective mode exactly `0600`. Lock acquisition is exclusive
and bounded. A stale unlocked file is harmless; a symlink, directory, hard
link, wrong owner/mode, open error, parent replacement, or lock deadline fails
closed. The lock is held from the first durable snapshot read through every
composition check and final commit or rejection.

An envelope is authenticated and accepted inside that transaction:

1. read and retain the exact raw durable-store snapshot while holding the
   exclusive lock;
2. strictly decode the v2 envelope, validate its key ID and algorithm, locate
   the pinned public key, and verify the Ed25519 signature;
3. strictly decode and validate the signed payload, including nonzero revision,
   issued-at/expiry boundaries, and the complete network profile;
4. calculate the exact-envelope digest and classify the candidate identity
   against the locked snapshot;
5. validate every remaining immutable composition input, including the sidecar
   trust manifest and final verified factory configuration; and
6. obtain the commit clock and recheck `issued_at <= now < expires_at`; then
   reread the exact durable-store bytes under the same lock. Any change from
   the retained snapshot is an uncooperative writer, corruption, or replacement
   and rejects the transaction. Otherwise, commit the classified result.

Owned reads are bounded before allocation and again while reading: the policy
envelope and policy trust bundle are each at most 64 KiB, the sidecar trust
manifest is at most 16 KiB, and either durable revision-record version is at
most 4 KiB. Empty, oversized, short/changed-during-read, or non-regular inputs
fail closed. These are independent from the stdio record ceiling.

The replay decision is exact:

- no record: accept the valid candidate and write a v2 record;
- candidate revision greater than the stored revision: accept and replace with
  the candidate v2 identity;
- candidate revision equal to a v2 record: accept only when revision,
  lowercase digest, and key ID all match exactly; classify this as idempotent
  and do not create, truncate, rename, chmod, or otherwise rewrite the record;
- candidate revision lower than the stored revision: reject;
- equal revision with different bytes, digest, or key ID: reject;
- malformed, unknown-version, symlinked, unreadable, or non-regular store:
  reject without mutation.

Idempotent acceptance does not bypass time validity. The exact resource is
rejected after its signed expiry even when its identity matches the store.
Changing JSON whitespace or field order produces a different exact-envelope
identity and is rejected at the same revision. A publisher must use a higher
revision for any byte change.

### v1 revision-record migration

The existing `{schema_version: 1, revision}` record is read only as a legacy
revision floor. Because it has no digest or key ID, equality cannot be proven:

- the same or a lower candidate revision is rejected;
- a valid higher revision is accepted and atomically replaces it with a v2
  identity record; and
- v1 is never rewritten merely by reading or by a rejected candidate.

### Publication, rollback, and retained private records

For `new`, `advance`, or legacy migration, the store creates a randomized
create-new name under the pinned `networking` descriptor. The name includes
128 bits of system entropy and is opened with `O_EXCL | O_NOFOLLOW`; the file
must be an effective-user-owned, single-link regular file with mode exactly
`0600`. KyClash writes only the bounded strict v2 identity record, syncs the
descriptor, and reopens the name to prove its inode and exact bytes immediately
before publication.

A `new` publication uses the descriptor-relative no-replace rename primitive.
It cannot overwrite an entry that appeared at the fixed active-record name. An
`advance` or v1 migration uses the descriptor-relative atomic exchange
primitive: the candidate becomes `policy-revision.json` and the exact previous
active inode becomes a retired record at the randomized temporary name. The
complete retained snapshot, including ctime, is compared immediately before
publication. Because the exchange itself legitimately changes the old inode's
ctime, post-exchange proof deliberately compares only its stable identity
fields (device, inode, length, and mtime), private-file shape, and exact retained
bytes; ctime equality after an exchange is neither expected nor accepted as an
integrity requirement. Before the transaction can report success, it also
proves the active name still refers to the exact candidate inode and bytes,
syncs the pinned directory, then repeats active-record and attachment checks.

`policy-revision.json` is the sole authoritative identity input. A retained
temporary orphan, an exchanged retired record, or a rollback quarantine is
never enumerated, parsed, promoted, or used as a revision floor. Normal
content-bearing store-created orphans and retired records are randomized,
effective-user-owned, single-link `0600` regular files of at most 4 KiB. A
create/permission failure may retain only an unwritten randomly named entry
created with requested mode `0600`; no application data is written until exact
private-file validation passes. A quarantine produced after detected pathname
substitution is untrusted, may contain attacker-controlled content, and is not
treated as a private regular record. KyClash never writes a profile, endpoint
credential, private key, Keychain value, signature bytes, decoded WireGuard
key, or any other secret to any of these files; its own retained files contain
identity metadata only.

If either immediate post-publication proof fails, rollback is conservative:

- after an exchange, it attempts one atomic exchange back, syncs the directory,
  and accepts rollback only after the prior active file's stable identity
  fields, private-file shape, and exact bytes are again proven at the active
  name. The rollback exchange also legitimately changes ctime, so rollback does
  not compare it to the pre-exchange ctime;
- after a fresh publication, it moves the suspect active entry to a new
  no-replace randomized quarantine name, syncs the directory, and accepts
  rollback only after the active name is proven absent; and
- any exchange, quarantine, sync, or proof failure leaves the outcome
  unresolved and returns a fail-closed error. It never reports the candidate as
  committed and never guesses which pathname is safe to delete.

Once the immediate candidate and retired-record proofs succeed, a later
directory-sync, attachment, or final active-record report-boundary failure also
returns an error without a blind compensating rename or unlink. The next
transaction must reacquire the named lock and classify a fresh authoritative
active-record snapshot; the failed attempt itself conveys no acceptance. This
permits recovery from an uncertain durability result without risking deletion
or replacement of an entry that changed after the last proof.

The transaction intentionally performs no orphan or retired-record cleanup.
Portable POSIX APIs provide no operation that both compares a pathname to a
previously verified inode and unlinks that same object atomically. An
`fstat`/`unlinkat` sequence would reintroduce a same-UID pathname-substitution
race and could delete an entry the transaction did not create. Retaining the
randomized ignored record is therefore the fail-closed choice. Any retention
limit or cleanup procedure is a separately reviewed maintenance design; it
must use an OS-specific descriptor-safe deletion proof and must not run inside
the identity transaction.

The locked threat boundary is explicit. The private directory, descriptor
pinning, exact snapshots, advisory lock, no-replace/exchange publication,
post-publication verification, and proven rollback detect corruption and
uncooperative same-UID changes at their defined checkpoints. POSIX advisory
locking cannot exclude a malicious process already running as the same
effective UID, and there is no claim of uninterrupted protection against that
process replacing a name between adjacent syscalls. Compromise of the user
account or arbitrary same-UID code execution is outside this store's security
boundary. The implementation must nevertheless fail closed whenever a
checkpoint observes replacement and must not weaken any check on the theory
that the same-UID case is out of scope.

Tests must also prove that a failed manifest/composition step or commit-time
snapshot change does not advance or migrate the durable identity.

## XPC client rematerialization decision

An XPC transport failure is not permission to replay `begin`, `apply`,
`rollback`, `heartbeat`, or any other ambiguous request on a new connection.
The current operation fails with its original typed error. Recovery is a
separate reconciliation session:

1. mark the current native client generation terminal;
2. invalidate and destroy exactly that client;
3. construct a fresh privileged `NSXPCConnection` with the same immutable Mach
   service name, protocol interface, timeout, and code-signing requirements;
4. on that one fresh generation, run only a bounded, read-only `discover`
   reconciliation loop with one total deadline and bounded backoff;
5. retry only the helper's typed transient `not_ready` response. A transport
   error terminates the fresh generation and is never recursively
   rematerialized; and
6. accept `idle` only when the helper certifies the connection barrier below,
   then clear the frozen Rust owner/reference. Retain them and fail closed for
   a deadline, transport error, unsupported protocol, corrupt or
   recovery-required journal, or any other state.

"At most once" means one client replacement and one reconciliation session per
failed native generation; it does not mean one `discover` RPC. The session
never calls `recover` across XPC connection identities: a lease is owned by one
concrete helper connection, and invalidation must roll it back. Within an
otherwise live connection, the existing exact-owner `recover` contract remains
available for an ambiguous reply.

The same bounded, same-generation, read-only `discover` loop is also the only
initial discovery path for `XpcProductionRouteBoundary::connect()`. A freshly
built service may overlap asynchronous unregister of an explicitly retired old
client and therefore may observe typed `not_ready` before authoritative
`idle`. Initial discovery never creates another connection recursively and
fails closed on its total deadline or any non-transient result.

### Authoritative helper connection barrier

Read-only polling alone is insufficient. A new connection could otherwise see
an empty journal before an already accepted old connection executes a queued
`begin`. The Swift helper therefore registers every accepted XPC connection ID
with `RouteCoordinator` before the connection is resumed. Registration, every
coordinator operation, invalidation, owned rollback, and unregister execute
under the coordinator's one state lock.

Every helper method first proves its connection ID is still registered, so a
message delivered after unregister cannot mutate state. `discover(connectionID)`
may return authoritative `idle` only when the caller is the sole registered
live connection, all older accepted connections have entered invalidation, any
owned rollback has completed successfully, and the journal is absent. While an
older connection is live or its invalidation/rollback barrier is incomplete it
returns typed `not_ready`. A failed rollback retains its journal and returns
the existing fail-closed recovery error; it never becomes idle merely because
the connection was removed.

The Objective-C bridge uses a heap-owned first-wins state for every request and
a separate live/terminal state for the client generation. A valid, correctly
correlated protocol reply completes only its own waiter and leaves the
generation live. A remote proxy error, request timeout, interruption,
invalidation, or invalid-protocol reply atomically changes the generation from
live to terminal; that winner fails and wakes every still-pending waiter exactly
once. A reply racing a terminal event may win only its own waiter before the
generation transition; every callback arriving after its waiter completed or
the generation became terminal is a no-op. Normal replies never fan out and
never kill the connection.

Transport status distinguishes at least timeout, remote failure, interruption,
invalidation, and protocol failure so Rust cannot treat them as a retriable
helper reply. A terminal generation rejects new requests. All native-client
replacement occurs under the Rust route-boundary serialization; no raw pointer
or callback from an old generation may be used after replacement.

If reconciliation discovers authoritative `idle`, cleanup may treat the route
lease as absent and continue carrier, tunnel, and sidecar teardown. It still
returns the original helper failure for the failed operation. A reconciliation
or cleanup error is recorded separately as a secondary redacted diagnostic and
never overwrites the primary failure. Any unresolved secondary error keeps the
frozen ownership and prevents retirement. A later, newly identified Connect
operation may reuse a successfully reconciled boundary; the failed operation
itself is never resumed.

## Terminal service rematerialization decision

The service exposes an observational generation-bound disposition: `busy`,
`reusable`, `terminal_candidate`, or `recovery_only`. Observing
`terminal_candidate` never authorizes replacement. The only authority is an
atomic, generation-checked `try_retire` operation under the service's one
mutation lock.

The internal gate states are Open, Retiring, RecoveryOnly, and Retired.
`try_retire` first changes Open to Retiring while holding the lock, then proves
there is no issued-but-unconsumed reservation, in-flight mutation, queued
lifecycle owner, or resource below. An outstanding reservation or legitimate
in-flight/queued owner returns the gate to Open and reports Busy. A service that
is fully reusable returns Open/Reusable. An unresolved terminal resource or
missing absence proof enters RecoveryOnly, never Retired. If every retirement
fact passes, `try_retire` explicitly terminalizes,
invalidates, and destroys the otherwise route-idle native client, changes
Retiring to permanently Retired, and returns an exact receipt that already
proves the mutation gate and native client are closed. The command layer may
replace a materialized service only with that receipt. Required positive facts
are:

- no active production operation and no queued lifecycle owner;
- no route heartbeat task;
- no native XPC waiter, detached blocking route call, or unjoined lifecycle
  task;
- the route boundary has destroyed its native generation, every callback is
  drained or inert, and an old service `Arc` can retain only an inert local
  boundary rather than a registered helper connection;
- route ownership is authoritatively absent, including a successful fresh-XPC
  `idle` reconciliation when the old client failed;
- the controller has stopped and reaped the exact sidecar child and publishes
  an exact-generation absence receipt. A timeout, CrashLoop label, closed
  command channel, or nominal terminal state without positive reap evidence is
  insufficient. Exact child reap (or a receipt that the generation never
  spawned) is the proof that child-owned utun and carrier descriptors have been
  closed;
- status is not Connecting, Reconnecting, Connected, Disconnecting, or any
  other live state; and
- no tunnel or carrier is claimed by the service.

Selection cannot return a bare service and reserve Connect later. While holding
the materialization mutex, `ProductionCommandState` asks the exact service
generation for one atomic `prepare_connect_or_retire` decision under its
mutation lock. A reusable open generation issues and counts a generation-bound
Connect reservation before the command releases the mutex. A terminal candidate
runs `try_retire` and returns only its already-closed receipt. Busy and
RecoveryOnly generations reject Connect.

An issued reservation makes retirement busy and cannot be revoked by a later
retirement attempt. It is consumed exactly once by the spawned operation or is
explicitly abandoned/dropped, under the same generation lock, if spawning
fails. Only after every issued reservation is consumed or abandoned may a
later call retire the service. Once Retired, every old `Arc` and every new
connect, cancel, or disconnect attempt is rejected and cannot reopen state.

RecoveryOnly rejects Connect, replacement, retirement, and every new owner or
operation. It accepts only a generation-bound recovery lease naming the exact
frozen generation, route owner/reference, and failed lifecycle operation. That
lease may retry only the bounded reconcile, rollback, sidecar shutdown/reap,
native waiter drain, and heartbeat/task join steps that were unresolved. A
successful retry proves absence and transitions to Open plus either
Disconnected/Reusable or TerminalCandidate; a failed retry retains the same
frozen lease and remains RecoveryOnly. A mismatched owner, new operation ID,
stale generation, or broader Disconnect request is rejected before mutation.
Only Retired permanently rejects every mutation.

The command state returns a reusable reserved service unchanged. For an exact
closed-gate retirement receipt it compare-removes only the same `Arc` and
generation, then builds the replacement completely off-slot. While still
holding the materialization mutex it obtains one Connect reservation from that
unpublished service, then compare-installs the service/reservation generation
into the still-empty replacement transaction. Publication is the last step;
status, list, and diagnostics can never clone an unreserved candidate.

Any build, reserve, or install-CAS failure explicitly abandons the reservation
and performs bounded close of the never-published service, proving native
client, controller, child, waiter, route, carrier, and tunnel absence before
return. The live slot remains empty; a later Connect may retry, and the retired
service is never restored. Only after successful install does the command
release the mutex and spawn the reserved operation. Two concurrent Connect
calls produce at most one replacement and one accepted reservation. Ordinary
Disconnect and Cancel pass through the same service generation/mutation gate;
RecoveryOnly exposes only its exact recovery lease path. Status, site listing,
and diagnostics are read-only and do not materialize or reserve anything.

The command state retains a bounded, redacted retired-generation diagnostic
record containing generation, primary error, optional secondary error, and
absence-receipt outcome. Replacement or a failed rebuild cannot erase the
evidence merely because the old service leaves the live slot.

A service that cannot prove the retireable receipt remains installed and fails
closed. Neither a status value alone nor a generic `last_error` is enough to
discard a service that may still own routes, a child, or a tunnel. The UI/status
invariant is exact: `Disconnected` means no owned route, heartbeat, child,
carrier, tunnel, or active mutation remains and Connect is safe; it may retain
the primary `last_error`. `Error` means cleanup or ownership is unresolved:
Connect remains disabled but the UI exposes the exact same-generation cleanup
retry as Disconnect. This makes a clean retireable failure reachable without
converting an unsafe terminal state into a new connection attempt.

Policy initialization and service rematerialization are separate. Rebuilding
a service uses the immutable verified factory and does not delete the replay
store, mutate the signed policy resource, regenerate a policy revision, or
reread a client private key outside its fixed Keychain reference.

## Required tests before lock can close implementation

### Policy tests

- fresh v2 identity write and exact same bytes accepted by a newly constructed
  file-store instance;
- exact same identity accepted concurrently through the command initialization
  single-flight without a second write;
- two independent processes interleaving revisions 42 and 43 under barriers
  prove that the lower candidate cannot overwrite the higher record and that a
  same-revision byte mismatch cannot win;
- an uncooperative raw-record replacement between initial read and commit is
  detected by the locked snapshot reread and leaves the replacement untouched;
- commit-time deletion, truncation, corruption, and expiry fail closed;
- exact idempotent initialization leaves record bytes, inode, and mtime
  unchanged;
- equal revision with changed whitespace/order, key ID, payload, or signature
  rejected as appropriate;
- lower revision rejected and higher valid revision accepted;
- exact identity rejected at expiry;
- legacy v1 equal/lower rejection and higher-revision migration;
- corrupt, unknown, symlinked, hard-linked, wrong-owner/mode, directory,
  permission-failed, lock-timeout, interrupted write, rename, and parent-sync
  failures fail closed;
- fresh publication refuses an occupied active name, while advance and v1
  migration atomically exchange the exact candidate and prior inode; tests
  prove the complete snapshot immediately before exchange, then prove the
  active candidate plus the retired record's stable device, inode, length,
  mtime, private-file shape, and exact bytes after exchange without requiring
  unchanged ctime;
- pre-publication write/sync/rename faults may retain one randomized private
  orphan, and a successful advance may retain its exact prior record under the
  randomized retired name; neither class is consulted by a later transaction;
- injected substitution immediately before publication and immediately after
  the last pre-publication proof is detected. Fresh rollback proves the active
  name absent, while advance rollback proves the prior active file's stable
  identity, private-file shape, and exact bytes without requiring its ctime to
  equal the pre-exchange value. An unprovable rollback returns an error without
  claiming commit success;
- no transaction fault path opportunistically unlinks a pathname after a
  separate identity check. Retained content-bearing store-created records
  remain bounded, single-link, `0600`, identity-only metadata, and diagnostics
  do not disclose their contents;
- parent-directory swap cannot create a second lock domain or redirect any
  record, temporary, rename, or directory-sync operation away from the pinned
  directory descriptor;
- clean-install creation of the absent `networking` leaf succeeds with mode
  `0700` and ancestor sync; symlink, `EEXIST` non-directory, unsafe owner/mode,
  `mkdirat`, open, and ancestor-sync faults fail closed;
- policy/trust/manifest/record empty, oversize, and changed-during-read cases
  fail before acceptance;
- process termination while holding the lock releases the kernel lock without
  corrupting or advancing the record;
- malformed sidecar manifest or failed composition leaves both v1 and v2 store
  bytes unchanged; and
- no record or diagnostic contains profile or secret material.

### XPC and service tests

- unit-injected reply/error/timeout/interruption/invalidation races release all
  waiters exactly once, distinguish the winning terminal status, and refuse
  late replies and requests on the dead generation;
- an invalid protocol reply terminalizes its client generation;
- no mutating request is replayed after an ambiguous native failure;
- a new connection cannot report idle before an accepted old connection's late
  `begin`; unregister makes every later old-connection method fail before
  mutation;
- active helper lease plus client invalidation rolls back exact IPv4/IPv6
  routes and removes the journal;
- within one live helper process, old-connection invalidation causes the fresh
  connection to observe typed `not_ready` until the coordinator barrier and
  owned rollback complete, then authoritative `idle` on that same fresh
  generation;
- helper process kill/relaunch performs synchronous startup journal recovery
  before listening, so its first successful `discover` is authoritative `idle`;
  recovery failure returns the exact fail-closed error and never transient
  idle;
- discovery transport failure, non-idle state, corrupt/recovery-required
  journal, total deadline, and fresh-generation failure retain frozen ownership
  and fail closed without recursive rematerialization;
- same service can accept a new operation after successful boundary
  reconciliation when its controller is reusable;
- a terminal controller without an exact child-reaped absence receipt cannot
  be replaced, including stop-timeout and CrashLoop cases;
- first rollback/stop/reap failure enters RecoveryOnly, rejects Connect and a
  mismatched owner/new operation, then permits the exact same-generation
  cleanup lease to reach absence and Disconnected;
- an exact retireable receipt causes exact-generation service replacement,
  while a live or ambiguously owned service cannot be replaced;
- an old Arc selected before retirement but delayed until after replacement
  cannot spawn, cancel, disconnect, or otherwise mutate;
- a deliberately retained retired old `Arc` has no live native client or
  helper registration, and its read-only status/diagnostics remain local;
- replacement initial discovery may observe `not_ready` while the old helper
  registration drains, then reaches authoritative `idle` on the same native
  generation and completes the build;
- disconnect and cancel racing replacement either reserve the exact live
  generation or reject; neither can mutate the retired generation;
- two concurrent Connect commands create at most one replacement service and
  one accepted generation-bound reservation;
- replacement build failure leaves no service and a later Connect can retry;
- replacement reservation or install-CAS failure keeps the candidate
  unpublished, explicitly closes it, and remains invisible to concurrent
  status/list/diagnostic reads;
- replacement and rebuild failure preserve the bounded prior-generation error
  evidence;
- primary helper failure remains the command/status error while a distinct
  reconciliation or cleanup failure is also retained as a secondary diagnostic
  and blocks retirement;
- `Disconnected` always has final resource absence and remains retryable with a
  retained last error; unresolved ownership remains `Error` and UI Connect is
  disabled;
- status/list/diagnostics never rebuild a service;
- helper kill -> rollback -> new connection -> same fixed policy candidate ->
  successful reconnect and clean disconnect; and
- repeated helper kill/restart cycles have bounded threads, file descriptors,
  native handles, sidecar children, utun devices, journals, and routes.

The macOS integration cases run only in `kyclash-macos-lab-work`. Evidence must
identify `VirtualMac*`, the guest receipt and nested signatures, guest PIDs,
exact route/utun ownership, and final absence. The host may build and
orchestrate but must not install or launch KyClash or mutate host networking.

## Policy-store amendment re-lock record

On 2026-07-22 the policy-store portion of this review was reconciled against
the Unix implementation's success paths, every injected publication fault
boundary, freshness decision, secret lifetime, restart behavior, and realistic
POSIX same-effective-UID concurrency guarantees. The blocking documentation
defect was the earlier instruction to remove an "exact temporary path" after
failure: pathname identity cannot remain exact across a later `unlinkat`, so
that wording would have required an unsafe compare-then-delete race.

The corrected publication, retained-record, rollback, active-authority, and
threat-boundary rules above resolve that defect without weakening the signed
policy identity or revision floor. This amendment is approved and locked for
implementation. Locking the design does not mark its required tests complete,
does not authorize orphan cleanup, and does not broaden access to secrets,
production infrastructure, App Store distribution, or release publication.
Adding cleanup, promoting a retained file, changing the active record name, or
claiming protection from arbitrary same-UID code requires a new reviewed and
locked amendment.

## Out of scope

- no App Store publication;
- no GitHub Release or updater activation;
- no production endpoint, PVE, ROS, K3s, DNS, route, credential, or tunnel
  changes;
- no policy auto-refresh or signing-key distribution protocol; and
- no notarization requirement for the internal signed VM package.
