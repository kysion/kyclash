# KyClash route-helper Mihomo interface ownership amendment

Status: approved and locked for S1.12/S1.13 implementation

Date: 2026-07-22

## Authority and scope

This is a narrow amendment to
`kyclash-route-helper-contract-review-20260721.md`. It authorizes the
less-specific covering-route exception that the locked networking architecture
allows for an active Mihomo TUN. It does not change the helper identity,
SMAppService registration, code requirement, XPC selector set, DNS scope,
default-route policy, single-site boundary, or production-infrastructure
authorization boundary.

The existing v1 helper remains the safe implementation until every v2 field,
source, and disposable-VM gate below passes. A historical broad-route probe is
not acceptance evidence.

## Decision

Use a new route-helper protocol version 2. Do not add the new ownership
exception as an optional v1 field and do not silently downgrade when an old
helper is installed. The fixed XPC methods remain:

`discover`, `begin`, `apply`, `rollback`, `recover`, `heartbeat`, and `status`.

The active Mihomo value is a typed foreign-owner allowlist, not KyClash route
ownership. The helper may use it only to classify an existing route; it never
deletes or claims a route through a Mihomo interface.

## v2 wire and journal contract

`RouteLeaseOwner`/`LeaseOwner` adds the following required field:

```text
active_mihomo_tun_interfaces: string[]  // canonical, 0 or 1 item
```

The array is always encoded, including when empty. Its canonical order is
lexicographic, duplicates are rejected, and its maximum cardinality is one for
the macOS single-Mihomo scope. Every item must be an existing-shape
`utun` followed by ASCII decimal digits and fit the Darwin interface-name
bound. A trusted Mihomo name equal to KyClash's owned tunnel name is invalid.
No `utun*` pattern, route gateway, PID supplied by the caller, or interface
name observed only after the fact implies trust.

The v2 owner also carries the complete tunnel family facts already present in
Rust (`has_ipv4` and `has_ipv6`); the current Objective-C/Swift bridge must not
silently drop them. CIDR families must be supported by the corresponding
tunnel fact. Integer fields are bounded before conversion (`profile_revision`
must fit the signed coding representation); negative or out-of-range
NSSecureCoding values fail closed.

`HelperReply` and the C `NativeReply` include `protocol_version`. Discovery and
every subsequent reply must report exactly v2. A missing, unknown, or mismatched
version returns `UnsupportedProtocolVersion`; there is no v1 fallback.

The durable journal becomes version 2. `JournalOwner` records the protocol
version, the frozen active-Mihomo list, complete tunnel family facts, and the
existing lease/operation/sidecar/interface/revision/CIDR tuple. The list is
frozen for the lease and is compared exactly on recovery.

The existing `route-lease-v1.plist` path is retained during migration. A v2
helper may decode a v1 journal only for startup rollback using the old exact
owner rules; it must never continue a v1 begin/recover/apply transaction. A
successful rollback removes the journal. A failed or ambiguous rollback leaves
the journal and reports `recovery_required`. New transactions always write v2.

## Rust production source of trust

Add a typed `ActiveMihomoTunSource` and `MihomoTunSnapshot` in the production
networking boundary (with a macOS implementation and injected test source).
`ProductionNetworkingService` samples it after the encrypted carrier health
gate and immediately before XPC `begin`; a source failure prevents journal
creation and route mutation.

The macOS implementation must obtain the live value from the managed Mihomo
control API (`Handle::mihomo().await.get_base_config()`), not from an
untrusted YAML guess. It must verify:

1. KyClash's `CoreManager` is running and the local Mihomo control endpoint
   answers successfully.
2. The live `tun.enable` state agrees with KyClash's TUN state.
3. When TUN is disabled or the core is stopped, the snapshot is empty.
4. When TUN is enabled, `tun.device` is a non-empty canonical macOS `utunN`,
   `if_nametoindex` confirms that the interface currently exists, and it is
   different from KyClash's sidecar-created interface.
5. An empty, `Mihomo`/Linux-style, malformed, missing, or inconsistent device
   fails closed; the implementation never selects an arbitrary `utunN`.

The live snapshot is passed as a typed value to the route boundary. The current
`XpcProductionRouteBoundary` has no application call site, so production setup
must inject this source when constructing the networking service; unit fakes
alone do not satisfy this amendment.

## Conflict and mutation semantics

For each desired private CIDR, the helper reads the normalized route table and
uses the exact `Netif` column:

- Existing `/0` routes retain the current underlay exception.
- An overlapping existing route with a shorter prefix (a covering,
  less-specific route) is allowed only when its exact interface is in the
  frozen active-Mihomo list.
- An exact-prefix route, a more-specific route, or any overlap through an
  unknown/other interface is `route_conflict`, including an interface whose
  name merely resembles `utun`.
- A permitted Mihomo covering route plus any other foreign overlap still
  rejects the transaction.
- IPv4 and IPv6 use the same rules. Desired CIDRs remain non-default,
  canonical, unique, and pairwise disjoint.

`begin` and `apply` preflight with the same frozen list. Postflight requires an
exact KyClash route on the owned interface and no unpermitted overlap.
Rollback rechecks ownership immediately before each delete, deletes only the
exact KyClash route, and never removes a Mihomo or unknown-VPN route. If the
interface observation is unavailable, ownership is ambiguous, or a journal
write/delete has an uncertain result, the journal remains durable and the
helper reports recovery required instead of declaring success.

## Exact implementation files

- `src-tauri/src/networking/route_helper.rs`: v2 constants, typed field,
  family/interface/revision validation, and serde tests.
- `src-tauri/src/networking/route_helper_client.rs`: v2 FFI arguments,
  protocol-reply mapping, typed snapshot injection, and cleanup on every
  begin/apply error.
- `src-tauri/src/networking/production_service.rs`: observation ordering and
  no-route-on-source-failure path.
- `src-tauri/src/networking/mod.rs`, `src-tauri/src/lib.rs`, and the relevant
  core setup module: export the source, inject it only under the production
  feature, and construct the real service instead of leaving the current
  `XpcProductionRouteBoundary` unreferenced.
- A new production source module under `src-tauri/src/networking/` (and its
  macOS app/core adapter): live Mihomo API and interface existence checks.
- `macos/route-helper/main.swift`: v2 `LeaseOwner`, `JournalOwner`, reply
  version, strict decoder, route classification, migration, and self-tests.
- `macos/route-helper/client.m`: matching secure-coding fields, required
  array/family facts, reply version, and C bridge signature.
- `macos/route-helper/lab-client.m`, `src-tauri/build.rs`, and the macOS CI
  workflow: v2 compile and isolated matrix fixtures.

The plist, Mach service, designated requirement, and authentication boundary
remain unchanged. No shell command, path, environment, DNS value, secret, or
generic dictionary is added to XPC.

## Required tests and acceptance evidence

### Cross-language and pure tests

- Rust rejects missing/unknown/malformed fields, duplicate or multiple
  Mihomo interfaces, own-interface collisions, unsupported CIDR families,
  noncanonical interface names, and integer bounds; reply-version mismatches
  fail closed.
- The source fake/live adapter covers inactive/stopped, active valid, missing
  device, API failure, state mismatch, nonexistent interface, and device
  collision cases.
- Production ordering proves `health -> Mihomo observation -> route begin/apply`
  and proves source failure performs no route mutation.
- Swift self-tests cover v4/v6 trusted covering routes, exact and
  more-specific trusted routes, unknown-VPN broad routes, default routes,
  mixed trusted/foreign overlap, journal v1 rollback-only migration, duplicate
  requests, invalidation, lease expiry, and ambiguous cleanup.
- Objective-C bridge compilation uses warnings-as-errors and exercises both
  empty and one-item arrays plus v2 reply decoding.

### Disposable macOS VM gate

Using the signed packaged helper and packaged Mihomo only:

1. Start Mihomo with an explicit macOS TUN device and record the live API
   device observation without retaining credentials.
2. Prove IPv4/IPv6 less-specific Mihomo covering routes coexist while KyClash
   installs and removes only its own exact routes.
3. Prove the same covering routes are refused when the list is empty, wrong,
   or owned by an unknown VPN; exact and more-specific routes are refused even
   for the trusted Mihomo interface.
4. Exercise Mihomo stop/restart, KyClash sidecar/app/helper termination,
   XPC invalidation, heartbeat expiry, helper restart, journal corruption,
   guest reboot, and retry. Assert no foreign route is deleted and no KyClash
   route, journal, lease, or utun remains after cleanup.
5. Keep all route mutations inside the authorized disposable VM. Do not touch
   production PVE, ROS, K3s, host routes, DNS, releases, or external
   endpoints.

## Risks and boundaries

- An interface name can theoretically be reused between observation and lease
  cleanup. The minimum mitigation is just-in-time live observation,
  `if_nametoindex`, a frozen one-lease list, and preserving the journal on any
  ambiguous ownership result. If the threat model requires kernel creation
  tokens or PID/signature attestation, that is a separately reviewed v3
  amendment, not an inferred v2 shortcut.
- The existing helper identifies an exact route primarily by destination and
  interface name. The VM must include sidecar-close/name-reuse evidence before
  this is treated as release-grade; absence of a current interface must never
  authorize deletion.
- The Rust `RouteConflictPolicy` is a policy mirror, not the privileged
  mutator. Swift packaged-helper behavior is the acceptance authority, and
  both implementations must share the matrix.
- A v2 helper/client mismatch is an upgrade state, not a reason to weaken the
  protocol. Re-registration/restart may be required in the disposable VM.
- Notarization, App Store Connect credentials, GitHub Release publication,
  production endpoints, and physical sleep/network-switch testing remain
  outside this amendment and are not current hard blockers for internal
  Developer ID-signed testing.

## Lock record

Parent review completed on 2026-07-22. This record is locked for implementation
under the single S1 delivery stage. The v1 candidate remains the fallback
artifact until the complete v2 wire, journal, live-source, and disposable-VM
gates pass; locking this design does not authorize production routes, DNS,
release publication, or a v1 compatibility downgrade.
