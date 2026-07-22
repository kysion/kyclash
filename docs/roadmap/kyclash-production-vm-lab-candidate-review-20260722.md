# KyClash production-feature disposable-VM candidate review

Status: design-approved and locked for disposable-VM construction; runtime acceptance pending

Final lock record (2026-07-22): the independent delivery recheck closed the
two previously identified boundary findings. Keychain creation is now an
atomic create-only operation with duplicate/foreign-item fail-closed handling,
and durable ownership requires both the `created=1` transition and the exact
public-key witness. The guest-to-host pull is restricted to the descriptor,
policy-revision preflight, and expiry-ceiling scalar, with same-session
VirtualMac proof, TOCTOU checks, and create-only host publication. The scoped
fixture uses only `net.kysion.kyclash.test`; ordinary production builds retain
the `.networking` service. A signed, unnotarized internal VM package remains
an allowed artifact; Apple notarization is a public-distribution enhancement,
not a prerequisite for this lab candidate.

This record has two deliberately separate approval layers. A **design lock**
fixes the marker, generator, verifier, guest guard, trust fixture, and command
contracts and then authorizes construction of a disposable-VM candidate. A
**runtime acceptance** is the later S1.13 evidence gate for the exact signed
App/PKG in `kyclash-macos-lab-work`. VM trust, install, launch, fallback,
reboot, and cleanup evidence cannot be claimed before execution, but their
absence does not create a circular requirement that prevents design lock and
therefore prevents the authorized execution that produces them.

Date: 2026-07-22

Parent authorities:

- `kyclash-plan-review-20260721.md`
- `kyclash-github-updater-review-20260721.md`
- `../architecture/kyclash-networking-v1.md`
- `../architecture/kyclash-network-runtime-v1.md`
- `kyclash-production-networking-work-program-20260721.md`
- `kyclash-production-restart-rematerialization-review-20260722.md`

## Scope

This review locks the build and trust fixture for the S1.13 exact
production-control-path run in the selected disposable
`kyclash-macos-lab-work` guest. The candidate must compile the default-off
`networking-production` feature, carry one short-lived signed loopback policy,
use the real production composition and macOS live-Mihomo source, and remain
unmistakably a disposable-VM lab artifact.

This record authorizes only the runtime acceptance sequence specified below in
the selected disposable work VM. It does not authorize a host launch, a
production or staging endpoint, a GitHub Release, updater activation,
production credentials, or external infrastructure mutation.

## Source findings

1. `production_composition.rs` reads fixed, app-owned resources at:

   - `Contents/Resources/resources/kyclash-networking-policy-keys.json`;
   - `Contents/Resources/resources/kyclash-networking-policy-v2.json`; and
   - the target-specific sidecar trust manifest.

   The first two files are intentionally absent from ordinary bundles, so an
   ordinary signed App fails closed during `initialize_networking`.

2. `tauri.networking.macos.conf.json` adds the signed sidecar, signed route
   helper, and helper plist, but neither enables the Rust production feature
   nor supplies a policy envelope or policy trust bundle.

3. The policy helpers and fixed Ed25519 seed in
   `production_composition.rs` are compiled only under `cfg(test)`. They are
   suitable for unit tests and must not become a packaged trust root, build
   script input, or reusable private fixture.

4. `tauri.conf.json` bundles the ordinary `src-tauri/resources` build-input
   directory. That directory is ignored by `src-tauri/.gitignore`, so Git
   status cannot detect contamination. Putting a disposable lab trust root
   there would make it easy for a later ordinary build to ship the lab root
   accidentally.

5. `scripts/verify-macos-package.mjs` currently proves the App, nested sidecar,
   helper, helper plist, target sidecar trust hash, PKG signature, and Team ID.
   It does not prove that the final App executable contains
   `networking-production`, does not authenticate the policy resources, and
   does not distinguish a lab candidate from an ordinary candidate.

These are release-composition gaps, not reasons to weaken the production
resource checks or reuse a development trust path.

## Locked decision

Use a separate, fail-closed `networking-production-vm-lab` candidate
profile with all of the following properties:

- runtime execution is allowed only in `kyclash-macos-lab-work` after an
  in-session `VirtualMac*` proof;
- carrier endpoints and the control-plane placeholder are numeric loopback IP
  literals; no DNS lookup or external endpoint is permitted;
- the App is compiled with `networking-production` and the ordinary production
  sidecar, Keychain, XPC route boundary, and `MacosActiveMihomoTunSource`;
- the lab policy key is generated afresh for one run, signs one bounded v2
  envelope, and is then destroyed without being serialized;
- only the public policy key and signed envelope enter the code-signed lab App;
- the ordinary `src-tauri/resources` build-input tree never receives the lab
  policy, lab public key, or lab-candidate marker;
- a signed resource marker and an independent compile-time marker identify the
  App as a production-feature disposable-VM candidate;
- ordinary package verification rejects the lab marker, while an explicit lab
  verifier mode requires and authenticates it; and
- Developer ID Application and Installer signatures are mandatory.
  Notarization and stapling remain optional public-distribution hardening. A
  signed but unnotarized result is an internal test candidate and must retain
  the corresponding Gatekeeper limitation in its evidence.

The lab candidate is not a release candidate and may not be uploaded or used
as an updater artifact.

## Candidate classes

The package verifier must use an explicit closed set rather than infer intent
from whichever files happen to be present:

| Verifier profile | Production compile marker | Lab resource marker | Lab policy key | Intended use |
| --- | --- | --- | --- | --- |
| `release-default` | forbidden until a later activation review | forbidden | forbidden | current ordinary signed package |
| `networking-production-vm-lab` | required | required | required, exactly one | disposable VM only |

Adding a formal production-networking release profile is outside this review
and requires the separately reviewed production policy-signing ownership and
release activation.

## Transient resource overlay

The host creates a private parent with `mktemp -d`; the preparation tool then
creates the requested child run root exclusively with `mkdir` and `0700`
permissions. It stages a complete public resource directory there:

```text
<run-root>/public/resources/
  <allowlisted copy of ordinary src-tauri/resources contents>
  kyclash-networking-policy-keys.json
  kyclash-networking-policy-v2.json
  kyclash-networking-vm-lab-candidate.json
<run-root>/public/policy-revision-preflight.json
```

The run-local Tauri overlay maps that complete directory to the bundle's
`resources/` destination and retains the existing signed sidecar/helper files
from `tauri.networking.macos.conf.json`. It must use an absolute source path,
must not follow a symlink, and must be generated as a new regular `0600` file
inside the run root. The preparation tool fails if it cannot prove the staged
directory contains the exact ordinary-resource allowlist plus the three lab
files and no private material.

The generated overlay is named
`tauri.networking-production-vm-lab.macos.conf.json`, is hashed into the
evidence, and is the only additional `--config` input for this candidate. A
checked-in generator owns its exact schema. Neither the generated overlay nor
its staged public resources is committed.

Preparation requires a clean tracked source tree and binds the marker to exact
`HEAD`. The resource root and base Tauri config are fixed to the reviewed files
inside this checkout; the CLI cannot substitute an external same-name tree.
Ignored build inputs are covered by the separate resource inventory and
component hashes rather than treated as source provenance.

The build command must pass `--features networking-production,networking-system-lab`
explicitly for this disposable candidate. No
change to Cargo default features or the ordinary release workflow is allowed.

## Two independent build markers

The candidate requires two markers because a resource alone cannot prove how
the Rust executable was compiled.

### Compile-time marker

When and only when `networking-production` is compiled for macOS, the App
executable contains exactly one 16-byte constant in the exact Mach-O section
`__TEXT,__kyclash_prod`. The bytes are ASCII `KYCLASH-PROD-V1` followed by one
NUL byte (`4b59434c4153482d50524f442d563100` in hexadecimal). The verifier reads
that section structurally and requires those exact bytes. It must not rely on
a debug symbol, filename, build log, `strings` coincidence, Info.plist value,
or caller assertion.

An ordinary build must not contain the section. The marker carries no endpoint,
key, credential reference, or other runtime input.

### Signed lab-resource marker

`kyclash-networking-vm-lab-candidate.json` is strict JSON with no extra fields:

```json
{
  "schema_version": 1,
  "candidate_kind": "networking-production-vm-lab",
  "run_id": "<16 lowercase hexadecimal characters>",
  "source_commit": "<40 lowercase hexadecimal characters>",
  "target": "aarch64-apple-darwin",
  "vm_name": "kyclash-macos-lab-work",
  "policy_key_id": "lab.vm.<run_id>",
  "policy_revision": 0,
  "issued_at": 0,
  "expires_at": 0,
  "policy_expiry_ceiling_epoch": 0,
  "policy_envelope_sha256": "<64 lowercase hexadecimal characters>",
  "policy_trust_sha256": "<64 lowercase hexadecimal characters>",
  "guest_descriptor_sha256": "<64 lowercase hexadecimal characters>",
  "policy_revision_preflight_sha256": "<64 lowercase hexadecimal characters>",
  "tauri_overlay_sha256": "<64 lowercase hexadecimal characters>",
  "mihomo_final_sha256": "<64 lowercase hexadecimal characters>",
  "mihomo_alpha_final_sha256": "<64 lowercase hexadecimal characters>",
  "build_inputs": {
    "ordinary_resources_inventory_sha256": "<64 lowercase hexadecimal characters>",
    "network_sidecar_sha256": "<64 lowercase hexadecimal characters>",
    "route_helper_sha256": "<64 lowercase hexadecimal characters>",
    "route_helper_plist_sha256": "<64 lowercase hexadecimal characters>",
    "mihomo_sha256": "<64 lowercase hexadecimal characters>",
    "mihomo_alpha_sha256": "<64 lowercase hexadecimal characters>"
  }
}
```

The numeric zeroes above are documentation placeholders, not valid generated
values. Before the Tauri build, the two final-Mihomo fields contain a
fail-closed all-zero pending digest. A dedicated post-build seal verifies the
reviewed source hashes, records both final signed Mach-O hashes, updates the
three identical marker copies, and re-signs the outer App. The lab verifier
rejects an all-zero/unsealed marker. The final marker is covered by the outer
App signature. The verifier checks its hashes against exact bytes and checks
its temporal/revision fields against the authenticated policy payload.

The marker is not an authority source. Production composition continues to
trust only the policy signature and fixed production resource boundary.

## Loopback policy contract

The policy generator accepts only a redacted, schema-validated public
descriptor emitted by the guest loopback peer. It emits envelope v2 using the
existing domain-separated signing bytes and a trust bundle containing exactly
one Ed25519 public key.

The decoded profile must satisfy all of these additional lab constraints:

- `profile_id`, site ID, Keychain account, and key ID are bound to the same
  run ID;
- `identity_ref` is exactly `keychain:kyclash.vm.lab.<run_id>`;
- `control_plane` uses `https://127.0.0.1:<port>/...` and is not contacted;
- QUIC, WSS, and TCP URLs all use numeric `127.0.0.1` with explicit nonzero
  ports, no user information, query, or fragment. The ports are selected once
  for the run, signed into the policy, and rebound unchanged after guest
  reboot; an unavailable recorded port fails closed rather than changing the
  endpoint;
- the primary and fallback order is exactly `quic -> wss -> tcp`;
- the inner WireGuard profile uses only the dedicated VM-lab host routes
  `10.88.0.2/32` and `fd00:88::2/128`, with client addresses
  `10.88.0.1/32` and `fd00:88::1/128`;
- the peer public key is exactly the public value in the guest descriptor;
- connect/health/fallback limits stay within the locked profile bounds; and
- no production hostname, endpoint, tenant, token, certificate, route, DNS
  setting, or credential reference is accepted.

`localhost` is rejected because it introduces name-resolution behavior. IPv6
carrier loopback may be added later as an explicit matrix case, but it cannot
replace the required numeric IPv4 loopback carrier boundary above. IPv4 and
IPv6 private-service reachability still cross the owned utun.

The policy lifetime is at most 24 hours and must cover the bounded test window.
The guest trust fixture records a public `policy_expiry_ceiling_epoch` equal to
the leaf certificate `NotAfter` minus a five-minute safety margin. The host
generator receives that scalar explicitly as
`--policy-expiry-ceiling <epoch>`; it does not widen the peer descriptor schema.
Preparation rejects a descriptor whose `expires_at` exceeds the ceiling, and
copies the same ceiling into the code-signed lab marker. The verifier requires the
authenticated policy payload and descriptor expiry to remain at or below the
marker ceiling, so a stale or manually shortened certificate window cannot be
silently bypassed. The ceiling must be in the future at preparation time.

Its revision must be nonzero. The guest-only public helper resolves the same
home directory that Tauri's macOS `dirs::data_dir()` uses (non-empty `HOME`
must exactly match `getpwuid_r`), safely creates the exact
`~/Library/Application Support/net.kysion.kyclash` root with `mkdir(0700)`,
and enters the production `policy-revision.lock` through
`FilePolicyIdentityStore`. It writes a strict redacted
`policy-revision-preflight.json` only when the locked production record is
absent. Legacy or identity records, including a same-key record, fail closed;
there is no preflight-time advance, rewrite, or delete operation. The record
binds the run ID, candidate revision, canonical public App-data root and its
raw-byte SHA-256, check time, and `absent/new` decision. Preparation requires
that file, checks it is no more than 15 minutes old at candidate-generation
time, copies it into the host public run root, and signs its exact SHA-256 into
the lab marker. The App's production store remains authoritative at startup;
the marker is not a durable claim about state after the lock is released.

## Private-material lifecycle

### Policy signing key

The host preparation process generates a fresh Ed25519 key object after the
exclusive run root exists. The private key remains process memory only: it is
never exported to PEM/DER, written to the run root, passed in argv or an
environment variable, printed, uploaded, or retained as evidence. The process
emits only the public key, strict trust JSON, and signed envelope, clears owned
message buffers, and exits immediately.

The existing fixed unit-test seed is forbidden for this path.

### WireGuard client material

Before the peer descriptor is created, a guest-only fixture creates one
32-byte WireGuard client key in the KyClash test service
`net.kysion.kyclash.test` under the exact run-bound account from the policy.
The disposable candidate enables `networking-system-lab`, which makes the
otherwise unchanged production composition select that test namespace; normal
production builds continue to use `net.kysion.kyclash.networking`. The fixture
refuses an existing item with an atomic `SecItemAdd`/`add_generic_password`
operation (a duplicate returns `created=false` without an update), derives
only the public key for the peer, and never prints or exports the private
value. This mutation is allowed only inside the
confirmed disposable guest and is deleted by exact service/account during
cleanup after durable ownership is recorded.

### Peer and TLS material

The compatible lab peer runs only in the disposable guest. Its WireGuard peer
private key and TLS leaf private key are created as new `0600` regular files
under one fresh, run-bound guest directory created exclusively with `mkdir`
and mode `0700` beneath the canonical `/private/var/tmp` path. The trust fixture creates an ephemeral
RSA-2048 root and RSA-2048 numeric-loopback leaf; the root signing key is used
only to issue that leaf, then deleted before fixture preparation succeeds, and
is never passed to the peer or the App. The leaf private key never leaves the
disposable guest. This narrowly bounded
persistence is required so the same signed policy, peer identity, and TLS
identity can be retried after the S1.13 guest reboot; regenerating them after
reboot would no longer test the exact signed candidate. The peer receives only
validated, canonical guest paths inside that run directory, checks ownership,
mode, link count, regular-file type, and recorded hashes before reading, and
clears owned in-memory copies. It writes a separate public descriptor and
public certificate files; no private bytes are printed, placed in the
environment, or included in evidence.

The short-lived RSA certificates are constrained to the numeric `127.0.0.1`
identity. The generated root certificate is temporarily trusted in the
disposable guest System Keychain by exact SHA-256 fingerprint so the
unmodified production sidecar exercises platform trust. The production binary
receives no lab CA through bootstrap, argv, environment, policy, or a new
production API.

Every imported certificate is random for the run, constrained to numeric
loopback identity, recorded only by public fingerprint, and removed by exact
fingerprint during cleanup. If exact removal or final trust-state proof fails,
the work VM must be reverted or destroyed; the base VM is never modified.

### Scoped Keychain lifecycle boundary

The disposable-account Keychain create/read/update/delete exercise is a
scoped manual test (and may remain `ignored` in automated suites). It exists to
avoid polluting or accidentally deleting entries in a user's real login
Keychain. When run, it may use only the KyClash test service/account, for
example `net.kysion.kyclash.test` (or the exact run-bound lab service), and the
fixture must prove pre-existing absence and exact ownership before cleanup.
This destructive lifecycle check is not a gate for all source development or
for producing a signed internal candidate; it is run later when a disposable
macOS account/VM is available. The production trust-certificate probe remains
separate: its before-import, after-import, and after-removal proofs are
required for the guest trust experiment, but they do not authorize touching a
daily-use account.

## Compatible guest peer requirements

The guest peer is a separate `networking-system-lab` executable and is never
bundled into KyClash. It shares the repository-owned KYNP, WireGuard, QUIC,
WSS, TCP, and labserver implementations, but it must add the missing external
fixture boundary:

- accept the run-bound client public key from a private regular input file;
- create or reopen only its exact run-bound WireGuard/TLS private files after
  validating ownership, mode, link count, type, and recorded public identity;
- bind every carrier listener only to `127.0.0.1`; choose fresh high ports at
  run creation, record them in the private run manifest, and reuse those exact
  ports for the bounded reboot matrix;
- provide both `10.88.0.2` and `fd00:88::2` inside its userspace WireGuard peer;
- expose a bounded echo service on both private addresses;
- write one strict public descriptor atomically after all listeners are ready;
- write public TLS certificates separately for exact guest trust import;
- the guest-only `kyclash-keychain-public-lab` helper writes only the derived
  public X25519 key to a new `0600` file under the canonical
  `/private/var/tmp/kyclash-networking-vm-lab/<run-id>/` root; it never writes
  or prints the Keychain private value;
- print fixed status messages only, never keys, policy bytes, endpoints, or
  certificate contents;
- terminate on its controller EOF/parent death and clear private buffers; and
- refuse non-loopback bind, an existing descriptor, symlinks, unsafe modes,
  unknown fields, or a client key not bound to the run ID.

The public descriptor may contain only run ID, loopback endpoint URLs, peer and
client public keys, private echo addresses, certificate fingerprints/paths,
and expiry. Its exact bytes are hashed into the signed lab marker.

## Package verifier amendment

`scripts/verify-macos-package.mjs` must gain an explicit
`--profile networking-production-vm-lab` mode and require an absolute
`--lab-public-root` pointing at the same run's non-secret descriptor and
generated overlay. It validates that directory and its files as regular,
non-symlink, run-bound inputs before using them. That mode fails unless all of
the following pass:

1. Existing App, helper, sidecar, plist, sidecar-trust, Team ID, deep-signature,
   PKG-signature, and sidecar-hash checks still pass.
2. The main executable contains exactly one valid production compile marker.
3. The lab marker, policy envelope, and policy trust bundle are regular,
   non-symlink, installed-app-readable resources covered by the App seal.
4. Marker fields are strict, internally consistent, bound to the current Git
   commit and arm64 target, and unexpired.
5. The trust bundle contains exactly the run-bound public key; the verifier
   authenticates the exact v2 envelope and validates the signed payload.
6. Exact policy/trust/descriptor/revision-preflight/overlay hashes match the
   marker; the preflight proves a fresh `absent/new` production record at
   candidate-generation time, and the envelope identity uses the exact
   resource bytes rather than reserialization. Runtime startup must still
   re-read the production store under its lock.
7. The decoded profile satisfies every loopback, route, identity, fallback,
   and lifetime constraint in this review.
8. The App resources contain no private-key PEM/DER marker, seed, password,
   token, updater key, non-loopback endpoint, second policy trust key, or the
   known raw public key derived from the fixed unit-test seed.
9. Expanding the PKG into a new temporary directory yields the same sealed App
   marker, executable hash, nested component hashes, policy bytes, and trust
   bytes as the audited App bundle.
10. The PKG has a valid Developer ID Installer identity with the expected Team
    ID. Absence of notarization is reported as
    `signed-unnotarized-internal`, not treated as a lab failure.

The existing/default verifier mode must fail if the lab marker, `lab.vm.*` key
ID, or lab-only compiled candidate classification is present. The ordinary
release workflow continues to use that default mode, so accidentally staging
lab resources turns the release job red before any draft is created.

The verifier writes only a redacted JSON result and artifact hashes. It never
copies or prints policy private material, Keychain values, or raw credential
output.

## Implemented command and evidence flow

The interfaces below exist in the reviewed and design-locked source. Every
builder requires a clean tracked worktree, so implementation and roadmap
changes are committed and pushed before candidate construction.

### 1. Host fixture and signed component build (`host-build`)

The local signing identity labels below are public metadata; the corresponding
private credentials remain in Keychain. The checked-in Go toolchain path is
added only to this command environment. Each guest fixture is built into the
same new private build root, with a create-only provenance file and SHA-256:

```bash
export APPLE_SIGNING_IDENTITY='Developer ID Application: Huang Chapping (RQUQ8Y3S9H)'
export APPLE_INSTALLER_SIGNING_IDENTITY='Developer ID Installer: Huang Chapping (RQUQ8Y3S9H)'
export APPLE_TEAM_ID='RQUQ8Y3S9H'
export KYCLASH_NOTARIZATION_ENABLED=false
export KYCLASH_GO_BIN="$PWD/target/toolchains/go1.26.5/bin/go"
export PATH="$(dirname "$KYCLASH_GO_BIN"):$PATH"
mkdir -p "$PWD/target/macos-vm-lab/build"
LAB_BUILD_ROOT="$(mktemp -d "$PWD/target/macos-vm-lab/build/candidate.XXXXXX")"
chmod 700 "$LAB_BUILD_ROOT"
export KYCLASH_VM_LAB_BUILD_ROOT="$LAB_BUILD_ROOT"
corepack pnpm macos:production-vm:trust-probe
corepack pnpm macos:production-vm:keychain-helper
corepack pnpm macos:production-vm:peer
corepack pnpm network-sidecar:macos aarch64-apple-darwin
corepack pnpm route-helper:macos
```

Only these three external guest fixtures and the checked-in shell fixture are
copied to the selected guest: `kyclash-system-trust-probe`,
`kyclash-keychain-public-lab`, `kyclash-networking-system-lab`, and
`macos-vm-keychain-trust-fixture.sh`. The shell fixture is copied to the exact
guest path `$HOME/kyclash-macos-vm-keychain-trust-fixture.sh`; the binaries are
copied into the exact run root after `prepare` creates it. They are never added to the App. The host
records each build provenance hash; the guest re-hashes the exact copied bytes
before execution and refuses a mismatch. The current guest IP is always
resolved immediately before `scp`/`ssh` with `scripts/macos-vm-lab.sh ip`.

### 2. Guest preflight and persistent peer (`guest-runtime`)

The copier is host-only. Before the visible guest session, the host resolves
the selected VM IP and copies the checked-in shell fixture with `--shell-only`;
it never launches the App or performs a privileged guest mutation:

```bash
# HOST / build-orchestration terminal
corepack pnpm macos:production-vm:copy-fixtures --shell-only
```

The user then runs `sudo -v` in the visible Terminal of
`kyclash-macos-lab-work`; no password is accepted through SSH or automation.
That same live guest session proves `VirtualMac*`, arm64, and the three exact
environment markers, creates a fresh public run ID and positive revision, and
creates the run root:

```bash
# GUEST / visible Terminal
export KYCLASH_RUNNER_ENVIRONMENT=local-virtualization-framework
export KYCLASH_VM_LAB_CONFIRM=authorized-kyclash-virtualization-framework-vm
export KYCLASH_RUNTIME_TARGET=kyclash-macos-lab-work
sudo -v
RUN_ID=<16-lowercase-hex>
REVISION=<positive-decimal>
FIXTURE="$HOME/kyclash-macos-vm-keychain-trust-fixture.sh"
"$FIXTURE" prepare --run-id "$RUN_ID"
```

After `prepare` creates that root, the host copies and hash-verifies the three
host-built fixtures into it. This command is still host-only:

```bash
# HOST / build-orchestration terminal
RUN_ID=<same-16-lowercase-hex>
corepack pnpm macos:production-vm:copy-fixtures \
  --run-id "$RUN_ID" --build-root <absolute-host-build-root>
```

The guest then performs the scoped trust, policy, and Keychain fixture steps:

```bash
# GUEST / same visible Terminal or a persistent SSH session with VM proof retained
"$FIXTURE" probe-absent --run-id "$RUN_ID"
"$FIXTURE" policy-revision-preflight --run-id "$RUN_ID" --revision "$REVISION"
"$FIXTURE" prepare-client-key --run-id "$RUN_ID"
"$FIXTURE" mark-keychain-created --run-id "$RUN_ID"
"$FIXTURE" import-cert --run-id "$RUN_ID"
"$FIXTURE" probe --run-id "$RUN_ID"
```

The preflight-to-launch boundary is fail-closed: any previously installed
KyClash App is stopped before preflight, the guest records that no old App or
sidecar PID is alive, and the candidate App is not launched until the package
hash/signature checks complete. A change made after the preflight is therefore
accepted only by the production store's lock/revision checks, never by the
marker alone.

`EXPIRES_AT` is computed once as the smaller of `now + 21600` seconds and the
public `policy_expiry_ceiling_epoch` printed by `prepare`; it must remain more
than ten minutes in the future and can therefore never exceed the peer's
24-hour lifetime limit or the certificate safety ceiling. The peer runs in a
dedicated persistent SSH execution session whose stdin stays open; the
host-only runner retains that session handle until cleanup. A one-shot/background
SSH command is forbidden because EOF or parent loss intentionally removes the
descriptor and terminates the peer. Use the checked-in runner from a second
host terminal so the three guest markers are injected into the remote `env`
command instead of relying on an unrelated guest shell export:

```bash
# HOST / keep this terminal attached until the App has disconnected and
# guest cleanup has proved that the peer descriptor is absent.
corepack pnpm macos:production-vm:peer-run \
  --run-id <run-id> --expires-at <EXPIRES_AT>
```

The runner resolves only `kyclash-macos-lab-work`, uses strict known-host and
batch SSH settings, launches the exact run-root binary, waits for the fixed
`KYCLASH_SYSTEM_LAB_READY` record, and does not close stdin before the caller
explicitly ends the session. It prints only the selected VM, run ID, and ready
status; it never copies peer keys, certificates, or manifests to the host.

Once the peer has published its descriptor and the guest fixture has written
the policy preflight, the host pulls only the three reviewed public inputs. The
pull command resolves `kyclash-macos-lab-work` immediately, proves the live
`VirtualMac*`/arm64 guest and `supen` home, validates regular-file ownership,
mode, size, duplicate-free JSON, run binding, and hashes in the same SSH
session, then creates a new private output root without replacing any file:

```bash
# HOST / build-orchestration terminal; the output child must not exist yet
PULL_PARENT="$(mktemp -d "$PWD/target/macos-vm-lab/pull.XXXXXX")"
chmod 700 "$PULL_PARENT"
PULL_ROOT="$PULL_PARENT/public-input"
corepack pnpm macos:production-vm:copy-fixtures \
  --pull-run --run-id <run-id> --output-root "$PULL_ROOT"
```

The resulting root contains only `guest-descriptor.json`,
`policy-revision-preflight.json`, and
`policy-expiry-ceiling-epoch.txt`. The complete guest `manifest.txt`, peer
manifest, certificates, private keys, Keychain values, helper output, and any
other run-root entry are intentionally not transferred. The generator consumes
the three paths explicitly:

```bash
corepack pnpm macos:production-vm:prepare \
  --descriptor "$PULL_ROOT/guest-descriptor.json" \
  --policy-revision-preflight "$PULL_ROOT/policy-revision-preflight.json" \
  --run-root <new-run-root> \
  --policy-expiry-ceiling "$(tr -d '\n' < "$PULL_ROOT/policy-expiry-ceiling-epoch.txt")" \
  --revision <revision>
```

Only `guest-descriptor.json`, `policy-revision-preflight.json`, and the public
expiry ceiling scalar cross back to the host. The guest manifest, certificate
files, private keys, Keychain value, and helper raw output never leave the VM.

### 3. Resource preparation, App seal, and signed PKG (`host-build`)

The host run parent is a new `0700` directory, while the child passed to the
generator must not yet exist. This matches the generator's atomic create-only
contract. Existing same-version generated App/PKG/digest artifacts are moved
to a unique ignored archive directory before construction, never overwritten
or deleted.

```bash
HOST_RUN_PARENT="$(mktemp -d "$PWD/target/macos-vm-lab/run.XXXXXX")"
chmod 700 "$HOST_RUN_PARENT"
HOST_RUN_ROOT="$HOST_RUN_PARENT/candidate"
corepack pnpm macos:production-vm:prepare \
  --descriptor <absolute-public-descriptor> \
  --policy-revision-preflight <absolute-public-preflight> \
  --run-root "$HOST_RUN_ROOT" \
  --policy-expiry-ceiling <public-ceiling> --revision <revision>
VITE_NETWORKING_PRODUCTION=true \
  APPLE_SIGNING_IDENTITY="$APPLE_SIGNING_IDENTITY" \
  APPLE_TEAM_ID="$APPLE_TEAM_ID" \
  corepack pnpm tauri build --target aarch64-apple-darwin --bundles app \
    --features networking-production,networking-system-lab \
    --config "$HOST_RUN_ROOT/public/tauri.networking-production-vm-lab.macos.conf.json"
corepack pnpm macos:production-vm:seal \
  --lab-public-root "$HOST_RUN_ROOT/public" --target aarch64-apple-darwin
CI=true APPLE_INSTALLER_SIGNING_IDENTITY="$APPLE_INSTALLER_SIGNING_IDENTITY" \
  KYCLASH_NOTARIZATION_ENABLED=false \
  corepack pnpm macos:pkg aarch64-apple-darwin
corepack pnpm macos:production-vm:verify aarch64-apple-darwin \
  --lab-public-root "$HOST_RUN_ROOT/public"
```

The preparation output is fixed/redacted and the verifier labels the allowed
internal artifact `signed-unnotarized-internal`. The ordinary default verifier
is then run separately and must reject this exact candidate for the expected
lab classification. That expected rejection is retained as release-separation
evidence, not misreported as a package failure.

### 4. Install and system matrix (`guest-runtime`)

After copying the exact signed PKG to the confirmed work guest, the user types
administrator authorization only in that guest's visible Terminal. The guest
then runs `installer -pkg <signed-pkg> -target /`, verifies the receipt and
signatures, and launches `/Applications/KyClash.app` through LaunchServices.
No password is accepted through SSH, argv, stdin automation, source, or logs.

The guest re-proves `VirtualMac*`, validates the exact package hash, receipt,
App/nested signatures, Team ID, compile marker, lab marker, policy hashes, and
expiry, then launches `/Applications/KyClash.app` through LaunchServices. The
window stays visible. The matrix invokes the production initialization and
Connect path, proves the production sidecar and helper identities, samples live
Mihomo after carrier health, reaches the private echo service over IPv4 and
IPv6 only while connected, and exercises the required QUIC -> WSS -> TCP
break-before-make, abort, restart, and reboot cases.

No App, sidecar, helper, installer, Keychain mutation, trust import, utun,
route, Mihomo, or lifecycle command runs on the host.

## Evidence contract

The redacted evidence manifest separates `build_target=host-build` from
`runtime_target=kyclash-macos-lab-work` and contains:

- source commit, target, run ID, policy revision and validity interval;
- generated overlay, marker, policy, trust, descriptor, policy-revision
  preflight, App, PKG, main executable, sidecar, helper, and plist hashes;
- production compile-marker and lab-resource-marker results;
- Developer ID Application/Installer Team IDs and signature results;
- explicit notarization state, including `signed-unnotarized-internal` when
  selected;
- VM name, `VirtualMac*` model, guest OS/architecture, receipt, installed path,
  guest PID, executable path, visible-window result, and screenshot path;
- loopback-only listener proof and public certificate fingerprints;
- redacted production state transitions, exact utun/route owner identities,
  live-Mihomo interface classification, fallback order, IPv4/IPv6 private
  reachability, and bounded cleanup times; and
- final absence of the exact route, journal, lease, utun, child, peer process,
  temporary certificate trust, and run-bound Keychain item; policy-record
  absence is evidenced only after the work VM is reverted/destroyed to its
  clean baseline.

The evidence never retains a private key, Keychain value, password, token,
raw bootstrap, unredacted endpoint document, certificate private material, or
credential-bearing process output.

## Threat model

| Threat | Required mitigation |
| --- | --- |
| Lab trust root ships in an ordinary package | No lab files under the ordinary resource tree; exact before/after resource inventory; default verifier rejects marker/key ID; release workflow keeps default profile |
| A resource marker falsely claims the feature is compiled | Independent exact Mach-O compile marker, checked after code signing |
| Production feature accidentally becomes default | Feature remains default-off; lab build passes it explicitly; ordinary verifier requires marker absence |
| Policy private key leaks through files, argv, logs, CI, or evidence | Fresh in-process Ed25519 key, never serialized; fixed-status output; secret-pattern and Git-tree scans |
| Test seed becomes packaged authority | `cfg(test)` helper remains test-only; verifier rejects both its known raw public key and key ID in a candidate |
| Policy or endpoint escapes the VM | Strict numeric-loopback profile verification; guest peer refuses non-loopback bind; no DNS name |
| Lab TLS trust changes production bootstrap | Use unchanged platform trust path; public cert imported only in disposable guest; no lab CA field/API |
| Resource substitution or symlink redirects build input | New `0700` run root, regular files, absolute mapping, no symlinks, exact hashes, final App seal and expanded-PKG comparison |
| Stale policy bypasses expiry/replay | Short signed validity, exact envelope digest, positive revision, fresh clean-VM preflight hashed into the marker, and production-store lock/commit-time freshness checks unchanged |
| Candidate runs on the host or base VM | Target-labelled commands, `VirtualMac*` proof in the same guest session, selected work-VM name in signed marker, base VM forbidden |
| Lab Keychain item or certificate survives a crash | Run-bound exact identifiers/fingerprints, recovery cleanup, final absence; revert/destroy work VM if absence is unprovable |
| Guest peer private files outlive the reboot matrix | Private files exist only in the exact fresh, exclusively created guest run root with `0700`/`0600` shape; scoped cleanup validates its allowlisted residue and the work VM is then reverted or destroyed |
| Lab package is uploaded or updater-enabled | No release/updater step; updater remains disabled; candidate kind forbidden by ordinary verifier and release gate |
| Signed but unnotarized package is presented as generally trusted | Evidence labels internal state and Gatekeeper limitation; notarization remains optional hardening, not silently claimed |

## Cleanup and recovery

Normal and failure cleanup must be idempotent and exact:

1. request production Disconnect when possible, then prove route rollback and
   lease release before tunnel/child termination;
2. terminate only recorded App, sidecar, helper-transaction, and loopback-peer
   PIDs after revalidating executable path and run identity;
3. prove exact utun, private routes, journal, XPC lease, listeners, and private
   service are absent;
4. when the optional scoped Keychain fixture was selected, delete only the
   run-bound generic-password item under `net.kysion.kyclash.test`, and
   only when preflight proved it absent and the fixture recorded creating it;
   otherwise perform no destructive login-Keychain operation;
5. remove only the imported public certificates whose exact fingerprints and
   Keychain locations match the run manifest;
6. remove every trust/Keychain fixture-owned file after exact validation, then
   allow only the validated peer binary plus `wg-private.key` and
   `peer-manifest.json` reboot state to remain; the descriptor must already be
   absent, and this allowlisted residue disappears only with the mandatory
   work-VM reset;
7. do not delete, restore, or rewrite the production policy identity record;
   after the candidate run, revert or destroy the exact work VM to its
   pre-run clean baseline, and require that reset before another run;
8. uninstall the lab-marked App/receipt only after its exact package and marker
   hashes match, then restore a pre-existing App baseline only if that App
   baseline was captured and verified; this never restores a policy record;
   and
9. remove the exact host run root and public staging after retaining only the
   allowlisted redacted evidence.

If a path, Keychain item, certificate, App, receipt, route, journal, or process
cannot be proven to belong to the run, cleanup refuses to delete it. The
remaining state is reported as unresolved and the disposable work VM is
reverted or destroyed. The clean base VM is never used for the test or
cleanup.

## Source/design gates required before design lock

- preparation refuses a dirty/pre-existing output, symlink, unsafe mode,
  unknown descriptor field, non-loopback URL, wrong route, mismatched run ID,
  non-run-bound certificate path, stale expiry, a missing/non-future ceiling,
  descriptor expiry above the guest ceiling, missing/stale/foreign revision
  preflight, any pre-existing policy identity, noncanonical CLI integer,
  unknown/duplicate CLI option, external resource/config root, or extra trust
  key;
- the policy signature and exact-envelope hash verify in both the generator
  test and production Rust verifier without sharing a private fixture;
- generated private policy material is absent from the filesystem, process
  arguments/environment capture, and logs;
- ordinary resource files are staged by an explicit allowlist, and the source
  `src-tauri/resources` tree is byte-identical before and after preparation;
  this proof uses an exact inventory and hashes because the tree is Git-ignored;
- compile-marker parser tests require exactly one fixed section/byte sequence
  for the lab profile and none for the default profile, including forged,
  duplicate, wrong-architecture, and malformed Mach-O rejection;
- post-build sealing is create/bind/fail-closed: it verifies both source Mihomo
  hashes, replaces only the three owned marker files, records both final signed
  hashes, and requires outer Developer ID Application re-signing;
- the peer process boundary refuses non-arm64 macOS, non-`VirtualMac*`, missing
  guest markers, an already-orphaned parent, arbitrary private roots, and
  non-run-bound certificate paths;
- userspace tests prove both private echo addresses, QUIC -> WSS -> TCP
  break-before-make, EOF cleanup, parent-identity change cancellation, TLS
  handshake timeout recovery, and WSS connection drain;
- package verifier source tests keep a closed two-profile set, require the
  exact final component hashes plus Developer ID Application/Installer
  authorities, and retain release-default rejection; and
- the Keychain resolver uses an atomic create-only primitive (`SecItemAdd` /
  `add_generic_password`) for ownership, never updates a foreign item, and the
  helper refuses duplicate, missing-witness, or non-durable ownership states;
- the guest-to-host pull accepts only the three public inputs, proves the
  canonical guest root and live VM in the same SSH session, validates hashes
  and file identity before/after read, and publishes into a new private root
  without replacement or symlink traversal; and
- no source test launches or installs KyClash, changes trust/Keychain, creates
  utun, or mutates routes on the host.

## Runtime acceptance gates after design lock

- a production-feature App has exactly one compile marker and the comparison
  default App has none;
- the explicit lab verifier accepts the exact sealed signed App/PKG while the
  default verifier rejects that same candidate for the expected lab
  classification;
- tampered marker, policy, trust, descriptor hash, overlay hash, App bytes,
  sidecar/helper/Mihomo bytes, authority, Team ID, target, commit, expiry
  ceiling, or expanded PKG fails closed;
- generated private policy material is absent from the package, PKG expansion,
  and retained evidence;
- the guest peer refuses non-loopback and proves both private echo addresses;
- the exact signed policy and guest peer identities survive the bounded guest
  reboot without regenerating any policy, WireGuard, or TLS identity;
- the guest trust probe uses exact run-bound certificate fingerprints and
  canonical `/private/var` paths; destructive Keychain create/read/update/delete
  remains a scoped manual/ignored test using only a disposable account and a
  KyClash-specific service such as `net.kysion.kyclash.test`, and is not a
  general source-development blocker;
- interruption after each preparation, trust import, build, install,
  initialization, connect, fallback, route apply, reboot, and uninstall
  boundary converges to the cleanup rules above; and
- every runtime-affecting command and screenshot is proven inside
  `kyclash-macos-lab-work`; the host remains build/orchestration only.

## Design-review closure

Independent review closed every lock question on 2026-07-22:

1. the dedicated Mach-O section name, exact marker bytes, arm64 shape, and
   duplicate/forged-section rejection are covered by the closed verifier
   contract;
2. the generated Tauri overlay schema, absolute-resource mapping, source
   inventory, and ordinary resource allowlist are exact and fail closed;
3. System-Keychain import/removal is bound to the exact certificate
   fingerprint, the retired root signing key must remain absent, and the
   CGO-disabled probe retains the unchanged platform-trust path. The actual
   before/import/after observation remains a runtime-acceptance gate;
4. the standalone peer's dual-stack private-service, break-before-make,
   parent-death, EOF, retry, and orphan-cleanup contracts pass; and
5. the package verifier has a closed two-profile set and the ordinary
   `release-default` profile rejects the lab candidate;
6. Keychain ownership is atomic and scoped to the `.test` service, with a
   durable marker plus public witness required before destructive cleanup; and
7. guest-to-host evidence transfer is public-only, same-session verified,
   TOCTOU-checked, and create-only published on the host.

The final independent rerun passed the full JavaScript script suite (41/41;
the production-candidate contract subset is 38/38 at the current revision),
Go full/race/
vet gates, Rust focused and full-library tests, explicit arm64 checks,
formatting, and `cargo clippy --all-targets --all-features -- -D warnings`.
The design is therefore locked. This authorizes only a transient, run-bound,
lab-marked App under the selected disposable work-VM flow. Runtime acceptance
is still pending, and adding a lab trust root or policy to the ordinary
resource tree or release workflow remains forbidden.

## Out of scope

- production/staging endpoints or credentials;
- production policy-key ownership, rotation, or distribution;
- App Store distribution;
- GitHub Release publication or updater activation;
- PVE, ROS, K3s, production DNS, routes, certificates, or tunnels;
- host runtime, host Keychain/trust mutation, host utun, or host route tests;
- notarization as a prerequisite for this internal VM candidate; and
- replacing the existing production policy, Keychain, sidecar trust, XPC, or
  route ownership boundaries with a lab-only bypass.
