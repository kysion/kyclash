# KyClash local macOS Virtualization.framework lab

Status: local fixed-scope system lab passed; signed GUI launch validated; PKG
lifecycle in progress

This lab supplies a disposable, full macOS guest for package installation,
Gatekeeper behavior, fixed-scope Keychain lifecycle, and TEST-NET route recovery.
It complements the GitHub-hosted macOS gate; it does not replace final checks for
physical sleep/wake or physical network-interface switching.

## Locked implementation

- Host: Apple Silicon Mac with Apple Hypervisor support.
- Hypervisor: Apple's Virtualization.framework through Tart.
- Tart: pinned to `2.32.1` and downloaded from the publisher's GitHub release.
- Guest source: Apple's latest supported IPSW, not a third-party prepared image.
- Base VM: `kyclash-macos-lab-base`; do not run destructive tests in it.
- Disposable clone: `kyclash-macos-lab-work`.
- Guest allocation: 6 vCPU, 8192 MiB RAM, 50 GB virtual disk, 1440x900
  display on the current 10-core/32 GB development Mac.
- Curated public input share: read-only, exposed as
  `/Volumes/My Shared Files/kyclash-staging` inside the guest. The repository
  root and host-private `target` trees are never shared. The work guest may
  export public review artifacts only through
  `/Volumes/My Shared Files/kyclash-review-client`.

Tart `2.33.0` was rejected for this host because the signed executable exited
with status 137 before command dispatch on macOS 26.5.1/M5. Version `2.32.1`
was checksum-verified against its release checksum and passed its version
preflight. Re-evaluate the pin after an upstream compatibility fix.

## One-time setup

Install the pinned tool without changing system paths:

```bash
mkdir -p target/tools/tart-2.32.1
curl --fail --location --proto '=https' --tlsv1.2 \
  https://github.com/openai/tart/releases/download/2.32.1/tart.tar.gz \
  -o target/tools/tart-2.32.1/tart.tar.gz
curl --fail --location --proto '=https' --tlsv1.2 \
  https://github.com/openai/tart/releases/download/2.32.1/tart_2.32.1_checksums.txt \
  -o target/tools/tart-2.32.1/checksums.txt
(cd target/tools/tart-2.32.1 && shasum -a 256 -c checksums.txt)
tar -xzf target/tools/tart-2.32.1/tart.tar.gz -C target/tools/tart-2.32.1
```

Create and initialize the base guest:

```bash
scripts/macos-vm-lab.sh preflight
scripts/macos-vm-lab.sh create
target/tools/tart-2.32.1/tart.app/Contents/MacOS/tart set \
  kyclash-macos-lab-base --cpu 6 --memory 8192 --display 1440x900
```

Complete Setup Assistant in the VM window using a dedicated local test account.
Do not reuse the host password, Apple Account, certificates, tokens, production
credentials, or real Keychain data. Enable Remote Login only if SSH automation
is needed. Shut down the guest after installing only the required development
tools; this becomes the clean base.

On 2026-07-21, the base guest was initialized, stopped cleanly, and cloned to
`kyclash-macos-lab-work`. The work guest obtained NAT address `192.168.64.3`.
Remote Login was not enabled at first boot, so SSH automation was pending at
that checkpoint. It was subsequently enabled for the dedicated guest account,
and the VM-only key below is now the automation boundary.

For the current two-VM lab, initialize the fixed role-specific management keys
and Layer-A inputs through the reviewed host courier. Only the client public
key is then present in the curated share. In the guest, enable **System
Settings → General → Sharing → Remote Login**, then install that public key:

```bash
mkdir -p ~/.ssh
chmod 700 ~/.ssh
cat '/Volumes/My Shared Files/kyclash-staging/layer-a-inputs/client-ssh-bootstrap-layer-a/client-management-ed25519-public.bin' \
  >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

The host management private key remains under the ignored, unshared fixed
private root. It must never be printed, committed, or copied into any Tart
share. The transactional external-peer bootstrap supersedes this manual block
for the current acceptance run.

## Local execution evidence — 2026-07-21

The disposable `kyclash-macos-lab-work` guest passed the fixed synthetic
Keychain lifecycle, normal TEST-NET route transaction, expected forced abort,
journal recovery, and final cleanup on macOS 26.5.2 (`25F84`), arm64,
`VirtualMac2,1`. The forced-abort exit status was 134. Independent post-run
checks confirmed that the synthetic Keychain item, fixed route, and route
journal were absent.

Redacted evidence was copied to ignored host directory
`target/macos-vm-lab/evidence`. Its result hashes are:

- `keychain.txt`: `7073766cf171a7a1bf654c5ee7293252fb77f151c81475791ea4c1038296b0fd`
- `route.txt`: `d6fdfbd590755ab253f362949d1d5a494fe5aec6ff19f93db3f4b8c3e1fc18ce`
- `route-after-abort.txt`: `7196a960c0dfc772c5dd7de56d8cb47e2688d6eed8e44c8001296633e4c91730`
- `route-journal-after-abort.json`:
  `5eb35f094be962897190e72ea08934783044de193f1a2a2928665bace982b664`

The PKG passed SHA-256 verification, Installer certificate validation, and
fresh installation into `/Applications`. Its app bundle is arm64, uses
`net.kysion.kyclash`, and passes strict code-signature verification. The same
signed package was subsequently accepted by Apple notarization, stapled, and
accepted by Gatekeeper on both host and guest as `Notarized Developer ID`.
Upgrading the installed unnotarized test build with the stapled package passed.
GUI process-lifetime validation remains separate; global Gatekeeper disabling
was neither needed nor permitted.

## GUI launch evidence — 2026-07-22

The newly rebuilt Developer ID arm64 bundle was copied to the guest's private
writeable test directory and launched through LaunchServices:

```text
~/kyclash-lab/app-run-20260722-2/KyClash.app
```

The launch stayed alive beyond the smoke interval and rendered the main window
with the KyClash title, logo, navigation, and home page. Independent guest
checks recorded:

- KyClash process remained alive (PID 1971 at capture time).
- Bundled `verge-mihomo` child remained alive for the normal local proxy
  lifecycle.
- The singleton listener held `127.0.0.1:33331` while the app was running.
- Clean screenshot evidence is retained at
  `target/macos-vm-lab/evidence/app-launch-20260722/kyclash-window.png` with
  SHA-256
  `4ce6fd1b9058ffa84f09243416475cb592aa797289db432405f319888250d0f3`.

The immediate exit was caused by unconditional registration of the Tauri
updater plugin while the locked base configuration intentionally has no
`plugins.updater` object. Tauri deserialized that missing value as `null` and
returned a builder error before creating a window. The runtime now registers
the updater plugin only when `APP_UPDATES_ENABLED` is true, preserving the
GitHub-updater/no-store gate and keeping current application updates disabled.
The bundle used for this GUI smoke was an isolated user-directory copy; the
installed `/Applications` package lifecycle remains a separate S1.15 gate.

The latest signed bundle was then launched directly after rebuilding the
nested sidecar with the parent-reparent cleanup fix:

```text
~/kyclash-lab/app-run-20260722-3/KyClash.app
```

The app was brought to the foreground on the Home page and remained alive
while independently checked. At capture time the main process was PID 1525,
the bundled `verge-mihomo` child was PID 1540, and the singleton listener was
`127.0.0.1:33331`. The nested sidecar is Developer ID signed for Team ID
`RQUQ8Y3S9H` with SHA-256
`fd041fc1b5e3d7b7b3498cc7714161a6c0047510c492f734b60659c11f20689b`.
The clean foreground screenshot is retained at
`target/macos-vm-lab/evidence/app-launch-20260722/kyclash-live-vm-home2-20260722.png`
with SHA-256
`37a762972cee3f067c7e0eb977a22bb3af40f772b910ffb06d246855f2d15377`.
The non-secret capture record is
`target/macos-vm-lab/evidence/app-launch-20260722/kyclash-live-vm-home2-20260722.txt`.

## Installed PKG trust-resource and launch evidence — 2026-07-22

Installing the first rebuilt internal PKG exposed a package-permission defect:
the public sidecar trust manifest was `root:wheel 0600`, so the non-admin app
user could not read that sealed resource and `codesign --verify --deep
--strict` returned `Permission denied`. The build now explicitly changes the
manifest to `0644` after every write, and the shared package verifier rejects
any other mode.

The replacement Developer ID-signed, intentionally unnotarized internal PKG
has SHA-256
`b06d0c64bce8b50459875bf905ade2a244d17537f8a22e34ca270b008ed434f1`.
It completed an upgrade installation in the disposable guest. The normal test
user then verified the `net.kysion.kyclash` 2.5.3 receipt, `0644` readable
manifest, deep strict app signature, Team ID `RQUQ8Y3S9H`, and equality between
the nested sidecar SHA-256 and the trust manifest. LaunchServices started
`/Applications/KyClash.app`; its bundled Mihomo child and
`127.0.0.1:33331` listener were live, and the previous user-directory app copy
was absent. The redacted record is
`target/macos-vm-lab/evidence/app-launch-20260722/pkg-readable-trust-upgrade-20260722.txt`.
The installed-app screenshot is
`target/macos-vm-lab/evidence/app-launch-20260722/kyclash-installed-pkg-live-20260722.png`
with SHA-256
`5630fa3513fbddf96af38c3a78eedf43bd3f327eb42ed2971fc5edf3c83cdea9`.

The retained historical notarized package was next installed as a rollback
probe. The package transaction succeeded, but that older app did not remain
running or restore the singleton listener and predates the production sidecar
trust resource, so it is not accepted as a functional rollback artifact. The
corrected current package was immediately restored and again passed non-admin
deep signature verification, `0644` trust-resource validation, installed-app
launch, Mihomo-child, and listener checks. The redacted record is
`target/macos-vm-lab/evidence/app-launch-20260722/pkg-rollback-restore-20260722.txt`.

## GUI termination and session lifecycle evidence — 2026-07-22

A second pass exercised the signed bundle's process and user-session boundary
in the same disposable guest. The exact app executable was validated before a
SIGKILL. The app process and `127.0.0.1:33331` singleton listener disappeared,
but the ordinary bundled `verge-mihomo` proxy core remained as an orphan with
PPID 1. Its full command line used the normal Mihomo config and
`/tmp/verge/verge-mihomo.sock`; it was not the production Go executable
`kyclash-network-sidecar`. The default GUI build does not enable the
`networking-production` feature, so this observation is not counted as a
production network-sidecar result.

The orphan was then checked against its complete expected path and terminated
by its exact PID in the disposable guest. A LaunchServices relaunch produced a
new KyClash process, a child `verge-mihomo`, and the singleton listener again.
The redacted command/output record is retained at
`target/macos-vm-lab/evidence/app-launch-20260722/lifecycle-login-relaunch.txt`.

An additional controller-boundary run used the signed Go executable
`kyclash-network-sidecar` copied into the same disposable guest. An isolated
controller generated ephemeral in-memory bootstrap material, read the sidecar
handshake, and kept its stdin pipe open. After exact command-path validation,
the controller alone was SIGKILLed. The sidecar disappeared within the 10
second poll window when stdin closed; no bootstrap material was written to the
evidence record. The redacted result is retained at
`target/macos-vm-lab/evidence/app-launch-20260722/production-sidecar-controller-kill.txt`.

This closes the signed Go sidecar's controller/EOF process-boundary
observation. It does not claim that the privileged utun or route cleanup gate
is closed; that portion still requires the authorized disposable privileged
run.

The authorized privileged VM run also exercised the standalone forced-
termination fixture `TestRealUTUNHoldForForcedTermination`. The signed lab
binary created the owned `utun4`, published only that interface name to the
fixed `/var/tmp/kyclash-utun-lab-*` path, and was terminated by exact PID
SIGKILL through an interactive sudo session. The interface was present before
termination and an independent privileged `ifconfig` check returned exit
status 1 afterward; the test process was absent as well. Redacted host-side
evidence is retained at
`target/macos-vm-lab/evidence/app-launch-20260722/utun-controller-kill-v3-20260722.txt`.
This proves kernel/device release for the standalone forced-termination case;
it is not a claim that the combined production-sidecar-owned utun controller
matrix or privileged route matrix is complete.

The exact combined controller matrix was then run with the signed production
`run()` boundary. A controller spawned the actual sidecar child and kept the
bootstrap/IPC writer open while the child prepared `utun4`. The controller PID
was validated from the child's parent relation and SIGKILLed; the child and
`utun4` were both absent on the first one-second poll. Redacted evidence is
retained at
`target/macos-vm-lab/evidence/app-launch-20260722/utun-combined-controller-20260722.txt`.
This closes S1.10's real-utun termination gate. The ordinary inherited Mihomo
proxy process surviving an app SIGKILL remains a separate non-production
cleanup limitation; the privileged route and Mihomo coexistence matrix remain
S1.12/S1.13 work.

The newly rebuilt signed bundle was used for a stronger parent-reparent test.
An isolated controller generated bootstrap material in memory and a separate
inherited writer kept the sidecar's stdin open after the controller was
SIGKILLed. Exact executable paths were checked before termination; the sidecar
exited within 100 ms while the writer remained alive, proving the parent-watch
cleanup path rather than relying on stdin EOF. The redacted record is retained
at
`target/macos-vm-lab/evidence/app-launch-20260722/production-sidecar-parent-watch-v3.txt`;
the tested sidecar SHA-256 is
`fd041fc1b5e3d7b7b3498cc7714161a6c0047510c492f734b60659c11f20689b`.
This still does not claim privileged utun or route cleanup completion.

The same pass sent the System Events and `loginwindow` logout actions. After
logout, `who` had no `console` session and independent checks found no KyClash
process, no Mihomo child, and no singleton listener. Restarting only the
disposable Tart guest returned the `supen` console session; its login item
auto-started the signed bundle and restored the listener. The latest clean
foreground capture is retained at
`target/macos-vm-lab/evidence/app-launch-20260722/kyclash-live-vm-home2-20260722.png`;
the earlier login/relaunch image remains in the evidence directory as the
session-transition record.

This closes the observed GUI logout/re-login path, but it does not close S1.10:
an ordinary Mihomo child surviving an app SIGKILL is a separate cleanup
limitation. The signed Go sidecar now has both EOF and parent-reparent
controller-kill observations; both standalone and combined production-sidecar
utun forced-termination subcases are now recorded. S1.10 is complete; the
privileged route and Mihomo coexistence work continues under S1.12/S1.13.

## Installed App and signed route-helper matrix — 2026-07-22

The corrected Developer ID PKG is installed at `/Applications/KyClash.app` in
the disposable guest and has been launched visibly with the KyClash brand,
Mihomo child, and singleton listener alive. The current installed-package
capture is retained at
`target/macos-vm-lab/evidence/app-launch-20260722/kyclash-installed-pkg-live-20260722.png`
with SHA-256
`5630fa3513fbddf96af38c3a78eedf43bd3f327eb42ed2971fc5edf3c83cdea9`.

The same guest then ran the signed production route helper and typed client on
an owned `utun4`. The following hash identifies the historical VM copy that
produced the raw probe below; it is not a current less-specific-coexistence
acceptance artifact:
`39bf4758ad3b346947621f9288c7ec81c2127e50d0787670daede9e4e10c056a`.
The matrix proved:

- dual-stack `begin/apply/status/rollback` succeeds with final route absence;
- exact IPv4 and IPv6 pre-existing routes return `route_conflict`;
- a more-specific `192.0.2.128/25` route also returns `route_conflict` even
  though the network-base lookup resolves through the default underlay;
- the v1 helper used for this historical probe failed closed on every non-
  default overlap, including less-specific `128.0.0.0/1` and `fd00::/8`
  coverage. That probe is superseded and is not current coexistence acceptance
  evidence; the typed active-Mihomo-interface ownership amendment is exercised
  separately by the v2 matrix below;
- no fixed test route, helper journal, helper process, or test utun remained
  after scoped cleanup.

The lookup parser and fail-closed overlap policy are also covered by the
helper's read-only self-test. The raw command/results file is retained only as
historical trace at
`target/macos-vm-lab/evidence/app-launch-20260722/route-helper-dual-conflict-20260722.txt`;
it must not be cited as current less-specific coexistence evidence. This was
partial historical S1.12 evidence and does not substitute for the v2 matrix
below, packaged Mihomo TUN, guest-reboot, or private-service reachability. The
v2 matrix now supplies the typed-ownership and helper journal-corruption/
restart evidence.

## Route-helper v2 fixture matrix

`scripts/macos-vm-route-helper-v2-matrix.sh` is the fixed S1.12/S1.13
fixture-level executor. Its `preflight` and `run` modes require all of the
following before they inspect or mutate the guest:

- macOS arm64 with `hw.model` beginning with `VirtualMac`;
- `KYCLASH_RUNNER_ENVIRONMENT=local-virtualization-framework` and the exact
  `KYCLASH_VM_LAB_CONFIRM` marker;
- the signed helper, primary production-sidecar utun fixture, separate signed
  synthetic-Mihomo utun test binary, and hold client staged as `root:wheel`
  executables below the private `/Library/Application Support/KyClash/route-lab`
  tree by `scripts/prepare-macos-vm-route-fixture.sh`; the same typed client is
  copied byte-for-byte to the fixed root-owned public path
  `/var/tmp/kyclash-route-helper-lab-client-v2.scp` because the private parent
  directory is intentionally mode `700`;
- both fixed launchd fixtures already bootstrapped, an idle v2 helper, and no
  pre-existing matrix route, helper journal, or combined-utun evidence file.

The caller can select only `dry-run`, `preflight`, or `run`; it cannot supply a
CIDR, interface, route command, executable, path, or launchd label. The static
dry-run performs no inspection or mutation:

```bash
scripts/macos-vm-route-helper-v2-matrix.sh dry-run

env -u BASH_ENV -u ENV \
  KYCLASH_RUNNER_ENVIRONMENT=local-virtualization-framework \
  KYCLASH_VM_LAB_CONFIRM=authorized-kyclash-virtualization-framework-vm \
  scripts/macos-vm-route-helper-v2-matrix.sh preflight

env -u BASH_ENV -u ENV \
  KYCLASH_RUNNER_ENVIRONMENT=local-virtualization-framework \
  KYCLASH_VM_LAB_CONFIRM=authorized-kyclash-virtualization-framework-vm \
  scripts/macos-vm-route-helper-v2-matrix.sh run
```

Use a clean shell boundary: unset inherited startup hooks (`BASH_ENV`/`ENV`)
before setting the two fixed confirmation variables. Bash reads these hooks
before a script can unset them internally, so leaving either variable set is
not an accepted invocation. The script itself still rejects every non-
`VirtualMac` guest and requires interactive `sudo`.

The preparer is fail-closed around the privileged boundary: it uses a fixed
system `PATH` and restrictive `umask`, verifies every staged executable/client
and launchd plist as a root-owned single-link file, pre-creates the launchd
stdout/stderr target as a root-owned `0600` file below the private stage tree,
and accepts only an explicitly absent launchd job during bootout. It waits for
both the job and its exact staged process to disappear before replacing or
removing them. User-writable binary and plist inputs are first copied to fixed
root-owned incoming files and revalidated there before they replace any
launchd-referenced slot. `remove` refuses to erase any synthetic-Mihomo owner
evidence or running fixture it cannot prove safe; inspect and clean that
evidence with the matrix's bounded cleanup first.

The current guest pre-populates both TEST-NET blocks on its `en0` underlay
(`192.0.2.0/24` and `198.51.100.0/24`), so the v2 fixture deliberately uses the
fixed private pair `10.200.0.0/16` and synthetic IPv6 `fd00:200::/48`, which
the guest route check confirms are absent. The run is restricted to those
fixed desired routes, their fixed `/24` and `/64` conflict probes, and their
fixed `/15` and `/47` covering-route probes. It never changes a default route
or DNS. The preflight overlap guard rejects an existing route within the fixed
`10.200.0.0/16`/`10.200.0.0/15` or `fd00:200::/48`/`fd00:200::/47` matrix
prefixes and probes representative addresses to catch less-specific coverage
(`10/8`, `10.128/9`, `fd00::/8`, or split-default routes). Unrelated guest
routes such as `10.127.0.0/16` and the combined fixture's own `10.90.0.1` host
route are not treated as collisions.
It covers v2 discovery, normal dual-stack apply/rollback, exact and
more-specific conflict refusal, an unknown-interface covering conflict, the
empty/wrong/matching `--mihomo-utun` boundary, helper kill/restart recovery,
corrupt-journal fail-closed behavior, and final route/journal/lease absence.
Its exit trap may remove only a route it recorded with the exact fixed
destination and interface, an exact PID it started, or the byte-identical
corrupt journal it installed. Evidence is copied as root-owned files below
`/Library/Application Support/KyClash/route-lab/evidence-v2`.

The retained primary launchd fixture writes exactly two root-owned `0600` lines
to `/var/tmp/kyclash-utun-lab-combined-hold.evidence`: the canonical primary
utun name and the production-sidecar child PID. Preflight verifies both lines,
the live launchd controller PID, the exact staged fixture command, and that the
recorded child has that controller as its direct parent before using the
interface.

The two Go test binaries are intentionally distinct: the launchd primary is the
`cmd/kyclash-network-sidecar` package (combined production controller/child),
while the second carrier is built from `internal/userspace`, which contains
`TestRealUTUNHoldForForcedTermination`. A source staging directory must contain
both fixed names, `kyclash-utun-lab.test` and
`kyclash-utun-mihomo-lab.test`; the preparer rejects a missing or unsigned
second binary instead of silently running a no-tests binary.

For a host-built arm64 fixture directory (under ignored `target/`), the two
test binaries can be produced with the same locked tags:

```bash
mkdir -p target/macos-vm-lab/v2-fixture
(cd network-sidecar && \
  go test -c -tags='kyclash_utun kyclash_utun_lab' \
    -o ../target/macos-vm-lab/v2-fixture/kyclash-utun-lab.test \
    ./cmd/kyclash-network-sidecar)
(cd network-sidecar && \
  go test -c -tags='kyclash_utun kyclash_utun_lab' \
    -o ../target/macos-vm-lab/v2-fixture/kyclash-utun-mihomo-lab.test \
    ./internal/userspace)
```

Each output must be Developer ID signed for Team ID `RQUQ8Y3S9H` before it is
copied into the guest staging directory; the preparer performs the strict
signature, arm64, owner, and mode checks again.

The pre-staged primary utun launchd fixture is intentionally left running so
the guest remains ready for the next isolated probe; the script stops and
checks absence of only the second synthetic utun it starts. Use the fixture
script's explicit `remove` mode when discarding the disposable guest. The
matrix's final-absence assertion is specifically for the fixed routes, journal,
and XPC lease, not for an intentionally retained primary fixture.

The second utun in this script is a signed synthetic carrier fixture. This
matrix validates the root-staged signed helper and typed v2 ownership boundary,
but it is not proof that the helper came from the installed app, nor is it
packaged-Mihomo/live-control-API, private-service reachability, guest-reboot, or
physical active-VPN coexistence evidence. It therefore does not by itself close
S1.13.

### v2 matrix run — 2026-07-22

The refreshed signed fixtures were staged and verified in the authorized
`VirtualMac2,1` guest with the fail-closed preparer (including bootout,
root-owned incoming validation, and atomic replacement), then the complete
`run` matrix passed. The redacted matrix log is retained at
`target/macos-vm-lab/evidence/route-helper-v2-20260722/route-helper-v2-matrix.log`
with SHA-256
`7054e0c0cf66b73e969ea880cd8a901eb4a71f68419feb205b8587b4b8645661`; the
synthetic owner log is beside it with SHA-256
`9df6a2394737ae626c1effcacc7452a8403e0f4eb1630e007decb2fbba3de7dc`.

Observed cases were dual-stack normal apply/rollback, exact and more-specific
conflicts even when the interface was presented as Mihomo, unknown-interface
covering conflict, empty/wrong/matching typed Mihomo covering classification,
helper SIGKILL/restart recovery, corrupt-journal error 8, and final absence of
the fixed routes, journal, and lease. The guest retained only the intentionally
running primary `utun4` hold fixture; the synthetic `utun5` and all matrix
routes were absent after cleanup. This closes the S1.12 v2 route-lease gate and
advances S1.13, but does not claim packaged Mihomo live API, private-service,
reboot, or physical coexistence evidence.

## Packaged Mihomo live-control matrix

The installed-package portion of S1.13 is implemented as the separate `live-*`
modes of `scripts/macos-vm-route-helper-v2-matrix.sh`. Static checks and the
mutating `live-run` passed in the authorized `VirtualMac2,1` work guest on
2026-07-22. The exact script used for the passing run had SHA-256
`f8ebda542ea98720b46eb35e18f48f4ece7ce5b1571c84507e6dd4c100859061`.
The root-owned log was copied to
`target/macos-vm-lab/evidence/packaged-mihomo-v2-790b3e50/packaged-mihomo-v2-matrix.log`;
its SHA-256 is
`a504fbe6c017b0719bca258b21a6f1a05fce1268d9c487d85245c8873b2fa317`.

The live boundary accepts only the installed `/Applications/KyClash.app` with
the `net.kysion.kyclash` package receipt, an intact Developer ID app seal, Team
ID `RQUQ8Y3S9H`, and the fixed nested identifiers. The root-staged helper must
be byte-identical to the installed app helper. Mihomo runs from the installed
bundle with a fixed DIRECT-only JSON configuration, explicit `utun4094`, a
root-private Unix controller socket, no TCP controller, no DNS section, and
only `10.200.0.0/15` plus `fd00:200::/47` auto-routes. The script retains only
allowlisted evidence from live `/configs`: `tun.enable` and `tun.device`. The
same signed lab client independently calls `if_nametoindex`; it is a test
harness and is intentionally not shipped in `KyClash.app`.

`live-preflight` fails closed if any packaged Mihomo process is already
running, if the managed app socket `/tmp/verge/verge-mihomo.sock` exists (even
as a stale path), or if the fixed lab job, directory, interface, route, journal,
or socket already exists. Do not delete or adopt ambiguous state. Quit the app
cleanly or reboot the disposable guest, then rerun preflight.

Prepare the already signed v2 fixtures exactly as for the synthetic matrix,
but copy the helper from the installed app so the later byte comparison is
authoritative. The client must be rebuilt after changes to `lab-client.m` so it
contains the read-only `--if-nametoindex` mode:

```bash
fixture_dir=/var/tmp/kyclash-packaged-mihomo-v2-fixture
mkdir -m 700 "${fixture_dir}"
cp /Applications/KyClash.app/Contents/Resources/kyclash-route-helper \
  "${fixture_dir}/kyclash-route-helper-fixed"
# Copy the current signed primary/synthetic utun fixtures and current signed
# lab client into this directory under the existing four fixed fixture names.

env -u BASH_ENV -u ENV \
  KYCLASH_VM_LAB_CONFIRM=authorized-kyclash-virtualization-framework-vm \
  scripts/prepare-macos-vm-route-fixture.sh stage "${fixture_dir}"
env -u BASH_ENV -u ENV \
  KYCLASH_VM_LAB_CONFIRM=authorized-kyclash-virtualization-framework-vm \
  scripts/prepare-macos-vm-route-fixture.sh bootstrap

env -u BASH_ENV -u ENV \
  scripts/macos-vm-route-helper-v2-matrix.sh live-static-check
env -u BASH_ENV -u ENV \
  KYCLASH_RUNNER_ENVIRONMENT=local-virtualization-framework \
  KYCLASH_VM_LAB_CONFIRM=authorized-kyclash-virtualization-framework-vm \
  scripts/macos-vm-route-helper-v2-matrix.sh live-preflight
env -u BASH_ENV -u ENV \
  KYCLASH_RUNNER_ENVIRONMENT=local-virtualization-framework \
  KYCLASH_VM_LAB_CONFIRM=authorized-kyclash-virtualization-framework-vm \
  scripts/macos-vm-route-helper-v2-matrix.sh live-run
```

The live matrix covers just-in-time `/configs` resampling, matching kernel
interface existence, IPv4/IPv6 less-specific coexistence, empty/wrong/unknown
classification, exact and more-specific refusal, Mihomo stop/restart, default-
route refusal, and final absence of its process, socket, utun, fixed routes,
journal, and lease. It deliberately does not claim the independent private-
service reachability, guest-reboot, app-abort, synthetic-credential, or physical
Mac portions of S1.13.

The first mutating run failed closed after launchd stopped Mihomo because the
process left its Unix socket pathname behind even though the exact PID,
`utun4094`, and covering routes were already gone. The cleanup trap validated
and removed the owned path. The executor was hardened to remove that exact
socket only after confirming its root ownership, single link, root-private
parent, absent job/process/utun/routes, and no open file holder. A clean
preflight followed by a full rerun then passed. Observed Mihomo PIDs changed
from 8086 to 9079 across restart; final process, socket, `utun4094`, fixed
routes, journal, and lease were all absent.

## Installed App-managed TUN matrix

`scripts/macos-vm-app-managed-tun-matrix.sh` passed in the same disposable
`VirtualMac2,1` guest against the freshly installed, Developer ID-signed
internal PKG. The script refuses the host and the base image, atomically moves
the entire guest user's App-data directory to a private backup, installs only
hash-pinned DIRECT fixtures, and launches `/Applications/KyClash.app` through
guest LaunchServices.

The passing run proved a frontmost visible guest window, the exact App and
root-owned packaged Mihomo executable paths, live `tun.enable=true`, fixed
`utun4093`, and disabled auto-route. A continuous monitor proved unchanged
system DNS, proxy state, IPv4/IPv6 default routes, and existing RFC1918/ULA
routes. Cleanup removed the App, Mihomo, Unix socket, and utun and restored the
same original App-data directory object. The 29-line redacted log is retained
under `target/macos-vm-lab/evidence/app-managed-tun-v1-20260722/` with SHA-256
`1e06355753e3856e01ac3e1aaf6f18687b8a6a6cb96d41e9f84c124abd6095bd`.

The run also exercised fail-closed recovery: an interrupted attempt restored
the original directory and left no runtime. This matrix proves ordinary App-
managed Mihomo behavior; it does not claim that the default-off production
Rust live-source adapter was invoked.

## Disposable test cycle

```bash
scripts/macos-vm-lab.sh clone
scripts/macos-vm-lab.sh run
```

Inside the disposable guest, copy any required build output to a guest-writable
directory before executing it. The repository is not mounted in the guest.
Publish only the exact reviewed public artifacts into `kyclash-staging`; never
place source trees, build caches, credentials, or private keys there. The
current dual-VM procedure is
[`kyclash-vm-external-peer-lab-app.md`](kyclash-vm-external-peer-lab-app.md).

The former workflow that executed `scripts/macos-system-lab.sh` directly from
a whole-repository share is retired. Re-running that historical system lab now
requires a separate reviewed builder and exact-artifact publisher; do not
restore the repository mount or manually copy a source/build tree into the
guest. Its existing evidence remains historical and does not authorize a new
runtime.

After collecting redacted evidence, stop and discard the work VM. VM deletion
is intentionally not automated by the repository script: inspect `tart list`
and explicitly delete only `kyclash-macos-lab-work` with Tart when appropriate.

## Coverage boundary

This VM is accepted for `.pkg` install/upgrade/uninstall, Developer ID signature,
Gatekeeper, synthetic Keychain, fixed route, crash recovery, GUI smoke, and
updater rollback tests. A physical Mac remains required for sleep/wake,
Wi-Fi/Ethernet handoff, and final coexistence testing with a real active VPN.
