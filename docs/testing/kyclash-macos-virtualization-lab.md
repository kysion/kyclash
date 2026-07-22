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
- Repository share: read-only, exposed as
  `/Volumes/My Shared Files/kyclash` inside the guest.

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
Remote Login was not enabled at first boot, so SSH automation remains pending.

To enable password-free automation without sharing the guest password, generate
a VM-only key under the ignored `target/macos-vm-lab/ssh` directory. In the
guest, enable **System Settings → General → Sharing → Remote Login**, then run:

```bash
mkdir -p ~/.ssh
chmod 700 ~/.ssh
cat '/Volumes/My Shared Files/kyclash/target/macos-vm-lab/ssh/id_ed25519.pub' \
  >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

The private key must remain under ignored `target/`, must never be printed or
committed, and must be deleted when the disposable work VM is discarded.

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
- the current helper fails closed on every non-default overlap, including
  less-specific `128.0.0.0/1` and `fd00::/8` coverage. The historical
  less-specific probe is superseded and is not current coexistence acceptance
  evidence; a typed active-Mihomo-interface ownership amendment is required
  before such coverage may be allowed;
- no fixed test route, helper journal, helper process, or test utun remained
  after scoped cleanup.

The lookup parser and fail-closed overlap policy are also covered by the
helper's read-only self-test. The raw command/results file is retained only as
historical trace at
`target/macos-vm-lab/evidence/app-launch-20260722/route-helper-dual-conflict-20260722.txt`;
it must not be cited as current less-specific coexistence evidence. This
advances S1.12 only and does not substitute for the typed ownership amendment,
packaged Mihomo TUN, journal-corruption/restart, guest-reboot, or
private-service reachability matrix.

## Disposable test cycle

```bash
scripts/macos-vm-lab.sh clone
scripts/macos-vm-lab.sh run
```

Inside the disposable guest, copy any required build output to a guest-writable
directory before installing it. Never write build products into the read-only
repository share.

Run the fixed-scope system lab only after Rust and the project dependencies are
available in the guest:

```bash
cd '/Volumes/My Shared Files/kyclash'
KYCLASH_RUNNER_ENVIRONMENT=local-virtualization-framework \
KYCLASH_VM_LAB_CONFIRM=authorized-kyclash-virtualization-framework-vm \
  scripts/macos-system-lab.sh
```

For the current Apple Silicon host and guest pair, the binaries may instead be
rebuilt on the host and copied from the read-only share into the guest's private
build directory. This mode is accepted only after the same `VirtualMac` check:

```bash
# Host
cargo build -p clash-verge \
  --features networking-route-lab,networking-keychain-lab,networking-system-lab \
  --bin kyclash-route-lab --bin kyclash-keychain-lab

# Guest, from the read-only repository share
KYCLASH_MACOS_LAB_OUTPUT="$HOME/kyclash-lab/evidence" \
KYCLASH_MACOS_LAB_BUILD="$HOME/kyclash-lab/build" \
KYCLASH_MACOS_LAB_USE_PREBUILT=1 \
KYCLASH_RUNNER_ENVIRONMENT=local-virtualization-framework \
KYCLASH_VM_LAB_CONFIRM=authorized-kyclash-virtualization-framework-vm \
  scripts/macos-system-lab.sh
```

The script independently verifies that `hw.model` starts with `VirtualMac`,
requires the exact confirmation string, restricts Keychain operations to
`net.kysion.kyclash.test`, and restricts route mutation to `192.0.2.0/24` on
`lo0`. It refuses a physical Mac even if the environment variables are copied.

After collecting redacted evidence, stop and discard the work VM. VM deletion
is intentionally not automated by the repository script: inspect `tart list`
and explicitly delete only `kyclash-macos-lab-work` with Tart when appropriate.

## Coverage boundary

This VM is accepted for `.pkg` install/upgrade/uninstall, Developer ID signature,
Gatekeeper, synthetic Keychain, fixed route, crash recovery, GUI smoke, and
updater rollback tests. A physical Mac remains required for sleep/wake,
Wi-Fi/Ethernet handoff, and final coexistence testing with a real active VPN.
