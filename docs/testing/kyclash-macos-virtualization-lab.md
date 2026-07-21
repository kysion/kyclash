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

The same pass sent the System Events and `loginwindow` logout actions. After
logout, `who` had no `console` session and independent checks found no KyClash
process, no Mihomo child, and no singleton listener. Restarting only the
disposable Tart guest returned the `supen` console session; its login item
auto-started the signed bundle and restored the listener. A clean GUI capture
is retained at
`target/macos-vm-lab/evidence/app-launch-20260722/kyclash-login-relaunch.png`
with SHA-256
`491c86a8be8900fca41608ba595100e2ad06271ea0cbd93bf7f841c4d6ab48e4`.

This closes the observed GUI logout/re-login path, but it does not close S1.10:
an ordinary Mihomo child surviving an app SIGKILL is a separate cleanup
limitation. The signed Go sidecar controller/EOF boundary is observed, while
privileged utun child absence after controller kill still needs its exact VM
observation. S1.10 remains in progress.

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
