# KyClash local macOS Virtualization.framework lab

Status: local fixed-scope system lab passed; PKG lifecycle in progress

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
