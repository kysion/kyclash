# KyClash VM utun lab App build

This path produces one unsigned Apple Silicon `KyClash.app` for the selected
disposable macOS VM. It compiles only the explicit
`networking-vm-utun-lab-app` feature
and accepts a current, loopback-scoped VM-lab public resource set. The visible
Connect path remains the separate VM-only lab command surface; it uses the fixed
`/var/run/net.kysion.kyclash.vm-utun-lab.sock` contract and cannot invoke the
production XPC route path.

The input directory still uses the reviewed legacy
`networking-production-vm-lab` public marker schema as a read-only compatibility
container for the run-bound loopback policy and resource hashes. That marker
does not enable a Cargo production feature, grant production authority, or
permit the derived App to retain helper, broker, XPC, route, or signing paths.
`result.json` records this explicitly as
`resource_marker_grants_production_authority=false`.

It does not sign or notarize the App, create a DMG/PKG, enable updater
artifacts, publish anything, contact the VM, launch the App on the host, or
accept an endpoint, password, token, key, certificate, or signing identity.
The explicitly supplied sidecar is checked as a bounded executable, thin
arm64 Mach-O, and byte-for-byte bundle input. Its Team ID, designated
requirement, and signature are not prerequisites for this no-sign lab build.
Privileged route-helper, tunnel-broker, LaunchDaemons, SMAppService, and
production compile-marker resources are deliberately excluded from this App.

## Build

Prepare and seal the public VM-lab resources with the existing scoped fixture,
then invoke the App-only builder with explicit absolute inputs:

```sh
PUBLIC_ROOT="$PWD/target/macos-vm-lab/<run>/candidate/public"
SIDECAR="$PWD/target/macos-vm-lab/build/kyclash-network-sidecar-lab"

corepack pnpm macos:production-vm:app \
  --lab-public-root "$PUBLIC_ROOT" \
  --sidecar "$SIDECAR"
```

To validate the resource/sidecar contract without compiling:

```sh
corepack pnpm macos:production-vm:app \
  --lab-public-root "$PUBLIC_ROOT" \
  --sidecar "$SIDECAR" \
  --validate-only
```

The build uses a new private directory below
`target/macos-vm-lab/build/production-app-nosign/` and prints the exact App
path, App tree SHA-256, and a redacted `result.json`. The result records the
source commit plus dirty-tree, staged-diff, worktree-diff, and source-tree
SHA-256 fingerprints; the build fails if the workspace source changes while
Tauri is compiling. This keeps a dirty development tree auditable instead of
claiming that `HEAD` alone describes the App. It verifies that the main
executable and sidecar are arm64-only, that the explicit sidecar and loopback
policy resources were bundled byte for byte, and that no `.pkg` or `.dmg` was
produced.

Each run is marked inside that generated directory. A later invocation removes
only previously marked KyClash no-sign build runs, and uses a non-incremental
release profile with debug info disabled to keep disposable VM builds from
consuming the host disk. No user directory outside this scoped target path is
cleaned.

## Scope

This is a disposable-VM development artifact, not a release candidate or a
production-composition candidate. The VM App's visible path is the
`networking-vm-utun-lab-app` harness. It intentionally does not bundle
privileged route-helper/tunnel-broker resources, does not register
SMAppService/XPC helpers, and cannot claim production route ownership. Normal
KyClash builds still omit both lab and production features; this explicit
command adds only the VM-utun lab feature. The visible lab connection must
report `runtime_mode=vm_utun_lab`, `tunnel_kind=darwin_utun`, and
`routes_installed=false`; it cannot select or bypass any production gate.

A successful build alone proves none of the runtime claims. Real-utun,
loopback QUIC -> WSS -> TCP, EOF cleanup, and final interface/socket absence
must be observed in `kyclash-macos-lab-work`. Private-route and packaged-Mihomo
coexistence remain production helper/XPC acceptance and cannot be inferred
from this lab App even after its real-utun run passes.

The fixed root harness is staged but its guest runtime still waits for one
visible Terminal `sudo` authorization. SSH uses the dedicated VM key and does
not need a password. Never use `sshpass`, `sudo -S`, scripted stdin, Keychain
retrieval, or UI password injection; no password may enter argv, environment,
source, logs, or evidence.
