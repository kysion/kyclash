# KyClash VM utun lab App

This is the explicit no-sign `.app` path for the selected disposable
`kyclash-macos-lab-work` guest. It is not the production broker, route helper,
installer, or release artifact.

## Host build boundary

Build the root harness on the Apple Silicon host only as a cross-build. The
command does not start it, open the App, create utun, mutate routes, or contact
the VM:

```sh
corepack pnpm macos:vm-utun-lab:harness
```

The output under `target/macos-vm-lab/build/vm-utun-lab/` is host-build
provenance only. It must be copied to the guest before any runtime action.

The App-only builder is also host-build only and requires the separately
prepared, loopback-scoped public VM-lab resources:

```sh
corepack pnpm macos:production-vm:app \
  --lab-public-root "$PWD/target/macos-vm-lab/<run>/candidate/public" \
  --sidecar "$PWD/src-tauri/sidecar/kyclash-network-sidecar-aarch64-apple-darwin"
```

It uses only `networking-vm-utun-lab-app` for the disposable candidate, passes
`--bundles app --no-sign`, and emits no DMG/PKG. The derived overlay removes
route-helper/tunnel-broker binaries and all LaunchDaemons mappings.

## Guest-only authorization

Before starting the harness, open a visible Terminal in the selected guest and
re-prove `VirtualMac*`, arm64, the logged-in console user, and the exact guest
name. Copy the fixed harness to a guest-private directory. Start it with the
fixed markers below; macOS will present the one local administrator prompt:

```sh
sudo env \
  KYCLASH_RUNNER_ENVIRONMENT=local-virtualization-framework \
  KYCLASH_VM_LAB_CONFIRM=authorized-kyclash-virtualization-framework-vm \
  KYCLASH_RUNTIME_TARGET=kyclash-macos-lab-work \
  /private/var/tmp/kyclash-vm-utun-lab-harness
```

The user must type the password visibly in that guest Terminal. No password is
passed through SSH, argv, stdin, environment, scripts, logs, or evidence.
`sshpass`, `sudo -S`, and UI scripting of the prompt are forbidden.

The harness creates exactly one socket, owned by the console user and mode
`0600`:

```text
/var/run/net.kysion.kyclash.vm-utun-lab.sock
```

It accepts one same-user App stream, verifies the root peer, then reuses the
authenticated protocol-v2 bootstrap and starts the fixed loopback
QUIC/WSS/TCP cluster. `PrepareTunnel` creates the real wireguard-go utun;
Connect exercises QUIC → WSS → TCP break-before-make. The App never installs
private routes, calls route-helper/XPC, reads Keychain, changes DNS, or contacts
a production endpoint.

## App and cleanup evidence

Build the App with `VITE_NETWORKING_VM_UTUN_LAB=true` and
`VITE_NETWORKING_SYSTEM_LAB=true`, copy it into the guest, and launch it there.
The page must visibly say:

```text
VM LAB · REAL UTUN · NO ROUTES
runtime_mode=vm_utun_lab
tunnel_kind=darwin_utun
routes_installed=false
```

Disconnect the App before closing the harness. An App EOF or harness signal
must close the exact WireGuard device, clear bootstrap material, stop the
loopback cluster, remove the exact socket, and leave no utun. Capture guest
`ifconfig`/process/socket absence only after independently proving
`VirtualMac*`; label the manifest `runtime_target=kyclash-macos-lab-work`.

These observations are lab evidence only. They do not close production
route-helper v3, privileged broker registration, private-route or Mihomo
coexistence, signing, install, release, updater, or S1 aggregate gates.
