# KyClash external-peer VirtualMac App lab

This is the App-only acceptance path for KyClash's current core-networking
slice. Its reviewed topology is:

```text
kyclash-macos-lab-work                 kyclash-macos-lab-peer
10.88.0.1/32 -- real utun -- WG over QUIC/WSS/TCP -- 10.88.0.2
```

The current implementation is a two-disposable-VM lab, not a production
control plane, public relay, or multi-user mesh service. Until the dual-VM run
passes, source and isolated tests must not be reported as working networking.

## App-only build

The fixed build takes no arguments and produces only an unsigned
`KyClash.app`:

```sh
corepack pnpm macos:vm-external-peer-lab:app
```

It does not sign, notarize, install, generate a DMG/PKG, create updater
metadata, publish a release, or embed the privileged supervisor, harness,
Mihomo, route helper, tunnel broker, endpoint, certificate, or credential.
The App talks only to the authenticated fixed Unix socket inside
`kyclash-macos-lab-work`.

The fixed data-plane binaries are built separately for root staging in their
reviewed VM roles:

```sh
corepack pnpm macos:vm-external-peer-lab:binaries
```

Nothing produced by either command may be executed on the host or on the
stopped base VM.

The separate fixed host courier, management-key bootstrap, explicit host-key
pin, and cancel-safe `start-lab` contract are documented in
`docs/testing/kyclash-vm-external-peer-host-start-lab.md`. Building that
courier is Layer A; executing `start-lab` remains Layer B.

## Create-only guest staging

The binary build also emits eight thin-arm64 guest staging commands: four for
the client role and four for the peer role. They accept no arguments and run
only as root inside their exact `VirtualMac*` target. They do not launch the
App, a supervisor, a carrier, Mihomo, a tunnel, or a route.

Staging is intentionally split so a collected listener inventory can never
become a runtime allowlist merely because macOS created it:

| Phase | Client command | Peer command | Mutation boundary |
| --- | --- | --- | --- |
| Layer A | `kyclash-vm-external-peer-lab-client-stage-layer-a` | `kyclash-vm-external-peer-lab-peer-stage-layer-a` | installs only the App/fixed role binaries and writes a root-owned listener inventory for review |
| Layer A SSH bootstrap | `kyclash-vm-external-peer-lab-client-bootstrap-ssh-layer-a` | `kyclash-vm-external-peer-lab-peer-bootstrap-ssh-layer-a` | after Layer A, installs the role-specific management public key and hardened sshd policy; the peer also creates/verifies the restricted account and regenerates only its own SSH host keys |
| Layer B prepare | `kyclash-vm-external-peer-lab-client-prepare-layer-b` | `kyclash-vm-external-peer-lab-peer-prepare-layer-b` | after the reviewed bridged IP facts exist, calls `NewListenerBaseline` and writes a candidate plus hash witness; it does not pin runtime files |
| Layer B pin | `kyclash-vm-external-peer-lab-client-pin-layer-b` | `kyclash-vm-external-peer-lab-peer-pin-layer-b` | accepts only a separately approved byte-identical baseline, re-audits the live listener set, then creates the config and exact runtime manifest |

Each command must be copied into its own fixed console-user-owned mode-`0700`
input directory and changed to mode `0500`. Every other regular input is
mode `0600`; executable inputs are mode `0500`. The command refuses an extra
entry, symlink, hard link, wrong owner/mode, replacement, changed stable-file
identity, pre-existing destination, or repeated run.

The fixed input directories are:

```text
/private/var/tmp/kyclash-vm-external-peer-lab-staging-input/client-layer-a
/private/var/tmp/kyclash-vm-external-peer-lab-staging-input/client-ssh-bootstrap-layer-a
/private/var/tmp/kyclash-vm-external-peer-lab-staging-input/client-layer-b-prepare
/private/var/tmp/kyclash-vm-external-peer-lab-staging-input/client-layer-b-pin
/private/var/tmp/kyclash-vm-external-peer-lab-staging-input/peer-layer-a
/private/var/tmp/kyclash-vm-external-peer-lab-staging-input/peer-ssh-bootstrap-layer-a
/private/var/tmp/kyclash-vm-external-peer-lab-staging-input/peer-layer-b-prepare
/private/var/tmp/kyclash-vm-external-peer-lab-staging-input/peer-layer-b-pin
```

Layer A input is role-specific. The client directory contains the command,
`KyClash.app` (top directory mode `0700`, no symlinks), client supervisor,
client harness, `mihomo`, and `mihomo-config.json`. The peer directory
contains its command, peer root supervisor, peer child, listener auditor, and
forced-command helper.

The client SSH-bootstrap input contains only its command and the canonical raw
`ssh.PublicKey.Marshal()` bytes in
`client-management-ed25519-public.bin`. The peer uses a different key in
`peer-management-ed25519-public.bin`; neither file is authorized-keys text,
and no private key enters a guest. The commands require Remote Login to
already be enabled visibly in System Settings. They never enable it, automate
a prompt, or accept a password.

The SSH bootstrap installs a create-only early sshd drop-in and proves the
effective configuration with `sshd -T`: public-key-only authentication,
root/password/keyboard-interactive authentication disabled, forwarding
disabled, and `AllowUsers` restricted to the console account on the client or
the console account plus `kyclashlabssh` on the peer. The peer-only account is
fixed to UID `502`, GID `20`, is non-admin and password-locked, and starts
with a mode-`0600` empty `authorized_keys` beneath its mode-`0700` `.ssh`.
Only the signed run-bound forced key may replace that empty baseline later.

Only the peer command backs up and regenerates the fixed Ed25519, ECDSA, and
RSA system host-key files; the client host keys must remain unchanged. Before
any dangerous mutation, the command records exact original identities and
root-private backups under
`/private/var/db/net.kysion.kyclash.vm-external-peer-lab/`. A failed or
interrupted attempt restores only those witnessed files and accounts; it
never uses a glob or touches the stopped base VM. Each role then publishes
only these public review artifacts:

```text
management-ssh-host-ed25519-public.bin
management-ssh-host-ed25519-fingerprint.txt
management-ssh-bootstrap-witness-v1.json
```

The raw host-public-key file and fingerprint must be imported into the
role-separated host known-hosts review. TOFU and a shared client/peer key are
forbidden. Layer B prepare refuses to proceed unless the listener inventory
and all three SSH-bootstrap review artifacts exist exactly.

Both Layer B prepare directories contain only their command plus:

```text
peer-config-v1.json
run-ticket-expectation-v1.json
courier-ed25519-public.bin
```

The config and run-ticket expectation are generated only after the Layer B
client/peer IP and identity facts are known. They are public-policy inputs,
not Layer A defaults. The prepare command writes the candidate to the fixed
role review directory and prints its path and SHA-256. A human must review
every exact listener allowance, including the explicit `launchd_pid1` fact,
then copy those unchanged bytes into the pin input as
`approved-listener-baseline-v1.json`. The pin input otherwise has the same
three files as prepare. The pin command rejects a changed config, expectation,
courier key, candidate, approval, or live listener set.

The visible guest-console invocation supplies only the already locked VM
confirmation markers:

```sh
sudo env \
  KYCLASH_RUNNER_ENVIRONMENT=local-virtualization-framework \
  KYCLASH_VM_LAB_CONFIRM=authorized-kyclash-virtualization-framework-vm \
  KYCLASH_RUNTIME_TARGET=kyclash-macos-lab-work \
  /private/var/tmp/kyclash-vm-external-peer-lab-staging-input/client-layer-a/kyclash-vm-external-peer-lab-client-stage-layer-a
```

Use `kyclash-macos-lab-peer` for the peer commands. Administrator
authentication is typed visibly in that VM console. Password piping,
`sshpass`, `sudo -S`, remote root startup, and running a staging command on
the host or base VM are forbidden.

The client pin creates App manifest schema v2 with the App and harness
device/inode/size/SHA-256 plus config, expectation, courier-key, and approved
baseline hashes. The peer pin creates the strict peer staging manifest with
device/inode/size/SHA-256 for every runtime file. Both use create-only
destinations. The shared client stage root is root-owned mode `0700`, matching
the client supervisor, harness, and Mihomo runtime checks.

## SSH behavior

SSH traffic is carried inside the WireGuard private route; it must never reach
the peer through the bridged `en0` path by accident.

- `10.88.0.2:22` is the in-process, run-bound, public-key-only proof service.
  It accepts one fixed nonce command and provides no interactive shell.
- `10.88.0.2:2222` is the fixed proxy to the peer VM's
  `127.0.0.1:22`. Automated acceptance uses the restricted
  `kyclashlabssh` account and one forced command through Apple's
  `/usr/bin/ssh`.
- A normal management account can theoretically use
  `ssh -p 2222 user@10.88.0.2` only when the peer's effective sshd policy and
  that user's public key independently allow it. Interactive shell/SCP/port
  forwarding are not part of the currently locked acceptance claim and must
  not be reported as verified.

Every automated SSH connection is bound to source `10.88.0.1` and the exact
KyClash-owned `utunN`. QUIC and WSS require the in-process proof; the final TCP
carrier additionally requires the Apple OpenSSH proof.

## Authorization boundary

Layer A permits source work, builds, creation of the disposable peer clone,
and visible/default-NAT isolated bootstrap. It does not permit a bridged
carrier run.

Before `--net-bridged=en0`, the fresh Layer B record must positively bind the
exact user-owned disposable lab LAN, both VM identities and regenerated SSH
host keys, closed listener baselines, private RFC1918 addresses, run window,
and absence of production/corporate/shared systems. No bridge or Connect is
allowed merely because an address is RFC1918.

No password, token, private key, signing credential, or private certificate
may enter the repository, argv, environment, logs, screenshots, evidence, or
the other VM. Guest administrator authorization is typed visibly into macOS;
`sshpass`, `sudo -S`, password piping, and UI password automation are
forbidden.

## Passing result

One visible App run passes only when all of these are observed in the same
authorized session:

1. the client owns a real `utunN` with `10.88.0.1/32`;
2. carrier health precedes the exact `10.88.0.2/32` route;
3. private echo, fixed SSH proof, and Mihomo `utun4094` coexistence pass;
4. typed carrier-unhealthy evidence precedes each explicit
   QUIC → WSS → TCP break-before-make transition;
5. TCP also passes Apple's `/usr/bin/ssh` forced-command probe; and
6. Disconnect, App EOF, peer loss, and supervisor cleanup leave no owned
   route, utun, listener, process, socket, journal, public run file, or
   authorized-key line.

The base VM remains stopped throughout and is never evidence.
