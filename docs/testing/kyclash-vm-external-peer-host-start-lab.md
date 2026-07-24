# KyClash external-peer host `start-lab`

This is the checked-in host courier for the locked two-`VirtualMac` lab. The
source and mock gates described here do not boot a VM, attach a bridge, run
SSH, mutate a route, or start a guest supervisor. Executing `start-lab`
remains a Layer B action and requires that run's separate bridge and Connect
authorization.

## Build result

```sh
corepack pnpm macos:vm-external-peer-lab:host-courier
```

The build accepts no arguments. Every invocation creates a new mode-`0700`
`target/macos-vm-lab/build/vm-external-peer-lab/host/run.*` directory. It
writes `result.json` only after the binary is complete and the source
commit, dirty status digest, complete source-tree digest, and file count are
unchanged from the pre-build snapshot. A failed or source-raced run never
overwrites or reuses an older artifact.

Read the new `result.json` to locate that run's binary. The binary has only
seven exact subcommands and accepts no path, VM, IP, user, credential, or
endpoint argument:

```text
key-init
management-key-init
management-host-key-pin
layer-a-inputs-init
layer-b-inputs-init
layer-b-listener-baseline-approve
start-lab
```

## Fixed Layer A input publication

`layer-a-inputs-init` accepts no arguments. It consumes exactly one complete
binary build result and one complete App build result from their fixed build
roots. Before publishing anything, it verifies:

- the pinned Go 1.26.5 identity and the complete, closed Go build environment;
- exact source snapshot equality between the binary and App builds;
- all 14 role/target/tag-bound thin arm64 Mach-O artifacts;
- `sha256.txt`, provenance, and result-file digests;
- the complete `KyClash.app` tree against `app-tree-manifest.json`;
- the fixed Mihomo binary/config digests; and
- the courier public key plus two different canonical role management public
  keys without reading any guest-bound private key.

It publishes one create-only tree:

```text
target/macos-vm-lab/guest-share/layer-a-inputs
├── client-layer-a
├── client-ssh-bootstrap-layer-a
├── peer-layer-a
└── peer-ssh-bootstrap-layer-a
```

The client input carries both `KyClash.app` and the exact
`app-tree-manifest.json` bytes bound by the App build result. Executables are
mode `0500`; public/config/manifest inputs are mode `0600`. Publication uses a
same-filesystem pending directory, fsync, and no-replace rename. An identical
retry only revalidates the final tree; a missing, extra, changed, symlinked,
role-swapped, source-mismatched, or private-key-like entry fails closed and is
never overwritten.

## Ordered Layer B input publication

`layer-b-inputs-init` also accepts no arguments. It first revalidates the
already-published Layer A tree. It then reads only these two fixed host
collection roots:

```text
target/macos-vm-lab/guest-client-output
target/macos-vm-lab/guest-peer-output
```

With the exact five Layer A/SSH review files in each root, the first
`layer-b-inputs-init` invocation:

1. validates the canonical VM identity, listener inventory, SSH host key,
   fingerprint, and role-specific hardened-SSH witness;
2. resolves each exact VM with fixed Tart ARP;
3. creates the exact `peer-config-v1.json` and eight-entry
   `run-ticket-expectation-v1.json`;
4. creates the fixed private workspace and copies only the six public SSH
   review artifacts into the role-prefixed review store; and
5. returns `management-host-key-pin-required`.

That invocation never creates `known_hosts`, opens SSH, publishes prepare
inputs, or calls the host-key pin operation. A reviewer must inspect the six
public review artifacts and the exact configuration, then separately invoke
the no-argument `management-host-key-pin` command. This is the only operation
that creates the two strict role `known_hosts` files, and it never discovers
or accepts a first-seen key.

After that explicit pin, a new `layer-b-inputs-init` invocation revalidates
the pinned store, performs fresh Tart-ARP plus pinned-SSH same-session identity
proofs for both roles, and publishes
`guest-share/layer-b-prepare-inputs`.

After both guests add the canonical listener baseline candidate and
`layer-b-review-witness-v1.json`—seven exact files per output root—a new
`layer-b-inputs-init` invocation validates every earlier byte and current VM
identity but returns `listener-baseline-approval-required`. It does not treat
either candidate as an approval and does not publish pin inputs. A reviewer
must inspect the exact candidate inventories and VM identities, then
separately invoke the no-argument
`layer-b-listener-baseline-approve` command. That command requires the
already-pinned host keys and the exact prepared review/workspace, repeats the
Tart-ARP and pinned-SSH identity proof, and creates only a create-once private
approval record. It never publishes pin inputs.

One final `layer-b-inputs-init` invocation revalidates that approval record
against the unchanged candidate, inventory, identity, configuration,
expectation, and courier key before publishing
`guest-share/layer-b-pin-inputs`. No single invocation can cross either
review-to-pin boundary. Identical reentry only validates existing bytes; a
client/peer phase mismatch, role swap, stale or changed identity, review-hash
mismatch, approval tamper, extra file, or changed publication fails closed
without replacement.

This command contacts the two disposable VMs through fixed Tart and pinned
management SSH. Merely building or testing the host courier does not execute
it.

## Separate host identities

`key-init` creates the dedicated raw Ed25519 courier-signing identity.
`management-key-init` creates two different OpenSSH Ed25519 management
identities, one for each VM. All private files are create-only, mode `0600`,
and remain below the ignored mode-`0700` root:

```text
target/macos-vm-lab/private/vm-external-peer-courier
```

The two public management keys are canonical raw
`ssh.PublicKey.Marshal()` bytes:

```text
management-ssh-public/client-management-ed25519-public.bin
management-ssh-public/peer-management-ed25519-public.bin
```

They map only to the matching fixed guest Layer A bootstrap input:

| Host public file | Guest input |
| --- | --- |
| `client-management-ed25519-public.bin` | `/private/var/tmp/kyclash-vm-external-peer-lab-staging-input/client-ssh-bootstrap-layer-a/client-management-ed25519-public.bin` |
| `peer-management-ed25519-public.bin` | `/private/var/tmp/kyclash-vm-external-peer-lab-staging-input/peer-ssh-bootstrap-layer-a/peer-management-ed25519-public.bin` |

The visibly authorized guest bootstrap installs only that role's public key,
hardens effective sshd policy, and writes public review evidence. It never
receives either host private key.

## Explicit host-key review and pin

There is no `ssh-keyscan`, first-use acceptance, shared `known_hosts`, DNS
lookup, or password fallback. The first `layer-b-inputs-init` invocation
imports the already root-published guest outputs into the fixed host review
directory with these role-prefixed names, but does not pin them:

| Guest output | Fixed host review name |
| --- | --- |
| client `management-ssh-host-ed25519-public.bin` | `client-management-ssh-host-ed25519-public.bin` |
| client `management-ssh-host-ed25519-fingerprint.txt` | `client-management-ssh-host-ed25519-fingerprint.txt` |
| client `management-ssh-bootstrap-witness-v1.json` | `client-management-ssh-bootstrap-witness-v1.json` |
| peer `management-ssh-host-ed25519-public.bin` | `peer-management-ssh-host-ed25519-public.bin` |
| peer `management-ssh-host-ed25519-fingerprint.txt` | `peer-management-ssh-host-ed25519-fingerprint.txt` |
| peer `management-ssh-bootstrap-witness-v1.json` | `peer-management-ssh-bootstrap-witness-v1.json` |

The review directory is:

```text
target/macos-vm-lab/private/vm-external-peer-courier/management-host-key-review
```

After independently reviewing those files, the reviewer must explicitly run
`management-host-key-pin`. Before it can succeed, the fixed control directory
must contain the same reviewed `peer-config-v1.json` and
`run-ticket-expectation-v1.json` staged in both guests. Pinning requires exact
directory inventories, stable non-symlink files, canonical Ed25519 bytes,
matching SHA-256/fingerprints, matching client/peer VM identity facts, the
role-specific management public key, hardened-sshd booleans, and the exact
allowed-user sets. It then creates the two separate canonical `known_hosts`
files once. `layer-b-inputs-init` never invokes this command. Missing evidence
or any mismatch fails closed; the command never discovers a replacement key.

## Fixed runner behavior

`start-lab` first proves peer `idle-ready`, then waits for the client's
root-published empty ready marker. Its 120-second monotonic transaction is:

```text
read client public bundle
  -> sign sequence 0 run ticket and sequence 1 client bundle
  -> create fixed peer inbox files and wake
  -> wait for the matching peer run
  -> read and validate the peer public bundle
  -> sign sequence 2 only now
  -> create fixed client inbox files and ready
  -> observe clean-postflight
```

Sequence 3 is not pre-signed. It is created at most once only after sequence
1 when cancellation or a failure requires it. Cancellation before sequence 2
permanently forbids sequence 2; cancellation after sequence 2 retains the
already signed response and adds sequence 3. `SIGINT` and `SIGTERM` cancel the
same context, allowing the runner's bounded cancel/clean observation to run;
process termination is not treated as cleanup.

Every individual read or create operation:

1. revalidates its role-specific private key and `known_hosts` witnesses;
2. re-hashes the fixed repository Tart 2.32.1 executable at
   `target/tools/tart-2.32.1/tart.app/Contents/MacOS/tart` and requires SHA-256
   `05b65d5c14e8b41e8e44b6d9fd1278de4bedbc8b735d9b99f3c748f76f75862d`;
3. runs only `tart ip <exact-VM> --resolver=arp`;
4. uses `/usr/bin/ssh` with the role key, role `known_hosts`,
   `StrictHostKeyChecking=yes`, no agent, no password, no forwarding, and no
   proxy; and
5. re-proves `VirtualMac*`, arm64, platform UUID, `en0` MAC/IP, sshd host
   fingerprint, console UID/user, and at most 30 seconds of wall-clock skew
   in that same SSH session.

The remote program can only read or create the checked-in allowlist. Creates
use `O_CREAT|O_EXCL|O_NOFOLLOW`; the host never runs `sudo`, starts/stops a
root supervisor, signals a guest process, selects a carrier endpoint, or
writes a root-owned guest path.

## Current claim boundary

The source, fake-executor, race, vet, contract, and cross-build gates can prove
the closed command/state machine without contacting a VM. They are not
cross-VM networking evidence. A real `start-lab` execution, bridge attachment,
Connect, utun, route, Mihomo, carrier, or SSH acceptance run must wait for the
fresh Layer B record and visible guest authorization required by the locked
external-peer review.
