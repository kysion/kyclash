# KyClash two-VM external-peer App lab review

Status: approved and locked for Layer A architecture, source implementation,
tests, builds, peer-clone creation, and isolated bootstrap only. Layer B
bridged runtime remains unauthorized until its per-run gate passes.

Date: 2026-07-23

Lock record:

- approved content SHA-256:
  `494f73c296c16a7692cf54168635cf44afbf3f17c2ae4ca14b04d3d07ad0e652`;
- independent security review: Critical 0, High 0, approved;
- independent courier/OpenSSH feasibility review: Critical 0, High 0,
  approved; and
- this status change is administrative only and does not expand Layer A or
  authorize `--net-bridged=en0`.

Parent authorities:

- `kyclash-plan-review-20260721.md`
- `../architecture/kyclash-networking-v1.md`
- `../architecture/kyclash-network-runtime-v1.md`
- `kyclash-production-networking-work-program-20260721.md`
- `kyclash-vm-utun-lab-app-review-20260723.md`
- `kyclash-vm-network-lab-app-review-20260723.md`
- `kyclash-production-vm-lab-candidate-review-20260722.md`

This document proposes a new sibling lab profile. It does not amend, weaken,
or replace any locked production, route-helper, tunnel-broker, Keychain,
signing, or existing loopback-lab contract.

## Current truth and reason for this review

The current no-sign VM network App does not connect to another machine. Its
carrier peer is created by `kyclash-vm-network-lab-harness` inside
`kyclash-macos-lab-work`. QUIC, WSS, and TCP listen on `127.0.0.1`, and the
peer WireGuard netstack and `10.88.0.2:8080` echo service live in the same
harness process as the client-side lab controller.

That existing profile can prove a real client `utun`, an exact private route,
Mihomo coexistence, carrier sequencing, and cleanup in one VM. It cannot prove
that carrier traffic leaves the client VM, that a non-loopback TLS endpoint is
authenticated, or that KyClash reaches a separately administered peer.

The proposed first external-peer batch changes only that missing boundary:

```text
kyclash-macos-lab-work                         kyclash-macos-lab-peer
┌─────────────────────────────┐               ┌─────────────────────────┐
│ visible unsigned KyClash.app│               │ unbundled lab peer      │
│             │               │               │ exact RFC1918 en0 bind  │
│ fixed local Unix socket     │               │ QUIC / WSS / TCP        │
│             │               │ temporary     │             │           │
│             │               │ bridged en0   │             │           │
│ root client harness         │──────────────▶│ one WG userspace peer   │
│ real utun + 10.88.0.2/32    │ encrypted     │             │           │
│             │               │ carriers      │ echo + fixed SSH probe  │
└─────────────┼───────────────┘               └─────────────────────────┘
              │
       App private-echo probe
```

The host is build and orchestration only. It is not a carrier relay, listener,
TLS terminator, WireGuard peer, route owner, App runtime, or evidence
substitute.

Tart's default VZNAT is not a valid direct two-VM transport for this review:
vmnet bridge isolation prevents the required guest-to-guest path. The proposed
underlay is a temporary `--net-bridged=en0` attachment for the two disposable
runtime VMs only. Softnet, a host relay, host port forwarding, and default
VZNAT as a data path are explicitly not used. A console-only or isolated
bootstrap boot may be used solely to regenerate and harden the peer clone's
SSH identity before bridging; it is not cross-VM or carrier evidence.
Bridging exposes the peer's random high ports to the host `en0` layer-2
network, so every carrier requires end-to-end mutual TLS, the exact client
source facts, a short run lifetime, and inner WireGuard authentication. That
residual layer-2 exposure requires an explicit independent-review conclusion
before this proposal can be locked.

## Proposed decision

Create a default-off feature named
`networking-vm-external-peer-lab-app`. It is mutually exclusive with:

- `networking-vm-network-lab-app`;
- `networking-vm-utun-lab-app`;
- `networking-production`; and
- ordinary release/updater composition.

The App communicates only with a new fixed client-VM socket:

```text
/var/run/net.kysion.kyclash.vm-external-peer-lab.sock
```

The client App creates the current ephemeral WireGuard identity and supplies
it only through the fixed private local bootstrap. The client harness derives
its public witness, creates the ephemeral mTLS/overlay-SSH client identities,
and owns the actual macOS `utun` and carrier backend. Its root supervisor owns
the App stream, journal, exact private route, Mihomo fixture, child lifecycle,
and teardown.
The peer fixture owns the peer WireGuard identity, TLS identity, three carrier
listeners, one carrier switchboard, and the userspace private echo/SSH
services.
Neither side accepts a path, endpoint, key, route, port, interface, command,
or policy from the frontend.

The first batch is deliberately limited to one cross-VM IPv4 private echo:

| Fact | Proposed fixed value |
| --- | --- |
| Client VM | `kyclash-macos-lab-work` |
| Peer VM | `kyclash-macos-lab-peer` |
| Clean clone source | stopped `kyclash-macos-lab-base` |
| Client public outbox | fixed run-bound directory under `/private/var/tmp/kyclash-vm-external-peer-lab-root/` |
| Client courier inbox | fixed run-bound console-user create-only directory under the same root |
| Client inner address | `10.88.0.1/32` |
| Peer inner address | `10.88.0.2` |
| Exact client route | `10.88.0.2/32` via the owned KyClash `utunN` |
| Private services | echo `10.88.0.2:8080`; run-bound `x/crypto/ssh` nonce `:22`; fixed real-OpenSSH proxy `:2222` |
| Carrier order | QUIC, then WSS, then TCP |
| WSS path | exactly `/kynp` |
| QUIC ALPN | exactly `kyclash-network/1` |
| Runtime underlay | temporary Tart `--net-bridged=en0` on the two disposable VMs |
| Mihomo fixture | client `utun4094` with covering `10.88.0.0/24` route |
| DNS/default route/proxy | read-only; mutation forbidden |
| Peer forwarding/NAT | disabled and unused |

The peer uses a userspace WireGuard netstack; it does not create a peer-side
kernel `utun`, install routes, forward packets, or expose another subnet. The
real `utun` and route acceptance requirements apply to the client VM.

## Claim boundary

A passing first batch may claim only:

- the visible KyClash App in the client VM initiated the connection;
- carrier traffic used the separate peer VM's private `en0` address and did
  not terminate on client loopback;
- WireGuard carried a bounded private echo through a real client `utun` and
  exact `/32` route;
- the same route carried a pinned, public-key-only SSH handshake to the
  userspace peer and one fixed no-shell run-nonce request;
- QUIC, WSS, and TCP were selected in the locked order without overlapping
  active carriers; and
- the exact KyClash `/32` route coexisted with the client VM's fixed Mihomo
  `10.88.0.0/24` covering route in the same run; and
- explicit disconnect and peer loss returned both lab roles to the defined
  clean state.

It must not be described as:

- a production server, control plane, staging endpoint, or multi-tenant
  service;
- a general interactive SSH shell, SSH forwarding service, or production
  remote-management endpoint;
- a LAN, site-to-site, subnet-router, exit-node, Internet, or NAT-traversal
  solution;
- proof of production `SMAppService`, XPC, tunnel-broker, route-helper, signed
  policy, Keychain, signing, packaging, notarization, updater, or release;
- physical-Mac, sleep/wake, network-switch, IPv6, or long-soak acceptance.

The locked one-VM Mihomo result remains historical evidence. This review
requires a fresh same-run Mihomo observation rather than silently combining
that historical result with a new external-peer result.

## VM provenance and identity boundary

Only the following VM roles are permitted:

| Role | Required identity and use |
| --- | --- |
| Client | existing disposable `kyclash-macos-lab-work`; visible App and privileged client harness only |
| Peer | new disposable `kyclash-macos-lab-peer`; unprivileged external-peer fixture only |
| Base | `kyclash-macos-lab-base`; stopped, read-only clone source only |

Before any later implementation run:

1. `kyclash-macos-lab-base` must be stopped before cloning and remain stopped
   before, during, and after the entire run.
2. No command may boot, mount, install into, copy a fixture into, change the
   configuration of, or collect runtime evidence from the base.
3. `kyclash-macos-lab-peer` must be created as a separate clone of that
   stopped base. All later mutations target only the clone.
4. Both runtime VMs must independently prove `arm64` and an `hw.model` value
   beginning with `VirtualMac`.
5. The two runtime VMs must have distinct Virtualization.framework machine
   identities, `IOPlatformUUID` values, `en0` MAC addresses, private `en0`
   addresses, and SSH host-key fingerprints.
6. Before any bridged attachment, the cloned peer's SSH host keys must be
   regenerated from its visible console or an isolated bootstrap session, and
   the new fingerprints must be pinned. A duplicate VM UUID, MAC, IP, or SSH
   host key is a fail-closed preflight result.
7. Before either peer listener starts, read-only inspection must prove that
   the two live VMs have different `en0` MAC and IPv4 addresses. Failure stops
   the run; no address is repaired by changing the base, host, DHCP, or LAN.
8. The same-session identity record must bind the exact VM name, model,
   architecture, OS build, console user, platform UUID, `en0` MAC/address, and
   SSH host-key fingerprint to the run ID.
9. Host discovery must use `tart ip <exact-vm-name> --resolver=arp` and bind
   that result to the VM's preflight-pinned unique MAC. Strict SSH then requires that
   VM's pinned regenerated host key and proves in the same session that the
   guest-reported `en0` IPv4 equals the ARP result. DNS, broad subnet scans,
   first-use host-key acceptance, and an address not bound to the pinned MAC
   are rejected.
10. The Tart ARP/MAC result, pinned SSH identity, guest `en0` fact, public
    descriptor, and later socket source/destination facts must all agree.
    Each SSH transfer re-resolves and revalidates that chain; an address,
    host-key, or MAC change invalidates the run.

The two VMs are role-isolated disposable guests, not network-isolated guests.
For this candidate they are both attached temporarily with Tart
`--net-bridged=en0`; no bridge configuration is written to the stopped base.
The client and peer must each receive a distinct RFC1918 `en0` address.

Each bridged run requires a fresh, explicit authorization record for one
user-owned disposable local lab LAN. It binds the exact host interface,
private IPv4 CIDR/gateway, client/peer MAC and expected address facts, network
owner, bounded run window, and statement that no production/corporate/site
system is attached. Public, corporate, production, office/site, shared,
guest/hotel, managed, Internet-facing, or ownership-unknown LANs are rejected
even when they use RFC1918 space. RFC1918 alone is never positive lab-network
classification. If the host's `en0` network cannot be positively proven and
authorized as that exact local lab LAN, the run stops before bridging.

Default VZNAT, Softnet, a host carrier proxy/relay, host port forwarding, host
route/PF changes, and a second bridge are forbidden.

The bridge is only a transport substrate. KyClash never advertises, captures,
forwards, or installs a route for the bridged LAN.

## Pre-bridge listener and SSH gate

Bridging exposes every non-loopback guest listener, not only the three
KyClash carrier ports. Before either VM receives `--net-bridged=en0`, a
console/isolated read-only audit must enumerate all IPv4 and IPv6 TCP/UDP
listeners with their bind address, port, owner UID, executable path, code
signature, launchd label, and role. Carrier and peer processes must be absent
at this point.

The resulting client and peer inventories are separate closed allowlists. An
entry is expected only when its exact process identity, protocol, address
scope, and port were independently reviewed for that role. A wildcard,
unicast, discovery, sharing, development, remote-control, proxy, or other
listener is not accepted merely because macOS started it. An extra, changed,
unclassified, unsigned, wrong-owner, or wrong-role entry prevents bridging.
This proposed review does not pre-approve an unknown baseline service. The
closed inventories are outputs of the later isolated bootstrap and attach to
the per-run bridge-authorization decision, not the earlier architecture/source
lock.

Remote Login is itself part of that exposed surface and must pass all of these
effective-config checks before bridging:

- `AuthenticationMethods` requires public key authentication;
- `PubkeyAuthentication yes`;
- `PasswordAuthentication no`;
- `KbdInteractiveAuthentication no` and no challenge-response fallback;
- `PermitRootLogin no`;
- agent, TCP, X11, gateway, and tunnel forwarding disabled;
- only the exact non-root management console user plus the peer-only
  `kyclashlabssh` restricted test account allowed; and
- management accounts contain only their role-specific VM-lab public key; the
  restricted peer account contains only the signed run-bound overlay key.

`kyclashlabssh` exists only in the disposable peer clone, has a locked
password, no administrator/sudo membership, and no management authorization
key. Its per-run overlay public key is installed only after a valid courier
signature and uses one exact authorized-keys line beginning with
`from="127.0.0.1",restrict,command="<fixed-helper>"`. No wider source or
option set is accepted.
It is not an orchestration login. The ordinary client VM has no such account.

The client and peer use different authorization keys. Their private halves
remain only in separate host-private files/Keychain identities, never in the
repository, argv, environment, guest, logs, or evidence. The host also uses
two separate known-hosts files: one pins the client host key and one pins the
peer host key regenerated before bridging. `StrictHostKeyChecking=yes` is
mandatory; first-use acceptance, a shared known-hosts record, SSH agent
forwarding, password fallback, and root SSH are forbidden.

If the effective sshd configuration, authorized-key inventory, listener
inventory, host-key fingerprint, or role separation cannot be proved from the
visible console/isolated bootstrap, that VM must not be bridged. After
bridging, the same audit runs again before fixture transfer and continuously
during the bounded run. The only new peer listeners may be the three exact
descriptor-bound mTLS carrier ports; the client may add no non-loopback
listener. Any drift triggers cancellation and cleanup.

The inventory is collected by a checked-in, fixed no-argument, read-only root
auditor started through visible guest authorization during isolated bootstrap.
It may inspect only socket/process/interface/launchd/code-signing facts and
write one root-owned redacted inventory; it exposes no socket, accepts no
path/command/environment input, and mutates no service, firewall, interface,
route, or process. During the bridged run the already-authorized root
supervisors invoke the same in-process inventory code continuously.

Apple-signed system entries still require the exact reviewed role allowlist.
The only unsigned non-loopback listener exception after the peer starts is the
one root-manifest-pinned peer executable at the exact path, owner, dev/inode,
SHA-256, arm64 shape, PID/start identity, and three descriptor ports. A second
unsigned process, changed hash/path/identity, or an unsigned client listener
fails closed.

## Threat boundary

The review treats the local host and hypervisor administrator as the trusted
lab orchestrator. Compromise of that authority is out of scope, but the design
still keeps every private network key out of the host and out of the other VM.
Guest-local unprivileged processes, stale files, role confusion, descriptor
replacement, endpoint substitution, and process crashes remain in scope.

| Threat | Required mitigation |
| --- | --- |
| The old loopback peer is mistaken for the external peer | New mutually exclusive feature/socket/profile; reject every loopback endpoint; prove no carrier listener on the client VM or host |
| The clean base is accidentally used as a runtime | Base-off preflight and postflight; exact client/peer allowlist; no base target in runtime commands |
| A clone retains the base or client's identity | Distinct platform UUID, MAC, IP, and regenerated SSH host-key proof before fixture transfer |
| A descriptor is stale, replaced, replayed, or belongs to another role | Strict schema, run/VM identity binding, expiry, create-only publication, exact-byte SHA-256, owner/mode/link/type checks, and before/after read identity checks |
| A listener binds loopback, wildcard, public, or the wrong interface | Exact numeric RFC1918 address currently assigned to peer `en0`; all other classes rejected |
| A carrier port is hijacked or changes after publication | Bind and retain all three sockets before atomic descriptor publication; fail rather than substitute a port |
| A same-L2 process reaches an exposed high port | Mutual TLS on QUIC/WSS/TCP, exact run-bound client certificate, exact client source IP, random per-run ports, short lifetime, and no discovery advertisement |
| Bridging exposes SSH or another guest service | Closed pre/post-bridge listener inventory; role-specific key-only SSH; separate host keys, authorization keys, and known-hosts; forwarding/password/root login disabled |
| An RFC1918 production/shared LAN is mistaken for a lab | Fresh exact-CIDR/interface/owner/time authorization; positive disposable-local-lab classification; corporate, production, site, shared, public, managed, or unknown networks rejected |
| TLS authenticates the wrong peer or client | Exact peer-`en0` IP SAN, run-bound client certificate, short-lived lab CA, pinned public CA bytes/fingerprint, TLS 1.3, fixed QUIC ALPN and WSS path |
| WireGuard keys or TLS private material cross a VM | Client private material stays in App/harness memory across the fixed local bootstrap; peer private material stays in peer process memory; only public identities cross |
| More than one carrier is attached | One peer WireGuard device and one switchboard; explicit close/absence observation before the next attach |
| A route captures unrelated traffic | One fixed `10.88.0.2/32` route on the exact owned `utun`; default, DNS, LAN, and covering routes forbidden |
| Peer loss leaves client state behind | Bounded health failure, fallback exhaustion, route-first rollback, exact `utun` teardown, socket/journal cleanup, positive absence checks |
| Client loss leaves peer state behind | Controller EOF/parent-death handling, listener/device/descriptor cleanup, and peer final-absence proof |
| UDP impairment changes the guest or host globally | Lab peer drops QUIC datagrams inside the exact run process; no PF, firewall, DNS, default-route, or host mutation |
| A networking workaround expands host privilege | Default VZNAT is rejected as isolated, and Softnet/SUID tools, host relay, forwarding, or proxying are never installed or invoked |
| A same-UID process races the App socket | `LOCAL_PEERPID`/audit-token identity plus root-pinned exact App executable path, dev/inode, SHA-256, arm64 shape, PID/start identity, and continuous connection-owner monitoring |

Out of scope are a malicious host/hypervisor administrator, denial of service
by another device already present on the bridged layer-2 network, production
tenancy, production authorization, and production key distribution. Bypassing
authentication from that layer-2 network remains in scope and must fail
closed through mutual TLS and WireGuard.

## Private-key and public-identity lifecycle

“Keys never cross VMs” means every private key remains inside the VM and fixed
private process/channel boundary that owns it. WireGuard necessarily
exchanges public keys; TLS necessarily supplies public certificates. Those
public values are the only key material permitted to cross a VM boundary.

### Client role

- On Connect, the App follows the current lab behavior and generates one fresh
  WireGuard private key in App memory.
- The App sends that value once through the fixed authenticated local Unix
  bootstrap to the root harness. It never enters argv, environment, disk,
  Keychain, host transfer, log, evidence, or the peer VM.
- The harness derives the WireGuard public key, creates one fresh mTLS client
  private key/CSR and one overlay-SSH client private key in harness memory,
  and atomically publishes only their public identities in the client bundle.
- The harness waits while the host couriers the public client bundle to the
  peer and the public peer bundle back. The App-facing startup budget for this
  reviewed exchange may be widened to at most 120 seconds; expiry,
  cancellation, App EOF, or a changed App peer credential aborts the run.
- Before backend construction, the harness proves the returned client
  certificate matches its in-memory TLS private key/CSR and that the peer
  descriptor contains the WireGuard public key derived from the original App
  bootstrap.
- The App-owned WireGuard bootstrap is cleared after the fixed local send; the
  harness-owned WireGuard bootstrap is cleared only after the device has
  accepted its configuration.
- The mTLS client private key remains in backend-owned mutable memory through
  QUIC, WSS, TCP, fallback, and final carrier teardown, then that owned buffer
  is cleared. The review does not claim it can locate or clear opaque copies
  made inside a cryptographic library.
- The overlay-SSH client private key remains in client-harness memory through
  the three carrier probes and is cleared after the final SSH session or
  teardown. It never enters the host management SSH agent or key files.
- An App/harness restart invalidates the first-batch run; it never regenerates
  a key behind an existing peer descriptor.

### Peer role

- The peer process generates a fresh WireGuard private key, TLS server private
  key, overlay-SSH server host private key, and ephemeral CA signing key in
  peer-VM memory.
- The CA signs exactly one server leaf for the peer `en0` IP and exactly one
  client leaf for the validated client CSR. Its private signing key is cleared
  immediately after both certificates have been issued.
- The peer WireGuard and TLS server private keys remain only in the live peer
  process; its owned mutable buffers are cleared on exit without claiming
  control over opaque cryptographic-library copies.
- The peer publishes only the WireGuard public key, public CA certificate,
  public server/client certificates and fingerprints, overlay-SSH host public
  fingerprint, and strict peer descriptor.
- A peer restart invalidates the first-batch run. Persistence across reboot is
  not part of this review.

No private key, password, token, bootstrap secret, production credential,
Keychain value, or certificate private material is copied by the host. The
peer CA, TLS server, WireGuard, and overlay-SSH host private keys never leave
`kyclash-macos-lab-peer`; the client TLS, WireGuard, and overlay-SSH private
keys never leave
`kyclash-macos-lab-work`. This profile reads, creates, updates, or deletes no
System/login Keychain item, including both the `.test` and production
networking services.

## Public-artifact transfer and descriptor validation

The host may act only as a courier for reviewed public artifacts. It resolves
each exact VM through the Tart ARP/pinned-MAC authority immediately before
transfer, requires the pinned SSH host key, and re-proves that VM's live
`en0` identity in the same session. It never opens a carrier port, rewrites an
endpoint, obtains a private key, or writes a root-owned destination.

The courier has a dedicated Ed25519 signing identity independent of VM SSH,
TLS, WireGuard, overlay SSH, source-policy, and release keys. Its public key
and fingerprint are pinned by the client's root-owned staging manifest and by
the peer's root-owned exact-binary/config manifest. The host private key
is accepted only from one dedicated host file beneath an exact mode-0700
parent. The runner opens it with `O_NOFOLLOW` and requires the expected host
user, mode `0600`, regular-file type, link count one, and stable
dev/inode/size/mtime before and after use. This key is never loaded from
Keychain and is never reused for VM SSH, TLS, WireGuard, overlay SSH, policy,
release, another repository, or another purpose. It never enters the
repository, argv, environment, either guest, transfer directory, log,
screenshot, or retained evidence.

Courier signatures never depend on canonical JSON or a locally invented
serializer. The exact signed bytes begin with the byte sequence
`net.kysion.kyclash.external-peer.courier/v1\0`. The remaining encoding uses
only:

- one-byte message kind;
- unsigned 64-bit fixed-width big-endian integers;
- raw fixed-width IPv4 (4), MAC (6), SHA-256/nonce/Ed25519-public-key (32), and
  Ed25519-signature (64) bytes; and
- strings encoded as an unsigned 16-bit big-endian byte length followed by
  strict UTF-8 bytes, with no NUL, invalid encoding, normalization,
  truncation, or duplicate filename.

The fields appear in this exact order:

```text
domain
message_kind
sequence
run_id
issued_at
expires_at
nonce
source_role, source_vm_name, source_platform_uuid,
source_ssh_host_fingerprint, source_mac, source_ipv4
destination_role, destination_vm_name, destination_platform_uuid,
destination_ssh_host_fingerprint, destination_mac, destination_ipv4
ticket_hash
manifest_exact_bytes_sha256
file_count
repeated filename, byte_length, exact_file_sha256
```

The direction-specific file table uses the reviewed allowlist order, not
sorting or map iteration. `file_count` is unsigned 16-bit big-endian; each
byte length is unsigned 64-bit big-endian. An absent/not-applicable
32-byte field is all zeroes only where the layout below explicitly permits it.

Before either bundle, the host signs a sequence-zero `run-ticket` message
(`message_kind=0`, `sequence=0`). Its `ticket_hash` and manifest-hash fields
are 32 zero bytes. Its file table has exactly eight fixed labels, byte lengths,
and SHA-256 values, in this order: App, client supervisor, client harness, peer
supervisor, peer child, peer config, listener auditor, forced-command helper.
It is valid for at most 120 seconds. The ticket hash is SHA-256 over the exact
ticket signed bytes followed by its 64-byte signature.

The `client-to-peer` message is `message_kind=1`, `sequence=1`; the
`peer-to-client` message is `message_kind=2`, `sequence=2`. Both include the
same nonzero ticket hash, exact direction-specific manifest-bytes SHA-256, and
file table. Each uses a different 32-byte nonce. The pinned courier public key
is exactly 32 bytes, and every Ed25519 signature is exactly 64 bytes.

The terminal cancellation message is `message_kind=3`, `sequence=3`. It uses
the accepted nonzero ticket hash, a fresh nonce, the exact client-to-peer
VM/address facts, a zero manifest hash, and `file_count=0`; it expires no later
than the run ticket. It is accepted at most once after sequence 1 and means
only `cancel`, with no free-form action or parameter. A later bundle, cancel,
or wake trigger is rejected.

On receipt, each side first opens every allowlisted file safely, captures the
exact bytes, lengths, and SHA-256 values, and compares them with the decoded
fixed-layout file table and exact manifest hash. Only then does it reconstruct
the signed bytes and verify the Ed25519 signature. It still must not parse or
use a descriptor, certificate, SSH key, or endpoint until verification passes.
Unknown kinds/fields, trailing bytes, integer overflow, invalid UTF-8,
duplicate/out-of-order names, nonzero forbidden fields, bad ticket hash,
unknown key, bad public/signature length, future/stale time, reused nonce or
digest, wrong sequence/direction, role swap, VM/address change, missing/extra
file, or hash/size mismatch fails closed.

Before Connect, the root harness creates and retains stable directory
descriptors for two fixed run-bound directories:

- a root-published, public-only client outbox from which the exact console SSH
  user may read but not replace files; and
- an initially empty courier inbox owned by the exact console user, mode
  `0700`, into which that user may create the allowlisted peer public files
  once with `O_CREAT|O_EXCL`.

The host courier writes only as the console SSH user. It cannot use `sudo`,
chown a file, replace an existing name, write another directory, or ask the
root harness to open a caller-selected path. The inbox accepts exactly the
peer descriptor, public CA/server/client certificates, overlay-SSH server
host public key, system-sshd Ed25519 host public key, canonical transfer
manifest, and courier signature; it is never a general root import directory.

The root harness reads each allowlisted name relative to its retained
directory descriptor with `openat` and `O_NOFOLLOW`, then requires one regular
file, exact console-user ownership, mode `0600`, link count one, bounded size,
and unchanged dev/inode/size/mtime before and after the read. It validates the
manifest, hashes, schema, certificates, run/VM/source facts, and absence of
private fields before copying bytes into owned memory. Any pre-existing,
replaced, renamed, linked, partial, extra, or changing entry fails closed.
The harness never promotes a courier-created file into a root-owned path.

The peer uses the symmetric boundary. During Layer A isolated bootstrap, a
visibly authorized root staging step installs only the exact peer binary,
fixed config, and manifest that pins their hashes, paths, owners/modes,
arm64 shape, and courier public key. At runtime a narrow root peer supervisor
opens a pre-created console-user inbox through a retained directory descriptor,
verifies file identity and the `client-to-peer` courier signature, and passes
validated public bytes to the exact unprivileged peer child through an
inherited pipe. The child returns its public bundle through a second inherited
pipe; the supervisor validates it and atomically publishes a root-owned
public-only outbox. The host revalidates that outbox before applying its
`peer-to-client` signature. No same-UID process can substitute a peer input or
output without breaking the root-pinned process identity, stable-fd facts, or
courier signature.

The client public bundle contains `client-public-v1.json`, the separate public
`tls-client.csr.der`, and
`overlay-ssh-client-ed25519-public.bin`, whose hashes and standard SSH
fingerprints are fixed by that descriptor. The peer public bundle contains
`peer-public-v1.json`, the public CA/server/client certificates,
`overlay-ssh-server-ed25519-public.bin`, the canonical raw system-sshd Ed25519
host public key, and a create-only transfer manifest.
The two SSH files contain the exact canonical bytes returned by
`ssh.PublicKey.Marshal()` for one `ssh-ed25519` key; they contain no comment,
option, private seed, authorized-keys text, or second key. The flow is:

1. after the App's private local bootstrap, the waiting client harness creates
   the client public bundle containing its run identity, exact bridged-`en0`
   source facts, derived client WireGuard public key, and TLS client
   CSR/public-key fingerprint plus canonical overlay-SSH client public bytes;
2. the concurrently supervised host courier reads that public bundle and
   transfers only those public bytes to the exact peer VM;
3. the peer validates it, creates its in-memory identities, binds every
   carrier, starts the private echo, `x/crypto/ssh`, and fixed loopback-
   OpenSSH proxy, proves all three ready, and only then atomically publishes
   `peer-public-v1.json` plus public CA, server-certificate, signed client-
   certificate, and raw SSH host-public bytes;
4. the host transfers only those public peer artifacts and the public signed
   client certificate into the pre-created client courier inbox using
   console-user create-only writes; and
5. the waiting client harness validates exact bytes, completes the mTLS
   client identity, and returns the bounded App handshake.

Neither descriptor contains a private path from the other VM. The App receives
only redacted typed status and never receives either public descriptor, raw
certificate bytes, endpoint URLs, ports, or public keys.

`client-public-v1.json` is bounded to the exact fields:

- `schema_version`;
- `run_id`;
- `expires_at`;
- `vm_name`;
- `virtual_mac_model`;
- `platform_uuid`;
- `en0_private_ipv4`;
- `en0_mac`;
- `wireguard_public_key`;
- `tls_client_csr_der_sha256`;
- `tls_client_public_key_sha256`;
- `overlay_ssh_client_public_key_sha256`;
- `overlay_ssh_client_public_key_fingerprint`; and
- `descriptor_sha256` in the transfer manifest, not recursively inside the
  descriptor.

`peer-public-v1.json` is bounded to the exact fields:

- `schema_version`;
- `run_id`, `issued_at`, and `expires_at`;
- exact client and peer VM names and platform UUIDs;
- `bind_interface` fixed to `en0`;
- exact numeric private peer-`en0` IPv4;
- exact client source `en0` IPv4 and both distinct `en0` MAC addresses;
- the three ordered typed endpoint URLs;
- peer and client WireGuard public keys;
- `private_echo_ipv4` and `private_echo_port`;
- public CA DER SHA-256;
- server-certificate SHA-256, exact IP SAN, and validity interval;
- client-certificate SHA-256, exact run identity, client-auth usage, and
  public-key fingerprint;
- overlay-SSH address fixed to `10.88.0.2:22`, server-host public-key
  raw-artifact SHA-256/fingerprint, exact client raw-artifact
  SHA-256/fingerprint, and run-nonce SHA-256;
- real-OpenSSH proxy fixed to `10.88.0.2:2222 -> 127.0.0.1:22`, restricted
  account/helper identity, and exact system-sshd Ed25519 host-public
  artifact/fingerprint; and
- fixed transport order, QUIC ALPN, WSS path, and inner client/peer addresses.

Validation must reject:

- malformed UTF-8/JSON, duplicate or unknown fields, non-canonical integers,
  overlong strings, or a descriptor over 16 KiB;
- an unsupported schema, wrong/randomly altered run ID, wrong VM role/name or
  UUID, expiry more than two hours away, or fewer than ten minutes remaining;
- a private-key-shaped field, credential reference, token, path, hostname,
  user information, query, fragment, or control-plane field;
- a loopback, wildcard, multicast, link-local, public, IPv4-mapped, or
  non-`en0` address;
- an endpoint address not byte-for-byte equal to the current peer `en0`
  address, an address equal to any client-local address, a client source
  address not byte-for-byte equal to the current client `en0` address, equal
  client/peer MAC or IP facts, or an underlay address overlapping
  `10.88.0.0/24`;
- any transport order except QUIC -> WSS -> TCP, a missing TLS requirement, a
  WSS path other than `/kynp`, or a QUIC ALPN other than
  `kyclash-network/1`;
- a client public key that differs from the live client harness witness, a
  peer public key with invalid WireGuard shape, or duplicate public keys;
- a CA/certificate/CSR hash mismatch, wrong server IP SAN, wrong client
  identity or extended-key usage, client public-key mismatch, invalid chain,
  expired/not-yet-valid certificate, absent client certificate requirement, or
  TLS version below 1.3;
- a non-`ssh-ed25519`, noncanonical, missing, extra, or mismatched raw overlay-
  SSH public artifact/fingerprint; any overlay address other than
  `10.88.0.2:22`; an invalid/missing run-nonce SHA-256; or peer publication
  before echo, `x/crypto/ssh`, and fixed real-OpenSSH proxy readiness;
- a real-OpenSSH target other than `10.88.0.2:2222 -> 127.0.0.1:22`, wrong
  account/helper/system-host-key artifact or fingerprint, or any general
  proxy/shell/forwarding capability; and
- a changed file identity, symlink, non-regular file, unsafe owner/mode/link
  count, digest mismatch, pre-existing destination, or partial publication.

The public CA is loaded only into a lab-only in-memory `x509.CertPool` owned by
the client harness/sidecar bootstrap. It is not installed into a System
Keychain and cannot affect ordinary or production composition.

## Peer root-supervisor authorization and lifecycle

After the two disposable VMs have booted on the authorized bridged network and
passed the repeated identity/listener preflight, but before the user presses
Connect, the user visibly authorizes one fixed, no-argument peer root
supervisor from the peer VM console. The exact root-staged executable and
manifest are revalidated before it enters `idle-ready`. It is a one-run
supervisor that stays alive through clean postflight and exits only after it
has proved all peer-owned run state absent. It is not started through host SSH,
remote `sudo`, password automation, or `launchd`; persistent launchd operation
would require a separate review.

The supervisor retains directory descriptors for a fixed root-owned state
directory, a pre-created console-user inbox, and a root-published public-status
outbox. The console user may only create the exact allowlisted run ticket,
signed public bundle, fixed no-argument wake trigger, or signed cancel token
with create-only semantics. The trigger contains no authority and accepts no
command, path, endpoint, environment, PID, or caller-selected parameter; it
only wakes the fixed state machine. The supervisor independently reads the
exact inbox bytes through stable descriptors and verifies the pinned courier
signature, ticket, sequence, run/VM/address facts, freshness, and file hashes
before using any public artifact or starting a child. A bad, missing, replayed,
replaced, extra, or out-of-order artifact fails closed.

The sequence-3 cancellation token uses the exact fixed courier encoding above;
the wake trigger itself remains unsigned and conveys no authority.

Only after sequence 1 validates does the supervisor spawn the exact
root-manifest-pinned unprivileged peer child and bind its PID, process start
identity, executable path/dev/inode/hash/owner/arm64 shape, inherited
controller pipes, and process session to the run journal. The supervisor, not
the host runner or child, owns the run transaction, child reaping, courier
inbox consumption, root public outbox, listener-audit loop, and the restricted
account's `authorized_keys` install/remove transaction. Before changing
`authorized_keys`, it journals the exact original file identity/hash and the
one witnessed
`from="127.0.0.1",restrict,command="<fixed-helper>"` line, then publishes the
single-line addition atomically without changing any foreign line. Cleanup
atomically removes only that exact witnessed line, preserves all other bytes,
fsyncs the file and containing directory, and proves the line absent before
releasing the journal.

A valid signed cancel token, authenticated child controller EOF, carrier/client
EOF, supervisor TERM, ticket/startup expiry, child exit, or validated child
death enters the same peer cleanup state. The supervisor stops and reaps only
the bound child, closes the inherited pipes, removes only its run's listeners,
services, public artifacts, trigger/status files, and witnessed authorized-key
line, clears owned private buffers, and proves final absence before reporting
`clean-postflight`. Host-runner EOF is not root authority; if it cannot deliver
a signed cancel token, the fixed 120-second startup expiry or the authenticated
child/carrier EOF still drives cleanup.

Peer-supervisor SIGKILL cannot imply immediate cleanup. On its next visibly
authorized start, the exact supervisor enters `recovery-only` before
`idle-ready`, validates the durable journal and bound child identity, removes
the witnessed authorized-key line and other exact run residue, reaps or
rejects only the journal-bound child, and proves positive absence. It refuses
every new trigger or run until recovery succeeds; ambiguous identity or
cleanup remains `recovery-only`.

## Concurrent `start_lab` courier supervision

The later implementation requires a checked-in sibling `start_lab` runner on
the host. It is started before the user presses Connect and remains idle while
proving the exact base/client/peer power and identity facts and observing the
peer supervisor's public `idle-ready` status. It does not start a listener,
peer supervisor, peer child, App, or privilege operation in that idle state.

After Connect supplies the private WireGuard bootstrap locally, the client
harness publishes the client public outbox and enters a cancellable
`waiting_peer_bundle` state. The host runner then performs one supervised
transaction:

```text
observe exact client public outbox
  -> re-resolve client through Tart ARP + pinned SSH + guest en0
  -> read only the allowlisted public client bundle
  -> re-resolve peer through Tart ARP + pinned SSH + guest en0
  -> create the signed peer public run input and fixed wake trigger without replacement
  -> observe the root supervisor's public run status
  -> wait for peer listeners/echo and root-published public bundle
  -> validate/read only the peer public bundle
  -> re-resolve the client identity chain
  -> create the allowlisted client inbox files as console user
  -> observe public peer status until client and peer clean postflight
```

The host runner is only a public-artifact courier and observer. It never
starts, stops, signals, reparents, or retains a root supervisor or peer-child
session and cannot write a root-owned path. When cancellation is requested, it
may sign and create only the fixed sequence-3 public cancel token and wake
trigger as the console user; the peer root supervisor independently validates
and acts on that token.

The sibling startup budget, measured from the accepted App bootstrap to the
fully validated peer bundle, is at most 120 seconds. The App UI stays in
`waiting for validated peer`; the harness does not return a ready handshake,
create `utun`, start Mihomo, or install a route before the public exchange
passes.

The host runner enforces that budget with a monotonic clock. Before exchange,
host/client/peer wall clocks must be within 30 seconds; a courier `issued_at`
more than 30 seconds in the future, an expiry later than
`issued_at + 120 seconds`, wall-clock rollback, non-increasing direction
sequence, or repeated nonce/digest fails closed. Wall-clock checks never widen
the monotonic 120-second startup ceiling.

Cancel, App EOF, App peer-credential change, harness EOF, timeout, SSH identity
change, descriptor rejection, or runner interruption cancels the same
transaction. The runner delivers the signed cancel token when it remains able
to do so, the client harness closes its authenticated carrier/controller state
and clears all client private memory and public run files, and the peer root
supervisor performs its own bounded cleanup. Neither side reports Ready. A
one-shot or background SSH command that starts or stops the privileged
supervisor or peer child is forbidden; abrupt runner loss grants no peer
process authority and cannot bypass expiry/recovery.

## Strict peer `en0` bind and ports policy

Default Tart VZNAT is not probed and then treated as a candidate: it is known
not to provide the required direct guest-to-guest path because of vmnet bridge
isolation. After the two disposable VMs start with temporary
`--net-bridged=en0`, read-only preflight first proves distinct MAC and IPv4
facts. Only then may the peer fixture discover its current IPv4 addresses on
`en0` and require exactly one usable private RFC1918 address. That address
must:

- be assigned to `en0` at descriptor publication and at every accept;
- differ from every address on the client VM and host;
- not be loopback, unspecified, link-local, multicast, broadcast, public, or
  inside the inner `10.88.0.0/24` range; and
- remain reachable directly from the client VM without a host proxy.

All three carrier sockets bind that exact numeric address. Raw TCP can inspect
the accepted socket's remote IP before beginning TLS and must reject any value
other than the descriptor-bound client `en0` IPv4. QUIC and WSS establish
their transport/TLS handshake first, then immediately validate both the
authenticated client certificate and the connection/request `RemoteAddr`.
That validation must complete before accepting a QUIC stream, upgrading or
reading a WebSocket frame, attaching the switchboard, or reading any KYNP or
WireGuard frame. Binding `127.0.0.1`, `localhost`, `0.0.0.0`, `::`, a
hostname, an alternate interface, or a caller-provided address is forbidden.

The peer selects three cryptographically random, distinct, unprivileged ports
in the inclusive `20000..60000` range. Selection is bounded, occurs once per
run, and succeeds only when the fixture has bound and retained:

- one UDP socket for QUIC;
- one TCP socket for WSS/TLS; and
- one different TCP socket for raw KYNP-over-TLS.

Port zero, a repeated port, a privileged port, post-publication substitution,
caller-requested historical reuse, sequentially caller-selected ports, or
bind-to-wildcard fallback is rejected. All sockets and the private echo must
be ready before atomic descriptor publication. A later address or socket loss
invalidates the descriptor and causes bounded teardown.

No script may install Softnet or another SUID/root networking tool, start a
host relay, or disable/reconfigure the macOS firewall. If temporary bridged
mode plus end-to-end mutual TLS cannot pass the three selected ports without
such a mutation, the run stops for a separate review.

## TLS and carrier contract

Mutual TLS authenticates both external carrier roles; WireGuard authenticates
the inner KyClash peers. Neither substitutes for the other. QUIC, WSS, and TCP
must all require and verify the same run-bound client certificate.

- The server leaf certificate contains exactly one IP SAN equal to the peer's
  current private `en0` IPv4. It contains no DNS SAN, wildcard, localhost,
  email, URI, or alternate IP.
- The client leaf contains the exact run-bound client identity, client-auth
  extended-key usage only, and the public key from the validated client CSR.
- The server leaf has server-auth extended-key usage only. The CA cannot be
  used as a leaf.
- Both leaves and the CA are run-bound and valid for no more than two hours.
- Client verification uses the exact transferred public CA bytes and expected
  peer IP; system trust and hostname fallback are disabled for this lab pool.
- Peer verification uses the same CA, the exact client certificate
  fingerprint/identity, and the exact descriptor-bound client source IP.
- A missing, optional, foreign, expired, replayed, or wrong-purpose client
  certificate fails before any KYNP or WireGuard frame is accepted.
- TLS 1.3 is the minimum and maximum reviewed version for the first batch.
- QUIC requires ALPN `kyclash-network/1`.
- WSS requires TLS, binary messages, compression disabled, and path `/kynp`.
- TCP is the existing `tcp://` profile form but the accepted socket is still
  wrapped in TLS before any KYNP frame is read.
- Frame bounds, authentication, replay, cancellation, and protocol-v2 limits
  from the locked runtime architecture remain unchanged.

The peer owns one WireGuard device and one carrier switchboard shared by all
three listeners. It must not create three independently keyed peer devices.
Listeners may remain bound for fallback readiness, but at most one
authenticated carrier may be attached to the switchboard.

## Overlay SSH proof contract

The peer's userspace WireGuard netstack also runs a bounded
`golang.org/x/crypto/ssh` server at `10.88.0.2:22`. This is inside the
encrypted overlay and does not bind peer `en0`; it is distinct from the
hardened host-to-VM Remote Login used only for orchestration.

The overlay server uses the peer-memory ephemeral host private key, publishes
its exact public fingerprint in the peer descriptor, and accepts only the
client-harness ephemeral public key fixed by the client bundle. Password,
keyboard-interactive, anonymous, host-based, and every other authentication
method are absent. The client pins the descriptor fingerprint and rejects
unknown/change-on-first-use behavior.

No shell or general SSH service is exposed. The server rejects PTY, shell,
subsystem, environment, agent, TCP/streamlocal forwarding, X11, and arbitrary
exec requests. It accepts one exact protocol request equivalent to
`kyclash-read-run-nonce-v1`; the Go server does not invoke a shell or external
process, returns the run nonce, and closes. The harness hashes the returned
nonce and requires equality with the peer descriptor.

Before the KyClash `/32` exists, the overlay SSH address must be unreachable.
After each QUIC, WSS, and TCP private-echo proof, a new pinned SSH handshake
and fixed nonce request must pass through the same real `utun` and `/32`.
Wrong client key, wrong host fingerprint, password attempt, arbitrary command,
and post-teardown connection must fail. Teardown closes the userspace SSH
listener/sessions and clears owned mutable client/server key buffers.

### Real OpenSSH endpoint acceptance

The `x/crypto/ssh` nonce server proves the in-process overlay protocol but does
not by itself prove that a user can reach an actual OpenSSH endpoint after
networking. The same first batch therefore adds a second, fixed userspace
service at `10.88.0.2:2222` that proxies only to the peer VM's
`127.0.0.1:22`. It accepts no target address/port and cannot reach the peer
LAN or another host. Its host-side dial uses numeric `127.0.0.1:22` and binds
numeric source `127.0.0.1`; DNS, another loopback address, and caller-selected
targets are forbidden.

During Layer A isolated bootstrap, the peer creates the non-admin,
password-locked `kyclashlabssh` account and root-stages one exact harmless
forced-command helper. After validating the signed client bundle, the peer
supervisor installs only the run's overlay Ed25519 public key in that account
as `from="127.0.0.1",restrict,command="<fixed-helper>"`. The helper accepts
only the exact `kyclash-read-run-nonce-v1` original command, prints the run
nonce, and exits.
It provides no shell, PTY, subsystem, environment, forwarding, sudo, file
transfer, or caller-selected command.

The client starts no standalone `ssh-agent`. The root harness implements a
single-key agent with `golang.org/x/crypto/ssh/agent.ServeAgent` on one
run-bound mode-0600 Unix socket beneath its root-private directory. The agent
lists only the overlay client key, allows at most one signature, and rejects
add/remove/remove-all/lock/unlock/extension and every other key. On connection
it requires `LOCAL_PEERPID`/audit credentials matching the one deliberately
spawned `/usr/bin/ssh` child and revalidates that child's PID/start time,
path/dev/inode, Apple signature, SHA-256, and arm64 shape.

The harness also writes the matching canonical `ssh-ed25519` public key to
one root-owned mode-0600 public-only identity file beneath the same private
run directory. It opens and revalidates that file with `O_NOFOLLOW`, regular-
file/link-count-one, owner/mode, exact-byte hash, and stable dev/inode facts.
The file contains no private seed or comment. It exists only so
`IdentitiesOnly=yes` can select the matching key exposed by the in-process
agent; the private key remains solely in harness memory.

The harness executes the exact Apple system `/usr/bin/ssh` with a closed fixed
argument set equivalent to:

```text
-F /dev/null
-B <exact-owned-utunN>
-b 10.88.0.1
-p 2222
-o BatchMode=yes
-o PreferredAuthentications=publickey
-o PasswordAuthentication=no
-o KbdInteractiveAuthentication=no
-o IdentitiesOnly=yes
-i <root-private-public-only-identity.pub>
-o IdentityAgent=<fixed-private-agent-socket>
-o StrictHostKeyChecking=yes
-o UserKnownHostsFile=<root-published-run-known-hosts>
-o GlobalKnownHostsFile=/dev/null
-o ClearAllForwardings=yes
-o ForwardAgent=no
-o RequestTTY=no
-o PermitLocalCommand=no
-o ProxyCommand=none
kyclashlabssh@10.88.0.2
kyclash-read-run-nonce-v1
```

Unsupported bind-interface/source options fail the probe rather than being
omitted. The harness first waits for and reaps that exact SSH child, then
closes the agent listener/session, clears its owned mutable private-key
buffer, and removes only the exact witnessed public-only identity file. It
never clears the key while the child or agent request is live and does not
claim control over opaque library/process copies after their owning process
has exited.

The known-hosts entry pins the peer's regenerated system-sshd public host key;
that existing host private key remains only in the peer root filesystem. At
final TCP, the real system client must traverse the real `utun` and `/32`,
receive the correct nonce, and exit zero. Wrong user/key/host fingerprint,
password fallback, arbitrary command, pre-route, and post-teardown probes must
fail. Direct use of the same run key against the peer's bridged `en0:22` must
also fail because the authorized key is restricted to source `127.0.0.1`.
Cleanup reaps the SSH child and in-process agent as above. The peer root
supervisor, not the unprivileged peer child, removes the witnessed run key,
reaps the run-bound proxy through its bound child, and removes the run nonce
state. The root-staged fixed helper remains immutable and is revalidated, not
deleted. Host management SSH remains a separate orchestration path and is not
evidence for this overlay result.

## App and UI contract

The artifact is an unsigned `.app` copied to and launched only inside
`kyclash-macos-lab-work`. This review does not authorize an installer, DMG,
PKG, signing, notarization, or host launch.

The existing KyClash Network entry remains the user-facing location. Under
this feature it renders one fixed site with the permanent banner:

```text
VM LAB · EXTERNAL PEER · REAL UTUN · MIHOMO COEXISTENCE
```

The page must also state that the peer is
`kyclash-macos-lab-peer`, the result is non-production, and LAN forwarding is
not enabled. The allowed user actions are only:

- `Connect`;
- `Cancel`; and
- `Disconnect`.

The visible state machine includes:

- waiting for validated peer;
- ready;
- preparing the fixed Mihomo TUN fixture;
- preparing real `utun`;
- connecting/connected QUIC;
- switching to/connected WSS;
- switching to/connected TCP;
- exact KyClash route and Mihomo covering route coexisting;
- private echo healthy/unhealthy;
- overlay SSH verified/unavailable;
- peer lost and cleaning up;
- disconnected; and
- one structured, redacted failure.

After preparation, the UI may show the owned `utunN`, fixed
`10.88.0.2/32` route, fixed Mihomo `utun4094`, covering
`10.88.0.0/24` route, active carrier name, private-echo result, and a redacted
overlay-SSH verification boolean. It must
not show underlay endpoint URLs, ports, public keys, raw descriptors,
certificates, hashes, private paths, process IDs, bootstrap material, or
credentials.

`overlay SSH verified` becomes true only after both the pinned in-process SSH
probe and the real Apple `/usr/bin/ssh` forced-command probe pass in this run.

Ordinary/default builds register neither these commands nor this navigation
variant. Production commands and this lab command surface remain separate.

The fixed root socket does not trust console UID alone. On accept, the root
supervisor obtains `LOCAL_PEERPID`, the peer audit token/credentials, and the
process start identity. It then opens the exact guest App executable without
following links and requires the root-owned staging manifest's path,
dev/inode, SHA-256, arm64 Mach-O shape, and expected non-root audit UID. It
rechecks the PID/start/executable identity before consuming bootstrap bytes
and continuously while the connection owns a transaction. A same-UID process,
PID reuse, changed executable, writable/replaced App, missing audit token, or
second connection fails closed. The unsigned App gains no Team-ID claim; the
root-pinned exact bytes are the lab identity.

## Client ownership, route, and cleanup order

One root supervisor owns the fixed socket, durable journal, Mihomo transaction,
route mutation, and harness-child lifecycle. Its exact child owns the
WireGuard backend, carriers, and `utun` after the supervisor accepts the
authenticated App's one-time bootstrap. The frontend cannot supply or mutate
authority. Starting the supervisor later requires one visible client-VM
Terminal authorization; password automation, `sshpass`, `sudo -S`, scripted
password stdin, Keychain password retrieval, and UI password injection remain
forbidden.

Initial connection order is:

```text
prove client VM, fixed socket, and clean public-artifact absence
  -> accept one exact audit-token/PID/executable-bound App on the fixed socket
  -> consume one-time WireGuard private bootstrap
  -> derive the WireGuard public witness and create mTLS client CSR
  -> publish client public bundle and wait at most 120 seconds
  -> validate the couriered peer public bundle and mTLS client certificate
  -> persist Mihomo start intent
  -> start and authenticate exact Mihomo utun4094 and 10.88.0.0/24 route
  -> create/configure one real WireGuard utun
  -> connect QUIC with mTLS to the peer's exact private en0 address
  -> prove exact client source, mutual carrier identity, and WireGuard health
  -> persist exact route add-pending
  -> install only 10.88.0.2/32 on the owned utun
  -> positively inspect the route owner/interface
  -> prove the fixed Mihomo /24 remains on exact utun4094
  -> prove 10.88.0.2:8080 echo through that route
  -> prove pinned-key no-shell SSH nonce at 10.88.0.2:22
```

No route is installed before the first carrier is healthy. During bounded
fallback, the same `utun` and exact route remain owned; the failed carrier is
closed and positively absent before the next carrier attaches. The route is
not re-added during a successful switch.

The only allowed pre-existing overlap is the exact less-specific
`10.88.0.0/24` route on the supervisor-owned, positively authenticated Mihomo
`utun4094`. An exact or more-specific route, a covering route on any other
interface, a changed Mihomo process/device, or an unknown VPN fails closed.

Explicit Disconnect, App EOF/SIGKILL, cancellation, peer-process death,
fallback exhaustion, supervisor-initiated harness-child termination,
supervisor TERM, or bounded command failure converges through the live
supervisor:

```text
disconnect/close any active carrier
  -> persist route delete-pending
  -> delete only the exact owned 10.88.0.2/32 route
  -> positively inspect route absence
  -> stop/close the WireGuard device and exact owned utun
  -> release the carrier backend and clear every owned mutable private buffer
  -> stop/reap the exact Mihomo child
  -> prove utun4094 and the covering route absent
  -> close the App stream and fixed socket
  -> remove only exact owned journal/public artifacts
  -> prove final process/interface/route/socket absence and unchanged Keychain
```

If route deletion or absence is ambiguous, the supervisor retains its private
journal in recovery-only state, accepts no new App, and does not destroy
ownership evidence or claim cleanup. A missing inspection is never positive
absence.

The root supervisor remains outside the harness child and holds the durable
route/Mihomo/child ownership journal. For a supervisor-initiated child
termination, it first rolls back and proves the exact `/32` route absent, then
signals/reaps the child/`utun` and Mihomo. App SIGKILL is observed as socket EOF
plus the continuously monitored PID/start identity and follows that supervised
order.

An unexpected external harness-child SIGKILL closes device descriptors before
the supervisor can choose an order and may destroy the `utun` first. The
supervisor therefore makes no route-before-`utun` claim for that case. It
immediately enters journal reconciliation, inspects the exact route and
interface, deletes the owned route if still present, proves final route
absence even when the `utun` is already gone, and then reconciles Mihomo and
the remaining journal state. Ambiguous inspection remains recovery-only.

Supervisor SIGKILL cannot promise immediate cleanup. That case may leave
journaled route, child, `utun`, or Mihomo state until the exact supervisor is
started again. On its next start it must enter recovery-only, reconcile the
journal, perform route-first cleanup and positive absence checks, and refuse
every App until recovery completes. Evidence may claim the eventual
post-restart recovery result, never instantaneous absence after supervisor
SIGKILL.

The unprivileged peer child handles controller EOF, parent identity change,
TERM, and normal stop by closing every listener and active carrier, closing
the userspace WireGuard device and echo/in-process-SSH/OpenSSH-proxy services,
and clearing its owned key buffers. It never edits the restricted account or a
root-owned artifact. The peer root supervisor observes and reaps that child,
then removes only the journal-bound public artifacts, trigger/status files,
and exact witnessed authorized-keys line. A peer-child `SIGKILL` leaves no
kernel `utun` or route by design; the supervisor must still clean validated
residue after independently proving the exact child absent. Immediately before
any intentional peer-child kill, and again while confirming absence, the
supervisor binds the PID to process start time, executable path, dev/inode,
SHA-256, owner, arm64 shape, session, and run ID. PID reuse or any changed
identity refuses the signal and cannot be reported as peer absence.

## UDP block and ordered fallback

The first batch uses a deterministic peer-process impairment instead of a
global firewall mutation. A peer-local, run-bound controller can enter
`block_quic_udp`, which keeps the exact UDP socket bound but drops every QUIC
datagram before QUIC processing and records only bounded counters. This proves
that an already working QUIC path fails because UDP responses become
unavailable; it is not permission for the client to skip QUIC.

The control boundary:

- exists only as a mode-0600 Unix socket or inherited controller pipe inside
  `kyclash-macos-lab-peer`;
- accepts a closed typed set: `block_quic_udp`, `refuse_wss`, `status`, and
  `stop`;
- accepts no shell, path, endpoint, port, address, duration, or arbitrary
  command;
- is not reachable over `en0`; and
- is removed with the peer run.

The required sequence is:

1. connect over QUIC and prove private echo plus pinned overlay SSH nonce;
2. activate `block_quic_udp`;
3. observe QUIC health failure, explicitly close QUIC, and prove no active
   carrier;
4. attach mTLS WSS and prove the same KyClash/Mihomo devices, routes, and
   private echo plus pinned overlay SSH nonce;
5. activate `refuse_wss`, close the active WSS carrier, and prove its absence;
6. attach mTLS TCP and prove the same KyClash/Mihomo devices, routes, and
   private echo plus pinned overlay SSH nonce, then run the exact system
   `/usr/bin/ssh` through `10.88.0.2:2222` and verify the forced nonce; and
7. disconnect and prove full client cleanup.

The evidence must distinguish peer-process UDP ingress drop from an operating-
system PF rule. Apart from the locked temporary bridged attachment, this
review does not authorize PF, firewall, host route/relay/listener, or global
guest network mutation. A later requirement for OS-level packet-filter
evidence needs a separate lock.

## Required acceptance matrix after lock

No row may be marked passing from source tests or the existing one-VM result.
Every runtime row must use the same exact client App/harness and peer fixture
bytes in the two named VMs.

| Gate | Required observation |
| --- | --- |
| Base isolation | base stopped before/during/after; no base runtime or file mutation |
| Distinct guests | both report `VirtualMac*`/arm64 and distinct VM UUID, MAC, IP, and SSH host key |
| Underlay authority | exact en0/CIDR/gateway/owner/time record positively authorizes one disposable local lab LAN; corporate/production/site/shared/public/managed/unknown networks fail |
| Pre-bridge exposure | role-specific listener inventories contain no unreviewed entry; effective SSH is separated, pinned, key-only, non-root, and has no forwarding |
| Bridged underlay | both disposable VMs use temporary `--net-bridged=en0`; default VZNAT, Softnet, and host relay are absent |
| Peer supervisor readiness | after bridged preflight and before Connect, one visible peer-console authorization starts the fixed no-argument root supervisor; it validates the manifest/recovery journal and reports public `idle-ready` |
| Peer bind | peer owns all three listeners only on its exact RFC1918 `en0` IP and random run ports |
| No local peer | client VM and host own no carrier listener or peer process; no endpoint is loopback or client-local |
| Mutual TLS | exact server IP SAN, pinned run CA, exact client certificate/source facts pass; missing/wrong client, SAN, CA, purpose, source, or expiry fails closed |
| App socket identity | audit token, `LOCAL_PEERPID`, start identity, exact root-pinned App path/dev/inode/SHA-256/arm64 all pass; same-UID replacement fails |
| App checkpoint | visible frontmost KyClash window shows the external-peer banner and Ready state in client VM |
| Final visible checkpoint | one same-run client-VM screenshot at final TCP shows real `utunN`, exact `/32`, Mihomo `utun4094`/`/24`, active TCP, echo healthy, and overlay SSH verified |
| Mihomo preflight | exact managed `utun4094` and `10.88.0.0/24` covering route are healthy; DNS/default/proxy snapshots unchanged |
| QUIC | real client `utun`, mTLS QUIC, exact `/32`, same-run Mihomo `/24`, peer echo, and overlay SSH nonce pass |
| UDP block -> WSS | peer drops QUIC UDP, QUIC closes before mTLS WSS attaches, same KyClash/Mihomo devices/routes/echo/SSH pass |
| WSS -> TCP | WSS closes before mTLS TCP attaches, same KyClash/Mihomo devices/routes/echo/in-process SSH pass |
| Real OpenSSH | exact Apple `/usr/bin/ssh` reaches the fixed `:2222 -> 127.0.0.1:22` proxy on final TCP and the restricted forced command returns the run nonce |
| Overlay SSH negatives | both SSH boundaries reject wrong client key, host fingerprint, password, arbitrary exec, pre-route, and post-teardown attempts |
| Cancel during courier | Cancel/App EOF in `waiting_peer_bundle` causes fixed signed-token or authenticated EOF/expiry cleanup within the 120-second budget; the host never signals a root/child process and no peer, Mihomo, `utun`, route, socket, authorized-key line, or private material remains |
| Explicit Disconnect | `/32` removed before KyClash `utun`, then exact Mihomo teardown; App returns to Disconnected; no client residue |
| Peer-child kill | peer root supervisor revalidates PID/start/executable dev/inode/hash/session/run identity before signal and absence; all fallback attempts fail boundedly and both roles clean without PID-reuse ambiguity |
| Supervised client stop | App EOF/SIGKILL or supervisor-initiated child termination performs route-first cleanup and reaches positive absence |
| Unexpected child SIGKILL | supervisor immediately reconciles the journal and proves exact route/interface final absence without claiming route-before-`utun` order |
| Supervisor SIGKILL | no immediate-clean claim; the next supervisor start enters recovery-only and proves route/child/utun/Mihomo final absence before accepting an App |
| Peer stop/EOF | peer root supervisor reaps the bound child and proves listeners, device, echo, control socket, descriptors, run public files, trigger/status files, witnessed authorized-key line, and owned mutable key buffers gone |
| Peer-supervisor SIGKILL | no immediate-clean claim; next visible start enters recovery-only, reconciles the journal/child/authorized-key line, proves peer residue absent, and refuses a new run until success |
| Final invariants | DNS, default route, system proxy, host networking, base VM, and unrelated processes/routes remain unchanged |

For the no-local-carrier-listener gate, evidence must include all of:

- before/during/after client-VM listener inventory showing no local TCP or UDP
  listener on the descriptor's three carrier ports;
- host listener inventory showing no relay/listener on those ports;
- peer-VM inventory showing the exact listeners bound to the peer `en0` IP;
- client socket observations whose remote address is the peer `en0` IP and
  peer observations whose source is the client `en0` IP;
- endpoint validation proving the peer IP is absent from every client-local
  interface; and
- private echo unreachable before the KyClash route and again unreachable
  after cleanup.

Merely displaying `Connected`, connecting to `127.0.0.1`, or observing bytes
inside one process cannot satisfy this review.

## Evidence contract

Redacted evidence binds one run ID to:

- exact source commit and hashes for App, client harness, and peer fixture;
- base/client/peer VM names and the base stopped-state proof;
- exact per-run local-lab LAN authorization, interface/CIDR/gateway/owner/time
  classification, and negative production/corporate/shared/unknown result;
- both runtime guests' `VirtualMac*` model, arm64 architecture, OS build, and
  distinct identity checks;
- closed pre/post-bridge listener inventories, effective key-only sshd
  settings, role-specific authorization keys, regenerated/pinned host keys,
  and separate known-hosts results;
- exact temporary `--net-bridged=en0` classification and negative proof for
  default VZNAT, Softnet, and any host listener/relay;
- public descriptor, public certificate, and exact-byte digest validation
  results without retaining private material;
- pinned courier public fingerprint plus both canonical signed-manifest hashes,
  direction/nonces/sequences/times, and signature-verification results;
- `start_lab` supervision, Tart ARP/pinned-SSH/en0 agreement, console-user
  create-only inbox/trigger/cancel publication, stable-fd root reads,
  public-status observation without host process control, and the 120-second
  startup/cancellation result;
- visible peer-console authorization, root-supervisor manifest/recovery check,
  `idle-ready`/run/`clean-postflight` states, exact child PID/session binding,
  authorized-keys journal transaction, and peer-supervisor-SIGKILL recovery;
- peer `en0` private-address classification, listener ownership, and no-local-
  listener result;
- visible client App window and one same-run final-TCP screenshot showing the
  fixed banner, real `utunN`, exact `/32`, Mihomo `utun4094`/`/24`, TCP
  active, echo healthy, and overlay SSH verified;
- real `utunN`, exact `/32` route ownership, exact Mihomo
  `utun4094`/covering `/24`, private-echo result, carrier order, and
  break-before-make observations;
- overlay-SSH client/server public fingerprints, pinned-handshake/fixed-nonce
  results on all three carriers, exact system-OpenSSH proxy/client/forced-
  command result on final TCP, and negative-auth/request results;
- deterministic QUIC UDP-drop and WSS-refusal reason codes;
- bounded peer-kill, explicit-disconnect, App EOF, peer EOF, and harness-child
  kill cleanup times plus supervisor-SIGKILL restart recovery; and
- final absence plus unchanged DNS/default-route/proxy/host/base invariants.

Evidence excludes every private key, password, token, bootstrap secret,
credential, raw process environment, raw controller traffic, and certificate
private value. Public descriptors/certificates may be retained only with their
lab classification and short-lived run ID; UI and ordinary logs remain
redacted.

## Source gates required before runtime construction

After this review is independently approved and locked, implementation must
close all of these source gates before any two-VM acceptance run:

- old loopback and new external-peer features are mutually exclusive and the
  old validator still rejects non-loopback endpoints;
- the new validator accepts only the exact private peer-`en0` contract and has
  negative tests for loopback, wildcard, public, alternate-interface,
  client-local, hostname, overlap, malformed descriptor, and stale identity;
- one peer WireGuard device and one switchboard serve all three listeners;
- private-key lifecycle tests prove no serialization or cross-VM transfer;
- `x/crypto/ssh` tests prove ephemeral host/client keys, pinned fingerprints,
  public-key-only auth, exact no-shell nonce request, rejection of every other
  channel/request/auth method, and teardown;
- real-OpenSSH tests prove the fixed userspace-to-loopback proxy, restricted
  account/authorized-key/forced-command shape, private in-memory `ssh-agent`,
  matching public-only IdentityFile selection under `IdentitiesOnly=yes`,
  exact Apple `/usr/bin/ssh`, pinned system host key, nonce result, negative
  auth/command cases, and run-key/agent/public-file/proxy cleanup;
- descriptor tests bind each canonical raw `ssh-ed25519` public artifact to its
  exact SHA-256/fingerprint, `10.88.0.2:22`, and run-nonce hash, and refuse peer
  publication until echo, in-process SSH, and the fixed OpenSSH proxy are ready;
- mutual-CA/server-SAN/client-certificate/source binding, TLS 1.3, ALPN, WSS
  path, random port allocation, descriptor atomicity, and digest/TOCTOU checks
  have focused tests;
- raw TCP source refusal occurs before TLS, while QUIC/WSS source plus
  certificate refusal occurs immediately after handshake and before every
  stream, upgrade, KYNP, WireGuard, or switchboard operation;
- the client courier inbox is pre-created by the harness, writable only by the
  exact console user with create-only semantics, and consumed only through
  retained directory descriptors plus `openat(O_NOFOLLOW)` and stable
  before/after file identity;
- both courier directions and the terminal cancel token require a valid
  Ed25519 signature over the exact fixed-layout run/direction/VM/address/time
  facts using the public key pinned by root-owned client and peer manifests;
  tests reject replay, role swap, future/stale time, wrong kind/sequence,
  post-cancel input, whole-bundle substitution, and any TOCTOU change;
- isolated-bootstrap tests/build checks bind the root-staged peer
  binary/config/courier public key and symmetric inherited-pipe input/output
  provenance without putting the courier private key in a guest;
- App/socket handshakes expose only fixed redacted fields and accept no
  frontend authority; the external sibling startup budget is bounded to 120
  seconds and Cancel/App EOF causes fixed signed-token or authenticated
  EOF/expiry cleanup without host authority over a peer process;
- socket tests reject same-UID races through audit-token/`LOCAL_PEERPID` plus
  exact root-pinned App path/dev/inode/SHA-256/arm64/PID-start binding;
- supervisor tests retain the journal outside the harness child, prove
  route-first cleanup for supervisor-initiated child termination, reconcile
  unexpected external child SIGKILL without an ordering claim, and treat
  supervisor SIGKILL as next-start recovery rather than immediate absence;
- peer-supervisor tests prove visible one-shot startup, manifest validation,
  `idle-ready`, create-only fixed trigger/inbox handling, independent courier
  verification, exact unprivileged child PID/session binding, root outbox and
  authorized-keys journal ownership, signed cancel/EOF/TERM/child-death
  cleanup, clean postflight, and next-start SIGKILL recovery before a new run;
- actual-child tests prove route-after-health, exact route ownership,
  QUIC -> WSS -> TCP break-before-make, UDP drop, WSS refusal, cancellation,
  peer loss, same-run Mihomo coexistence, and route-before-`utun` cleanup only
  on normal or supervisor-initiated teardown;
- default/release builds contain no external-peer commands, UI, public CA,
  descriptor, fixture, or feature activation;
- scripts refuse the host and base as runtime targets, accept only the two
  exact disposable VM roles, require temporary `--net-bridged=en0`, and reject
  default VZNAT, Softnet, host relay/proxy, non-RFC1918 peer bind, or any
  bridged network lacking the exact per-run disposable-local-lab authorization;
- the host runner uses only Tart ARP plus the pinned VM MAC/SSH-host-key/guest-
  `en0` chain, transfers only the two allowlisted public bundles as console
  users, creates only fixed signed run/cancel artifacts and no-argument wake
  triggers, observes only public status, never writes a root-owned directory,
  and never starts, stops, signals, or retains a root/peer-child session;
- the fixed read-only root listener auditor has no input/mutation surface,
  continuous inventory tests fail on every extra/changed listener, and the
  root-manifest-pinned peer child is the sole unsigned non-loopback exception;
- secret scans cover repository, build output, argv/environment captures, and
  retained evidence; and
- repository formatting, Go race/vet/test, Rust fmt/clippy/test, frontend,
  contract, and diff checks pass from the same source state.

No passing source test substitutes for the visible two-VM App matrix.

## Two-layer lock and runtime authorization

This review deliberately separates the locked architecture/source phase from
the later bridge runtime gate. A live closed-listener inventory cannot exist
until the peer clone has been booted in isolation; requiring that inventory
before authorizing the clone would be circular.

### Layer A — architecture, source, and isolated-bootstrap lock

Layer A was locked only after independent review reported no unresolved
critical or high finding in the contracts for:

1. the trusted-host/threat boundary and public-only courier model;
2. private keys remaining inside their owning VM memory and fixed local
   bootstrap;
3. strict RFC1918 peer-`en0` bind, mutual TLS identities, exact client source
   facts, and random ports;
4. descriptor freshness/role/TOCTOU validation plus exact raw overlay-SSH
   public-key/fingerprint/address/nonce binding;
5. console-user create-only courier inbox, stable-fd root consumption,
   independently pinned host-courier signatures, and Tart
   ARP/pinned-SSH/guest-`en0` authority;
6. the pre/post-bridge closed-listener and separated hardened key-only SSH
   preflight contract, without claiming a not-yet-collected inventory passed;
7. exact audit-token/PID/executable App authority and cancellable 120-second
   sibling startup;
8. real client `utun`/route/Mihomo ownership, deterministic UDP unavailability,
   QUIC -> WSS -> TCP break-before-make, and cleanup/recovery semantics;
9. base immutability, distinct `VirtualMac` identities, and the restricted
   clone/bootstrap workflow;
10. peer/disconnect, supervised child termination, unexpected child SIGKILL,
    peer root-supervisor authorization/ownership, and both supervisors'
    SIGKILL recovery distinctions;
11. in-process and real-OpenSSH public-key/forced-command proofs separated
    from host management SSH; and
12. the cross-VM echo/SSH plus same-run client-Mihomo claim boundary without
    LAN-gateway or production claims.

The Layer A lock authorizes source implementation,
tests, builds, and creation of `kyclash-macos-lab-peer` from the stopped base.
It also authorizes booting only the disposable client/peer through visible
console or default-NAT isolated bootstrap to regenerate/pin peer SSH host keys,
install the two separated VM-lab authorization keys, prove effective key-only
sshd configuration, create the peer-only restricted SSH test account, and
collect the closed listener inventories. A visible root staging step may place
only the exact peer root supervisor, unprivileged child/config, listener
auditor, forced-command helper, client/peer root manifests, and courier public
key/fingerprint at their fixed paths with pinned hashes/owners/modes. The base
remains stopped and untouched.

The locked source realization uses two no-argument commands per role before
Layer B. The first create-only staging command installs the fixed role bytes
and publishes the listener inventory. The second,
`kyclash-vm-external-peer-lab-{client|peer}-bootstrap-ssh-layer-a`, consumes
only the corresponding canonical raw
`{client|peer}-management-ed25519-public.bin`. It requires Remote Login to
already be visibly enabled, writes an early create-only sshd drop-in, proves
the effective key-only/AllowUsers/no-forwarding policy, and publishes the
canonical Ed25519 host public key and fingerprint. Only the peer form creates
or verifies fixed UID `502`, GID `20` `kyclashlabssh` and regenerates the
peer's fixed host keys. The client host keys remain unchanged. Exact
root-private originals and a recovery record exist before each dangerous
mutation; no password, private key, caller path, shell command, service-enable
operation, or base-VM action is in either command's authority surface.

Layer A does not authorize `--net-bridged=en0`, carrier listeners, public
courier transfer, starting the peer root supervisor, the App runtime,
privilege fixture, Mihomo, real `utun`, route mutation, or impairment
execution.

### Layer B — per-run bridged runtime authorization

Every bridged run requires a new recorded Layer B transaction after Layer A
source gates pass. Its pre-bridge checkpoint must positively bind and approve:

- the exact user-owned disposable local lab LAN interface, CIDR, gateway,
  owner, client/peer MAC/IP facts, and bounded time window;
- explicit rejection of corporate, production, site, shared, public, managed,
  guest, or ownership-unknown networking;
- the actual closed client/peer listener inventories and their independently
  reviewed role allowlists;
- effective hardened key-only SSH, separated client/peer authorization keys,
  regenerated/pinned host keys, and separate known-hosts files;
- the two distinct `VirtualMac` identities and Tart
  `--resolver=arp`/pinned-SSH/guest-`en0` agreement;
- exact source/App/harness/peer bytes and all clean preflight invariants; and
- fresh user authorization for that exact bridge target and run.

The fixed host-courier implementation preserves two independent reviewer
boundaries while assembling that record. An initial no-argument
`layer-b-inputs-init` may import the six public SSH review artifacts and
publish the exact private configuration, but it must stop at
`management-host-key-pin-required`: it cannot call
`management-host-key-pin`, create `known_hosts`, open SSH, or publish prepare
inputs. Only an independent `management-host-key-pin` invocation after
reviewer inspection may create the two role-separated pins. A later
`layer-b-inputs-init` may then prove Tart-ARP/pinned-SSH identity and publish
prepare inputs.

Likewise, receiving the two guest listener baseline candidates is evidence,
not approval. After validating the seven-file prepared review for each role,
`layer-b-inputs-init` must stop at
`listener-baseline-approval-required`. Only the separate no-argument
`layer-b-listener-baseline-approve` invocation, after revalidating the pinned
host keys, exact workspace, current VM identities, inventories, candidates,
and review witnesses, may create the private create-once approval record. It
cannot publish pin inputs. A final `layer-b-inputs-init` invocation may publish
the guest pin inputs only after matching that unchanged approval record. No
single invocation crosses either review-to-pin boundary; reentry validates
existing bytes, and tamper, role swap, or changed evidence fails closed
without replacement.

Only that passing pre-bridge checkpoint authorizes temporary
`--net-bridged=en0`; it does not authorize Connect. After bridged boot, the
same Layer B record must capture repeated identity/listener preflight and the
visible peer-console authorization of the fixed no-argument root supervisor,
including recovery-clean and public `idle-ready` proof. Only that passing
post-bridge checkpoint completes Layer B and authorizes Connect plus the
runtime acceptance matrix. Any missing/changed inventory, identity, network
classification, authorization, supervisor recovery/readiness, or source fact
forbids Connect and requires bounded cleanup.

Layer A now authorizes only the actions listed above. No bridge is authorized
until the Layer B pre-bridge checkpoint passes, and no Connect/runtime network
action is authorized until its post-bridge checkpoint passes.

## Out of scope

- production or staging servers, credentials, policy authorities, and
  endpoints;
- LAN/subnet routing, IP forwarding, NAT, DNS, default-route, proxy, PVE, ROS,
  K3s, or production infrastructure;
- default Tart VZNAT as a cross-VM path, Softnet or another host SUID/root
  networking tool, host runtime, host listener/proxy/relay, host port
  forwarding, host `utun`, host route, or host PF;
- changes to the stopped base VM;
- persistent peer enrollment or reboot-stable lab identities;
- System/login Keychain mutation;
- production helpers/XPC/broker registration;
- packaging, install, signing, notarization, App Store, GitHub Release, or
  updater activation; and
- physical-Mac and general release acceptance.
