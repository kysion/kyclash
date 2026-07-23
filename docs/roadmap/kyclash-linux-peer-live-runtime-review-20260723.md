# KyClash Linux Peer live-runtime review

Status: approved and locked for source implementation and isolated Linux
acceptance; live deployment remains unauthorized

Date: 2026-07-23

Lock record:

- approved content SHA-256:
  `e68c5938fe26b4729f4f4404c7ce222a1b6eed18e671c327e384e3ff5e57c998`;
- independent security/WAL review: Critical 0, High 0, Medium 0, approved;
- independent protocol/implementation review: Critical 0, High 0, Medium 0,
  approved;
- independent Linux/systemd/config-schema review: Critical 0, High 0,
  Medium 0, approved; and
- this status and lock-record insertion is administrative only. It does not
  alter the approved content or expand the activation/authorization boundary.

Amends and supersedes before first live deployment:

- `../architecture/kyclash-linux-peer-v1.md` clauses that permit 1–32
  configured clients, require only the root-owned credential shape, name
  `preprovisioned_linux_tun`, or reserve a future pre-provisioner;
- `../architecture/kyclash-network-runtime-v1.md` startup and carrier
  wire-order clauses, solely to require the versioned TLS-bound
  WireGuard-possession exchange below before the existing KYNP-v1 packet
  envelope and to bind each post-auth WSS binary message to exactly one
  complete KYNP-v1 frame or one phase-specific fixed KYCR ready record instead
  of an unbounded byte-stream adapter;
- `../architecture/kyclash-networking-v1.md` production profile contract,
  solely to make the first live macOS profile schema version 2 and add the
  matching `carrier_auth_version: 1` plus public
  `tunnel.local_public_key` fields to the macOS client and Linux Peer pair;
- `network-sidecar/schemas/kyclash-linux-peer-v1.schema.json`; and
- `/etc/kyclash/network-peer-v1.json`.

The superseded v1 skeleton was never a live or deployed protocol. The live
implementation increments the machine contract to schema version 2, uses
`kyclash-linux-peer-v2.schema.json` and the fixed
`/etc/kyclash/network-peer-v2.json` path, and rejects v1 in live mode.

Parent authorities:

- `kyclash-plan-review-20260721.md`
- `../architecture/kyclash-networking-v1.md`
- `../architecture/kyclash-network-runtime-v1.md`
- `kyclash-production-networking-work-program-20260721.md`
- `kyclash-vm-external-peer-lab-review-20260723.md`
- `../architecture/kyclash-linux-peer-v1.md`

This review covers the first deployable Linux endpoint that terminates the
locked KyClash QUIC, WSS and TCP carriers, authenticates one WireGuard client,
and forwards only explicitly configured private prefixes. It does not
authorize deployment, production credentials, a production endpoint, a
Shenzhen infrastructure change, or a claim that site SSH is already
reachable.

## Findings that block the current skeleton

The existing `productionpeer` package is a useful fail-closed configuration
and lifecycle skeleton, but it is not a safe live runtime yet:

1. a real systemd `LoadCredential=` directory may remain root-owned and grant
   the service UID access with a POSIX ACL, while the current reader requires
   UID 0 and rejects the ACL mask reflected in group mode bits;
2. the public configuration admits as many as 32 WireGuard public keys but
   there is no handshake-bound admission implementation enforcing one active
   client;
3. string-only forwarding facts cannot prove the identity or continued health
   of a TUN, network namespace, route, forwarding gate or site interface;
4. a process-local reverse close cannot recover privileged state after
   `SIGKILL`, OOM or a peer-process crash;
5. the three listener implementations, candidate/session arbiter, live
   command, systemd sandbox and native Linux evidence do not exist; and
6. a carrier ping proves only KYNP carrier liveness. It does not prove an
   authenticated WireGuard handshake or private-IP/SSH reachability.

The live runtime remains default-off until every locked source and isolated
Linux gate below passes.

## Locked scope proposed by this review

The first live version remains:

- one site;
- exactly one configured and active WireGuard client;
- each enabled address family is end-to-end consistent across server address,
  client address, private prefixes, forwarding facts and acceptance tests;
- routed return path only;
- no NAT, SNAT, masquerade, exit-node, DNS or default-route behavior;
- QUIC first, then WSS, then TCP;
- break-before-make;
- TLS 1.3 server authentication with inner WireGuard client authentication;
  and
- ordinary private IP transport, including TCP/22, rather than a built-in SSH
  shell or command service.

Increasing the configured-client count, adding outer client certificates,
adding NAT, or changing carrier order requires another review.

## Configuration amendment

The source decoder and JSON Schema must enforce all of these:

- `schema_version` is exactly 2 and `forwarding.mode` is exactly
  `brokered_linux_tun_fd`. The v1 pre-provisioned-TUN value fails closed.
- `carrier_auth_version` is exactly 1 on both the Linux public configuration
  and the schema-version-2 macOS signed production profile. The live macOS
  profile also contains the canonical Base64
  `tunnel.local_public_key`; the client sidecar derives its public key from
  the Keychain bootstrap, compares it in constant time, and clears the raw
  private bootstrap before readiness. An absent, v1 or unknown profile,
  version/key mismatch, or missing field fails before a socket is opened. The
  pair validator compares the public client key and auth version exactly.
- `wireguard.clients` contains exactly one item. A runtime-only check while the
  public schema still advertises 32 clients is not sufficient.
- Every private prefix is wholly contained in exactly one of
  `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, or `fc00::/7`.
  Merely testing the prefix's first address is forbidden. Default, public,
  multicast, link-local, boundary-crossing and tunnel-overlapping prefixes
  fail closed.
- `forwarding.private_cidrs` contains 1–16 canonical, nonoverlapping entries
  with at most 1 KiB of canonical encoded prefix text. The complete
  effective-FIB partition may contain at most 256 disjoint entries and 32 KiB
  of canonical evidence; exceeding either bound fails before intent rather
  than truncating a journal, nft set or review artifact.
- IPv4-mapped IPv6 addresses, zones, non-canonical addresses and non-canonical
  prefixes fail closed.
- All three listeners bind the same exact canonical numeric IPv4 local
  address and three distinct unprivileged ports. IPv6 carrier underlay is
  rejected in live version 1; inner WireGuard and private routes remain
  independently dual-stack. The outer listener NIC therefore needs only the
  explicitly allowed ARP path. Inner/site IPv6 uses the separately locked
  permanent-neighbour/reciprocal-mapping contract and does not depend on
  runtime NDP during a lease. The advertised URL port equals the bind port, its host equals
  `tls.server_name`, and its serialized URL is canonical. Empty-query
  markers, raw paths, user information, fragments and opaque URLs fail
  closed.
- `tls.server_name` and every advertised URL host are the same canonical
  lowercase DNS name, never an IP literal. This is required because every
  carrier requires a nonempty TLS SNI HostName. Numeric IP underlay remains
  only in each listener's `bind` field.
- Startup resolves that one bind address to exactly one current local
  interface and ifindex, resolves the configured site interface, and requires
  the two persistent ifindices to be distinct. The address and both ifindices
  become readiness facts and are monitored for drift.
- The public config cannot select a gateway, route or MAC. Phase A derives
  exactly one site gateway per enabled family from the complete pre-existing
  effective FIB, then requires exact agreement with the sole root-owned
  runtime manifest. There is no separate host manifest: throughout this
  review that historical term means only the fixed
  `/usr/lib/kyclash/network-peer-runtime-v1.json` runtime manifest. It binds
  the canonical gateway address, exact
  lowercase six-byte unicast nonlocal gateway MAC, site-interface MAC and
  directly reachable transport prefix. The gateway is outside every
  configured private and WireGuard tunnel prefix and is the sole next hop for
  every protected FIB partition of its family. A directly connected private
  prefix, second gateway, interface-only private route, recursive lookup,
  multicast/broadcast/zero MAC or family mismatch fails before intent.
- The existing exact QUIC -> WSS -> TCP order, `/kynp`, ALPN
  `kyclash-network/1`, MTU 1420 and bounded policy intervals remain
  unchanged.
- `policy.shutdown_grace_seconds` is exactly 10. `health_interval_seconds`
  schedules one serialized, payload-free KYNP-v1 Ping while no earlier Ping
  is outstanding. Only the next valid payload-free KYNP-v1 Pong on the same
  authenticated carrier, or authenticated correctly decrypted WireGuard
  traffic for the configured peer, advances active health. Raw TLS activity,
  carrier-auth control bytes, unsolicited/duplicate Pong, malformed KYNP,
  unknown WireGuard traffic and writes without a response do not. A Pong is
  due within the smaller of five seconds and one health interval. A missed
  response, or no qualifying event for `idle_timeout_seconds`, closes and
  joins the carrier, runs WireGuard Down/drain/detach, and frees the single
  slot before fallback/reconnect. This does not change the locked KYNP-v1
  Ping/Pong wire format.

The already implemented full-prefix containment check is retained as a
required regression gate.

## Fixed non-root service identity

The steady-state Peer runs as the fixed, non-login `kyclash` account and the
fixed shared primary group `kyclash-ipc`:

- real, effective, saved-set and filesystem UID all equal the nonzero
  `kyclash` UID;
- real, effective, saved-set and filesystem GID all equal the nonzero
  `kyclash-ipc` GID;
- the kernel supplementary group list contains exactly the same sole
  `kyclash-ipc` GID added by systemd's `initgroups(3)` path and no other GID;
- inheritable, permitted, effective, bounding and ambient capability sets are
  all empty, and `NoNewPrivs` is 1;
- the Peer never invokes a shell, `ip`, `route`, `nft`, `sysctl` or another
  privileged executable;
- the Peer cannot create, rename, configure or reopen a TUN by name; and
- changing the system account or granting the Peer `CAP_NET_ADMIN` requires a
  new review.

The privilege boundary is a separate fixed-surface broker running as the
distinct non-login, nonzero `kyclash-broker` account and the same fixed
`kyclash-ipc` primary group. Its real, effective, saved-set and filesystem
UID/GID values are exact; its supplementary group list contains exactly the
same sole IPC GID and no other GID. Its inheritable,
permitted, effective, bounding and ambient capability sets contain exactly
`CAP_NET_ADMIN`, no other capability, and `NoNewPrivs` is 1. It is not UID 0
and has no `CAP_BPF`, `CAP_DAC_OVERRIDE`, `CAP_DAC_READ_SEARCH`,
`CAP_SYS_ADMIN` or `CAP_SYS_PTRACE`. The broker cannot load or attach a BPF
program. The broker cannot access the Peer credential mount or
credential stores, read TLS or WireGuard credentials, open carrier listeners,
parse caller-supplied routes, run commands, or perform
DNS/default-route/NAT work. The broker unit makes `/run/credentials`,
`/run/credstore`, `/run/credstore.encrypted`, `/etc/credstore`,
`/etc/credstore.encrypted`, `/usr/lib/credstore`,
`/usr/lib/credstore.encrypted`,
`/etc/kyclash/credentials.encrypted`, and the Peer service's private state
inaccessible.

Both processes parse `/proc/self/status` and use `getresuid(2)`,
`getresgid(2)` and `capget(2)` to fail closed on any mismatch. Native evidence
records only numeric identity/capability facts, never process environment.
Installation records the allocated nonzero numeric Peer UID, broker UID and
IPC GID in the fixed root-owned binary/identity manifest; each start compares
NSS resolution and kernel credentials with those numeric values. Reusing or
remapping one of the names/IDs is a startup conflict.
The `kyclash` numeric UID is dedicated to this Peer unit; another process
running under the same UID is inside the same credential trust domain and is
therefore an installation conflict. Before reading any credential, the Peer
sets `PR_SET_DUMPABLE=0`, re-reads it with `PR_GET_DUMPABLE`, and fails closed
unless it is zero. The broker performs the same operation before opening its
socket. Both units set `LimitCORE=0`; neither process grants ptrace access or
emits a core dump.

## systemd credential materialization

The production unit declares only the three fixed credential names:

```text
tls-chain.pem
tls-private-key.pem
wireguard-private-key
```

The initial live unit supplies all three through fixed
`LoadCredentialEncrypted=` entries whose encrypted source files live only
under the fixed root-owned mode-`0700`
`/etc/kyclash/credentials.encrypted` directory. Each encrypted source is a
UID/GID-0, mode-`0600`, regular, single-link file, is not writable by any
service UID/group, and has no symlink in its fixed root-owned path. Plain
`LoadCredential=`,
`SetCredential=`, credential-store name lookup, caller-selected source paths,
argv, arbitrary environment values and working-directory files are
forbidden.

`$CREDENTIALS_DIRECTORY` is the sole systemd-supported directory-discovery
interface and is accepted only in no-argument live mode after the process has
proved its exact unit and invocation identity. It must be a canonical
absolute path with no symlink component. Only the three compiled basenames
may be opened relative to its already-open directory descriptor; the value
is never logged or copied into a child environment. `--check-config` never
reads the variable or credentials. A caller-supplied variable outside the
exact systemd unit therefore cannot turn an interactive process into a live
service.

The Peer requires systemd's read-only credential copy and records the tested
systemd version and observable mount facts. It does not assume a stable
filesystem type, mountpoint string, inode owner or mode beyond the safe
profiles below: those are implementation details which systemd may vary.
Native gates instead prove that the Peer UID can read but cannot modify,
replace or rename the files, while the broker, shared IPC group and unrelated
UID cannot read them. A writable or ordinary caller-created directory fails
closed.

For the pinned/tested systemd version, the reader accepts the following two
observed materialization shapes:

1. a UID/GID-0 directory and UID/GID-0 files whose POSIX access ACL contains
   only the fixed Peer UID as an additional named user; the file named-user
   permission and mask are exactly `r--`, the directory named-user permission
   and mask are exactly `r-x`, `group::---` and `other::---`, and there is no
   other named or default ACL; or
2. a Peer-UID-owned mode-`0500` directory and mode-`0400` files with no
   extended/default ACL.

ACL mask bits reflected in `stat(2)` group bits are not ordinary group access
and must be parsed, not guessed. A normal group grant, extra named user/group,
default ACL, writable/shared credential view, wrong owner, symlink,
non-regular file, regular-file link count other than one, or changing
device/inode/size or security-relevant mode/UID/GID/ACL/mount metadata fails
closed. Atime is not an identity field and is never compared. Directory link
count is not fixed.
The existing directory-relative `openat(O_NOFOLLOW)` and before/after stable
identity checks remain mandatory.

These owner/mode/ACL shapes are a compatibility profile for the pinned
systemd version, not a claim that they are a stable systemd ABI. The stable
live outcome is that the Peer UID can read but not write, replace or rename
the three files, while the broker UID, IPC group and an unrelated UID cannot
read them. Mount ID, filesystem type and `ro,nodev,nosuid,noexec` observations
are recorded before and after reads when the kernel exposes them; changed
facts fail closed, but an exact filesystem type or mount layout is not
treated as a systemd ABI.
systemd's current implementation first writes credential files read-only,
grants the unit UID a precise ACL when supported, and uses ownership only on
a credential filesystem that can be made read-only:

- [systemd credentials documentation](https://systemd.io/CREDENTIALS/)
- [systemd `exec-credential.c`](https://github.com/systemd/systemd/blob/main/src/core/exec-credential.c)

## Opaque identity lease

The live identity provider loads and validates the three credentials once per
process generation. Its lease:

- verifies the leaf DER SHA-256, exact server name, server-auth EKU, current
  validity, complete chain and TLS private-key match;
- enforces TLS minimum and maximum version 1.3, the exact QUIC ALPN, no
  `KeyLogWriter`, no 0-RTT and no hot credential replacement;
- derives and constant-time matches the WireGuard public key;
- exposes a narrowly typed TLS-server capability and a one-use WireGuard
  device-configuration capability rather than raw PEM/private-key getters;
- owns a certificate-expiry `Done()` signal;
- clears every owned source/decoded WireGuard byte on success, failure and
  close; and
- has a fixed redacted `String`/error/status representation.

Opaque copies retained by Go's TLS implementation are destroyed by closing
the process generation; the implementation must not claim byte-level erasure
inside opaque library objects.

## Privileged broker and TUN-FD lease

The broker reads the same fixed public configuration independently and accepts
only one request over a fixed `AF_UNIX/SOCK_SEQPACKET` endpoint. PID 1 creates
the exact `kyclash-broker:kyclash-ipc` mode-`0750`
`/run/kyclash-network-peer-broker` `RuntimeDirectory=`. The nonroot broker
validates that directory and creates only `broker.sock` as
`kyclash-broker:kyclash-ipc`, mode `0660`. A systemd socket unit is
deliberately not used: otherwise PID 1 would be the listening process
represented by peer credentials. The broker never accepts or chmods a
caller-selected endpoint.

Linux 6.5 and systemd 255 are minimum source-compatible versions, but minimum
versions are not live authority. A live broker additionally requires the exact
kernel release, kernel build ID, systemd version and hook-enumeration ABI in
the reviewed runtime manifest below. An unlisted kernel or systemd build,
including a newer one, fails closed until another review adds it. Both sides
require `SO_PEERCRED` plus `SO_PEERPIDFD`; absence is a startup failure with no
PID number fallback. The pidfd must identify the same live PID reported by
`SO_PEERCRED` and remains open for the complete lease. Through systemd's
`GetUnitByPIDFD` D-Bus method, each side requires the exact other unit and
invocation ID, then checks that unit's exact main PID, cgroup, fixed root-owned
`ExecStart` path and root-owned public binary-manifest SHA-256.

The binary and identity manifest is
`/usr/lib/kyclash/network-peer-binaries-v1.json`: canonical schema-version-1
JSON of at most 4 KiB, UID/GID 0, mode `0644`, one regular link, no ACL or
symlink, containing the exact numeric Peer UID, broker UID, IPC GID and
SHA-256 for `/usr/libexec/kyclash-network-peer`,
`/usr/libexec/kyclash-network-peer-broker` and the root oneshot
`/usr/libexec/kyclash-network-peer-host-bootstrap`. All three executables
must independently be UID/GID 0, mode `0755`, one regular link, have no
ACL/symlink and be unwritable by either service identity. They have no
`security.capability` file xattr; capabilities come only from the reviewed
units. Directory-relative `openat2` plus before/after metadata and digest
checks are mandatory.

Start-time and unit facts are checked before and after the exchange while the
same pidfd remains live. This avoids granting either nonroot service
`CAP_SYS_PTRACE` merely to inspect the other UID's `/proc/PID/exe`.

The sole runtime manifest is the fixed root-owned
`/usr/lib/kyclash/network-peer-runtime-v1.json`: canonical
schema-version-1 JSON of at most 256 KiB, UID/GID 0, mode `0644`, one regular
link, no ACL/symlink and protected by the same directory-relative
open/digest/race checks. It contains no secret or caller-selected path. It
pins the exact kernel release and build ID, systemd version, expected
`NFNL_SUBSYS_HOOK` ABI, the complete allowed built-in netfilter hook tuples
(family, hook number, priority, hook type, function and module), and the
complete netdevice BPF attach-type/attestation-mechanism list for that kernel,
the one-device `NETDEV_UNREGISTER`/one-`RTM_DELLINK` behavior and nft notifier
release of every base chain bound to that device, every rule in each released
chain, every rule-carried set/map binding and every anonymous set/map whose
final reference is released with those rules,
the exact `CONFIG_NF_CONNTRACK_ZONES=y` and
`CONFIG_NF_CONNTRACK_MARK=y` configuration, ctnetlink
`CTA_ZONE`/`CTA_MARK` filter plus `CTA_ID` delete ABI, nft `ct zone set` and
32-bit replacement `ct mark set` support in inet hooks, nft `notrack`
support in raw-priority inet prerouting/output before conntrack, and skb
`meta mark set`/match support in inet postrouting and netdev egress. It pins
the table-local named `NFT_OBJECT_LIMIT` ABI and shared-object reference
semantics used by both family-specific new-flow rules. It
explicitly records that the pinned kernel rejects every conntrack expression
in the netdev family; no netdev chain in this design may contain one. The
manifest also pins the upstream Linux v6.8 commit, the KyClash strict
conntrack-limit patch SHA-256, kernel Build ID/config and the enabled
default-off `CONFIG_KYCLASH_NF_CONNTRACK_STRICT_LIMIT` ABI. That patch uses
one VM-global atomic try-reserve before allocation and a release paired with
the unique final free path. It admits at most 1024 successfully allocated,
not-yet-freed non-template `nf_conn` objects across every network namespace,
including normal, unconfirmed, dying and externally reference-held objects.
At the limit it fails new allocation without running `early_drop` or evicting
an existing flow. Allocation-failure and final-free paths release exactly one
reservation; the manifest rejects an unpatched kernel, a disabled option, a
counter ABI mismatch or a counter above 1024.

The repository must carry that patch as
`linux/patches/0001-kyclash-nf-conntrack-strict-limit.patch` plus its
upstream-commit/provenance record and KUnit selftests. It applies only to
upstream commit `e8f897f4afef0031fe618a8e94127a0934896aba`; any offset,
fuzz, extra patch or tree diff fails the image build. The Kconfig option is
`bool`, defaults `n`, and when enabled compiles the immutable limit 1024. The
patch exposes only two mode-`0444` unsigned read-only facts,
`/proc/sys/net/netfilter/kyclash_nf_conntrack_strict_limit` and
`kyclash_nf_conntrack_strict_count`; their proc handlers return `-EPERM` for
every call with `write != 0`. The broker
opens and re-reads both fixed files with the same proc visibility and numeric
canonicalization rules as the other pinned netfilter facts. Their samples are
monitoring evidence, not a substitute for the pinned Build ID/config/patch
hash.

The try-reserve occurs before `kmem_cache_alloc` in
`__nf_conntrack_alloc`; `old >= 1024` fails immediately. Once reserved, the
ordinary per-net count is still maintained, but exceeding
`nf_conntrack_max` takes a direct allocation-failure path and cannot call
`early_drop`. Every error after reservation and before publishing the object
uses one common release path; every published object's sole release is paired
with `nf_conntrack_free`. The disabled Kconfig path remains byte-for-byte
upstream outside the guarded declarations/calls. Templates are deliberately
outside this counter and therefore accepted only through the separately
pinned finite possible-CPU/template inventory.

`nf_conntrack_max=1024` remains a pinned operating setting, not the
cardinality proof. The manifest additionally pins the possible-CPU count and
the finite per-CPU template inventory, and forbids NFQUEUE, helpers,
expectations and any other queued or template-producing path outside that
inventory. Start count at most 128, active global shutdown watermark 896,
current-mark shutdown watermark 224, the shared new-flow limiter of 16 per
second with burst 16 and the one-second monitor reconciliation deadline are
early fail-close controls, not object quotas. The strict VM-global patch is
the sole hard 1024 bound; therefore a generation zone or current mark can
never cover more than 1024 still-allocated non-template objects.

The two-second post-retirement interval is only a cleanup watchdog/SLO, never
a kernel completion bound. It caps one cleanup attempt, not object lifetime,
DESTROY delivery or the number of retry requests. Expiry durably enters
the global `boot_terminal` first and, only for the matching current lease
journal, then enters `conntrack_reboot_required`; it retains all fail-closed
authority and forbids another lease on the same boot. It pins the complete relevant conntrack
timeout, `IPCTNL_MSG_CT_GET_DYING`, event-delivery, accounting, hash-table and
netlink attribute/reserved-bit ABI. The manifest also pins the upstream
source fact that Linux v6.8
`ctnetlink_dump_unconfirmed()` returns an empty dump without enumerating
unconfirmed entries; `IPCTNL_MSG_CT_GET_UNCONFIRMED` is therefore forbidden
as readiness, cleanup or absence evidence. The pinned
`nf_conntrack_count` allocation semantics include entries before
confirmation, so the global count is only a resource bound over visible plus
hidden objects, never proof that a particular zone is empty.
It pins the final-close path
`tun_chr_close -> tun_detach -> __tun_detach -> unregister_netdevice`, the
single-queue/non-persistent TUN preconditions, and the exact
`unregister_netdevice_many_notify` ordering: device unlist,
`flush_all_backlogs()`, first `synchronize_net()`, `NETDEV_UNREGISTER`,
`RTM_DELLINK`, then the second `synchronize_net()`. It also pins the Linux
v6.8 `RTM_GETLINK` registration flags and the `rtnetlink_rcv_msg()` non-dump
doit path: the registered doit is not marked `RTNL_FLAG_DOIT_UNLOCKED`, so
that path explicitly takes `rtnl_lock()` around each fresh request. It does
not attribute this boundary to the netlink dump callback mutex. Fresh
exact-name and exact-ifindex non-dump `RTM_GETLINK` requests cannot execute
until the synchronous RTNL unregister phase, including both
`synchronize_net()` calls and notification send, has returned. This is
registered-link absence evidence only; it does not claim delayed
`netdev_run_todo`/free or an entire close syscall has completed.
It also contains an `ipv6_force_forwarding_abi` enum whose only values are
`present` and `absent`, the exact trusted OS
process/unit/executable/cgroup/capability inventory permitted after static
network handoff, and the complete security-relevant ethtool feature-name/bit
inventory. For each enabled family it pins the one
site gateway address, direct gateway-reachability prefix/route, permanent
gateway-neighbour MAC, local site-interface MAC and the expected effective
protected-prefix FIB partition count plus canonical SHA-256. It pins
boot-initial IPv4/IPv6 forwarding zero, the fixed
`inet kyclash_guard_v1` table and `forward_guard` base-chain
schema (inet/filter/forward/priority `-50`/policy drop/initially empty), and
the state-specific complete hook/object allowlists for bootstrap-pre, closed,
active, draining and clean. It also pins
`manager_mode=permanently_masked_for_peer_image_v1`, the complete finite
systemd-networkd and NetworkManager activation closure for the selected image
(canonical services, aliases, sockets, D-Bus activation names, paths, timers,
wait-online/dispatcher/cloud helpers and every `Alias=`, `Also=`, `Sockets=`,
`Wants=` or `Requires=` edge), every persistent `/etc/systemd/system` mask
symlink and target, package/unit/DBus-service/executable hashes, the initrd
image SHA-256 plus the complete build-time initrd-inventory SHA-256, and the
fixed host-bootstrap unit/configuration hashes. The bounded build evidence,
not a runtime caller path, retains that complete inventory.
A bootstrap invocation opens exactly this runtime manifest and the fixed
`/etc/kyclash/network-peer-v2.json` public configuration; it has no third
network, gateway, interface or host-manifest source. Both files use
directory-relative `openat2` with the fixed owner/type/mode/link-count,
no-ACL/no-symlink, before/after metadata, digest and replacement-race checks
defined by this review. The broker independently opens the same two fixed
files and additionally validates the binary manifest. No executable accepts
a manifest or configuration path from arguments or environment.
A unit/alias/activator absent from this closed manifest or an additional
ifupdown, netplan runner, cloud-init network stage or other network
administrator fails image acceptance.
A concrete runtime
manifest is deployment evidence. This review permits a test-only manifest
bound to the exact disposable acceptance image and virtual hardware; it is
rejected outside that lab. A production manifest requires the later
host-bound deployment review, and the repository default is non-activating.

Only after identity passes does the broker generate a 32-byte CSPRNG
generation, a separate nonzero 32-byte CSPRNG transfer nonce and a separate
nonzero 32-byte CSPRNG reservation ID. The reservation ID is encoded in both
durable files as exactly 64 lowercase hexadecimal characters; every other
length, case or encoding is invalid. No generation, nonce or reservation ID
supplied by the Peer is accepted as authority.
It independently generates one nonzero 16-bit default/undirected
`conntrack_zone` in the closed range 1..32767, one nonzero 32-bit `flow_mark`,
and two nonzero, pairwise distinct 32-bit
`site_skb_mark`/`tun_skb_mark` values. The zone must be clear in the current
boot's durable used-zone bitmap; a bit is never cleared or reused until a
positively observed boot-ID change. At most 4096 zones may be reserved in one
boot, after which live start requires a reboot rather than weakening the
rule. The broker selects uniformly from the remaining allowed bits and first
durably sets the used bit plus an exact `reserved` active record. It accepts
that a crash after this fsync permanently wastes the zone for this boot.
After the matching `intent` is durable, it advances that record to
`intent_bound`; no kernel mutation is authorized until both files
positively match that phase.

Before reservation it opens the loss-detecting conntrack event subscription,
performs the retired-zone catch-up, checks `nf_conntrack_count` against the
start bound, and performs one complete IPv4/IPv6 normal and dying global
ctnetlink dump. Every nonzero visible zone must classify as the exact active
journal zone or ledger-reapable; unused and spent-unowned entries fail as a
TCB/rollback violation. Any active journal is fully recovered before
reservation. Only after reaper cleanup and a fresh stable dump may it select
a candidate. That unused zone must be absent from all four views. A
normal-view zone
filter may be used only when the pinned ABI proves it complete; dying views
are always bounded full dumps filtered in userspace by the exact zone. An
entry in an unused zone is a trusted-image/setter violation and fails the
boot; the broker does not merely choose another zone. It never treats the
empty unconfirmed-dump stub as evidence. The complete hook allowlist, fixed
startup ordering, no-other-network-administrator contract and same-boot
never-reuse ledger mean a hidden unconfirmed entry can belong only to an
already-used, permanently retired zone, never the next generation.
Zone zero and directional original/reply zones are forbidden: both packet
directions use the same default-direction zone so they resolve to one
connection. Exhaustion, dump/event loss, an unknown zone representation or
failure to enumerate either supported view fails before mutation. The full
generation and marks plus the zone's exact journal/ledger binding are
retained only in private broker state and the generation-owned kernel
rules/state. Allowlisted evidence contains only the single domain-separated
truncated generation evidence ID defined below, never separate hashes of
those fields.
Caller-provided interface, address, route, nft expression, path, command and
environment data are never authority.

The broker's durable journal lives only in a fixed mode-`0700`
`StateDirectory=` owned by `kyclash-broker`. No UID-0 supervisor pre-opens it,
and neither the Peer nor an unrelated group can read or write it. The broker
unit has a closed writable-path allowlist containing only that state directory
and the fixed runtime directory. The runtime directory may contain only the
one socket; journal or temporary state there is forbidden.

The durable mutation-journal path is
`/var/lib/kyclash-network-peer-broker/lease-v1.json`. Its schema version is
exactly 1, its canonical JSON is capped at 16 KiB, and it contains only the
transition enum, non-credential recovery facts, full broker generation and
exact zone/marks, full transfer nonce, handoff reply hash when known, and the
compact public hashes/object identities named by this review. It never
contains a TLS/WireGuard key, carrier derived key, credential byte, numeric
FD, kernel pointer, OFD value or purported persistent FD/OFD identity;
its required `journal_sha256` is exactly 64 lowercase hexadecimal characters
and equals SHA-256 of the complete canonical JSON payload with that one field
omitted. The broker verifies this digest on the main journal and temporary
file before interpreting any phase, mask, handle or cleanup authority. Every
durable transition recomputes it before the exclusive write; the digest and
field name are included inside the fixed 3,072-byte envelope budget below.
exported evidence derives exactly one `generation_evidence_id` as the first
16 bytes of
`SHA-256("net.kysion.kyclash.generation-evidence/v1" ||
generation[32] || transfer_nonce[32] || zone_u16_be ||
flow_mark_u32_be || site_skb_mark_u32_be || tun_skb_mark_u32_be)` and encodes
it as 32 lowercase hexadecimal characters. No individual raw or hashed
generation, nonce, zone or mark value is exported.

The schema has closed maxima of two generation-table records, eleven chain
records (the ten generation chains plus the observed fixed guard), 64
generation-rule records, one generation-owned named-stateful-object record,
16 anonymous set/map records and two client-route records. A table or
rule record is the canonical JSON array
`[slot_u8,handle_u64,"spec_sha256"]`. A chain record is
`[slot_u8,handle_u64,old_policy_u8,new_policy_u8,"identity_sha256"]`, where the
hash covers every immutable family/table/type/hook/priority/device/userdata
identity field and the two numeric policy fields are explicit; they are equal
outside a journaled policy transition. A named-object or anonymous-object
record is `[kind_u8,slot_u8,handle_u64,"spec_sha256"]`; the closed `kind`
distinguishes the table-local named `NFT_OBJECT_LIMIT` from each anonymous
set/map class. A binding is not an independently handled or dumped nft
object: its complete reference is covered by the owning rule specification
digest and the referenced set/map identity, and it never receives a separate
compact record. Every generation-created set/map has a fixed
generation-derived `NFTA_SET_NAME`; a `%` allocation template or
kernel-selected name is forbidden even when the anonymous flag supplies
last-reference release semantics. A route record is the closed
family/destination/table/protocol/metric/ifindex tuple. A handle is an
unsigned decimal integer of at most 20 digits, every SHA-256 is exactly 64
lowercase hexadecimal characters, and every enum/slot has the fixed numeric
range in the schema. The canonical serialized maximum, including commas,
quotes, keys and brackets, is 112 bytes for each table, chain, rule, named or
anonymous record and 192 bytes for each route record. The remaining fixed
envelope,
including all phase facts, generation/nonce/reservation IDs, marks, hashes,
systemd invocation identity and transition-specific counters, is capped at
3,072 serialized bytes. Therefore the exact worst case is
`3072 + 2*112 + 11*112 + 64*112 + 1*112 + 16*112 + 2*192 = 13,984`
bytes, leaving 2,400 bytes below the 16-KiB rejection boundary. Counts, field
lengths and both the per-class and total serialized budgets are checked before
the first kernel mutation and before every durable update.

Every generation-created nft record is phase-sensitive. In `nft_pending`,
every object that the create batch will create has `handle=0` and is
`planned`; zero is never deletion authority. The create batch omits every
persistent `NFTA_*_HANDLE` attribute. Deterministic
`NFTA_CHAIN_ID`/`NFTA_RULE_ID`/`NFTA_RULE_POSITION_ID`/`NFTA_SET_ID` values
may refer within that one transaction, but are derived from the closed slot
map, are not handles, are not persisted as handles and have no meaning after
the batch. The already-existing fixed guard table/base chain are the sole
exception: their independently observed nonzero handles remain baseline
evidence and never become deletion authority for those baseline objects.

Every created nft object carries exactly this 80-byte userdata:

```text
"KYC-NFT\0"[8] | version=1[u8] | object_class[u8] |
slot[u16 big-endian] | reserved_zero[u32] |
SHA-256(generation)[32] | spec_sha256[32]
```

The specification digest excludes the handle, transaction-local ID,
userdata, the digest itself, counters and mutable statistics. The journal
stores no full nft expression. It stores the phase-sensitive handle plus the
SHA-256 of the one canonical expression/specification selected by the fixed
configuration, generation, zone/marks and runtime manifest. Full canonical
expressions exist only transiently in broker memory for reconstruction and
comparison.

Immediately before creation, one uninterrupted complete nft/hook dump must
prove every planned generation object absent and the fixed guard exact,
empty and policy-drop. After the one batch attempt and notification
resynchronization, another complete dump admits only:

1. `absent`: every planned object is absent and the baseline is unchanged; or
2. `target`: every planned object exists exactly once with its deterministic
   name/userdata/specification, nonzero correctly scoped kernel handle, exact
   rule order/references and no extra object.

A subset, duplicate userdata, zero observed handle, wrong specification or
order, changed baseline or unindexed object is `partial` and ambiguous. Only
the same process that durably wrote `nft_pending` and has not attempted the
batch may send it once. A restarted process never replays it: complete
`absent` enters rollback, while complete `target` atomically replaces every
planned zero with the observed nonzero handle in `nft_ready` and then enters
cleanup rather than resuming acquisition. Recovery reconstructs the exact
specification from immutable inputs and requires its complete nfnetlink
re-read to match before an observed nonzero handle is deletion authority.
Durable or exported acceptance evidence contains only specification digests
and allowlisted redacted role/count/result facts, never raw generation, zone,
flow mark, skb mark or an expression containing one of those values. The
compact records also index the complete TUN-netdev auto-release closure
defined below without exceeding the same
table/chain/rule/named/anonymous-object caps.

The broker opens
the state-directory descriptor with `O_DIRECTORY|O_NOFOLLOW`, resolves every
entry beneath it with `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|
RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV)`, and accepts only broker-owned
mode-`0600`, single-link regular files. Each transition is written to the
fixed broker-owned mode-`0600` exclusive `lease-v1.tmp`, fsynced, atomically
renamed over the already-validated journal and followed by a directory fsync.
No kernel mutation may occur until that rename and directory fsync complete.
Consequently, recovery may delete an exact broker-owned `lease-v1.tmp` only
after the valid main journal and observed kernel state still match its prior
transition (or both main journal and owned kernel objects are absent); the
temporary content is never cleanup authority. An unknown entry, invalid
owner/type/mode, oversized/duplicate-key/malformed main journal, or mismatch
is an ambiguous-recovery failure. Clean removal unlinks the validated journal
and fsyncs the directory.
The closed directory entry allowlist is the lease journal and temporary plus
the zone ledger and its temporary; every other entry is the “unknown entry”
failure above.

The same directory contains one separately durable boot-zone ledger,
`zone-epoch-v1.json`, provisioned in the accepted image as a schema-version-1
uninitialized sentinel and never optional. It is canonical JSON of at most
16 KiB with the same exact owner/mode/link/ACL/path checks and contains the
current boot ID, network-namespace inode, reservation count, canonical base64
for one 4096-byte `used` bitmap and one 4096-byte `reapable` bitmap covering
zones 0..32767 (RFC 4648 standard alphabet, required padding, no whitespace),
plus either no active record or exactly one
`{zone,generation_hash,reservation_id,journal_intent_hash,phase}` record and a
strictly increasing same-boot `ledger_sequence`, either no `boot_terminal` or
exactly one closed record
`{reason,source,failing_zone,generation_hash?,normal_v4,normal_v6,dying_v4,dying_v6,strict_count,snapshot_sha256,guard_sha256,deadline_result}`,
plus SHA-256 of the canonical payload excluding that digest field. The
terminal reason is exactly `conntrack_watchdog`, source is exactly one of
`lease|startup_reaper|active_reaper`, deadline result is exactly `expired`,
counts are unsigned integers `0..1024`, the zone is `1..32767`, and both
snapshot/guard hashes are lowercase 64-hex. `generation_hash` is required and
lowercase 64-hex only for `source=lease`; it is absent for either reaper
source because a clean/unlinked retired generation deliberately leaves only
its monotonic zone bit as authority. The closed active phase enum is
`reserved|intent_bound|setter_armed`; `journal_intent_hash` is absent only in
`reserved`. Bit zero is permanently set in `used` and never allocatable;
`reservation_count` must equal `popcount(used)-1`, and `reapable` must be a
subset of `used`.

For every nonzero zone, load accepts exactly one of four mutually exclusive
and exhaustive classifications:

```text
unused         used=0, reapable=0, and active.zone is not this zone
spent-unowned  used=1, reapable=0, and there is no active record for this zone
active         used=1, reapable=0, and the sole active.zone is this zone
reapable       used=1, reapable=1, and active.zone is not this zone
```

An active and reapable classification can never overlap. The sole active
zone must be in `1..32767`; its used bit must be one and its reapable bit
zero; its generation and intent hashes and 64-character reservation ID must
be canonical and match the journal rules for its phase. A `reserved` record
must omit `journal_intent_hash`, while `intent_bound` and `setter_armed` must
contain it. `reservation_count` must be at most 4096 as well as equal to
`popcount(used)-1`. Zone zero, an active zone with a wrong bit, a reapable
active zone, a noncanonical/zero ID or hash, an out-of-range zone, an unknown
phase, or any other bitmap/active combination is an impossible state that
permits only the guard-baseline safety shrink and disposable reset. Its only
temporary is `zone-epoch-v1.tmp`; every update uses the same exclusive-write,
fsync, atomic-rename and directory-fsync discipline as the lease journal. On
a matching boot ID and namespace, a used/reapable bit may transition only
zero to one and `boot_terminal` may transition only absent to present. It is
never cleared, replaced or weakened on the same boot. Canonical maximum-size
fixtures include both the active and terminal records and must remain below
the 16-KiB boundary.

The boot-terminal record is global to this boot and may coexist with no lease
journal, the matching failing-lease journal, or one different active/cleanup
journal. It never overwrites a journal. On any reaper or current-generation
cleanup watchdog expiry, the broker first fsyncs the absent-to-present
terminal ledger update. When `source=lease`, its required generation hash must
match the failing journal. If a crash occurs after that global fsync but
before the matching journal reaches `conntrack_reboot_required`, recovery
uses that journal's existing authority to finish the exact data-plane safety
shrink, then idempotently fsyncs its terminal mirror; it performs no
conntrack deletion. If another generation is active, the broker instead immediately uses
only that generation's existing journal authority to restore the fixed guard
drop, remove its exact routes/accept paths, drain it and prove link absence.
If that journal has not yet passed zone retirement, it may follow its existing
non-conntrack transitions through `zone_retired` and then stops; if it was
already in a later cleanup phase, it remains at the last positively persisted
phase. A reaper-source terminal never writes or fabricates
`conntrack_reboot_required` in that other journal. It performs no further
conntrack deletion or lease mutation. A crash after the global fsync but
before safety teardown re-enters exactly that shrink path under the unchanged
journal phase plus terminal ledger. With no active journal, startup performs
only baseline validation/shrink and refuses readiness. A terminal ledger with
a missing/mismatched active journal is ambiguous and permits only
guard-baseline shrink plus reboot.

Zone reservation first writes `used=1`, `reapable=0`, the fresh reservation
ID and active phase `reserved`; the matching lease `intent` records the
ledger sequence/reservation ID and is then fsynced; a second ledger write
stores the exact intent hash and advances the active phase to `intent_bound`.
A crash with only `reserved` and no lease journal authorizes no kernel
mutation and may clear active only after a complete link/route/nft/guard dump
equals the closed pre-intent baseline and complete normal/dying dumps show no
entry in the reserved zone. The zone remains used but not reapable: it is
spent-unowned and never deletion authority.

The cross-file cut with a matching durable `intent` while the ledger is still
`reserved` is a closed abort branch, never permission to finish
`intent_bound` and resume acquisition. Recovery first proves complete absence
of the exact TUN name, every client route, every generation nft object and
guard rule, and every normal/dying visible entry in that zone, together with
the exact empty/drop guard baseline. It then fsyncs the journal directly to
`zone_retire_pending` with disposition `spent-unowned` and an
`intent_pre_mutation_abort=true` fact. The same forward-only abort is used
when the ledger already reached matching `intent_bound` but the journal is
still `intent`: recovery never replays the uncertain TUN-create call or
adopts a same-name link. These two exact no-object cases are the sole
authorized `intent -> zone_retire_pending` edges. Only then does one ledger
update clear active while retaining `used=1,reapable=0`, after which the
journal advances to `zone_retired`, proves the same stable visible-empty cut, advances through
`retired_zone_quiescent`, `nft_absent` and `clean`, and is unlinked normally.
A crash before the ledger update sees either `reserved` or `intent_bound`
plus the matching `zone_retire_pending`; in both cases it repeats only the
complete no-object/visible-zone proof and the same forward update that clears
active to spent-unowned. A crash after that update sees the matching
spent-unowned zone plus the pending journal and advances only to
`zone_retired`; it never recreates active authority.
Any object or visible zone entry at this pre-mutation abort cut is impossible
and requires reset with zero guessed deletion. A journaled acquisition at
`intent_bound` or later requires the exact matching active record;
`intent_bound` or `setter_armed` with a missing/corrupt journal is ambiguous
and requires reset.

Before publishing the generation nft batch, the broker fsyncs `nft_pending`
and then advances the matching ledger active phase to `setter_armed`; only
then may the raw-zone setters be published. After the freeze has positively
removed every setter/accept path and link absence is proved, the broker
fsyncs `zone_retire_pending`. If the active phase reached `setter_armed`, one
ledger update sets `reapable=1` and clears active; otherwise it only clears
active and leaves `reapable=0`. It then fsyncs `zone_retired`. A
ledger-reapable/journal-retire-pending crash can only recover forward; it
never clears the bit. Thus the reaper never treats active or spent-unowned
zones as deletion authority, and every clean zone remains used until reboot.

A missing, malformed, rolled-back, same-boot-cleared/replaced boot terminal,
wrong-boot-with-live-residue or
same-boot-cleared ledger is ambiguous and permits no lease or guessed
cleanup. After a positively observed boot-ID change, old link, route, nft and
supported conntrack-view absence plus the exact empty/drop guard permits one
atomic ledger reinitialization with only used bit zero set, all reapable bits
zero, no active record, no boot terminal and sequence zero; reboot has destroyed the old
network namespace and its non-enumerable unconfirmed entries.
Exported boot-ledger evidence contains only the ledger SHA-256, boot ID, reservation
count and terminal reason/source when present, never the bitmap, failing zone
or raw generation hash.
The accepted TCB explicitly forbids restoring a live VM snapshot, rolling
back or cloning the state disk while retaining the same boot ID. A normal
file checksum and sequence detect corruption and in-process regression but
cannot prove monotonicity across such a host-level rollback; supporting it
would require a separately reviewed TPM or host monotonic counter.

The schema-version-1 transition enum is closed and contains exactly:

```text
intent
tun_created
tun_features_pending
tun_features_ready
link_config_pending
link_config_ready
client_routes_pending
client_routes_ready
nft_pending
nft_ready
link_up_pending
link_up_ready
handoff_pending
leased
drop_gate_pending
drop_gate_ready
client_routes_delete_pending
client_routes_absent
tun_ingress_policy_drop_pending
tun_ingress_policy_drop_ready
tun_nft_detach_pending
tun_nft_detach_ready
peer_tun_close_pending
link_down_pending
link_down
broker_tun_slot_consume_pending
link_absent
zone_retire_pending
zone_retired
retired_zone_cleanup_pending
conntrack_reboot_required
retired_zone_quiescent
nft_delete_pending
nft_absent
clean
```

The enum above defines a forward phase order, not a requirement that every
failed generation visit every entry. The success path uses every adjacent
acquisition state. A failure edge may enter the earliest applicable cleanup
pending state only after a complete dump proves that every bypassed object
class was never created or is already absent. An `intent`-only TUN-create
ambiguity has no durable ifindex authority and never reaches `clean`
directly. With matching `reserved` or `intent_bound` ledger state, it takes
the exact pre-mutation `zone_retire_pending` abort above only after
process-owned descriptors are gone and complete dumps prove
TUN/client-route/generation-nft/visible-zone absence plus the guard baseline;
any same-name link or object is ambiguous and requires reset.
After `tun_created`, a pre-route failure enters `link_down_pending`;
post-route/pre-nft failure enters
`client_routes_delete_pending`, post-nft failure enters
`drop_gate_pending`, and post-handoff normal release additionally visits
`tun_ingress_policy_drop_pending`, `tun_ingress_policy_drop_ready`,
`tun_nft_detach_pending`, `tun_nft_detach_ready` and
`peer_tun_close_pending`. A process restart re-enters recovery for the
recorded state, never treats an unrecorded mutation as complete and never
moves backward.
`conntrack_reboot_required` is a terminal branch for the current boot, not a
step that precedes `retired_zone_quiescent`. It authorizes no same-boot
conntrack mutation or lease; only exact active-generation data-plane safety
shrink may continue. It appears in `lease-v1.json` only when that journal's
own zone hit the watchdog. A boot-wide reaper failure without that journal is
represented solely by the zone ledger's monotonic `boot_terminal`; a
different active or cleanup journal retains its last phase as specified
above. Only the changed-boot recovery contract may consume either form.
`intent` contains the exact ledger sequence/reservation ID, zone, generation
and a fresh nonzero 32-byte CSPRNG `transfer_nonce`; its canonical SHA-256
must match the ledger's later `intent_bound` record. The sole durable
authorization for one TUN-create attempt is the combination of that exact
journal plus the matching fsynced `intent_bound` ledger record. An `intent`
alone authorizes only the pre-mutation abort above. `tun_created` is written
only after the exact down, non-persistent name+ifindex+netns identity has been
observed and the creating broker has installed its one in-memory local
ownership slot. That slot binds generation, transfer nonce, numeric descriptor,
name, ifindex and an unsent/sent-or-unknown/consumed transfer state. It is
process-local and deliberately non-serializable: the journal stores the
nonce and public TUN facts, never an FD number or a claimed kernel
open-file-description identifier.
`tun_features_pending` records generation, boot ID, network-namespace inode,
exact name/ifindex, feature-inventory SHA-256 and bit count, `deny`,
`mutable_deny`, all four pre-mutation bitsets and `desired_wanted`, using
fixed-length canonical hexadecimal bitmaps. `tun_features_ready` records all
four complete post-mutation bitsets and their SHA-256.
`link_config_pending` additionally records the phase-B snapshot hash and the
exact MTU/address mutation list; `link_config_ready` follows only a complete
positive link/address dump.

`client_routes_pending` records every exact family-specific host-route tuple
and four two-bit masks: enabled `E`, create-armed `A`,
create-observed `P` and explicit-negative `N`, with bit 0 IPv4, bit 1 IPv6,
`P subset A subset E`, `N subset A`, `P intersect N = 0`, and all upper bits
zero. A complete pre-dump first
proves every enabled target and every conflicting client-destination/
protocol-196 route absent and persists its canonical hash. The broker then
fsyncs `(A=0,P=0,N=0)` and, in fixed IPv4-then-IPv6 order, fsyncs `A|=bit`
before sending exactly one sequence-correlated
`RTM_NEWROUTE|NLM_F_CREATE|NLM_F_EXCL` for that slot. ACK is never state
evidence or deletion authority. A positive or
lost/timeout/transport-ambiguous ACK still requires resynchronization and the
complete target dump; when that dump proves the unique exact target with no
conflict, the running process must fsync `P|=bit` before it owns or may clean
that route. A
sequence-correlated explicit negative ACK, including `EEXIST`, stops
acquisition; before any other action the receiving process fsyncs `N|=bit`
and then requires the target to remain absent. A crash before that fsync is
an `A`-only recovery, never inferred ownership. Once `N` is durable, exact-present,
duplicate or conflicting state after that error is foreign/drift ambiguity
with zero deletion authority. A dump that cannot prove the unique exact
target stops acquisition without setting `P`.
`client_routes_ready` is legal only when `P=A=E`, `N=0` and a final complete dump
proves all targets and no extra protocol-196/client-destination route.

Restart never continues route acquisition. For an unarmed slot, only absence
is valid. An armed but not observed slot may be absent; any exact-present,
wrong, duplicate or conflicting tuple is ambiguous and is never deleted,
whether the missing durable result followed a positive, unavailable or
explicit-negative ACK. Only a persisted `P` bit authorizes ownership of an
exact-present route.
`client_routes_delete_pending`
retains enabled `E`, create-armed `A`, create-observed `P` and
explicit-negative `N`, then stores owned `O`,
cleanup-armed `C` and absent `Z`, with
`O subset P subset A subset E`, `N subset A`, `P intersect N = 0`,
`C subset O`, `Z subset E` and
`O union Z = E`.
At entry, `O` and `Z` are disjoint: the complete dump assigns each enabled
slot either unique exact-present persisted-`P` owned or absent. An
`A`-only or `N` slot may join `Z` only when absent; if exact-present it is
ambiguous with zero deletion. A successfully deleted slot
then remains in `O` and joins `Z`. Before each
individual exact `RTM_DELROUTE`, the broker fsyncs `C|=bit`; it then
resynchronizes, proves absence and fsyncs `Z|=bit`. Recovery may retry only a
cleanup-armed exact owned tuple that remains present. `client_routes_absent`
requires `Z=E`. There is no multi-message route transaction or rollback.

`nft_pending`/`nft_ready` and `link_up_pending`/`link_up_ready` apply the same
write-ahead/positive-dump rule to the exact generation nft batch and the sole
link-up mutation respectively. These states are strictly before FD handoff.

`tun_ingress_policy_drop_pending` references the already observed TUN-ingress
chain handle, its full identity and old/target policies `accept -> drop`.
After this state is durable, one policy-only `NFT_MSG_NEWCHAIN` transaction
changes that chain. A complete dump must prove ingress policy drop, egress
policy drop, and every indexed rule/set/reference byte-for-byte unchanged
before `tun_ingress_policy_drop_ready(outcome=drop_observed)` is durable.
Recovery with the link present may replay that policy-only transaction only
from the complete old snapshot; the complete target snapshot writes ready
without replay, and every mixed snapshot is ambiguous.

Only after policy-drop ready may `tun_nft_detach_pending` reference the
already indexed complete auto-release closure of both TUN-bound base chains:
both chain identities, every contained observed rule handle/specification
digest, every rule-carried binding and every exclusively owned deterministic
anonymous set/map whose last reference is in either chain. Its separate
batch contains no policy update. It removes the indexed rules, allowing
last-reference anonymous objects to release through rule unbind, and leaves
both base chains present. A complete nft dump must prove both exact chains
remain policy-drop and empty and every indexed last-reference set/map is
absent before `tun_nft_detach_ready(outcome=emptied)` is durable. The source,
fixtures and syscall traces reject any nfnetlink batch that combines the
TUN-ingress policy update with deletion of a rule in that chain.

If final TUN close wins a crash race, the RTNL link-absence boundary and a
complete nft dump must prove the entire pre-indexed auto-release closure,
and no other generation object, disappeared. Only then may policy pending
advance to
`tun_ingress_policy_drop_ready(outcome=link_auto_released)`, followed by
detach pending and `tun_nft_detach_ready(outcome=auto_released)`. Link-present
recovery cannot use this branch. No partial closure, unindexed disappearance
or guessed anonymous-object ownership is accepted.
Failure before or during the feature SET holds the link down, durably enters
the ordinary link-down/broker-slot-consume states before the corresponding
action, takes and consumes the current process's local ownership slot exactly
once, and positively observes TUN, client-route/generation-nft absence and the
empty/drop guard baseline before reaching `clean`. On process
restart, a pre-handoff feature state never authorizes replay or adoption: a
complete dump proving all three transient object classes absent permits
journal cleanup, while any same-name link or impossible route/nft object is
ambiguous and permits no mutation.

Each phase snapshot also contains an `observed_foreign_facts` section with
the enabled-family gateway address, direct gateway route, protected-prefix
FIB partition count plus canonical SHA-256, permanent-neighbour tuple,
gateway/site MAC pair and their public hashes. The bounded complete partition
is retained in allowlisted evidence, not duplicated into the 16 KiB journal.
Those observations are readiness/conflict evidence only and never deletion
authority.

Every broker-issued configuration or cleanup phase, including each
dual-stack object in a compound phase, is preceded by a fsynced pending record
with an indexed exact object list and followed by a positive kernel
observation plus a fsynced ready/absent record. The sole exception to
per-object indexing is the bounded set of generation-zone conntrack entries:
per-packet state changes can occur only through the already-journaled
current-generation nft rule, and ID-checked deletion is authorized only by
the later `retired_zone_cleanup_pending` transition after complete freeze,
positive link absence and the cross-file `zone_retired` commit.
Recovery interprets only the named transition and its exact indexed objects;
it never infers completion from a later-looking object or skips an
unrecognized value. The `clean` transition can be written only after link,
client routes, every generation nft object and every guard generation rule
plus every currently enumerable normal/dying conntrack entry in the exact
generation zone are positively absent, the zone's used bit remains durable,
and the fixed guard is exact, empty and policy-drop. `clean` does not assert
that the standard kernel's non-enumerable unconfirmed view is empty; it
asserts that the zone is retired and cannot authorize or collide with a
later same-boot generation.
It is immediately followed by the validated unlink and directory fsync.
Accordingly `nft_absent` means absence of generation tables/chains/rules/
sets/maps/stateful objects plus the exact empty/drop guard baseline, never
absence of the fixed guard itself.
After `retired_zone_quiescent`, `nft_delete_pending` durably indexes every
residual generation object still present. For
`tun_nft_detach_ready(outcome=emptied)`, the validated
unregister-plus-dump boundary must have consumed exactly the two already-empty
TUN-bound chain identities. For
`tun_nft_detach_ready(outcome=auto_released)`, that earlier boundary must have
consumed their complete pre-indexed chain/rule/last-reference-anonymous-object
closure. If any expected member remains, only part of a closure disappeared
or any different object disappeared, recovery is ambiguous and performs no
guessed deletion. One atomic delete batch removes exactly the indexed
residual set;
`nft_absent` follows only a complete positive dump. `clean` is then the sole
journal-unlink authorization.

For one accepted generation the broker:

1. refuses any pre-existing `kyclash0` or conflicting journal/object;
2. before the first kernel mutation, resolves and pins the one listener
   interface and one distinct site interface and completes the persistent-NIC
   phase-A checks below. Both persistent NICs are standalone terminal layer-3
   `ARPHRD_ETHER` boundaries with `IFLA_LINK`, `IFLA_MASTER` and
   `IFLA_LINKINFO` absent, no other link referring to either as a
   parent/master/lower/upper, and no bridge, bond, team, VRF, VLAN, macvlan,
   ipvlan, veth, netkit or tunnel kind. This deliberately requires a
   dedicated Peer VM with two unstacked hypervisor NICs and does not support a
   container/K3s/Docker host or stacked Linux link;
3. after both the intent and its exact matching `intent_bound` ledger record
   are durable, creates one non-persistent, single-queue
   `IFF_TUN|IFF_NO_PI|IFF_TUN_EXCL` interface named exactly `kyclash0` and
   proves it is initially down;
4. immediately derives the exact three-member protected-ifindex set
   `{listener interface, site interface, kyclash0}`. While `kyclash0` is
   still down, before address, MTU, route, nft, link-up or FD handoff, it
   writes `tun_features_pending`, applies the one exact TUN feature mutation
   described below, positively re-reads the complete feature bitsets, and
   writes `tun_features_ready`. It then completes phase B on all three
   interfaces. Only after phase B, while `kyclash0` remains down, does it
   write `link_config_pending`, set MTU 1420 and the exact configured server
   addresses, positively re-read them and write `link_config_ready`;
5. derives a complete finite effective-FIB partition for every configured
   private prefix from all overlapping local/main/default route-trie
   boundaries; checking only one exact route or a sample address is
   forbidden. For every resulting destination partition the only accepted
   winning outcomes are an exact table-255 local/broadcast result that the
   `kyclash0` input rule terminally drops, or a table-254 `RTN_UNICAST`
   universe-scope route with one exact `RTA_OIF` equal to the site ifindex and
   one exact `RTA_GATEWAY` equal to the single family gateway. No connected,
   interface-only, on-link, default/listener, less-specific or more-specific
   route may win for any other protected destination. A direct prefix used
   only to reach the gateway may not intersect a configured private prefix;
   a wider connected site prefix that would make a protected target on-link
   is a conflict. The gateway lookup itself resolves directly through the
   exact site ifindex with no recursive gateway or nexthop flag. An IPv4
   gateway is canonical unicast and not zero, multicast or broadcast. An
   IPv6 gateway is canonical unicast; link-local is permitted only with the
   exact site ifindex as scope. The gateway cannot equal a Peer local,
   client-tunnel or server-tunnel address.
   It requires the family-specific default policy-rule set and order: IPv4 has
   exactly priority 0 -> table 255 local, priority 32766 -> table 254 main and
   priority 32767 -> table 253 default; IPv6 has exactly priority 0 -> table
   255 local and priority 32766 -> table 254 main, with no priority-32767
   rule. Neither family may contain a suppressor, `goto`, l3mdev or other
   rule;
   every accepted table-254 private or gateway-reachability route has one
   exact `RTA_OIF`, no nexthop flags and a closed attribute set consisting
   only of destination, output interface, the required single gateway for a
   private route, optional preferred source, optional priority, optional same
   table, optional pinned router preference, and optional cache-info with the
   exact ABI size/reserved bits. Cache-info's volatile counters are recorded
   for evidence but are not route identity or cleanup authority.
   `RTA_ENCAP`, `RTA_ENCAP_TYPE`, `RTA_MULTIPATH`, `RTA_NH_ID`, `RTA_VIA`,
   `RTA_NEWDST`, `RTA_MARK`, metrics, flow, expiry, TTL propagation, LWT-BPF,
   seg6, MPLS, IP encapsulation and every unknown attribute are forbidden.
   Header family/destination length, zero source length/TOS, table, protocol,
   scope, type and flags plus each security-relevant allowed attribute are
   pinned and monitored;
   and requires exactly one foreign neighbour entry per enabled family
   binding `(family, gateway, site-ifindex)` to the manifest-pinned six-byte
   unicast, nonzero, nonlocal gateway MAC. Its netlink header is exactly
   `NUD_PERMANENT`, `RTN_UNICAST` and zero neighbour flags. Its closed
   attribute set contains only exact destination and link-layer address plus
   optional pinned-ABI cache-info and protocol values; volatile cache
   counters are evidence, not identity. Proxy, managed, externally learned,
   router-flagged, duplicate, VLAN/FDB, probes, port/VNI, master, alternate
   ifindex, network-namespace ID, next-hop ID, unknown attribute and every
   other NUD state are conflicts. The site gateway must independently hold a
   static return-neighbour mapping from the Peer's exact return-next-hop
   address to the exact site-interface MAC, or use a separately reviewed
   point-to-point equivalent. Disposable acceptance provisions and proves
   that reciprocal fact; a later host-bound deployment review must bind it
   before production and this review does not authorize changing a real
   gateway. The broker treats routes, FIB partitions and neighbours as
   pre-existing foreign facts: it never creates, refreshes, replaces,
   journals them for deletion or deletes them;
6. completes the route pre-absence dump and writes
   `client_routes_pending(E,A=0,P=0,N=0)`, then in fixed IPv4-before-IPv6 order
   fsyncs the slot's create-armed bit before creating only that exact
   configured client `/32` or `/128` host route via `kyclash0` in table 254
   with the fixed KyClash protocol and metric. Each slot uses one exclusive
   sequence-correlated request followed by resynchronization and a complete
   route dump; the broker fsyncs its observed bit only after the unique exact
   tuple is present. It writes `client_routes_ready` only when
   `P=A=E`, `N=0` and
   the final complete dump is exact. There is no cross-family route
   transaction;
7. installs only the generation-scoped raw-zone, forward provenance,
   postrouting direction-mark and netdev L2/L3 gates below for configured
   client tunnel sources to configured private destinations and the exact
   reverse traffic;
8. writes `link_up_pending`, issues `RTM_NEWLINK` for the exact name+ifindex
   to set `IFF_UP`, then
   re-reads flags, operstate and addresses until `IFF_UP` is present,
   operstate is exactly `IF_OPER_UNKNOWN` or `IF_OPER_UP`, and every IPv6
   address has left tentative/DAD-failed state;
9. writes and fsyncs `link_up_ready`, constructs the exact
   `public_lease_facts_v1` and 184-byte reply in the dependency order below,
   then writes and fsyncs `handoff_pending` with the generation, transfer
   nonce, derived lease token, exact reply hash, TUN name/ifindex/netns,
   public-facts hash and the pidfd-verified Peer unit/InvocationID/cgroup/
   MainPID identity before publication;
10. sends the already-open TUN descriptor exactly once with `SCM_RIGHTS`;
    successful `sendmsg` is the publication point, after which the broker
    writes and fsyncs `leased`. A restart in `handoff_pending` assumes the
    descriptor may have escaped even when no send result was journaled: it
    first performs the journal-authorized data-plane freeze and removes the
    client route, then stops/waits for the exact old Peer invocation through
    the unit lifecycle and proves link absence before zone cleanup. The old
    broker process and all of its local descriptors already ceased to exist;
    a restarted broker never claims it can close or recover that old FD. Any
    still-queued SCM_RIGHTS reference is released only when the old seqpacket
    connection/Peer unit is gone. No protocol acknowledgement or resend is
    permitted.

The inspection timeline is exact:

- phase A, before the intent and every broker kernel mutation, proves `kyclash0`
  absent, validates the global hook/runtime facts, and performs complete
  topology, BPF-query, XDP, TC/qdisc, flowtable and ethtool-feature checks on
  the listener and site NICs plus the read-only policy/FIB/gateway/
  neighbour/MAC checks;
- phase B, after the sole TUN-create mutation and the journaled, verified TUN
  feature-disable mutation while `kyclash0` is still down, performs the same
  complete per-interface checks on all three protected ifindices and re-reads
  every foreign FIB/gateway/neighbour/MAC fact before any address, MTU, route,
  nft, link-up or FD-handoff mutation; and
- phase C repeats the global, all-three-interface and all foreign-fact checks
  after the last mutation and before readiness, after which the loss-detecting
  subscriptions and periodic reconciliation remain active.

The design never claims that an absent pre-create `kyclash0` has an ifindex or
can be queried.

The forwarding gate uses only the reserved fixed guard and KyClash-owned
generation tables and never flushes or rewrites another owner. IPv4/IPv6
global and every current protected-interface forwarding value must equal one
for an enabled family. The runtime manifest resolves the kernel-version
boundary for IPv6 `force_forwarding`: when
`ipv6_force_forwarding_abi=present`, the proc-sysctl files and complete
`RTM_GETNETCONF`/`NETCONFA_FORCE_FORWARDING` dump for `all`, `default` and
every extant relevant interface must both exist and equal zero; when it is
`absent`, both the files and every corresponding netconf attribute must be
exactly absent. `ENOENT` or a missing attribute is accepted only in the
manifest-pinned `absent` mode. A proc/netconf disagreement or an observed ABI
that differs from the manifest fails closed. The broker verifies and never
changes these host-bootstrap-owned forwarding facts.
The TUN address's own connected/local route belongs to the interface lifetime.
Cleanup first removes only the exact generation accept/set paths and client
host routes, then closes every TUN reference and positively proves link
absence. Only afterward may it delete ID-matched entries in the exact
generation zone and residual indexed generation nft objects. It never deletes
the fixed guard, a conntrack entry outside the exact generation zone, a
private-site route or a foreign neighbour.

The client host route constants are table 254, protocol 196, metric 42760 and
the exact `kyclash0` ifindex, with no gateway. IPv4 `/32` uses link scope;
IPv6 `/128` uses universe scope. Both family-specific tuples must pass native
netlink feasibility tests before live activation. Any pre-existing route to
the client host, or any route already using protocol 196 with a different
tuple, is a conflict.

The active nft objects span the fixed bootstrap-created
`inet kyclash_guard_v1` plus generation tables
`inet kyclash_p_<first-16-lower-hex-generation>` and
`netdev kyclash_e_<first-16-lower-hex-generation>`. Active state contains
exactly eleven type-`filter` base chains: the one fixed `forward_guard` plus
ten generation chains (input, raw prerouting, raw output, invariant
prerouting, postrouting, three ingress and two egress). Closed and clean state
retain only the exact empty, policy-drop fixed guard and no stateful object.
Active state adds one
generation-owned, table-local named `NFT_OBJECT_LIMIT` object named
`kyclash_l_<first-16-lower-hex-generation>` inside the fixed
`inet kyclash_guard_v1` table, because named-object references cannot cross
an nft table boundary. The IPv4 and IPv6 new-flow rules in `forward_guard`
both reference this one object; an inline per-rule limiter is forbidden.
In active state the input, both prerouting, postrouting and three ingress
chains have policy `accept`; the fixed forward guard, raw-output, site netdev
egress and `kyclash0` netdev egress chains have policy `drop`.
During `tun_ingress_policy_drop_pending`, only the TUN-bound ingress chain is
journaled for the policy-only `accept -> drop` transaction; the site and
listener ingress chains remain `accept`. At
`tun_nft_detach_ready(outcome=emptied)`, both TUN-bound base chains are empty
and policy `drop`.

The default-direction nonzero `conntrack_zone` is generation ownership, the
exact 32-bit `flow_mark` is authenticated connection provenance, and the two
direction skb marks are single-packet handoff capabilities from inet
postrouting to netdev egress. Exactly two logical directions per enabled
family may set the zone through distinct raw-priority inet prerouting rules:
one for a syntactically valid TUN-original candidate on `kyclash0`, and one
for its syntactically valid site-reply direction. All
Exact public-carrier ingress and response traffic is marked untracked before
conntrack, while host-local and unrelated traffic is dropped before
conntrack. Only a genuine
current-zone TUN-original `new` connection with mark zero may pass the shared
generation-owned new-flow rate limiter, replace its complete ct mark with `flow_mark`, and
accept; a current-zone connection already bearing the exact flow mark may
continue. Reply forward and both per-family postrouting direction-mark rules
require the same zone and exact flow mark. A site preseed can create only an unmarked
generation-zone entry and cannot authorize a reply; listener/host preseed is
in zone zero. A prior generation's zone/mark pair cannot match.

No netdev-family chain contains any `ct` expression. The inet postrouting
chain first sets `meta mark 0` unconditionally for every IP packet, erasing
any socket/earlier-hook mark. Only after complete current tuple, input/output
ifindex, generation zone/flow mark, state and no-NAT validation does it set
the exact nonzero direction mark. Hook exclusivity proves there is no later
mark writer. Netdev egress consumes only that skb mark plus direct L2/L3
facts:

- an `input`-hook chain at priority `-300` whose listener rules bind the exact
  listener interface ifindex, QUIC UDP port, WSS/TCP ports and destination
  bind address; packets for those destination ports arriving on any other
  ifindex are dropped, and every inner packet whose input ifindex is the
  owned `kyclash0` is dropped before local delivery, including a packet whose
  private destination happens to resolve through table 255 to an address on
  the Linux Peer itself. Every IP packet whose input ifindex is the site
  interface and that resolves to local delivery is also dropped; the site
  interface is forwarding-only for this lease; and
- a raw-priority `prerouting` chain at priority `-300`, before conntrack
  lookup. Its first three closed rules match the exact listener ifindex,
  destination bind address and QUIC/WSS/TCP destination port, apply `notrack`
  and continue only that carrier packet; all other listener-interface IP
  traffic was already dropped by netdev ingress. Its remaining setters assign
  the same exact default-direction generation zone to the two direct,
  header-valid tuple directions on the exact `kyclash0` or site input
  ifindex. It never assigns a directional zone, never changes unrelated
  traffic and never accepts a caller-selected zone;
- a raw-priority `output` chain at priority `-300`, before output conntrack,
  with policy drop. Its only three rules match the exact listener output
  ifindex, source bind address and QUIC/WSS/TCP source port, apply `notrack`
  and accept. It drops every other host-local IP packet before conntrack;
  there is no DNS, NTP, package-manager or management-network exception while
  a lease service is active;
- the fixed policy-drop `forward_guard` at priority `-50`, whose only two
  logical accept directions require the same direct-header/no-option/
  no-extension/no-fragment and protocol bounds as the ingress gates. The
  original direction is exact
  `kyclash0/configured-client-host -> configured-private-prefix/site-ifindex`,
  matches the complete current tuple to the conntrack original tuple, requires
  the exact generation zone and neither SNAT nor DNAT status. One physical
  rule admits only tracked `new`, mark-zero connections through the one
  table-local, shared 16-per-second/burst-16 named limit object, replaces the
  complete 32-bit ct mark with `flow_mark`, and accepts; a second admits only `new` or `established`
  connections already bearing the exact flow mark. An unmarked established
  connection is never adopted. The reply direction is exact
  `site-ifindex/configured-private-prefix -> configured-client-host/kyclash0`,
  matches the direction-correct complete reply tuple, requires tracked
  `established` state, the same exact zone/no-translation condition and the
  exact current flow mark. Every
  listener-to-site, site-to-listener, other-interface, host-unrelated,
  conntrack-`related` and otherwise unmatched forwarded packet is dropped.
  Each enabled family has exactly three physical accept rules: two original
  states and one reply. Dual stack therefore has six, not an unproved
  family-generic set. Every rule has fixed schema userdata plus
  `SHA-256(generation)`;
- an invariant `prerouting` chain at priority `-90`, after destination NAT,
  that drops an exact current-zone KyClash flow when conntrack
  original/current tuples or `ct status dnat` show destination translation;
  and
- a `postrouting` chain at priority `110`, after source NAT, whose first rule
  unconditionally sets `meta mark 0` on every IP packet. Translation or
  original/current-tuple mismatch for an exact current-zone KyClash flow
  drops. Its only two direction setters per enabled family require the exact input/output
  ifindices, complete direct and conntrack tuple, current zone, exact flow
  mark, allowed state and no SNAT/DNAT, then replace the complete skb mark
  with `site_skb_mark` or `tun_skb_mark`. Every other packet leaves with mark
  zero. The pinned hook dump permits no later mark writer;
- a netdev `ingress` chain at priority `-500`, bound to each exact protected
  interface. Each runs before IP prerouting/conntrack defragmentation and
  permits an IP packet only when IPv4 has `IHL == 5`, no option,
  `(fragment-offset-and-flags & 0x3fff) == 0` and Protocol directly names
  TCP, UDP or ICMP, or when the IPv6 base `Next Header` directly names TCP,
  UDP or ICMPv6. Thus every IPv4 option,
  every IPv6 extension header (including Hop-by-Hop, Destination, Routing/
  SRH, Fragment including atomic, AH, ESP, Mobility, HIP, Shim6 and
  experimental values), every truncated/unparseable IP header and every
  unsupported IP protocol is dropped before L3 processing. On the listener
  NIC, IP is further restricted to the exact destination bind address and
  QUIC/WSS/TCP destination ports; every other IP frame drops before
  conntrack. Non-IP link control such as ARP remains permitted only on the
  listener NIC;
- the site ingress chain additionally drops every tagged frame or VLAN
  metadata, every non-IPv4/IPv6 frame including ARP, and every frame whose
  Ethernet source is not the manifest-pinned family gateway MAC or whose
  destination is not the exact site-interface MAC. Its remaining IP path
  permits only direct TCP/UDP reply candidates, ICMP echo reply or ICMPv6
  echo reply; IPv4 Redirect and IPv6 RS/RA/NS/NA/Redirect therefore drop
  before neighbour, route and input processing. The `kyclash0` ingress chain
  likewise drops every non-IPv4/IPv6 protocol;
- a policy-drop netdev `egress` chain at priority `0`, bound to the exact site
  interface, whose sole accept path requires input from exact `kyclash0` and
  the exact `site_skb_mark`,
  an allowed IPv4 packet with `IHL == 5` or IPv6 packet whose base
  `Next Header` directly names the allowed transport, contains no option,
  extension or fragment, and is a TCP, UDP, ICMP echo or ICMPv6 echo flow.
  Its complete direct current protocol tuple has the configured client host
  source and configured private-prefix destination.
  The Ethernet source/destination must also be the exact
  site-interface/gateway MAC pair for that family. Every other
  packet is dropped, including host-local traffic, listener-to-site
  forwarding, packets to the gateway, configured or unconfigured site
  addresses, tagged/VLAN-metadata frames and all ARP/IPv6-neighbour/router-
  discovery output. A locally originated packet has no exact `kyclash0`
  input ifindex and drops even if it binds the site source or copies an
  otherwise allowed tuple. The pinned permanent
  family-specific gateway neighbour and reciprocal site-gateway neighbour
  make those link-control exceptions unnecessary during a lease; and
- a netdev `egress` chain at priority `0`, bound to the exact `kyclash0`
  interface, whose sole accept path requires input from the exact site
  interface, the exact `tun_skb_mark`, the same
  IPv4-IHL/IPv6-direct-next-header/no-option/no-extension invariant, an
  allowed TCP, UDP, ICMP echo or ICMPv6 echo flow, and a complete direct
  current tuple with private-prefix source and configured-client destination.
  Its policy drops every other packet, including host-local TCP, UDP, ICMP or
  raw traffic routed to the client host with no site input interface. Neither
  netdev egress rule reads zone, ct mark, tuple, state or status from
  conntrack.

Before `nft_pending`, the fixed guard must be exact, empty and policy-drop.
That transition's indexed object list contains both generation tables, all
ten generation base chains, the one generation-owned named limit object in
the fixed guard table, all `3 * enabled-family-count` guard accepts,
`2 * enabled-family-count` raw zone setters,
`2 * enabled-family-count` postrouting direction-mark setters,
`2 * enabled-family-count` netdev egress accepts, the six fixed public-carrier
ingress/response notrack rules and the one unconditional skb-mark clear.
Every to-be-created generation record has planned handle
zero, deterministic name/slot/userdata/specification and exact rule order;
only the separately observed fixed-guard baseline records have nonzero
handles.
After that exact `nft_pending` record is durable, the broker advances the
matching zone-ledger active record from `intent_bound` to `setter_armed` and
fsyncs it; a mismatch permits no batch. One atomic nfnetlink batch then
creates the generation objects and named limit,
then inserts every rule and its same-table named-object reference at the exact
guarded position; a partial family/direction set or a state where forward
accept exists before both egress drops is never visible.
`nft_ready` is written only after a complete hook/object dump proves names,
nonzero kernel-assigned handles, order, canonical expressions, exact 80-byte
userdata, rule counts and absence of
every extra table/chain/rule/set/map/stateful object. No caller expression, comment or path is
accepted; any anonymous typed set required by a compiled rule is indexed,
given a deterministic generation-derived name with no `%` template, and
created and deleted in the same transaction as that rule. A rule-carried
binding has no standalone handle or record.

The complete tuple means network family, IP protocol, source/destination
address and, for TCP/UDP, source/destination port. For ICMPv4/v6 only echo
request/reply are supported and type, code and echo identifier must match the
directional conntrack tuple. IPv4/IPv6 fragments, IPv6 extension chains that
contain any extension header, every IPv4 option, conntrack `related` traffic
and every other IP protocol are dropped in live version 1. In particular,
IPv4 LSRR/SSRR and IPv6 RH0/RH2/SRH can never carry a later non-private
destination past the configured-prefix gate. This is a deliberate
first-version service boundary for SSH/HTTP/TCP, UDP and ping; expanding it
requires review.

The exact hook types, priorities, canonical specification SHA-256 values and
ifindices are stored in the planned compact write-ahead records; nonzero
table/chain/rule/object handles are added only after the complete target dump
and re-read from nfnetlink. Full expressions are
deterministically reconstructed from the fixed config/manifests plus the
journaled generation/zone/marks and are never duplicated into the WAL. The
fixed guard handle is an observed per-boot fact and never deletion authority
for its table/base chain.
The full generation zone/marks and compact identities of their exact
setter/consumer rules are journaled before the atomic nft batch. Cleanup does
not begin ctnetlink
deletion merely because nft acknowledged a freeze: that ACK is not an
in-flight packet barrier. `drop_gate_pending` indexes every referenced rule
and the exact named limit object, every rule-carried binding and every
deterministically named anonymous set/map whose final reference is released
by one of those rules. Its one batch atomically removes
every fixed-guard accept and every per-family raw zone setter, postrouting
direction-mark setter and netdev egress accept, then removes the now-unreferenced
generation named limit object from the fixed guard table; the policy-drop
guard/egress chains and unconditional postrouting mark-clear remain. Recovery
admits only the complete indexed old snapshot or the complete frozen target.
The target requires every selected rule, binding, last-reference anonymous
set/map and named limit object absent while every retained object remains
exact. `drop_gate_ready` atomically consumes only the exact observed
rule/named-object/anonymous-set/map handles from the residual journal set; a
rule-carried binding has no independent handle and is consumed only with its
owning rule specification. Partial release, a surviving selected member or
loss/change of a retained member is ambiguous and authorizes no guessed
completion. After that positive dump and ready fsync, every client route is removed
individually and the complete TUN-bound auto-release closure is durably
selected. While the link remains, a policy-only transaction first changes
TUN ingress policy `accept -> drop`; only after its complete target dump and
ready fsync does a separate no-policy detach batch remove every contained
rule and release every last-reference anonymous object, followed by a dump
proving both policy-drop chains empty.
The Peer and every queued SCM_RIGHTS reference are then drained, the current
process's broker slot is consumed when present, and the exact RTNL-serialized
`link_absent` boundary plus selected empty-chain/full-crash-closure nft outcome
is positively observed. Only then may conntrack cleanup start. The unregister
backlog flush and `synchronize_net()` calls are useful
bounded shutdown evidence but are not falsely promoted into an enumerable
unconfirmed-view or final-netdevice-free proof.

After `link_absent`, the broker fsyncs `zone_retire_pending`, performs the
matching ledger disposition and then fsyncs `zone_retired`. A generation that
reached `setter_armed` is now reapable; an earlier failure is only
spent-unowned. The broker then completes bounded global normal and dying dumps
for IPv4 and IPv6. `retired_zone_cleanup_pending` records the exact
disposition, zone, per-view/per-family counts and canonical streaming SHA-256
values over every matching entry's view, family, original/reply tuple,
default-direction zone, `CTA_ID` and mark. This one pending transition is the
explicit exception to per-object journal indexing: the zone bit was durably
reserved before intent, only the journaled raw setters could assign a
setter-armed zone, those setters are now absent, and the exact zone will never
be reused on this boot. Together with the strict VM-global allocation cap,
those facts make every enumerable entry in a reapable zone bounded
generation-owned deletion authority while a 16-KiB journal cannot contain
1024 full tuples. An entry in a spent-unowned zone is instead a TCB/ledger
violation: it is never deleted and requires reset.

For the normal view the broker may use the pinned complete zone filter and
may encounter at most 1024 distinct currently allocated non-template objects
across all views in any complete snapshot. It deletes each matching entry
only with the same family, original tuple, zone and `CTA_ID`, and never falls
back to tuple-only deletion or a bulk flush. The count bounds distinct
objects, not delete requests: an `ENOENT`, ID mismatch or resynchronization
may require a retry until the watchdog expires.
`ENOENT` or ID mismatch causes a fresh normal-view zone dump, not a weaker
delete. Dying views are complete global bounded dumps filtered in userspace
by the exact zone and are observation-only. A failed or delayed DESTROY event
may leave an entry in the dying view after it has disappeared from the normal
hash. The standard kernel exposes no usable unconfirmed enumeration, so the
broker never guesses that view, claims it is empty or waits on its empty
stub.

The broker drains the already-open event subscription and requires two
consecutive complete four-view scan cycles in which the exact zone is empty,
with no intervening NEW/UPDATE/DESTROY event for that zone, before writing
`retired_zone_quiescent`. That transition means only: normal and dying were
stably empty at this cut, every setter is absent, and the durable used bit
will remain set until reboot. A hidden entry that confirms later remains
confined to this retired zone and cannot match a future generation's
zone/mark rules.
The patched kernel-wide strict reservation keeps all visible and hidden
non-template objects together at or below 1024. Neither the strict count nor
the stable visible cut is an unconfirmed-view absence proof.

The broker is the sole zone-ledger writer and also keeps the boot-wide
retired-zone reaper; no second service or advisory lock participates. Before
any new lease, throughout an active lease and after every loss-detecting event
reconciliation, one global normal dump and one global dying dump per family
classify all nonzero entries in O(1) through the bitmaps. The current active
zone is journal recovery authority, reapable zones are reaper authority,
and an entry in an unused or spent-unowned zone is an undeletable TCB
violation. For a reapable normal entry, the reaper uses the just-completed
live dump's family, exact original tuple, default-direction zone and `CTA_ID`
in one delete; zone-only, ID-only, tuple-only and every flush are forbidden.
The boot-exclusive zone, not the flow mark, is deletion authority, so a
mark-zero site-preseed entry in a reapable zone is included.
`ENOENT` or ID mismatch restarts the complete dump. Dying entries are only
observed. Notification loss also forces a complete dump. The start threshold
of 128 and global 896 watermark make hidden/late-object pressure trigger
early fail-close; neither is a proof that allocation stopped at that value.
Inability to reconcile or resource growth retains durable authority. A late
confirm while the broker is stopped is tolerated only because the zone is not
reusable; the next explicit start must finish this catch-up before
reservation.

Failure to obtain the stable visible cut within the two-second cleanup
watchdog first fsyncs the boot-zone ledger's monotonic `boot_terminal` with
the last complete per-view/per-family counts and streaming hash,
strict-counter value, deadline result and fixed-guard baseline hash. If the
failing zone is the current lease, it completes only the journal-authorized
data-plane safety shrink and then fsyncs the lease journal's
`conntrack_reboot_required`; if it is an older reapable zone, no stale or
different-generation journal is fabricated or overwritten. The global
terminal is authoritative in both cases.

The broker retains every existing journal, guard-drop and route/nft
retirement authority plus every zone used/reapable bit, reports only
`failed_closed_reboot_required`, and never writes
`retired_zone_quiescent`/`clean`. On the same boot it rejects every lease and
all further reaper/conntrack deletion. It may only finish exact
journal-authorized data-plane safety shrink for a concurrently active
generation as defined above. It does not spin beyond the shutdown deadline
or assert that a reference-held, dying or unconfirmed object has been freed.
The only terminal-clear edge is a positively observed
boot-ID/network-namespace change followed by the changed-boot full-absence
procedure; reboot destroys the old namespace and supplies the exact reset
boundary.

Only the exact journaled active zone or a ledger-reapable zone is deletion
authority. A
missing/corrupt journal or zone ledger, unavailable supported view, or
zone/setter mismatch permits only the fixed-guard safety shrink, never guessed
conntrack deletion; the disposable VM must be reset. `clean` and final
evidence require both families' normal/dying views to be stably empty at the
retirement cut and the zone's used bit to remain set; they explicitly make no
unconfirmed-absence claim.
The invariant chains are terminal fail-closed checks: an earlier accept
cannot bypass them. The broker does not claim it can statically analyze
arbitrary foreign nft sets/maps, extensions, BPF hooks or legacy rules; it
rejects every non-allowlisted hook below instead of interpreting its content.
The netdev egress gates run after layer-3 postrouting and make the direct
current tuple plus postrouting-issued skb capability authoritative; NAT and
conntrack expressions are not valid there. Native acceptance attempts real
flows, proves all inet invariant/mark rules see no translation, and observes
the original client tunnel source address in the site namespace. A foreign
hook present at startup refuses readiness; one detected later closes the gate
before lease failure.

That reasoning is valid only in the dedicated clean Peer VM with strict hook
exclusivity. Before link-up or listener readiness, and continuously for the
lease, the broker therefore requires all of the following:

- an `NFNL_SUBSYS_HOOK/NFNL_MSG_HOOK_GET` dump for every protocol family plus
  a complete nft object dump must equal the state-specific manifest:
  bootstrap-pre is built-ins only with forwarding zero; closed/clean is
  built-ins plus the exact empty/drop fixed guard; active adds the exact
  generation named limit, guard/zone/mark/egress accepts and ten generation
  hooks;
  draining has the empty/drop guard plus only the indexed generation hooks
  and non-accepting clear/drop rules not yet deleted. The journal indexes the
  complete notifier-owned closure for the exact TUN-bound ingress and egress
  base chains: both chain identities, every contained rule and every
  rule-carried binding plus chain-private deterministic anonymous set/map
  whose last reference disappears with those rules. Bindings have no
  independent handle or record. Before an intentional final close, a
  policy-only transaction changes the TUN ingress policy from `accept` to
  `drop` and a complete dump proves every other member unchanged. Only after
  that ready fsync does a separate no-policy detach batch remove the latter
  members and prove both exact policy-drop chains empty. Each pending state
  admits only its complete old or complete target snapshot; ready admits only
  the target snapshot. After
  TUN unregister, those two empty chain identities may disappear through the
  pinned kernel's one device-level `NETDEV_UNREGISTER` nft notifier pass.
  Userspace never expects a per-chain delete notification: it may observe one
  exact `RTM_DELLINK` for `kyclash0`, then a complete link dump proves
  name+ifindex absence and a complete nft dump proves either exactly the two
  already-empty journaled chain identities disappeared or, for a crash before
  detach, exactly the entire pre-indexed auto-release closure disappeared.
  Only that dump consumes the selected closed set and its handles from the
  journaled residual set at `link_absent`; notification loss is resynchronized
  by the same full dumps. A partial closure, an earlier unexplained
  disappearance or loss of another chain/object is drift.
  Table/chain/stateful-object type, hook, priority, policy, handle,
  rule/set/map/object count/order, canonical expressions and userdata are all
  checked. Every other nft, legacy
  iptables/ip6tables/arptables/ebtables, BPF-netfilter
  (`NFNL_HOOK_TYPE_BPF`), queueing, bridge, unknown-type or unknown-module
  hook at ingress, prerouting, input, forward, output, postrouting or egress is
  rejected regardless of apparent rule content or priority;
- the broker invokes `bpf(BPF_PROG_QUERY, ...)` for every queryable netdevice
  attach type named by the exact-kernel manifest, including TCX
  ingress/egress, against each of the three protected ifindices and requires
  zero program/link IDs. XDP in generic, native, hardware-offloaded or
  BPF-link form is independently proved absent through the pinned rtnetlink
  ABI. An unsupported/result mismatch is failure, not absence. The manifest enumerates
  every netdevice-affecting attach type in that pinned kernel and its one
  required attestation mechanism; a new kernel, attach type or mechanism
  requires review;
- `kernel.unprivileged_bpf_disabled` is exactly `2`; the broker has no
  `CAP_BPF` or `CAP_SYS_ADMIN`. The pinned kernel, hypervisor and fixed OS TCB
  (PID 1 plus only the exact system units/processes named in the runtime
  manifest) are trusted. Before and after static network handoff, the
  complete network-manager activation closure is persistently masked and
  absent; no non-TCB administrator or workload may obtain or use
  `CAP_NET_ADMIN`, `CAP_BPF` or `CAP_SYS_ADMIN` against the selected network
  namespace or its BPF/netfilter/link/route state. From early boot through
  shutdown, the only permitted nonzero conntrack-zone setters are the one
  ledger-bound generation's reviewed raw rules; every other producer is a
  TCB violation;
- the complete manifest-pinned conntrack sysctl/module/netlink inventory must
  match, global count is at most 128 before intent and never exceeds the
  patched VM-global strict allocation cap of 1024, and the loss-detecting event
  subscription plus one-second full reconciliation tracks total,
  generation-zone and exact-flow-mark counts. Both family-specific new-flow
  rules reference the same table-local generation named limit object, so
  their aggregate—not each family independently—is bounded to 16 per
  second/burst 16; existing marked flows bypass it, while established
  unmarked flows cannot be adopted. Reaching the early 224 marked-flow
  shutdown watermark, 896 total entries, a one-second reconciliation miss or
  event loss immediately starts the atomic data-plane freeze and client-route
  removal. Native timing records the count at freeze-batch commit, but no
  userspace timing is misrepresented as a 256-entry kernel quota. The only
  hard marked/zone/global upper bound is 1024 and is never a truncation point.
  A site reply preseed may consume an unmarked entry in the generation-owned
  zone but cannot bypass provenance and remains inside the strict allocation
  bound. Exact public listener traffic is untracked and unrelated
  listener/host traffic is dropped before conntrack, so neither consumes
  zone-zero conntrack capacity;
- independent rtnetlink checks still require no generic, native or
  hardware-offloaded XDP program on any protected interface; no ingress or
  `clsact` qdisc on any of them; and no TC ingress/egress filter, action,
  classifier, BPF attachment, redirect, mirror or hardware-offloaded rule;
- a generic-netlink `ETHTOOL_MSG_FEATURES_GET` dump for every protected
  ifindex must match the exact-kernel feature inventory, including the
  complete `HW`, `ACTIVE`, `WANTED` and `NOCHANGE` bitsets. The closed
  shape-changing deny mask is exactly
  `NETIF_F_GSO | NETIF_F_GRO | NETIF_F_LRO | NETIF_F_GRO_HW |
  NETIF_F_GRO_FRAGLIST | NETIF_F_GRO_UDP_FWD |
  (NETIF_F_GSO_MASK & ~NETIF_F_GSO_ROBUST)` for the pinned kernel build. It
  therefore includes generic GSO plus TSO4/TSO6/ECN/mangle-ID, UFO/USO,
  SCTP, FCoE, GRE, IP-in-IP, UDP-tunnel, partial, tunnel-remcsum, ESP and
  every other protocol/tunnel segmentation variant present in that build.
  The manifest expands this compile-time set into exact feature names and bit
  numbers; a missing, renamed or additional aggregation/segmentation bit is
  not classified by string heuristics and fails closed. The exact L2
  transform deny mask additionally contains
  `NETIF_F_HW_VLAN_CTAG_RX`, `NETIF_F_HW_VLAN_CTAG_TX`,
  `NETIF_F_HW_VLAN_CTAG_FILTER`, `NETIF_F_HW_VLAN_STAG_RX`,
  `NETIF_F_HW_VLAN_STAG_TX` and `NETIF_F_HW_VLAN_STAG_FILTER`.
  In the formulas below, `deny` is the union of the shape-changing and L2
  transform masks. Every deny bit must be inactive and unwanted before
  readiness; every other checksum/scatter/hash/DMA/VLAN capability remains
  exact-bitset pinned rather than broadly allowed.
  `NETIF_F_GSO_ROBUST` is the sole segmentation-family capability exception
  because pinned virtio devices may expose `ACTIVE=1, HW=0, WANTED=0`; that
  exact exception must be interface-specifically present in the manifest.
  The only other accepted state is all zero with manifest-matching
  `NOCHANGE`; `HW=1`, `WANTED=1`, any unpinned state or drift fails. It grants no
  packet-shaping operation and never authorizes `IFF_VNET_HDR` or
  `TUNSETOFFLOAD`. `NOCHANGE` is retained as a pinned observation of
  `NETIF_F_NEVER_CHANGE`, not misused as the fixed-on/configurability test;
- the host bootstrap disables every changeable deny-mask bit on the
  persistent listener and site NICs. A persistent mismatch or
  `(ACTIVE & deny & ~HW) != 0` fails phase A; the broker never changes a
  persistent NIC. Each startup resolves the dynamic generic-netlink ethtool
  family through `CTRL_CMD_GETFAMILY("ethtool")`, requires family version
  `ETHTOOL_GENL_VERSION=1`, and uses a non-compact
  `ETHTOOL_MSG_FEATURES_GET` so complete feature names and bit numbers are
  checked. A new TUN cannot be pre-provisioned, so after `tun_created` and
  while `kyclash0` remains down the broker computes
  `fixed_active_deny=ACTIVE&deny&~HW`,
  `mutable_deny=deny&HW` and
  `desired_wanted=pre.WANTED&~mutable_deny`; both
  `fixed_active_deny` and `pre.WANTED&deny&~HW` must be zero.
  `tun_features_pending` durably records the feature inventory hash/bit
  count, deny/mutable masks, all pre-mutation bitsets and desired wanted
  bitset before one SET;
- that sole SET uses `NLM_F_REQUEST|NLM_F_ACK`,
  `ETHTOOL_MSG_FEATURES_SET`, exact `kyclash0` ifindex,
  `ETHTOOL_FLAG_COMPACT_BITSETS|ETHTOOL_FLAG_OMIT_REPLY`, and a `WANTED`
  bitset with manifest feature count, all-zero value and mask exactly
  `mutable_deny`. Device name, `NOMASK`, named `BITS`, extra header flag or
  extra attribute is forbidden. Success requires the same socket/sequence
  ACK followed by a complete non-compact GET; ACK is never state evidence.
  An explicit error fails. On ACK timeout, while the same process still owns
  the live descriptor in its broker-local slot and the exact ifindex, exactly
  one GET may prove the desired state;
  the SET is never blindly retried. The postcondition is
  `(ACTIVE&deny)==0`, `(WANTED&deny)==0`, unchanged `HW`/`NOCHANGE`, unchanged
  non-deny bits and exact manifest agreement including the constrained
  `GSO_ROBUST` exception. `tun_features_ready` stores all observed bitsets and
  their hash. SET error, partial application, active deny outside `HW` or an
  unrelated change deletes the still-unhanded-off ephemeral TUN and fails
  closed. Recovery never restores an old TUN feature value or replays a
  pending SET: these pre-handoff journal states may be cleaned only after the
  broker descriptor is closed and exact TUN/client-route/generation-nft
  absence plus guard baseline is proved; a
  same-name link or impossible route/nft residue is ambiguous and receives
  zero mutation. During a lease any bitset drift first closes the gate and
  client route;
- a root egress scheduler on any protected interface is allowed only when its
  complete qdisc tree is
  `noqueue`, `fq`, `fq_codel` or `pfifo_fast`, or an `mq` root whose leaves
  are exclusively those same four non-`mq` kinds; every handle, parent,
  interface and kind is pinned, and no other qdisc such as `netem`, `htb`,
  `tbf` or an unknown kind is accepted; and
- no nft flowtable contains any protected interface and no hardware flow
  offload is enabled for a path involving any of them.

The broker performs the phased checks below using complete hook, nft,
BPF-query, link-topology, route/nexthop/neighbour/FIB, XDP, TC and
ethtool-feature dumps,
opening the loss-detecting nfnetlink, route/link/neighbour rtnetlink and
generic-netlink subscriptions before their corresponding first dump. It
drains and sequence-checks changes around each snapshot, then retains those
subscriptions with periodic full reconciliation of every fact, including
facts without a notification API. Notification loss,
an unknown attribute, a foreign hook that existed before startup, a new hook
after startup, link/route/FIB/neighbor topology or MAC/offload drift, a
nonzero BPF query result, conntrack bound/monitor failure or drift in an
allowed qdisc tree first runs the one atomic batch that removes every
generation forward accept, raw zone setter, postrouting direction setter and
netdev egress accept while retaining the policy-drop chains and postrouting
mark clear, then removes the client route and fails the lease. The immutable site
egress MAC pair blocks a changed gateway before detection; neighbour loss can
emit only discovery packets that the site egress policy drops. Gateway,
neighbour and protected-prefix FIB facts are observation/conflict authority,
never cleanup authority. The capability exclusion is a deployment
precondition; the subscriptions are detection and fail-close controls, not a
claim that a second network administrator can be safely co-administered.

`kyclash_guard_v1` is a reserved KyClash-owned fail-close namespace, not a
foreign object. If its chain is missing, non-drop, wrongly hooked or contains
an unknown/partial/stale rule while forwarding is one, the broker has one
pre-authorized emergency operation: atomically delete/recreate that reserved
table as the exact empty policy-drop baseline, removing every non-baseline
rule/set/map/stateful object. It performs this safety shrink before pidfd wait, route cleanup
or process exit. This is the distinct
`guard_emergency_recreate` operation and never enters, resumes or writes
ordinary `drop_gate_pending/ready`: its authority is the statically reserved
table name plus the fixed manifest, and its one idempotent nft transaction is
either wholly absent or wholly the baseline. A crash causes the next startup
to inspect and, if needed, repeat only that same full-table transaction.
After a positive baseline dump it records only the redacted
`guard_emergency_recreate_observed` outcome, retains every valid, corrupt or
ambiguous lease journal at its prior phase, reports
`failed_closed_reset_required`, and never uses invalidated generation handles
for ordinary cleanup or starts a new lease. Failure to positively observe the
empty/drop baseline is VM/reset-level fatal and must not be reported as
`failed_closed`. Ordinary `drop_gate_pending` is legal only from its complete
indexed old snapshot and can never delete/recreate the table; a partial/mixed
snapshot has zero deletion authority. Foreign nft objects remain
non-deletable. Manager masks and the TCB contract forbid interface creation/
ifindex reuse until explicit recovery has restored the guard baseline.

As an additional socket check, TCP and WSS validate each accepted socket's
exact local address and port; Linux offers no portable accepted-TCP ingress
ifindex API, so the broker-owned nft `iif` rule is the interface authority.
QUIC additionally enables and requires IPv4 `IP_PKTINFO` on
every received datagram and compares the ancillary ifindex and destination
address with the broker facts. Missing/truncated/ambiguous ancillary data
fails closed. A later `SO_BINDTODEVICE` design would require a separate
socket-FD broker contract; it is not silently added here.

The typed lease includes at least:

- exact config SHA-256;
- exact binary/identity and runtime-manifest SHA-256 values;
- boot ID and network-namespace inode;
- an unguessable generation;
- the independent transfer nonce and derived lease token;
- TUN name, ifindex, flags, MTU and server addresses;
- listener and site interface names/ifindices;
- both persistent standalone-link topology proofs, the exact three-member
  protected-ifindex set, complete hook snapshot and per-ifindex zero-ID BPF
  attach queries plus security-relevant ethtool feature snapshots;
- exact client source/private destination sets;
- SHA-256 of the broker-private zone/mark tuple and proof that both families'
  normal/dying view pairs were empty before intent, together with the
  predecessor clean/initial-boot no-setter proof;
- exact policy-rule and kernel route facts, every protected-prefix effective
  FIB partition, each direct gateway-reachability route, each permanent
  gateway-neighbour tuple and the exact gateway/site MAC pair;
- exact KyClash nft object handles; and
- a process-local owned TUN descriptor slot that is never serialized as a
  durable lease field.

After mutual process identity verification, the Peer sends one exact 40-byte
request:

```text
magic "KYBR"[4] | version 1[1] | kind acquire=1[1] | reserved zero[2] |
SHA-256(canonical public config)[32]
```

It is one complete `SOCK_SEQPACKET` message with zero ancillary data and a
five-second total exchange deadline. The broker rejects wrong length,
magic/version/kind/hash, nonzero reserved bytes, ancillary data, truncation,
trailing bytes or deadline and closes the connection without a kernel
mutation. Once that first complete request is accepted, the connection
atomically enters the request-accepted acquisition phase. An extra packet
already observable in the receive queue at that cutover is rejected before
mutation. The design does not claim that it can prove no future packet will
be sent: a later acquire or any other out-of-phase packet after mutation
begins immediately starts the common fail-closed cleanup below.

Before serializing a reply, both sides independently construct exactly this
216-byte, network-byte-order `public_lease_facts_v1` value:

```text
magic "KYLF"[4] | version 1[1] | reserved zero[3] |
config SHA-256[32] |
binary/identity-manifest SHA-256[32] |
runtime-manifest SHA-256[32] |
generation[32] | transfer nonce[32] | boot-ID SHA-256[32] |
netns inode u64[8] | ifindex u32[4] | MTU u16[2] | TUN flags u16[2]
```

There is no variable field, JSON canonicalization or length prefix in these
216 bytes. Every integer is unsigned big-endian. The value deliberately
excludes the lease token, reply hash, descriptor, process-local ownership
slot and broker-private nft/zone/mark handles. The config hash binds the
server addresses, listener/site identities and route/prefix policy; the two
manifest hashes bind the reviewed binary and kernel/runtime facts. The Peer
must already have independently opened and validated those same fixed public
files and must reproduce all 216 bytes before accepting the facts hash. This
hash is a protocol binding over public roots; it is not a claim that the Peer
observed broker-private object handles.

The successful broker reply is then one exact 184-byte,
network-byte-order packet:

```text
magic "KYBF"[4] | version 1[1] | kind lease=2[1] | reserved zero[2] |
config SHA-256[32] | generation[32] | transfer nonce[32] |
boot-ID SHA-256[32] |
netns inode u64[8] | ifindex u32[4] | MTU u16[2] | TUN flags u16[2] |
SHA-256(public_lease_facts_v1 exact 216 bytes)[32]
```

It contains exactly one `SCM_RIGHTS` control message and one descriptor. All
integer fields use unsigned big-endian encoding. The Peer calls
`recvmsg(MSG_CMSG_CLOEXEC)`, rejects `MSG_TRUNC`, `MSG_CTRUNC`, another
packet/control item/descriptor, a zero/old transfer nonce, unexpected payload
length or any trailing byte, and takes every received descriptor into a
temporary local slot so every rejection path consumes and closes each one
exactly once. The broker retains its original descriptor in its own local
slot. The `handoff_reply_hash` is SHA-256 over exactly these 184 protocol
bytes; it never covers, identifies or authenticates an OFD.

The construction order is mandatory and acyclic:

```text
public_lease_facts_v1 bytes
  -> public facts hash
  -> exact 184-byte reply
  -> handoff reply hash
  -> lease token
  -> fsync handoff_pending
  -> one ancillary-bearing sendmsg
```

The broker durably enters `handoff_pending` only after all prior values have
been constructed and before sending this reply. A successful
atomic `sendmsg` publishes the descriptor and changes the connection's
protocol phase immediately; only afterward may `leased` be fsynced. A crash
between those events is recovered as a possibly published handoff and the
message is never replayed. Each generation permits at most one
ancillary-bearing `sendmsg`. Both sides derive:

```text
lease_token =
  SHA-256(
    "net.kysion.kyclash.tun-lease/v1\0" ||
    config_hash || generation || transfer_nonce || handoff_reply_hash
  )
```

Every later packet is exactly 40 bytes, carries no ancillary data and uses
`"KYBR"[4] | version 1[1] | kind[1] | reserved zero[2] |
lease_token[32]`. A zero, old-reply, wrong-nonce, wrong-generation or
cross-connection token is rejected. The only valid normal sequence is:

```text
Peer kind release=3
  -> broker atomically freezes every data-plane accept/set path
  -> broker fsyncs client_routes_delete_pending
  -> broker removes each owned client route under its own armed bit,
     proves every absence and fsyncs client_routes_absent
  -> broker fsyncs tun_ingress_policy_drop_pending
  -> broker changes only TUN ingress policy to drop, proves all indexed
     rules/set references unchanged and fsyncs tun_ingress_policy_drop_ready
  -> broker fsyncs tun_nft_detach_pending
  -> broker empties both TUN-bound chains in a separate no-policy batch
  -> broker fsyncs tun_nft_detach_ready
  -> broker fsyncs peer_tun_close_pending
  -> broker kind drain-ready=4
  -> Peer Down/join/device-close
  -> Peer kind tun-closed=5
  -> broker link-down/broker-slot-consume/link-absent
  -> broker generation-zone conntrack and nft/journal cleanup
  -> broker kind released=6 and write-half close
  -> Peer requires EOF and closes
```

Both `handoff_pending` and `peer_tun_close_pending` bind the exact unit name
`net.kysion.kyclash.network-peer.service`, its pidfd-verified 128-bit systemd
InvocationID encoded as exactly 32 lowercase hexadecimal characters, the
canonical cgroup
`/system.slice/net.kysion.kyclash.network-peer.service`, and the exact
pidfd-verified MainPID, in addition to generation, transfer nonce, lease
token, handoff reply hash and TUN name+ifindex+netns facts. The MainPID is
evidence for that exact invocation only; a numeric PID by itself is never
identity or recovery authority. The nonce and token are protocol ownership
facts, not OFD identities.

Recovery treats either pending handoff message as possibly sent and never
resends it. If PID 1 reports the same InvocationID active with the same
canonical cgroup and MainPID, recovery waits for PID 1 to finish stopping
that exact unit and then positively proves its cgroup empty. If that
InvocationID is inactive with no remaining cgroup, recovery continues only
to final RTNL/link absence proof. A different InvocationID, changed MainPID,
noncanonical cgroup, unavailable/unclassifiable systemd state or any identity
mismatch authorizes no guessed stop, descriptor recovery or new lease; only
the pre-authorized guard safety shrink is allowed and disposable reset is
required. A `tun-closed` packet is a protocol event, not FD-close proof.

One receive loop owns the connection from acceptance through close. Once
mutation has begun, an out-of-phase, duplicate, late extra, wrong-generation
or ancillary-bearing packet first closes the forwarding gate and removes the
client route, then rolls back the generation within the one remaining
deadline. There is no application-data, caller-selected operation or
extensible map. EOF/pidfd exit is the abnormal cleanup signal. All release
messages share the one remaining monotonic shutdown deadline.

Before and after handoff, `TUNGETIFF` must return exact `kyclash0` flags
`IFF_TUN|IFF_NO_PI`; `IFF_MULTI_QUEUE`, `IFF_VNET_HDR`, persistence and every
extra flag fail closed. The Peer revalidates ifindex, network namespace, MTU
and addresses.

The Peer starts each invocation with an empty process-local TUN slot. After
the complete reply, ancillary and identity checks pass, it installs the
received descriptor exactly once as
`Received{owned_fd, transfer_nonce, lease_token, name, ifindex, netns}`.
Installation fails unless the slot is empty. The slot is not journaled,
reconstructed, compared by `kcmp`, copied with `pidfd_getfd`, or reopened by
name. It is atomically taken and marked consumed before ownership is passed
to wireguard-go.

The pinned upstream `tun.CreateUnmonitoredTUNFromFD` cannot be called:
after its internal `os.NewFile`, some error paths return without closing and
leave an unreachable `os.File` finalizer, so a caller close could later
double-close a reused descriptor. KyClash instead pins a repository-local
wireguard-go fork with recorded upstream module hash/license and exactly one
reviewed ownership patch:
`tun.CreateUnmonitoredTUNFromOwnedFD`. That API takes ownership at function
entry, closes the descriptor exactly once on every `SetNonblock`, `NewFile`,
`Name` or `initFromFlags` failure, and transfers sole ownership to the
returned `tun.Device` only on success. Tests inject every error boundary,
force GC and descriptor-number reuse, and prove no leak/double-close. CI
compares the local fork against the pinned upstream tree and permits only the
recorded patch/test/provenance files.

The Peer passes only the descriptor atomically taken from that slot to the
owned-FD API and never closes it afterward, regardless of result. API entry
is the ownership-transfer point. The Peer never calls the unsafe upstream
entry point, `tun.CreateTUN`, `TUNSETIFF`, `kcmp`, `pidfd_getfd` or a
name-based reopen.

A broker-owned netlink and nfnetlink subscription plus periodic full
reconciliation closes
`Done()` on deletion, rename, notification loss, ifindex/netns/address/MTU,
client-route/site-route/site-interface/listener-address or nft drift. A
transfer nonce, lease token or handoff reply cannot be accepted in another
generation or connection; the descriptor itself has no persistent identity
that can be replay-checked. The same broker
periodically re-reads `net.ipv4.ip_forward` and, when IPv6 is configured,
`net.ipv6.conf.all.forwarding`, plus every extant protected interface's
family-specific `forwarding` and the manifest-selected proc/netconf
`force_forwarding` presence/value contract; required forwarding values are
one, and the force override is either consistently present as zero or
consistently absent. Drift first restores the guard empty/drop baseline and
fails the lease. The Peer has no permission to read these facts as authority.

Before the first kernel mutation, the broker atomically writes and fsyncs a
generation/config/netns-bound intent and fsyncs its state directory. Before
each later route or nft mutation it durably records an exact
`*_pending` transition; after positive inspection it records the observed
object identity and fsyncs again. The non-persistent TUN is created into the
current broker process's empty local ownership slot. A broker crash releases
that process-local reference and removes an otherwise unreferenced interface
even in the narrow interval before its ifindex can be journaled; a restarted
broker begins with an empty slot and cannot inherit or reconstruct it.
Every persistent nft/client-route object uses a generation-derived fixed name
or the exact family-specific route tuple that recovery can inspect from its
write-ahead transition without guessing. The route itself has no
generation-bearing kernel attribute. Its sole creation/rollback ownership
chain is the complete pre-absence dump, the fsynced per-slot armed bit, the
exclusive manager-free `CAP_NET_ADMIN` TCB, the same live `kyclash0`
name+ifindex, the complete post-request dump and, before any rollback
authority exists, the fsynced per-slot positive-observed `P` bit. After
process loss an `A` bit without `P` is deliberately insufficient even when an
exact route is present. Notifications only trigger resynchronization; their
presence or absence is never route identity or ownership evidence.

The initial threat model therefore requires a dedicated Peer VM whose pinned
kernel, hypervisor and runtime-manifest OS TCB are trusted. PID 1 necessarily
retains lifecycle authority and is not falsely claimed to lack capabilities.
The image is permanently manager-free for the entire boot: every
runtime-manifest-named systemd-networkd/NetworkManager canonical unit,
alias, socket and other activation-closure member has a persistent
root-owned `/etc/systemd/system/<exact-unit> -> /dev/null` mask, all
wants/requires enablement links are absent, and the corresponding D-Bus
activation files cannot select an unmasked unit. The local-disk initrd is
hash-pinned and contains no networkd, NetworkManager or other network
administrator; network-root/initrd networking is unsupported. The masks are
not created, removed or changed per lease. Same-boot transition to a general
network-manager host is unsupported: leaving the Peer role requires shutdown
and replacement with another reviewed image.

One fixed root-owned `net.kysion.kyclash.network-peer-host-bootstrap.service`
is the only pre-Peer network mutator. It is a hash-pinned, no-argument,
no-shell, no-child, no-secret `Type=oneshot` executable in the OS TCB, has
only `CAP_NET_ADMIN`, uses only typed rtnetlink/generic-netlink, and has no
listener, IPC endpoint or broker-journal access. It opens a loss-detecting
rtnetlink subscription before enumerating links. Within the unit's one
30-second start deadline it waits for exactly the runtime-manifest-pinned
listener and site hardware identities, their final configured names and
distinct unstacked ifindices; a started udev service is not device-readiness
evidence. Rename, remove or re-add events, rtnetlink overflow or deadline
expiry fail the boot without guessing an ifindex.
Before its first mutation it validates every persistent manager
mask/alias/activator and initrd/unit/
package hash, proves every manager MainPID/cgroup/BusName/socket absent,
proves no unexpected KyClash TUN, protocol-196 route or generation table
exists, validates the fixed listener/site NIC hardware identities, and
requires IPv4 `ip_forward=0`, IPv6 `conf/all/forwarding=0`, every current
per-interface forwarding value zero and the runtime-manifest-selected
proc/netconf `force_forwarding` contract: both representations are present
and zero, or both are absent.
The pinned kernel command line and `systemd-sysctl` configuration guarantee
those boot defaults and forbid another unit from setting them. If bootstrap
instead observes forwarding enabled before an exact guard, its only allowed
safety action is to set forwarding back to zero; that boot is permanently
non-acceptable even if later repaired.

While forwarding remains zero, bootstrap applies only the fixed public
listener/site addresses, MTUs, routes, family-specific permanent gateway
neighbours and persistent-NIC feature deny mask from the sole runtime
manifest and fixed public configuration. Within the same start deadline it
requires each configured address to be present and neither tentative nor
DAD-failed, each exact MAC and MTU to match, the required operstate to be
reached, and the complete route/neighbour state to be positively observed.
It then uses one nfnetlink batch to create the unique reserved
`inet kyclash_guard_v1` table and empty `forward_guard` type-filter base
chain at forward priority `-50`, policy drop. A complete hook and nft-object
dump must equal pinned built-ins plus that empty guard. Only then does the
bootstrap write the exact enabled-family forwarding sysctls to one, re-read
global and every current per-interface forwarding value plus the pinned
force-forwarding presence/value contract, and publish success. The guard
oneshot is not `PartOf=` Peer or broker and
ordinary stop/cleanup never flushes it. Success leaves the oneshot
active/exited with zero tasks. Failure keeps or restores forwarding zero
unless the exact empty/drop guard is positively present, leaves both managers
masked, starts neither broker nor Peer, performs no automatic retry and
requires console reimage/reboot. From bootstrap-pre through closed, active,
draining, clean and shutdown, no observable accepted state may contain
`forwarding=1` without the exact guard.

During a lease or incomplete recovery, the deployment contract forbids any
non-TCB workload from obtaining or using `CAP_NET_ADMIN`, `CAP_BPF` or
`CAP_SYS_ADMIN` against the selected network namespace or its
BPF/netfilter/link/route state. The broker does not claim
`ProtectProc=invisible` lets it prove whole-VM capability absence; it enforces
the kernel-state allowlists, continuously revalidates the immutable manager
mask/activation facts, and treats notification loss, hook/attach query drift
or an unexpected mutation as failure. Root changing a mask/initrd or directly
executing a manager is explicitly a trusted-image/TCB violation, not an
operation this design falsely claims systemd can contain.

On the same boot, a ledger active record or generation object with missing
journal history, a netns/link mismatch, a route that cannot be proved to be
the exact previously created tuple, or any other ambiguous identity is not
authority to delete: the broker retains any surviving journal, refuses
readiness and requires disposable-environment reset or separately reviewed
administrative recovery. Journal absence is normal only when the ledger has
no active record and the complete preflight classification succeeds.

Across a changed boot ID, the kernel has already destroyed the
non-persistent TUN. The broker may remove only a validated, broker-owned stale
journal and temporary file when a complete dump proves that the exact
`kyclash0` name, every exact journaled client route, every generation-owned
nft table, every indexed pending object, every old-generation guard rule and
every normal and dying conntrack entry in the journaled zone for both
families are all absent. The changed boot itself destroyed the old network
namespace and its unconfirmed conntrack objects; the new boot's closed-hook
baseline must prove that no generation-zone setter has run and that the
current boot's fixed guard is exact/empty/drop. It fsyncs stale-journal
cleanup, performs the one authorized fresh-boot zone-ledger
reinitialization, and fsyncs the directory before beginning a new generation.
If any same-name or
exact generation object exists, or absence cannot be proven, the new boot
remains ambiguous: the broker retains the journal and performs only the
pre-authorized guard-baseline safety shrink, never lease mutation.

The broker binds the lease to the Peer connection and pidfd lifecycle. Normal
release is a fixed request/ack sequence inside the single shutdown deadline:
the broker first fsyncs `drop_gate_pending`, atomically removes every
generation forward accept, raw zone setter, postrouting direction setter and
egress accept, proves the exact fixed/egress drop plus mark-clear state, and
records `drop_gate_ready`. It writes/fsyncs
`client_routes_delete_pending`, removes each exact owned client route,
proves each absence through the per-slot cleanup-armed/absent masks and
writes/fsyncs `client_routes_absent`. It then fsyncs
`tun_ingress_policy_drop_pending`, sends one policy-only ingress-chain update,
proves ingress/egress policy drop with every indexed rule/set/reference
unchanged, and fsyncs
`tun_ingress_policy_drop_ready(outcome=drop_observed)`. It next fsyncs
`tun_nft_detach_pending`, deletes all remaining rules in a separate batch
containing no policy update, lets rule unbind release last-reference
anonymous objects, proves both exact chains remain present, policy-drop and
empty, and fsyncs `tun_nft_detach_ready(outcome=emptied)`. It then
writes/fsyncs
`peer_tun_close_pending`, sends `drain-ready` at most once, and waits for the
Peer to take WireGuard Down, join it, close its wireguard-go TUN copy and send
`tun-closed`. The broker records `link_down_pending`, sets the exact link
down, proves it, records `link_down`, then writes/fsyncs
`broker_tun_slot_consume_pending`.

Before its one Linux `close(2)` call, the same running broker atomically takes
the descriptor from its local ownership slot and changes that slot to
`Consumed`. It calls close exactly once; even `EINTR` is never retried because
Linux may already have released and reused the descriptor number. A restarted
broker's slot is `Empty`; it never reconstructs a number from the journal or
attempts a compensating close.
Because `kyclash0` is non-persistent, final reference close is the only
supported destruction operation; the broker never requests rtnetlink link
deletion. On normal release, the close call must return; in crash recovery,
the exact old broker and Peer invocations plus their old seqpacket/queued
ancillary reference must be gone. The broker then issues two fresh,
sequence-checked non-dump `RTM_GETLINK` requests, one by old ifindex and one
by exact name, and requires `NLMSG_ERROR=-ENODEV` from both. The pinned
Linux v6.8 non-dump `RTM_GETLINK` doit registration has no
`RTNL_FLAG_DOIT_UNLOCKED`, so `rtnetlink_rcv_msg()` takes `rtnl_lock()` and
serializes those requests after the synchronous RTNL unregister critical
section, including backlog flush, both
`synchronize_net()` calls, `NETDEV_UNREGISTER` and `RTM_DELLINK`; it does not
claim deferred netdevice free is complete. A lost `RTM_DELLINK` notification
therefore triggers these queries rather than blocking cleanup.
A subsequent uninterrupted complete link dump must also show name+ifindex
absent before `link_absent`. One device unregister may yield one exact
`RTM_DELLINK`; it never yields two user-visible per-chain notifications. A
subsequent complete nft dump must prove that exactly the two already-empty
journaled TUN-bound ingress/egress chain identities auto-disappeared and only
then consumes those identities from the residual set. A crash that reaches
final close before the detach batch is recovered by the distinct
`outcome=auto_released` rule: the same link boundary plus full nft dump must
prove the entire pre-indexed chain/rule/last-reference-anonymous-object
closure disappeared and every non-closure generation object remained exact.
It then fsyncs
`zone_retire_pending`, commits the ledger disposition and fsyncs
`zone_retired`; a reapable zone proceeds through
`retired_zone_cleanup_pending`, strictly capped ID-checked cleanup and
`retired_zone_quiescent` when the visible cut completes within the watchdog.
Watchdog expiry first fsyncs the global absent-to-present `boot_terminal`;
when the failing zone belongs to this journal, it completes the exact
journal-authorized data-plane safety shrink and only then fsyncs that
journal's same-boot `conntrack_reboot_required`. A spent-unowned zone permits no deletion
and must prove the same supported views empty. Only the quiescent path writes/fsyncs
`nft_delete_pending`, deletes every residual indexed generation nft object,
proves link/route/zone/generation-nft absence plus guard baseline, records
`nft_absent`, then records `clean` and fsyncs/unlinks the clean journal.

Peer-socket EOF or loss of the lease is itself an immediate fail-close signal;
pidfd exit is evidence but never a prerequisite. The broker first fsyncs the
`drop_gate_pending` transition, atomically removes every generation
accept/set path in the complete freeze batch (accepting an already-absent
indexed rule during crash recovery), positively proves the exact frozen state
and records `drop_gate_ready`. It writes/fsyncs
`client_routes_delete_pending`, removes each exact owned client route under
its cleanup-armed bit, positively proves every absence and records
`client_routes_absent`. If the TUN remains registered it then fsyncs
`tun_ingress_policy_drop_pending`, executes only the policy change, proves
the complete target with every rule/set/reference unchanged, and records
`tun_ingress_policy_drop_ready(outcome=drop_observed)`. It next fsyncs
`tun_nft_detach_pending`, executes and verifies the separate no-policy
chain-emptying batch, and records
`tun_nft_detach_ready(outcome=emptied)`. If a concurrent final reference close
has already unregistered the TUN, it records
`tun_ingress_policy_drop_ready(outcome=link_auto_released)` and then
`tun_nft_detach_ready(outcome=auto_released)` only after the exact
full-closure and link proofs above. It then writes/fsyncs
`link_down_pending`, sets the exact link down when still present, proves it,
records `link_down`,
writes `broker_tun_slot_consume_pending`, takes its current process-local slot
to `Consumed` and calls close once, all within the one remaining ten-second
deadline and without attempting to close a remote descriptor. A restarted
broker begins with `Empty` and skips this process-local action; unlike normal
release, another Peer or queued SCM_RIGHTS reference may still exist. Only
after freeze and route removal may
it wait for the retained Peer pidfd within the remaining time. Peer EOF/release
cleanup observes link absence after the Peer/queued socket reference closes;
only then may it clean the generation zone. If the Peer remains alive, the
broker exits with the journal retained; `BindsTo=` causes PID 1 to stop the
Peer, and the next explicit recovery must observe link absence before zone or
nft cleanup and before any new lease. If broker drift or internal failure
occurs while the Peer is alive, it performs the same freeze/route/link-down/
owned-FD-consume ordering and exits rather than waiting for an impossible
in-process post-exit observation. The broker does not signal, request systemd
to stop, or otherwise require cross-UID process-control authority, and never
uses `pidfd_getfd`.

An ifindex/name mismatch is not authorization to delete. The
`kyclash-broker`-owned atomic journal is retained on timeout, ambiguous
cleanup, corruption or identity conflict. A new lease is refused until exact
recovery proves all owned objects absent. Broker `SIGKILL` closes its TUN
copy; `BindsTo=` stops the Peer, whose first stop action is WireGuard
Down/device close, so the non-persistent link becomes unusable and
disappears. Remaining generation guard accepts can match only the vanished
TUN ifindex; the TCB forbids creating/reusing an interface before explicit
recovery atomically returns the guard to empty/drop, removes the client route
and every other generation accept/set path, proves link absence, cleans the
exact generation zone and then removes the residual indexed generation
objects. Automatic process restart remains disabled in live version 1 even
after broker/Peer `SIGKILL`, OOM, journal-corruption and reboot recovery pass;
each recovery test uses an explicit unit start or normal boot activation, not
an in-process or crash-loop restart. Changing `Restart=no` requires another
review.

## WireGuard device and authenticated admission

One wireguard-go device, one `wgcarrier.Switchboard` and the broker-issued TUN
descriptor live for the service generation. The identity capability configures
only:

- the exact server private key;
- the one configured client public key;
- that client's exact tunnel host addresses as `allowed_ip`; and
- no UDP endpoint or caller-selected peer field. The Linux server peer has no
  endpoint and persistent keepalive zero. The macOS client uses only the
  compiled switchboard endpoint identifier for the current carrier and an
  exact one-second persistent keepalive so `Up()` deterministically emits a
  fresh handshake initiation without waiting for application traffic.

The device is configured while carrier output is closed. The server identity
capability also derives one 32-byte static-static X25519 shared secret from the
server private key and configured client public key. The macOS client derives
the same value before clearing its WireGuard private bootstrap. This derived
secret is used only for the following carrier preauthentication and is cleared
with the identity/device generation. Canonical key decoding, X25519 execution
and a constant-time all-zero result check are mandatory; low-order/all-zero
public keys and any derivation failure reject the configuration before a
listener opens.

### TLS-bound WireGuard possession proof

A TLS connection cannot reserve the one WireGuard candidate merely by staying
open. Before either side may deliver a KYNP frame or WireGuard packet, every
transport performs this fixed preauthentication:

1. both sides export 32 bytes from the exact TLS 1.3 session with label
   `EXPORTER-KyClash-Carrier-Auth-v1` and no caller context;
2. the server constructs a never-reused 32-byte nonce as 24 fresh bytes from
   the OS CSPRNG followed by one unsigned, strictly increasing,
   generation-local 64-bit big-endian connection counter, then sends the fixed
   106-byte challenge
   `magic "KYCA"[4] | version 1[1] | kind challenge=1[1] |
   transport[1] | reserved zero[1] | SHA-256(broker generation)[32] |
   nonce[32] | ASCII "net.kysion.kyclash.carrier-auth/v1"[34]`;
3. both sides perform exactly
   `HKDF-Extract(SHA-256, salt=32-byte TLS exporter,
   IKM=32-byte X25519 shared secret)` followed by
   `HKDF-Expand(SHA-256, info=complete 106-byte challenge, L=32)`;
4. the client returns the fixed 72-byte proof
   `magic "KYCA"[4] | version 1[1] | kind proof=2[1] | transport[1] |
   reserved zero[1] | SHA-256(challenge)[32] |
   HMAC-SHA-256(key, "net.kysion.kyclash.carrier-proof/v1" ||
   challenge)[32]`, which the server compares in constant time and accepts
   once; and
5. after proof verification, the server first wins the candidate CAS or the
   one bounded proof-waiter slot described below. Only the winning arbitration
   token may drive the serialized incumbent drain and server WireGuard
   Down/detach/replace/fresh-zero sequence; a waiter must first complete that
   drain and atomically become candidate. A losing or pre-proof connection
   performs no WireGuard mutation. After the candidate reset, while both WireGuard
   devices remain Down and no candidate is attached to either switchboard,
   the server generates a fresh nonzero 32-byte CSPRNG `accept_nonce`,
   atomically arms `await_first_binder(slot_empty)` on the carrier receive
   path, and only then sends the fixed 104-byte
   success
   `magic "KYCA"[4] | version 1[1] | kind accept=3[1] | transport[1] |
   reserved zero[1] | SHA-256(challenge)[32] | accept_nonce[32] |
   HMAC-SHA-256(key, "net.kysion.kyclash.carrier-accept/v1" ||
   complete 106-byte challenge || accept_nonce)[32]`. The client must
   require a nonzero nonce and validate the current challenge hash and HMAC
   in constant time, then arm `await_server_type2(slot_empty)` before its
   candidate attachment/Up or any KYNP/WireGuard send. The accept
   acknowledges possession only; it never asserts that the server WireGuard
   data path is already active; and
6. the client's first post-control send is one exact 136-byte binder followed
   immediately by one complete KYNP-v1 frame:
   `magic "KYCB"[4] | version 1[1] | kind first-frame=1[1] |
   transport[1] | reserved zero[1] | SHA-256(challenge)[32] |
   accept_nonce[32] | kynp_frame_sha256[32] |
   HMAC-SHA-256(key, "net.kysion.kyclash.post-accept/v1" ||
   complete 104-byte accept || kynp_frame_sha256)[32]`.
   `kynp_frame_sha256` is exactly SHA-256 over the complete 20-byte KYNP
   header followed by its 148-byte WireGuard payload. It is the only
   handshake-frame hash carried in the binder.
   That frame must be the current generation's first sequence and contain
   exactly one WireGuard message-type-1 initiation. The server validates the
   entire binder and frame before queueing, attaching, calling WireGuard Up or
   delivering a byte. Because the client cannot construct the binder before
   receiving the fresh authenticated `accept_nonce`, a proof-valid client
   cannot pipeline a usable pre-accept first frame.

Transport bytes are exactly `1=QUIC`, `2=WSS`, `3=TCP`; all multibyte hashes
are raw octets and concatenation has no implicit length, padding or host
endianness. The TLS exporter already binds the TLS handshake transcript; no
unavailable TLS-library transcript API is assumed. Independent known-answer
tests cover X25519 (including low-order negatives), exporter-fed HKDF and
HMAC layouts byte for byte in the shared Go client/server codec. Rust
validates the signed profile and bootstrap version but never receives this
derived secret or a new raw-key getter; existing Rust/Go profile/bootstrap
fixtures prove the exact version handoff.

Every causal receive state is armed before the send that can cause it: server
`await_proof` before challenge, client `await_accept` before proof, server
`await_first_binder` before accept, client `await_server_type2` before
binder/type-1, server `await_client_counter0` before type-2, client
`await_server_ack` before client counter-zero, server `await_client_ready`
before server acknowledgement, client `await_server_ready` plus its
receive-only gate before client-ready, and the server ordinary receive gate
before server-ready. Send failure closes the token and cannot disarm a slot
then continue the generation.

For QUIC, the server opens exactly the first server-initiated bidirectional
stream (stream ID 1) and its first write is the 106-byte challenge. The client
opens no stream, accepts exactly stream ID 1, reads exactly the challenge,
writes exactly the 72-byte proof and half-closes its write side. The server
requires proof EOF, verifies it, writes exactly the 104-byte accept and
half-closes; the client requires accept EOF before attaching. This ordering is
mandatory because quic-go does not expose a locally opened stream to the peer
until data/reset/close makes it visible. The server advertises no
client-initiated bidirectional or unidirectional stream; the client permits
only this one server-initiated bidirectional stream. Any extra/wrong-ID stream
closes the connection.

A datagram receive gate runs from connection creation and, while
preauthentication is incomplete, drains any delivered datagram, records a
protocol violation and closes the connection. Only a connection with no such
violation may atomically transition to
`await_first_binder(slot_empty)` and fresh KYNP replay/fragment state. That
transition completes before the first accept byte is written, so a fast
client response cannot race an unarmed queue. The client is forbidden to send
a datagram before accept. QUIC's first post-control datagram contains exactly the 136-byte binder
plus its one complete, unfragmented type-1 KYNP frame. Later datagrams contain
either one ordinary KYNP frame/fragment or, only in the exact state, the
complete unfragmented 200-byte client-ready or 136-byte server-ready `KYCR`
record. A network-delayed
proof-valid pre-accept datagram delivered only after the transition lacks the
fresh accept nonce and binder, so it is rejected before attachment or
delivery.

WSS uses three preauthentication binary control messages after upgrade
(challenge/proof/accept) and, later, the exact client-ready/server-ready
messages. TCP uses the same five phase-specific fixed-length records after
TLS. The
WSS/TCP parser likewise enters `await_first_binder(slot_empty)` before
publishing accept. The first post-accept WSS binary message is exactly the
136-byte binder followed
by one complete unfragmented type-1 KYNP frame and remains within the existing
65,555-byte message ceiling. Every later WSS message contains exactly one
ordinary KYNP frame except the exact 200-byte/136-byte `KYCR` message admitted
by the current ready state. On TCP the state parser reads the exact 136-byte
binder immediately before the first bounded KYNP frame, dispatches the
phase-specific 200-byte/136-byte `KYCR` records by their four-byte magic, and
otherwise resumes ordinary bounded KYNP framing. Carrier-auth, ready-control
or binder bytes cannot be interpreted as KYNP. Ready controls never consume a
KYNP sequence number, enter its replay/fragment state or generate a WireGuard
counter. There is no application-layer retry after a ready-control send
failure or ambiguous result; an exact duplicate may be discarded only by the
already-consumed state, and a different duplicate/substitution fails. Wrong
kind/version/size/domain/
transport, trailing bytes, counter exhaustion/reuse, wrong exporter/HMAC,
zero accept nonce, binder/frame digest mismatch, timeout, premature data or
an extra control message closes the connection. All implementation-owned
shared/HKDF/HMAC/accept-nonce byte buffers are cleared; no claim is made about
byte erasure inside opaque standard-library hash/TLS objects.

Unauthenticated work is limited to 16 connections globally and two per exact
canonical IPv4 source address, each for no more
than five seconds and never longer than
`carrier_handshake_timeout_seconds`. QUIC address validation is mandatory.
TCP and WSS acquire that shared token immediately after raw accept and before
TLS. QUIC sets `Transport.VerifySourceAddress` to require Retry for every
connection and acquires the same token in `Transport.ConnContext`, releasing
it on the returned context's close. The server configuration sets
`MaxIncomingStreams=-1` and `MaxIncomingUniStreams=-1`; the client
configuration sets `MaxIncomingStreams=1` and
`MaxIncomingUniStreams=-1`. Both set initial/maximum stream receive windows
of 128 KiB, initial/maximum connection receive windows of 256 KiB, and a
five-second-or-shorter handshake idle timeout.
The test matrix saturates all unauthenticated limits from multiple and one
source, proves bounded rejection/resource use, and proves an unauthenticated
connection or candidate-CAS loser cannot displace an authenticated active
client. Only the sole proof-valid takeover may enter the serialized waiter
path below. Passing TLS or KYNP ping/pong without this proof never becomes a
candidate.

### Candidate and fresh WireGuard handshake

Only a possession-proof-authenticated connection may reserve the one
`candidate`. Before opening each first or fallback transport, the macOS client
must locally:

```text
close old carrier and join all carrier goroutines
  -> detach switchboard and prove active count zero
  -> WireGuard Down and synchronously drain/ZeroAndFlushAll peer key state
  -> replace the sole peer with the same reviewed public key and allowed IPs
  -> positively prove fresh peer state and keep WireGuard Down
```

The Linux Peer never performs that sequence merely because a socket connected
or a challenge was sent. After a proof verifies, one atomic compare-and-swap
either reserves the idle candidate slot or reserves the sole bounded
`proof_waiter`. The token binds generation, transport, connection counter,
challenge hash, TLS-derived authentication key and carrier instance. A
winning idle candidate token closes and joins any already-failed carrier,
detaches the switchboard, proves active count zero, takes the server WireGuard
device Down, replaces the peer and proves fresh zero state. Only after that
reset may it generate and bind the fresh accept nonce, arm the first-binder
slot and publish accept. Pre-proof, invalid-proof and losing connections
cannot mutate the WireGuard device, switchboard or incumbent carrier.

The one proof waiter is allowed only while an incumbent candidate/active
token is being failed or while its reset is incomplete. Its authenticated
arrival atomically changes that incumbent to `draining`; the incumbent gates
close before any further ordinary ingress/output, then its carrier closes,
all goroutines join, the switchboard detaches and the complete server reset
and positive zero proof run under the incumbent token. The waiter is promoted
to candidate only after that cut. A second waiter closes without mutation.
A proof-valid waiter is never closed merely because reset is still running.
The client has exactly one connection attempt in flight and, after completely
writing proof, cannot open the next transport until it receives authenticated
accept. An ambiguous close before accept fails the whole client generation
rather than burning another transport; a server that cannot finish reset
fails its whole generation instead of releasing the waiter early. Failures
before proof publication may advance directly to the next transport.
Failures after accept may advance only after the client has completed its own
local reset; the resulting proof-valid connection occupies the server waiter
until the old server token has completed the same reset. Thus QUIC, WSS and
TCP fallback is break-before-make even when the two peers observe failure at
different times.

`Down()` must complete the pinned wireguard-go peer `Stop()` path. Because
`Stop()`/`ZeroAndFlushAll()` does not clear `peer.endpoint`, that path alone is
forbidden as a generation boundary. While Down, each side uses one
`replace_peers=true` UAPI transaction to destroy the old peer object and
recreate exactly one peer. A positive UAPI read must show zero handshake time,
zero rx/tx counters and no inherited endpoint. The server peer remains without
an endpoint and with persistent keepalive zero. The client then sets only the
compiled endpoint identifier for this candidate and persistent keepalive one.
Any old endpoint, keypair, counter, staged packet or timer surviving the
replacement fails the generation.

After the client validates accept, it attaches the authenticated carrier
generation to its switchboard and calls WireGuard `Up()`. The exact
persistent keepalive makes the fresh client peer emit message type 1. The
client candidate output gate is the sole client `Bind.Send` boundary in this
phase. It accepts exactly one one-packet batch containing a 148-byte
little-endian type-1 initiation, records the complete frame SHA-256 and its
sender index `I` from bytes 4..7, and publishes exactly one
binder-authenticated KYNP frame. A second output, another batch member,
wrong length/type or non-nil/ambiguous carrier-send result fails the
candidate; the initiation is never retried. Zero is a valid `I`. No client
type-2/3/4 output or TUN read can precede this publication.

The server remains detached and Down after sending accept; its carrier session
admits and holds at most one bounded post-accept binder-plus-KYNP frame, whose
binder must authenticate that complete frame and whose payload must be a
WireGuard message-type-1 initiation for the current generation. It must be
exactly 148 bytes, use little-endian type 1, and the gate records the full
20-byte-header-plus-148-byte-frame hash as `kynp_frame_sha256`, the exact
148-byte WireGuard payload hash as `wg_type1_sha256`, and its sender index
`I`. At this point the server compares only the binder's published
`kynp_frame_sha256`; `wg_type1_sha256` and `I` are local evidence until the
later authenticated client-ready record. Only after validating the binder
and local frame facts does the server attach the same
candidate generation, call `Up()`, and deliver the held initiation exactly
once to wireguard-go, allowing the inbound endpoint to be learned and the
type-2 response to be emitted. Both client and server TUN-read admission gates
are closed and synchronously quiescent from fresh-peer reset until their
respective promotion cuts, so no inner packet can be staged before promotion.
Both carrier-to-WireGuard input gates likewise reject non-handshake transport
data during this interval. Any server WireGuard output before that held
type-1 delivery, or any client KYNP/WireGuard send before validating accept,
is a fatal protocol violation. WSS/TCP enforce this as the first post-control
binder and KYNP frame; QUIC enforces it as the first post-control datagram.

The candidate gate is the sole server Bind ingress and output boundary.
Before delivery of the one type-1 can cause a type-2 publication, the server
serial input pump atomically arms
`await_client_counter0(slot_empty)`. After the one type-1 delivery, the output
gate accepts exactly one 92-byte little-endian type-2 for the same candidate
token whose receiver index equals `I`, records its sender index `S` and the
exact 92-byte payload hash as `wg_type2_sha256`, forwards it exactly once, and lets
`Bind.Send` return. A second type-2, wrong receiver, any type-1/3/4 output or
multi-packet output batch fails the candidate. A non-nil or ambiguous send
result also fails and performs the full reset; the type-2 is never retried.
This correlation is not based
on the 32-bit receiver alone: binder authentication fixes the sole delivered
type-1, the fresh peer has no other input, pinned wireguard-go copies that
type-1 sender into the response receiver, and a later valid type-4 must use
the resulting Noise key and `S`. The controller never waits on UAPI from
inside `Bind.Send`.

The client serial input gate accepts exactly one complete 92-byte
little-endian type-2 for the candidate. Its receiver must equal the
client-recorded `I`; the gate records the exact 92-byte payload hash as
`wg_type2_sha256` and sender index `S`, and atomically delivers the frame to
wireguard-go exactly once. These are client-local facts until client-ready
authenticates them to the server. A
second or replayed type-2, wrong receiver/sender/hash, another batch member,
another WireGuard type, truncated/trailing bytes or a second delivery attempt
is fatal. No client empty keepalive output, early-ACK-slot arming or UAPI
promotion read is admitted until this one delivery has returned
successfully.

After the server type-2 send completes and while all client type-4 input is
still held, two serialized server UAPI reads must stably show exactly one
peer, the exact candidate endpoint, `last_handshake=(0,0)`, `rx_bytes=148`
and `tx_bytes=92`. A
transient `tx_bytes=0` may be observed before wireguard-go accounts a
successful send, but it is not the baseline; any value above the exact target
fails. The responder timestamp must remain zero here: pinned wireguard-go
does not call `timersHandshakeComplete()` merely for the type-1/type-2 path.

The client's only permitted next WireGuard output is the automatically
generated encrypted empty keepalive. The client output gate requires exactly
one 32-byte little-endian type-4 packet, receiver index `S`, fresh counter
zero and no encrypted inner payload; a longer/nonempty type-4, another packet
in the batch, counter greater than zero, or any type 1/2/3 fails. It forwards
that packet exactly once and never retries an ambiguous send. Before the send
can publish, the client serial input pump arms one bounded early-ACK slot.
After the correlated type-2, it may validate and hold outside wireguard-go at
most one complete 32-byte type-4 with receiver `I` and counter zero. An exact
duplicate ciphertext is discarded without a second slot; a different
counter-zero ciphertext, nonempty/wrong-length packet, wrong receiver,
counter greater than zero or another type fails. A held packet is never
delivered if the client keepalive send returns an error or ambiguous result.
Two serialized client UAPI reads after the successful send, while any early
server acknowledgement remains held outside wireguard-go, must stably show
the exact sole peer/endpoint, nonzero handshake timestamp,
`rx_bytes=92` and `tx_bytes=180` (148-byte initiation plus the 32-byte empty
keepalive). The client TUN-read and private-route gates remain closed.

The server serial input pump may hold only that one early, complete 32-byte
type-4 in one bounded slot. It must use receiver `S` and counter zero. A
nonempty or wrong-length packet, counter greater than zero, counter zero with
different ciphertext, wrong receiver or another type 1/2/3 fails; an
identical duplicate is discarded as replay and can never become promotion
evidence. Loss of counter zero times out this candidate rather than promoting
with a later counter. Once the server baseline is stable, the gate atomically
consumes the slot before delivering it to wireguard-go and continues to block
all other input and ordinary output.

The post-delivery server UAPI loop may transiently see a nonzero timestamp
with `rx_bytes=148`, but server confirmation requires two stable snapshots
with the same sole peer/endpoint, nonzero `last_handshake=(sec,nsec)`,
`rx_bytes=180` and `tx_bytes=92`. This proves that the selected 32-byte
counter-zero keepalive passed AEAD/replay checks,
`ReceivedWithKeypair()` and exact receive accounting. A bad AEAD, replay,
nonempty transport packet, under/oversized delta, endpoint/peer drift or stale
candidate callback cannot satisfy it.

Only after that cut may the server invoke the pinned peer's `SendKeepalive()`
exactly once as the explicit authenticated promotion acknowledgement. The
server output gate permits exactly one 32-byte little-endian type-4 with
receiver `I`, server fresh counter zero and empty plaintext; it rejects a
batch, nonempty packet, another type or counter. Successful exact-once send
must be followed by two stable server UAPI reads with `rx_bytes=180` and
`tx_bytes=124`; ambiguous send fails and the acknowledgement is never
application-retried. Before that output is allowed to publish, the server
arms exactly one authenticated `await_client_ready(slot_empty)` control slot.
After the send and UAPI cut the server enters
`server_ack_sent_wait_client_ready`; its TUN-read, ordinary carrier-output and
active-health gates remain closed.

After the client pre-ACK UAPI baseline is stable, its input gate waits for
that exact held-or-later 32-byte receiver-`I`, counter-zero server
acknowledgement, atomically consumes its sole slot and delivers it exactly
once. An identical duplicate remains discarded with no second delivery,
while a different counter zero, wrong receiver, nonempty packet, counter
greater than zero or another type fails. Client promotion requires two stable UAPI
snapshots with the exact sole peer/endpoint, the same nonzero handshake
timestamp, `rx_bytes=124` and `tx_bytes=180`. The client records
`server_ack_type4_sha256` over that exact 32-byte acknowledgement. Only then
may it authorize installation and positive verification of the exact macOS
private routes through the current candidate and operation token. A stale
candidate, stale operation, wrong route-set digest or partial dump reply is
rejected and any partial installation is rolled back without ready. Its
TUN-read/client-to-server ordinary output remains closed while route
installation can queue local traffic.

After the routes are exact, the client opens only the bounded
server-to-client ordinary WireGuard receive/write-to-TUN gate and atomically
arms `await_server_ready(slot_empty)`. It then sends exactly one authenticated
200-byte client-ready record:

```text
magic "KYCR"[4] | version 1[1] | kind client-ready=1[1] |
transport[1] | reserved zero[1] |
SHA-256(challenge)[32] | accept_nonce[32] |
wg_type1_sha256[32] | wg_type2_sha256[32] |
server_ack_type4_sha256[32] |
HMAC-SHA-256(key,
  "net.kysion.kyclash.client-ready/v1" || preceding 168 bytes)[32]
```

The server consumes this record only from its already-armed slot, compares
the challenge, nonce and all three hashes to its independently recorded exact
WireGuard payloads, and rejects any mismatch, duplicate or phase error.
After that validation it enters `server_ready_publishing` and arms its
ordinary client-to-server receive gate while TUN-read, ordinary output and
proactive health remain closed. It must arm that receive gate before
publishing exactly one authenticated 136-byte server-ready record:

```text
magic "KYCR"[4] | version 1[1] | kind server-ready=2[1] |
transport[1] | reserved zero[1] |
SHA-256(challenge)[32] | accept_nonce[32] |
SHA-256(complete 200-byte client-ready)[32] |
HMAC-SHA-256(key,
  "net.kysion.kyclash.server-ready/v1" || preceding 104 bytes)[32]
```

Only after the server-ready send succeeds exactly once may the server mark its
half active and open TUN-read and ordinary server-to-client output. The
client's receive-only gate was open before client-ready publication, so QUIC
may reorder that later ordinary data ahead of server-ready without losing or
prematurely rejecting it. After the client consumes and validates
server-ready from its already-armed slot, it atomically opens its TUN-read,
client-to-server ordinary output and marks the carrier active. It initiates
the first authenticated post-ready health ping; only its receipt may enable
the server's proactive health schedule and the normal two-sided health
cadence. The server receive gate was armed before server-ready publication, so
fast client traffic cannot race an unarmed server. No client-originated inner
packet can leave before this final cut, and no server-originated inner packet
can arrive before the client has installed the exact routes and opened its
receive-only gate.

Loss of the promotion acknowledgement leaves the client gates/routes closed
and times out the candidate; server EOF then resets its briefly active half.
Arrival after the client keepalive but before either client baseline read is
held and therefore cannot race the accounting cut. Arrival before the
client send attempt arms that slot, duplication, reordering or substitution
cannot satisfy the receiver/counter/UAPI cuts. Loss, duplication, wrong phase
or mismatch of either ready record fails closed and removes any installed
client routes. TLS traffic, possession proof, accept, KYNP ping/pong,
type-1/type-2 counter growth, a historical timestamp or the server
acknowledgement without both ready records cannot promote. The one
`carrier_handshake_timeout_seconds` deadline is never extended. Old callbacks
whose candidate token no longer matches may only close themselves.

Unknown WireGuard keys cannot pass the possession proof. A proof-valid but
non-handshaking candidate times out, is taken Down and detached before another
candidate. While an active carrier is healthy all new pre-proof connections
are bounded but cannot mutate it; at most one proof-valid replacement becomes
the authenticated waiter and drives the incumbent through the draining/reset
cut above. The server never chooses QUIC/WSS/TCP fallback for the client.

Each carrier generation resets KYNP sequence, QUIC replay-window and fragment
state. WireGuard remains responsible for inner cross-connection replay
protection.

## Production listeners

The listener factory opens QUIC, WSS and TCP in configuration order and
publishes no accept barrier until all three exact sockets and the forwarding
lease are healthy. A partial open closes in reverse order and cannot publish
ready.

- QUIC requires an `udp4`/`AF_INET` socket, TLS 1.3, exact ALPN, datagrams, disabled 0-RTT, bounded
  streams/idle/handshake resources, exact nonempty SNI and the existing KYNP
  datagram limits. Its UDP socket is wrapped by a production
  `quic-go.OOBCapablePacketConn` implementation whose `ReadMsgUDP` parses and
  validates exact IPv4 `IP_PKTINFO` destination address and ifindex before
  returning the packet and unmodified OOB data to quic-go; no application
  callback from quic-go is assumed.
- WSS and TCP listener constructors use only `tcp4`/`AF_INET`; an
  `AF_INET6` socket, IPv4-mapped bind or wildcard fallback is a startup
  failure. The macOS carrier dialer resolves the canonical DNS name but
  selects only A/IPv4 candidates for live version 1; AAAA-only resolution
  fails, and mixed A/AAAA resolution cannot dial an AAAA address.
- WSS requires `GET`, exact Host/SNI, exact `/kynp`, no query, absent Origin,
  bounded headers, disabled compression and a bounded TLS/upgrade deadline.
  Production never uses `websocket.NetConn`: it calls `SetReadLimit(65555)`
  before the first read and uses a direct binary-message adapter that requires
  exactly one fixed carrier-auth record, the one first-frame
  binder-plus-type-1 frame, one phase-correct fixed `KYCR` ready record, or one complete
  20-byte-header-plus-at-most-65,535-byte KYNP frame per message. The combined
  first-frame message must also remain within 65,555 bytes. Text, oversize and
  trailing bytes fail closed; any WebSocket fragmentation is reassembled only
  inside that bounded single logical message.
- TCP completes a bounded TLS 1.3 handshake with exact nonempty SNI before
  reading a bounded carrier-auth record, ready record or KYNP frame.
- All listeners use the shared codec/replay/fragment implementation.
- Cancel/close joins every accept/session goroutine and closes every socket.

Readiness facts include actual socket local addresses, local ifindex,
TLS/ALPN/path policy, listener generation, and zero active carriers. Configured
URLs alone are not readiness evidence.

At identity acquisition the leaf certificate must retain at least the
30-second service-start ceiling plus the configured carrier-handshake ceiling
plus the 15-second hard stop ceiling. The expiry timer leaves readiness and
starts the common shutdown deadline 15 seconds before `NotAfter`; a
certificate that cannot preserve that margin never opens a listener.

## Service, command and systemd lifecycle

Startup is:

```text
validate fixed public config and non-root execution identity
  -> acquire one opaque identity generation
  -> acquire one broker/TUN/kernel-facts generation
  -> configure one WireGuard device with carrier closed
  -> atomically open QUIC, WSS and TCP listeners
  -> revalidate every fact
  -> sd_notify READY=1
```

Shutdown and failed startup use one monotonic ten-second process deadline,
not a fresh deadline per component. The first action closes listener
acceptance and carrier output; then all sessions/goroutines are joined, the
Peer sends release and waits for the broker's drain-ready gate, WireGuard is
taken Down and its device/TUN copy is closed, the remaining
`tun-closed`/`released` exchange completes, and live generation, transfer
nonce, lease token and carrier-derived identity material are cleared.
`Done()` channels are non-nil and retain a stable typed cause. Certificate
expiry, listener failure, broker/forwarding drift, WireGuard device loss,
watchdog failure or cancellation leaves ready immediately and converges to
process exit. A stuck operation consumes only the remaining common deadline.
It may end `failed_closed` only after a positive complete dump proves the
fixed guard exact/empty/policy-drop; this state may retain a journal and owned
objects but means forwarding is proven closed. If that baseline cannot be
proved because the emergency batch, ACK, dump or notification boundary
failed, the only terminal status is the distinct
`fail_close_unproven_reset_required`. That status emits neither READY nor
`stopped`/`failed_closed`, retains all evidence, exits nonzero and requires
disposable-VM reset. `stopped` is reserved for fully clean absence.

The exact executable surface is:

```text
kyclash-network-peer --check-config
kyclash-network-peer
kyclash-network-peer-broker
kyclash-network-peer-host-bootstrap
```

The first performs only fixed-path
`/etc/kyclash/network-peer-v2.json` public validation. No arguments runs the
live Peer under the exact systemd unit. Broker and host bootstrap likewise
accept no arguments and require their exact unit/cgroup/invocation; direct or
wrong-unit execution fails before mutation. Every other argument and every
caller-selected path/secret/endpoint is rejected. `SIGTERM`/`SIGINT` enter
the one common deadline; stdin and a parent process are not lifecycle owners.

Live files are compiled only with the Go build tag
`kyclash_production_peer`; the ordinary build retains only
`--check-config` and fails closed if no arguments are used. The tagged binary
is built with the pinned Go toolchain, `CGO_ENABLED=0`, and only for
`linux/amd64` and `linux/arm64`; another toolchain, OS/architecture or cgo
requires review. It still cannot activate outside its exact systemd invocation. The unit files
are shipped disabled and are neither installed nor enabled by an ordinary
KyClash App build. This is the concrete default-off boundary.

The reviewed host-bootstrap unit contract for the dedicated Peer image is
exactly:

```ini
[Unit]
Description=KyClash dedicated Peer host bootstrap
DefaultDependencies=no
RequiresMountsFor=/etc/kyclash /usr/lib/kyclash
Requires=systemd-udevd.service systemd-sysctl.service
After=local-fs.target systemd-udevd.service systemd-sysctl.service
Before=network.target multi-user.target net.kysion.kyclash.network-peer-broker.service net.kysion.kyclash.network-peer.service shutdown.target
Wants=network.target
Conflicts=shutdown.target
RefuseManualStart=yes

[Service]
Type=oneshot
RemainAfterExit=yes
User=root
Group=root
SupplementaryGroups=
Slice=system.slice
ExecStart=/usr/libexec/kyclash-network-peer-host-bootstrap
Restart=no
KillMode=control-group
TimeoutStartSec=30s
TimeoutStopSec=15s
SendSIGKILL=yes
OOMPolicy=stop
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
SecureBits=noroot-locked
UMask=0077
LimitCORE=0
LimitNOFILE=256
TasksMax=64
PrivateMounts=yes
PrivateTmp=yes
PrivateDevices=yes
DevicePolicy=closed
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=no
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=all
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service @network-io seccomp
SystemCallErrorNumber=EPERM
RestrictAddressFamilies=AF_UNIX AF_NETLINK
KeyringMode=private
RemoveIPC=yes
ReadOnlyPaths=/etc/kyclash /usr/lib/kyclash /etc/systemd/system /usr/lib/systemd
ReadOnlyPaths=/proc/sys
ReadWritePaths=/proc/sys/net/ipv4/ip_forward
ReadWritePaths=/proc/sys/net/ipv6/conf/all/forwarding
InaccessiblePaths=-/run/credentials -/run/credstore -/run/credstore.encrypted
InaccessiblePaths=-/etc/credstore -/etc/credstore.encrypted
InaccessiblePaths=-/usr/lib/credstore -/usr/lib/credstore.encrypted
InaccessiblePaths=/etc/kyclash/credentials.encrypted
InaccessiblePaths=-/var/lib/kyclash-network-peer-broker

[Install]
WantedBy=multi-user.target
```

The reviewed Peer unit contract is exactly:

```ini
[Unit]
After=net.kysion.kyclash.network-peer-host-bootstrap.service net.kysion.kyclash.network-peer-broker.service
Requires=net.kysion.kyclash.network-peer-host-bootstrap.service net.kysion.kyclash.network-peer-broker.service
BindsTo=net.kysion.kyclash.network-peer-host-bootstrap.service net.kysion.kyclash.network-peer-broker.service

[Service]
Type=notify
NotifyAccess=main
User=kyclash
Group=kyclash-ipc
SupplementaryGroups=
Slice=system.slice
ExecStart=/usr/libexec/kyclash-network-peer
Restart=no
KillMode=control-group
TimeoutStartSec=30s
TimeoutStopSec=15s
SendSIGKILL=yes
OOMPolicy=stop
WatchdogSec=30s
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
SecureBits=noroot-locked
UMask=0077
LimitCORE=0
LimitNOFILE=4096
TasksMax=256
PrivateMounts=yes
PrivateTmp=yes
PrivateDevices=yes
DevicePolicy=closed
ReadOnlyPaths=/tmp /var/tmp
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service @network-io seccomp
SystemCallErrorNumber=EPERM
RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK
KeyringMode=private
RemoveIPC=yes
InaccessiblePaths=-/run/credstore -/run/credstore.encrypted
InaccessiblePaths=-/etc/credstore -/etc/credstore.encrypted
InaccessiblePaths=-/usr/lib/credstore -/usr/lib/credstore.encrypted
InaccessiblePaths=/etc/kyclash/credentials.encrypted
LoadCredentialEncrypted=tls-chain.pem:/etc/kyclash/credentials.encrypted/tls-chain.pem.cred
LoadCredentialEncrypted=tls-private-key.pem:/etc/kyclash/credentials.encrypted/tls-private-key.pem.cred
LoadCredentialEncrypted=wireguard-private-key:/etc/kyclash/credentials.encrypted/wireguard-private-key.cred
```

The reviewed broker unit contract is exactly:

```ini
[Unit]
After=net.kysion.kyclash.network-peer-host-bootstrap.service
Requires=net.kysion.kyclash.network-peer-host-bootstrap.service
BindsTo=net.kysion.kyclash.network-peer-host-bootstrap.service
Before=net.kysion.kyclash.network-peer.service
PartOf=net.kysion.kyclash.network-peer.service
StopWhenUnneeded=yes

[Service]
Type=notify
NotifyAccess=main
User=kyclash-broker
Group=kyclash-ipc
SupplementaryGroups=
Slice=system.slice
ExecStart=/usr/libexec/kyclash-network-peer-broker
Restart=no
KillMode=control-group
TimeoutStartSec=30s
TimeoutStopSec=15s
SendSIGKILL=yes
OOMPolicy=stop
WatchdogSec=30s
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
SecureBits=noroot-locked
UMask=0077
LimitCORE=0
LimitNOFILE=1024
TasksMax=64
PrivateMounts=yes
PrivateTmp=yes
PrivateDevices=no
DevicePolicy=closed
DeviceAllow=/dev/net/tun rw
ReadOnlyPaths=/tmp /var/tmp
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=all
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service @network-io seccomp bpf
SystemCallErrorNumber=EPERM
RestrictAddressFamilies=AF_UNIX AF_NETLINK
KeyringMode=private
RemoveIPC=yes
RuntimeDirectory=kyclash-network-peer-broker
RuntimeDirectoryMode=0750
StateDirectory=kyclash-network-peer-broker
StateDirectoryMode=0700
ReadWritePaths=/run/kyclash-network-peer-broker
ReadWritePaths=/var/lib/kyclash-network-peer-broker
InaccessiblePaths=-/run/credentials -/run/credstore -/run/credstore.encrypted
InaccessiblePaths=-/etc/credstore -/etc/credstore.encrypted
InaccessiblePaths=-/usr/lib/credstore -/usr/lib/credstore.encrypted
InaccessiblePaths=/etc/kyclash/credentials.encrypted
```

`ProcSubset=all` is deliberate for bootstrap and broker: bootstrap must
read/write the two exact forwarding sysctls and broker must read forwarding,
the manifest-selected force-forwarding ABI and
`kernel.unprivileged_bpf_disabled`. `ProtectProc=invisible` still hides other
users' process details. Bootstrap's read-only `/proc/sys` parent plus the two
exact `ReadWritePaths=` exceptions is its complete sysctl write surface;
broker's `ProtectKernelTunables=yes` keeps all of `/proc/sys` read-only. Peer
retains `ProcSubset=pid` because it has no sysctl-authority role.

No child process is part of the design. A systemd `SystemCallFilter=` cannot
deny `execve` before `ExecStart`, because it would block the service's initial
exec. Instead, immediately after identity/unit verification and before
credentials, the broker socket or any kernel mutation, each binary sets
`NoNewPrivs`, installs its own seccomp-BPF filter with
`SECCOMP_FILTER_FLAG_TSYNC`, and verifies the filter mode on every existing
thread before continuing.
That filter denies `fork`, `vfork`, `execve`, `execveat` and `clone3`, and
allows `clone` only when argument 0 is exactly `0x00050f00`
(`CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_SYSVSEM|CLONE_THREAD`)
with no child-exit signal; this is the pinned linux/amd64 and linux/arm64 Go
runtime thread call. The Peer and host bootstrap deny the `bpf` syscall. The broker permits
that syscall only when scalar argument 0 is exactly `BPF_PROG_QUERY`; every
other BPF command returns `EPERM`. The implementation constructs only the
fixed query attributes from pinned ifindices and manifest attach types, never
accepts a BPF fd or caller attributes, and requires the native test to prove
that `BPF_PROG_QUERY` works with only the exact broker identity/capabilities
while program load, attach, detach, map and link commands fail. The pinned
source value and native behavior are gates; a runtime/toolchain change
requires re-review. The broker's and host bootstrap's five exact
`CAP_NET_ADMIN` capability sets and the Peer's five empty sets are runtime
assertions; the unit directives are not accepted as evidence by themselves.

The same per-process seccomp filters inspect `ioctl` scalar argument 1 rather
than allowing the broad syscall admitted during PID 1's initial exec. The
host bootstrap denies every ioctl because its link, route, neighbour and
feature operations use only typed netlink.
Peer permits exactly `TUNGETIFF=0x800454d2` on the received TUN descriptor
and `SIOCGIFMTU=0x00008921` on the pinned wireguard-go read-only MTU socket
path. It denies `TUNSETIFF`, `TUNSETOFFLOAD`, `SIOCETHTOOL`, every `SIOCS*`
request and every other ioctl.
This is compatible only because the broker-created descriptor has no
`IFF_VNET_HDR`; the pinned `CreateUnmonitoredTUNFromOwnedFD` path therefore
queries flags but never enters wireguard-go's `TUNSETOFFLOAD` branch. The
broker permits exactly `TUNSETIFF=0x400454ca` for its one fixed TUN creation
and `TUNGETIFF=0x800454d2` for verification; its ethtool feature mutation and
all link/route queries use typed generic/rtnetlink, so `TUNSETOFFLOAD`,
`SIOCETHTOOL`, `SIOCS*` and every other ioctl are denied there too. On both
supported architectures the cBPF first requires argument 1's high 32 bits to
be zero, then compares the exact low 32-bit request number. Each request is
additionally bound in code to the one expected descriptor/object; seccomp's
request-number check is not treated as pointer-content validation. Broker
constructs the `TUNSETIFF` ifreq locally as exact
`kyclash0|IFF_TUN|IFF_NO_PI|IFF_TUN_EXCL`; Peer derives the sole
`SIOCGIFMTU` ifreq name from its validated `TUNGETIFF` result and requires
1420. TUN and socket descriptors are CLOEXEC/nonblocking and no additional
ioctl may establish that state. Native
`strace` evidence on both supported architectures must equal these closed
request sets, and any new ioctl required by a Go, kernel or wireguard-go
change requires review. Tests prove the Peer receives `EPERM` for
`TUNSETOFFLOAD`, `TUNSETIFF`, `SIOCETHTOOL` and all sampled `SIOCS*` calls
after FD handoff, so it cannot re-enable packet aggregation after phase C.

The binaries consume no environment-driven configuration. The Peer reads
only PID-1-provided `CREDENTIALS_DIRECTORY`, `NOTIFY_SOCKET`,
`WATCHDOG_USEC` and `WATCHDOG_PID`; the broker reads only the latter three.
They validate syntax, PID applicability and exact invocation before use and
ignore every other variable. None is logged. Unit inspection also requires
the exact `/system.slice/<unit>` control group and `Delegate=no`.

The Peer cannot start before the broker has recovered/cleaned its journal,
created the exact socket, and emitted its own `READY=1`. Reverse stop ordering
stops the Peer before the broker; `PartOf=` and `StopWhenUnneeded=` then stop
the broker, while Peer `BindsTo=` handles broker failure. The ten-second
in-process deadline leaves five seconds before PID 1's hard stop ceiling.
Both persistent NICs and their simple routes must already be statically
materialized by the active/exited host-bootstrap oneshot. Manager admission
is deliberately not coupled to successful `released=6`, the 15-second stop
ceiling or journal cleanup: the dedicated image's complete networkd/
NetworkManager activation closure remains persistently masked before, during
and after every lease. A canonical, alias, socket or D-Bus start attempt
therefore fails as masked even after a clean stop and after Peer/broker
timeout or `SIGKILL`; manager MainPID remains zero and no manager
`ExecStart` timestamp appears. Residual journal/route/nft state remains
fail-closed recovery input and can never unlock a manager. On reboot the
persistent masks participate in the initial unit load before bootstrap,
which must re-prove the transient kernel objects absent before recreating
static state; the broker alone applies the already-defined changed-boot
journal rule afterward. DHCP or manager-dependent addressing and same-boot
unmask/decommission are unsupported in live version 1.
`READY=1` and watchdog messages are emitted only by each exact main-process
generation. No process forks, daemonizes, uses a shell or delegates notify
access.

## Pair contract and private SSH meaning

A shared validator/fixture must prove that the macOS signed profile and Linux
Peer configuration agree on:

- macOS live profile schema version 2 and `carrier_auth_version` 1;
- server WireGuard public key;
- one client public key and its local/tunnel addresses;
- server name and ordered endpoint URLs;
- exact QUIC/WSS/TCP order, ALPN and WSS path; and
- exact private CIDRs.

Mismatches fail before the macOS client or Linux Peer starts a live generation.

The production Peer does not expose an overlay-specific SSH daemon. When the
kernel forwarding lease, site return route, firewall and destination OpenSSH
service are valid, ordinary packets to the private destination's TCP/22 flow
through the same TUN and carrier as any other private service. Acceptance uses
an isolated site namespace with a real OpenSSH server, pinned ephemeral host
key and noninteractive public-key command/SCP proof. The fixed two-VM lab
nonce services remain lab evidence and cannot substitute for this routed
private-IP test.

## Required source gates

Before a live binary is constructed:

- malicious-prefix, mapped-address, canonical bind/URL and exactly-one-client
  tests pass, including schema-v1 and missing/unknown carrier-auth-version
  rejection plus DNS-only server-name/IP-literal SNI negatives. Listener
  fixtures reject bracketed/global/link-local IPv6, IPv4-mapped IPv6,
  wildcard binds, differing listener IPv4 addresses, duplicate ports and
  bind/URL port mismatch. Startup inspection proves all three server sockets
  are `AF_INET`, no `AF_INET6` listener exists, AAAA-only client resolution
  fails, and mixed A/AAAA resolution dials only an A record;
- both systemd credential ACL shapes and every extra/writable/symlink/race
  negative pass on native Linux;
- identity capability, expiration, redaction and zeroization tests pass;
- broker wire messages and SCM_RIGHTS tests reject UID 0, wrong Peer or broker
  UID, process/cgroup mismatch, generation, config hash, zero/old/wrong
  transfer nonce, wrong handoff-reply-derived lease token, replay, extra
  fields and descriptor count. Request/40-byte-acquire,
  216-byte-`public_lease_facts_v1` and 184-byte-reply golden bytes,
  truncation, ancillary and deadline cases pass. Tests prove the exact
  facts-bytes -> facts-hash -> reply -> reply-hash -> token -> durable-pending
  dependency, reject every excluded/cyclic/variable/canonicalization variant,
  and independently reconstruct the public facts in Peer. The reply hash
  covers protocol bytes only, every rejection consumes all received
  descriptors once, and each generation can attempt at most one
  ancillary-bearing `sendmsg`.
  Phase-cutover tests distinguish an already queued extra acquire from a
  later leased-phase violation without claiming future queue emptiness;
- the local wireguard-go ownership patch matches its recorded upstream hash;
  every owned-FD failure path plus forced GC/fd-number reuse proves one close,
  and production source cannot reference the unsafe upstream API;
- shared Go client/server carrier-auth known-answer tests match exact X25519,
  low-order rejection, exporter-fed HKDF, challenge/proof bytes and
  104-byte accept plus 136-byte post-accept binder bytes, constant-time HMAC,
  connection-counter exhaustion/reuse, zero accept nonce and complete-frame
  digest binding, while Rust/Go fixtures match the profile/bootstrap version
  without exposing the derived secret to Rust; QUIC regression proves
  server-opened stream ID 1 completes and the old client-open/read-first
  ordering deadlocks under a bounded test and is forbidden. QUIC/WSS/TCP
  negatives pipeline a proof-valid first frame before accept and delay it
  across the transition; none can validate the fresh accept nonce or reach
  switchboard attachment;
- forwarding facts and drift tests cover TUN/site/listener ifindex, MTU,
  addresses, namespace, sysctl, nft identity, complete protected-prefix FIB
  partition, unique gateway, direct gateway reachability, permanent neighbour
  and gateway/site MAC pair; synthetic netlink fixtures exhaust the closed
  standalone-link, route/nexthop and neighbour attribute sets, including
  every forbidden stack, LWT, encapsulation, NUD state/flag and connected/
  on-link override; nft fixtures require all eleven exact chains, seven
  accept and four drop policies, exact L2 MAC/VLAN gates and the three pre-L3
  IP-header gates, including IPv4 option/source-route and every IPv6
  extension-header negative. They require both per-family raw default-zone
  setters, the exact six public-carrier ingress/response notrack rules and
  raw-output default drop,
  mark-zero/new-flow-limited exact ct-mark replacement, one named limit
  object in the fixed guard table shared by both family rules, rejection of
  inline or cross-table limit references, current-mark original/reply guard
  checks, unconditional postrouting skb-mark clear and the two direction
  setters. Netdev fixtures reject every `ct` expression and
  require only the exact direction skb mark plus direct L2/L3 facts. State
  fixtures require bootstrap-pre
  built-ins/forwarding-zero, closed/clean empty fixed guard, active one fixed
  plus ten generation base chains and the one generation named limit, and
  draining empty guard/no named limit plus only indexed non-accepting residual
  generation hooks. Fixtures require TUN ingress policy `accept` and TUN
  egress policy `drop` in active state, index the complete two-chain
  auto-release closure, and prove the policy-only transaction changes only
  TUN ingress `accept -> drop` while every rule/set/reference remains
  unchanged. Only after policy ready may a separate no-policy detach empty
  both exact chains. Source/trace fixtures reject both operations in one
  batch. Crashes before/after each commit and before each ready accept only
  the complete old or target snapshot. One later device unregister boundary
  may remove only those two identities. Crash fixtures before/during either
  phase instead permit the same boundary to consume only the complete pre-indexed
  chain/rule/last-reference-anonymous-object closure. Partial or foreign
  disappearance fails; full link/nft dumps, never a notification counter,
  prove the result. Fixed-guard table deletion is never a successful ordinary
  cleanup. Separate `drop_gate_pending` graph fixtures cover two selected
  rules sharing one anonymous object, a retained rule that keeps an anonymous
  object referenced, final-reference release, rule-absent/object-present,
  object-absent/rule-or-binding-present and handle reuse. At the complete
  target only exact rule/named/anonymous-object handles are consumed;
  bindings are consumed with their owning rule and never as standalone
  handles. Separate guard-corruption fixtures exercise only
  `guard_emergency_recreate`, never ordinary drop-gate recovery;
- runtime-manifest tests pin kernel/systemd/build/hook ABI, reject every
  unknown version/hook type/module/function/attach type, and prove only the
  exact built-in plus generation-owned hook set can become ready. They also
  pin the Linux v6.8 `RTM_GETLINK` doit registration without
  `RTNL_FLAG_DOIT_UNLOCKED` and the direct `rtnetlink_rcv_msg()` `rtnl_lock()`
  path; a callback-mutex-only or unlocked-doit fixture fails. Fixtures
  require the exact trusted-OS, manager-mask/activation/initrd closure and
  ethtool feature names/bit numbers/four-bitset inventories, conntrack
  zone/mark/CTA_ID plus normal/dying dump ABI, the source-pinned unusable
  unconfirmed-dump stub and a gate forbidding it as evidence, table-local
  shared `NFT_OBJECT_LIMIT` ABI, the upstream commit, strict-limit patch
  SHA-256, enabled default-off Kconfig, kernel Build ID, strict-counter ABI,
  possible-CPU/template inventory, exact operating
  setting/rate/watermark/timeout/event/hash-size facts and two-second watchdog
  semantics, 1..32767 zone range, 4096-per-boot
  reservation cap and the exact `ipv6_force_forwarding_abi` enum
  plus all three protected ifindices. Present-mode fixtures require zero from
  both proc and netconf; absent-mode fixtures require exact absence from both; every
  disagreement fails. Formula tests distinguish `NETIF_F_GSO` from
  `NETIF_F_GSO_MASK`, constrain `GSO_ROBUST`, disable every VLAN transform
  bit and reject `NOCHANGE` as a fixed-on proxy;
- bootstrap file-boundary fixtures prove it opens exactly
  `/usr/lib/kyclash/network-peer-runtime-v1.json` and
  `/etc/kyclash/network-peer-v2.json`, reject any third/alternate source and
  exercise owner/mode/link/ACL/symlink/digest/replacement races on both;
- journal and boot-zone-ledger schema/size/path/atomic-transition tests cover
  exact bitmap lengths/subset rules, zone zero, the four exhaustive zone
  classifications, active/reapable exclusion, active phases, the exact
  nonzero 32-byte/lowercase-64-hex reservation ID, intent hash, sequence and
  4096 reservation maximum. Negative fixtures cover every impossible
  bit/active/hash/phase combination. They also prove the
  2-table/11-chain/64-rule/1-named-object/16-anonymous/2-route compact record
  caps, every per-record serialized cap, the exact 13,984-byte worst case and
  rejection at 16 KiB without storing a full expression. The actual maximum
  canonical fixture includes every route mask/hash and every longest phase
  name and proves the fixed envelope remains at most 3,072 bytes. Nft
  fixtures require planned handle zero before creation and observed nonzero
  handles only after the complete target dump; NEW messages contain no
  persistent handle, and zero never authorizes deletion. They cover lost
  ACK, restart with full absent/full target, noncontiguous/reused handles,
  duplicate userdata and every partial target. The 80-byte userdata
  known-answer tests reject wrong class/slot/generation/specification and a
  recursive spec digest; `%` set names and standalone binding records fail.
  Route fixtures exhaust every legal/illegal `E/A/P/N/O/C/Z` mask, both
  per-route fsync boundaries, IPv4 success followed by IPv6 failure, lost
  ACK/notification, `EEXIST`, auto-disappearance and exact deletion recovery.
  They prove `N subset A`, `P intersect N = 0`, `O subset P`, and crash before
  or after the `N` fsync. An `A`-only exact-present target after any positive,
  lost or explicit-negative ACK is ambiguous with zero deletion; an `N`
  target may enter `Z` only when absent.
  They reject `NLM_F_REPLACE`, `NLM_F_ATOMIC`, any alleged dual-stack batch
  and an unarmed second route. Path tests cover
  owner/mode/link/openat2/checksum, every
  named enum value and every pending/observed crash point, stale temporary,
  symlink, duplicate key, forbidden numeric-FD/OFD/pointer fields, corruption,
  same-boot rollback/missing-ledger ambiguity, changed-boot reinitialization
  and clean directory fsync. Lease fixtures verify `journal_sha256` before
  interpreting main or temporary state and reject syntactically valid
  single-bit changes to every phase/mask/handle/identity field as well as a
  missing, uppercase, wrong-length or self-including digest. The maximum
  fixture proves the digest remains inside the 3,072-byte envelope. Crash matrices cover reservation, intent,
  both reserved-plus-intent and intent-bound-plus-intent pre-mutation aborts,
  each side of their direct `zone_retire_pending` writes, each active-phase
  recovery before the ledger update and both sides of the spent-unowned ledger
  update, nft-pending, setter-armed, freeze, retire-pending,
  ledger-reapable, zone-retired, cleanup watchdog,
  `conntrack_reboot_required`, quiescent and clean/unlink boundaries.
  Boot-terminal fixtures cover the sole absent-to-present transition,
  reject same-boot clear/replacement/weakening/rollback, and exercise
  `lease`, `startup_reaper` and `active_reaper` sources with the conditional
  generation-hash rule. They crash before/after terminal fsync and before/
  after safety shrink with no lease journal, the matching failing-lease
  journal, a different active journal and a non-active cleanup journal. The
  matching case also crashes on both sides of the journal terminal-mirror
  fsync and proves recovery completes safety shrink before idempotently
  writing `conntrack_reboot_required`. A reaper timeout never fabricates or
  rewrites another journal, and only changed boot plus complete absence clears
  the terminal.
  Feature-state fixtures
  cover pre-GET, pending-fsync, SET/ACK/GET and ready-fsync boundaries,
  forbid SET replay/adoption on restart and require exact transient-object
  absence before pre-handoff journal cleanup. Handoff fixtures crash before
  and after `link_up_ready`, `handoff_pending`, successful `sendmsg` and
  `leased` fsync; `handoff_pending` is always treated as possibly published,
  is never resent and cannot clean until the exact Peer generation has exited,
  the old broker connection/queued reference is gone and link absence is
  observed. Fixtures persist and validate the exact unit, InvocationID,
  canonical cgroup and pidfd-verified MainPID; same-invocation recovery waits
  for PID 1 stop/cgroup-empty, inactive recovery proceeds to RTNL proof, and a
  changed/unclassifiable invocation permits only guard shrink. Broker restart
  always begins with empty local slots and cannot
  reconstruct, compare or reopen an FD from WAL. Release fixtures fsync and
  verify `tun_ingress_policy_drop_pending/ready` before
  `tun_nft_detach_pending/ready`, both before
  `peer_tun_close_pending` and
  `drain-ready`, treat it as possibly sent after crash and never resend.
  Broker-slot fixtures atomically take `Owned -> Consumed` before one Linux
  close, never retry `EINTR`, force FD-number reuse and prove non-persistent
  TUN disappearance without a link-delete request;
- listener atomic-open/rollback, TLS, QUIC, WSS and TCP negative tests pass;
- QUIC OOB wrapper tests prove an `udp4`/`AF_INET` socket and reject
  missing/wrong/truncated IPv4 `IP_PKTINFO` before quic-go; WSS
  direct-message tests prove the 65,555-byte ceiling, exact phase-specific
  `KYCR` messages and forbid `websocket.NetConn`;
- candidate admission proves only a fresh configured-key WireGuard handshake
  plus both ready controls promotes. It proves pre-proof, invalid-proof and
  candidate-CAS-loser connections make zero server WireGuard/UAPI/reset/
  switchboard mutations; only the token winner may reset after proof.
  It covers atomic dual-candidate reservation, fresh peer zero
  facts, exact known-answer `kynp_frame_sha256`,
  `wg_type1_sha256`, `wg_type2_sha256` and
  `server_ack_type4_sha256` domains, a client output gate that publishes exactly one
  binder-authenticated 148-byte type-1 and records `I`/hash, and a client
  input gate that accepts and atomically delivers exactly one 92-byte type-2
  whose receiver equals `I` and records `S`/hash. A stable server baseline of
  timestamp zero/rx 148/tx 92, the exact client 32-byte empty counter-zero
  keepalive, stable client rx 92/tx 180, stable server rx 180/tx 92, and the
  exact server 32-byte empty counter-zero acknowledgement followed
  by stable server rx 180/tx 124 and client rx 124/tx 180. Exact 200-byte
  client-ready and 136-byte server-ready golden records cover every field,
  HMAC domain and three cross-peer payload-hash comparisons. Wrong/duplicate
  type-1 batch/duplicate/send ambiguity, wrong/second/replayed type-2 and
  second type-2 delivery, nonempty/early/replayed/replaced/
  counter-greater-than-zero type-4,
  acknowledgement loss/duplication/reordering/substitution, acknowledgement
  arrival before both client pre-ACK UAPI reads, exact early-slot hold and
  one-delivery consumption, invalid AEAD, intermediate UAPI states, stale
  callback tokens, concurrent batches, pre-active TUN reads/writes,
  pre-ACK macOS route installation, ACK-without-route-ready, route failure,
  stale candidate/operation replies and wrong route-set digest never promote.
  A deterministic scheduler injects each causal response before its triggering
  send returns and proves all nine receive slots/gates were armed before
  challenge, proof, accept, type-1, type-2, client counter-zero, server
  acknowledgement, client-ready and server-ready publication. Ready loss,
  exact duplicate, substitution, wrong phase and ambiguous send fail closed
  and remove client routes;
- break-before-make tests prove old close, detach and goroutine join before
  the next candidate. Delayed old-QUIC cleanup makes one authenticated WSS
  connection the sole proof waiter, proves the client never dials TCP while
  it waits, and promotes that same WSS connection only after server fresh-zero
  proof; the WSS-to-TCP case is identical. Waiter deadline expiry removes
  listener readiness and fails the generation rather than releasing another
  fallback attempt. QUIC reordering delivers later server ordinary data
  before server-ready and fast client data before server-ready send returns;
  the pre-armed receive-only/server gates admit them only at the specified
  cuts. Fallback with queued TUN traffic proves no old endpoint survives and
  no server WireGuard byte can precede accept plus the new client type 1;
- broker EOF tests prove the complete accept/set freeze batch and exact
  client-route removal start immediately on socket loss without waiting for
  pidfd exit, while zone retirement or reaper deletion cannot begin before
  link absence;
- service failure injection covers every acquire/open/configure/close step,
  non-nil `Done()`, cause retention, cancellation, common-deadline exhaustion
  and stuck cleanup. `failed_closed` is reachable only with a positively
  observed guard baseline; emergency-batch/ACK/dump failure produces only
  `fail_close_unproven_reset_required`, never READY/stopped/failed_closed;
- unit fixtures parse to the exact reviewed bootstrap/broker/Peer properties,
  persistent mask closure and broker-only `bpf` syscall admission. Static
  seccomp disassembly/property tests prove the exact ioctl request sets,
  zero high halves and `EPERM` for every other scalar; the tagged versus
  untagged live-command boundary is tested. Unit assertions require
  `ProcSubset=all` for bootstrap and broker, `ProcSubset=pid` for Peer, and
  prove the bootstrap/broker can see the required `/proc/sys` facts while
  only bootstrap can write exactly the two reviewed forwarding files. All
  three systemd syscall allowlists must admit the one `seccomp` call needed
  for TSYNC self-filter installation; no unit broadens to `@sandbox`;
- argv, environment, status, error, log, durable evidence and fixture secret
  scans pass; they reject raw generation, transfer nonce, zone, flow/skb marks
  and any reconstructed nft expression containing those values outside the
  private journal/in-memory comparison boundary. A known-answer test fixes the
  exact `generation_evidence_id` domain, field order, big-endian integer
  encoding and first-16-byte truncation. Negative fixtures reject a changed
  domain/order/endianness/truncation, the full 64-hex digest and every separate
  `SHA-256(generation)`, nonce hash or zone/mark-tuple hash at all status,
  error, log and retained-evidence exits;
- the Linux command cross-compiles; and
- Go format, test, race and vet pass.

## Required isolated native-Linux gates

These run only in disposable Linux machines. A GitHub-hosted standard
`ubuntu-24.04` VM, never `ubuntu-slim`, runs the portable source, cross-build,
unit parsing, credential and non-activating systemd subset. Evidence records
GitHub `ImageOS`, `ImageVersion`, `/etc/os-release`, kernel, systemd, nft and
Go versions, but the moving hosted image is never live authority and never
generates a runtime manifest.

Live broker, routing, hook/BPF and reboot gates run in a project-controlled
disposable two-VM Ubuntu 24.04 topology: one dedicated Peer VM with separate
unstacked hypervisor listener and site NICs, and one site-target VM on the
private virtual segment. Both source images, virtual hardware manifests,
kernel build IDs, systemd packages and runtime manifest are pinned by
SHA-256. A mismatch fails preflight rather than skipping. The Peer VM contains
no Docker, K3s, container bridge, host firewall, stacked link or unrelated
network administrator. A hosted job or network namespace is not claimed to
replace this reproducible full gate.

- real systemd `LoadCredentialEncrypted=` materialization under nonzero
  `User=kyclash`;
- Peer read/not-write plus broker/shared-group/unrelated-UID read denial for
  all credential files; persistent encrypted-source ownership/mode and secret
  absence from argv/environment/log/core;
- all Peer real/effective/saved/filesystem UID/GID and supplementary-group
  facts, all five empty Peer capability sets and `NoNewPrivs=1`;
- all broker identity/group facts, all five exact `CAP_NET_ADMIN` sets and
  `NoNewPrivs=1`, plus positive denial of credentials and every non-reviewed
  device/path/action;
- `systemd-analyze verify`, a recorded `systemd-analyze security` result, and
  direct `systemctl show` assertions for every reviewed dependency, identity,
  notify, capability, sandbox, device, path, restart, kill, timeout, OOM and
  watchdog property for the bootstrap, broker and Peer units. Bootstrap
  success is active/exited with `TasksCurrent=0`, exact sole
  `CAP_NET_ADMIN` capability facts and complete static state; its failure or
  loss prevents/stops broker and Peer through the reviewed dependencies.
  Native `/proc` probes prove bootstrap and broker can read the required
  forwarding, force-forwarding and
  `kernel.unprivileged_bpf_disabled` facts, bootstrap can write only
  `/proc/sys/net/ipv4/ip_forward` and
  `/proc/sys/net/ipv6/conf/all/forwarding`, every other bootstrap sysctl write
  fails, and every broker sysctl write fails;
- root bootstrap evidence matches the exact TCB inventory, persistent
  mask/activation/initrd/package hashes and static NIC/route/neighbour/
  offload handoff without claiming PID 1 lacks capabilities. A non-TCB
  privileged holder or an unexpected network administrator prevents initial
  acceptance. Root mask/initrd replacement or direct manager execution is an
  explicit TCB violation, not something `ProtectProc=invisible` is claimed to
  contain;
- cold-boot hardware tests delay each NIC independently, deliver udev
  enumeration before and after its final rename, delay IPv6 DAD, and prove the
  one 30-second bootstrap deadline waits through the loss-detecting rtnetlink
  subscription without selecting a transient name or ifindex. Wrong hardware
  identity, duplicate/final-name conflict, DAD failure, subscription overflow
  and deadline expiry leave forwarding zero and prevent broker/Peer startup.
  Removing or renaming either NIC after bootstrap but before broker phase A
  rejects the lease; removing it during a lease triggers the broker's
  fail-closed path;
- every canonical manager unit, alias, socket, path, timer, D-Bus name and
  other manifest-named activation edge is individually started/triggered on
  a fresh boot, active lease, clean stop, every broker-journal crash point and
  Peer/broker timeout-plus-`SIGKILL` state. Each attempt fails as persistently
  masked, manager MainPID stays zero, no manager `ExecStart` timestamp or
  cgroup appears and kernel state remains unchanged. The same proof is
  repeated before bootstrap on reboot; no test waits for `released=6` to
  admit a manager;
- from persistent NIC/route availability through forwarding enablement,
  continuous unauthorized IPv4 and IPv6 TCP/UDP/ICMP frames injected on the
  listener NIC toward the site prove forwarding remains zero before the
  atomic fixed-guard commit and every injected packet drops afterward.
  Separate positive traffic from `kyclash0` to the site proves the authorized
  inner IPv4/IPv6 path after lease activation. Pre-enabled sysctl, missing/wrong-policy/
  wrong-priority guard, extra rule/set/map, forbidden nft persistence and a
  bootstrap crash at every transaction boundary make the boot
  non-acceptable; no packet reaches the site;
- single- and dual-stack nft-batch tests prove the ten generation base
  chains, the fixed-table generation named limit object, all
  `3 * enabled-family-count` guard accepts, raw zone setters, postrouting
  clear/direction setters, egress accepts and the six exact public-carrier
  notrack rules appear atomically or roll back to empty/drop. All planned
  creation handles are zero; emitted NEW messages carry no persistent handle;
  a complete post-dump alone supplies every nonzero observed handle and exact
  80-byte userdata. Both family-specific new-flow rules must consume one shared
  token bucket with an aggregate 16-per-second/burst-16 bound; inline
  per-family buckets and cross-table references fail. `nft_pending`,
  `nft_ready` and ordinary `drop_gate_pending` crashes accept only their
  complete indexed old/target snapshots; one-direction rule loss or a
  partial anonymous/binding closure is ambiguous with zero ordinary
  deletion. Guard deletion/replacement/unknown state instead exercises the
  independent idempotent `guard_emergency_recreate` transaction, retains the
  prior journal phase and requires reset after positively observing the
  empty/drop baseline. Notification loss, broker/Peer `SIGKILL`, manager
  activation attempts and ifindex-reuse attempts cannot create a new
  interface or lease. Cleanup and reboot retain/recreate only that baseline.
  Native load tests prove inet raw
  `ct zone set`, exact 32-bit `ct mark set` and postrouting skb-mark
  replacement work, while inserting any `ct` expression into either netdev
  egress chain fails and production contains none. Listener-, site- and
  host-local connection attempts try to preseed matching TCP, UDP and ICMP
  tuples before a genuine TUN original: exact carrier ingress/responses are
  untracked, every other listener/host IP path drops before conntrack, site
  reply entries may enter the generation-owned zone but remain mark zero, and
  every reply path drops. Wrong-zone, mark-zero, wrong-mark and cross-lease
  tuple reuse likewise drop. Socket/SO_MARK and earlier-hook mark injection
  is erased by the unconditional postrouting clear and cannot pass either
  direction egress mark;
- native route traces prove fixed IPv4-then-IPv6 creation and cleanup with
  one rtnetlink message, sequence and durable armed bit per route. Crash
  injection spans each pre-request fsync, request, positive or lost ACK,
  explicit negative/`EEXIST`, both sides of the `N` fsync, dump and
  observed/absent fsync. An `A`-only exact-present route always produces
  ambiguity and zero deletion; IPv4-committed/IPv6-failed and the inverse
  cleanup cut recover without adding an unarmed route or deleting a foreign tuple.
  A route that auto-disappears with `kyclash0` is classified absent rather
  than recreated. No skb containing both route mutations, transaction claim,
  `NLM_F_REPLACE` or `NLM_F_ATOMIC` is accepted;
- conntrack resource tests pin the upstream commit, strict-limit patch hash,
  enabled default-off Kconfig, Build ID, strict counter/limit 1024, operating
  `nf_conntrack_max=1024`, start threshold 128, total watermark 896, marked
  shutdown watermark 224, aggregate shared 16-per-second/burst-16 limiter and
  one-second reconciliation deadline. Kernel KUnit/selftests cover the
  1023/1024 edge, a multi-CPU barrier race, allocation faults, unconfirmed,
  dying and externally held references, multiple network namespaces, and
  sysctl zero/below/above 1024. Every failed allocation/final free releases
  exactly one reservation, an eligible early-drop flow is never evicted, the
  global strict counter never exceeds 1024, and NFQUEUE/helper/expectation or
  an unpinned template inventory prevents acceptance.

  Exact-VM TCP/UDP/ICMP floods in both directions and paused DESTROY
  consumption prove the counter remains at or below 1024, new allocations
  fail closed at the cap and existing flows are not evicted. The broker
  records the marked count at freeze-batch commit without asserting a
  mark-specific kernel quota. A dual-stack client new-flow flood and site
  unmarked-zone preseed flood trigger freeze under the strict cap. Public
  carrier flood and unrelated listener/host traffic respectively prove
  notrack and pre-conntrack drop and do not increase the counter.

  On the pinned smallest VM, ordinary cleanup exercises complete global
  normal/dying dumps, up to 1024 distinct matching objects and exact
  family+original-tuple+zone+`CTA_ID` deletion. Zone-only, ID-only,
  tuple-only and bulk/zone/global flush calls are source- and
  syscall-trace-forbidden; mismatch or `ENOENT` forces a new complete dump.
  Held-reference and DESTROY-backpressure tests deliberately cross the
  two-second watchdog and must first durably create the global
  `boot_terminal`; the matching current lease additionally enters
  `conntrack_reboot_required`, while a reaper-source failure leaves every
  other journal phase unchanged. All variants reject same-boot start and
  retain the drop baseline. Only a real reboot/new boot ID and changed-boot
  absence proof may resume; no test asserts a two-second kernel cleanup bound
  or a maximum delete-request count.

  The ledger matrix proves zone zero is never allocated, all same-boot bits
  are monotonic, every failed reservation is spent, no more than 4096
  reservations occur, and exhaustion refuses before mutation. Visible entries
  injected into unused or spent-unowned zones cause reset with zero deletion.
  Crashes at every ledger/journal phase prove active zones never reach the
  reaper, setter-armed zones become reapable only after freeze/link absence,
  and a reapable/retire-pending mismatch recovers only forward.

  A separately tagged, non-production instrumentation-only acceptance hook
  that can never satisfy the live runtime manifest holds a real skb before
  conntrack confirm while standard `GET_UNCONFIRMED` still returns empty.
  After the old
  journal reaches clean and a different zone is reserved, releasing that skb
  must create only an old-zone late normal entry; the boot-wide reaper finds
  it by global dump and deletes it with the exact tuple+zone+ID without
  affecting an identical new-generation five-tuple. The same test covers a
  late confirm immediately after the final stable scan, 1024 hidden/late
  objects, delayed dying entries, missing NEW/DESTROY events, reaper crash/
  restart and startup catch-up. Hidden count above the start bound refuses a
  new lease. Missing/corrupt/rolled-back ledger, active ledger with
  missing/corrupt journal, boot ID/sequence/netns mismatch and forbidden
  same-boot snapshot restore all require guard shrink plus disposable reset;
- all three processes successfully install their exact TSYNC self-filter
  through the narrowly admitted `seccomp` syscall; every extant thread shows
  `Seccomp=2` and the expected filter layer before mutation. Attempted
  Peer/broker exec and child-process creation fail while Go thread creation
  and intended service operations succeed; broker
  `BPF_PROG_QUERY` succeeds for the fixed query set while every BPF load,
  attach, detach, link, map and other command fails, and bootstrap/Peer cannot
  call `bpf`;
- real broker-created `kyclash0`, one SCM_RIGHTS transfer and wireguard-go
  attachment, with initial-down, `IFF_UP`, operstate and IPv6 DAD facts;
  phase A proves absence plus complete persistent-NIC checks, phase B proves
  all-three-interface checks after TUN creation and the sole journaled TUN
  feature-disable mutation but before address/MTU/route/nft/link-up/FD
  mutation, and phase C proves the final pre-readiness snapshot. Native
  handoff crash cases prove a durable `handoff_pending` precedes `sendmsg`,
  never causes a resend, persists the pidfd-verified unit/InvocationID/cgroup/
  MainPID, and stops/waits a possibly published Peer or queued SCM_RIGHTS copy
  without claiming the restarted broker still owns its old FD. Same,
  inactive, changed and unclassifiable InvocationID cases exercise the exact
  recovery branches. Normal release fsyncs and verifies
  `tun_ingress_policy_drop_pending/ready`, then the separate
  `tun_nft_detach_pending/ready`, then `peer_tun_close_pending`, before the one
  `drain-ready`, tests crashes on both sides of that send and Peer close/
  `tun-closed`, and closes the Peer copy before the broker's durably pending
  local-slot consume. Abnormal release atomically consumes a currently owned
  broker slot once, while a restarted broker proves its slot starts empty;
  recovery relies on exact old Peer/socket termination for remaining copies
  and never uses `kcmp`, `pidfd_getfd`, a name reopen or SCM_RIGHTS resend.
  Nonce/token replay across generation/connection fails. Injected `close`
  EINTR plus immediate FD-number reuse proves no retry/double-close. TUN
  unregister produces one device boundary. Normal release proves the
  policy-only TUN ingress `accept -> drop` cut with every indexed member
  unchanged before the no-policy detach empties both TUN-bound chains; only
  afterward may full dumps consume their two identities. A
  crash before detach may consume only the exact
  pre-indexed chain/rule/last-reference-anonymous-object closure. Tests cover
  every policy/drop-ready/detach batch and unregister cut, reject a combined
  policy-plus-rule-delete batch, and cover partial closure loss and loss of the
  one RTM notification without waiting for per-chain events. Source and
  concurrency traces prove each fresh non-dump exact-ifindex/name
  `RTM_GETLINK` enters the locked doit path only after unregister returns;
  dump callback mutex behavior is not accepted as that proof. Every other
  disappearance fails. No path issues a link-delete request;
- real dual-stack addresses, routed site-target VM, return route and
  generation-scoped nft forwarding/NAT-invariant chains, including the exact
  IPv4- and IPv6-route scopes, one gateway per family, reciprocal permanent
  neighbours and pinned L2 MAC pair; an inner packet targeting a local-table
  address is dropped while a gateway-routed private target succeeds. The
  site-target VM acts as the disposable gateway and holds the private service
  IPs on loopback so the two-VM topology does not hide a connected-prefix
  shortcut;
- startup and live-drift injection reject every non-manifest netfilter hook
  at every hook number, including nft input/forward/output/postrouting,
  legacy xtables/ebtables, BPF netfilter plus NFQUEUE and unknown hook types;
  BPF XDP/TCX, classic XDP, ingress/clsact, every TC filter/action/redirect/
  rewrite/offload, disallowed qdisc, aggregation/segmentation/VLAN-transform
  feature and flowtable are independently rejected.
  Each attach/hook negative is injected separately on the listener NIC, site
  NIC and `kyclash0`;
  Negative flows include pre-conntrack IPv4/IPv6 address rewrites,
  post-conntrack TCP/UDP port and payload rewrites, and listener input
  address/port rewrites. IPv4 LSRR/SSRR and every IPv6 extension-header class,
  including RH0/RH2/SRH with an allowed current hop and non-private later hop,
  are rejected in both inner directions and at listener ingress before any
  accept counter; notification loss or query drift closes the gate;
- startup and drift reject every stacked/master/slave/parent/lower/upper site
  or listener link and every site route/nexthop with multipath, indirect ID,
  LWT, encapsulation, redirect or unknown attribute. Dual-stack cases
  independently reject two/missing gateways, any direct/connected/on-link/
  less-specific/more-specific route that can win for a non-gateway protected
  address, recursive/wrong-ifindex gateway reachability, absent/duplicate/
  wrong-ifindex/wrong-MAC neighbours, every non-permanent NUD state,
  neighbour flag/unknown attribute, gateway/site MAC drift, and route or
  neighbour deletion while traffic is queued;
- host-local TCP, UDP, ICMP and raw IPv4/IPv6 packets aimed at the configured
  client host are all dropped by the policy-drop `kyclash0` egress chain,
  while exact established TCP/UDP and ICMP echo site-interface replies
  succeed; fragment, extension-chain, `related` and unsupported-protocol
  negatives are dropped. IPv4 first/non-first/MF and IPv6 atomic/non-atomic
  fragment tests prove the site and `kyclash0` ingress counters drop them
  before conntrack defragmentation. Additional dual-stack negatives inject
  listener-to-site and site-to-listener TCP/UDP/ICMP plus Peer-UID and other
  host-local source-bound/output-interface-selected traffic to an in-prefix
  target, out-of-prefix site route and gateway. ARP request/reply/gratuitous/
  proxy, IPv4 Redirect, IPv6 RS/RA/NS/NA/Redirect, wrong gateway MAC,
  tagged/VLAN-metadata frames and every unsupported protocol reach only an
  explicit drop counter and produce no site payload;
- positive dual-stack TCP/UDP/ICMP captures prove exact
  `kyclash0 -> pinned gateway MAC -> private target` and reverse flows, with
  no Peer-emitted ARP/NDP for the full lease. Removing the local permanent
  neighbour leaves queued IP and discovery behind the site-egress drop,
  removes forward acceptance/client route and emits no accepted ARP/NDP. The
  reciprocal gateway neighbour is removed only after the disposable lease
  and is never broker-owned;
- native ioctl traces equal exactly
  `{TUNGETIFF,SIOCGIFMTU}` for Peer and `{TUNSETIFF,TUNGETIFF}` for broker.
  Wrong-FD allowlisted requests reach kernel `ENOTTY`; `TUNSETOFFLOAD`,
  TUN persistence/owner/group/link/queue/index/vnet-header/eBPF/filter/
  carrier requests, `SIOCETHTOOL`, interface/MTU/address/route setters,
  `SIOCGIFINDEX`, `FIONREAD` and every allow constant with nonzero high 32
  bits return seccomp `EPERM`;
- real QUIC, WSS and TCP private HTTP plus OpenSSH/SCP traffic;
- unknown key, candidate starvation, replay, TLS identity, no-return-route,
  pre-accept pipelining/delay, wrong accept nonce and binder/frame-substitution
  negatives. Traces prove every pre-proof, invalid-proof and CAS-loser
  connection performs zero server reset/UAPI/switchboard mutation. Candidate
  cases race two proof-valid reservations; inject
  repeated/batched client type-1 output and ambiguous client send, then
  wrong/repeated/replayed/batched client type-2 input,
  receiver/hash/sender mismatch and a second delivery attempt, early type-4,
  counter-one before counter-zero,
  nonempty/identical/substituted counter-zero replay, invalid AEAD, stale token
  callbacks, send-success/error ambiguity and concurrent batches around every
  UAPI cut. Only one binder-bound type-1, one atomically delivered
  correlated type-2, the exact client 32-byte empty
  counter-zero keepalive and the exact server 32-byte empty counter-zero
  acknowledgement may reach the server/client 180/124 byte cuts. Tests drop,
  duplicate, reorder and substitute the acknowledgement, force it to arrive
  before either client pre-ACK UAPI read, prove the bounded slot preserves the
  92/180 baseline and delivers exactly once. They verify exact 200-byte
  client-ready/136-byte server-ready records, stale operation and route-digest
  rejection, route failure rollback, every causal slot-before-send cut, ready
  loss/duplication/substitution and QUIC cross-datagram reordering. Injected
  pre-active TUN reads/writes and route-install attempts remain closed; ACK
  alone never promotes, and only exact routes plus both ready records do;
- UDP blocking followed by QUIC failure -> one authenticated WSS proof waiter,
  then WSS failure -> one TCP waiter, without recreating TUN or routes. Each
  server old-carrier cleanup is deliberately delayed; the client never opens
  the next transport while a waiter is pending, the same waiter receives
  accept only after fresh-zero proof, and waiter deadline expiry fails the
  generation/listener readiness rather than burning another fallback;
- TUN-feature crash injection covers before/after pending fsync, before SET,
  after SET before ACK, after ACK before GET, after GET before ready fsync,
  after ready before phase B and after phase B before link-config pending.
  Every case proves no FD handoff/address/client-route/generation-nft,
  eventual TUN absence and unchanged empty/drop guard,
  no journal state skip, no SET replay and no deletion/adoption of a foreign
  same-name link;
- Peer and broker cancellation, `SIGKILL`, OOM-equivalent termination,
  interface deletion/recreation, ifindex drift and reboot recovery from every
  valid write-ahead transition. EOF evidence measures that the complete
  freeze batch and client-route removal precede any pidfd wait, while zone
  retirement and any reaper deletion always follow old Peer/queued-reference
  termination and positive link absence. On a changed boot, journal-only
  absence is cleaned, while any
  same-name/exact object or supported normal/dying journalled-zone entry
  refuses with zero mutation; only that proved changed-boot boundary may
  reinitialize the zone ledger;
  same-boot, corrupted and other ambiguous journals likewise refuse until a
  separately authorized disposable reset. Timeout cases separately assert
  proven `failed_closed`, durable `failed_closed_reboot_required` versus
  `fail_close_unproven_reset_required`. Tests prove `Restart=no`
  throughout and use only explicit start or normal boot activation. Every
  non-reboot automatic path consumes one ten-second application deadline and
  remains below the 15-second systemd ceiling;
- loss, duplication, reordering, jitter, rate, MTU and KYNP-fragment
  boundaries, explicit inner-IP-fragment refusal, reconnect and bounded soak
  metrics; and
- final absence of the Peer, broker lease, TUN, client route, all generation
  nft objects/rules and both families' normal/dying views at the generation
  zone's retirement cut, plus durable used/reapable disposition, listeners
  and credentials, with the fixed guard alone exact, empty and policy-drop.
  Evidence explicitly states that standard Linux cannot prove the
  unconfirmed view empty and never labels it absent.

Retained evidence is allowlist-only and contains public configuration/binary
hashes, UID/capability facts, listener/TUN/route/nft public facts, transport
timelines, the sole 32-lowercase-hex `generation_evidence_id` of the expired
generation using the exact domain/layout above,
WireGuard public-key hash/handshake facts, SSH public host fingerprint and
exit result. It contains no live/full generation value, password, private
key, token, credential bytes, separate generation/nonce/zone/mark hash or raw
environment.

## Activation and authorization boundary

Source, tests, cross-compilation, systemd unit validation and disposable
Linux isolation work are authorized by the existing continuous-delivery
boundary. This review does not authorize:

- installing the host-bootstrap, broker or Peer unit on a production host;
- creating a TUN, route, nft object or system account outside an isolated
  disposable Linux environment;
- obtaining or deploying a production TLS/WireGuard private key;
- changing PVE, ROS, K3s, Shenzhen routes, services or credentials;
- contacting a production/staging endpoint; or
- enabling the macOS production profile/release.

After source implementation and isolated Linux acceptance, a separate
deployment review must bind an exact host, endpoint, trust chain, return path,
firewall, rollback and public-key enrollment before any real-site change.

## Review closure checklist

This record may be marked approved and locked only after:

1. independent security review reports no unresolved Critical or High finding;
2. independent Linux/systemd feasibility review reports no unresolved
   Critical or High finding;
3. every finding is resolved in this text without weakening the parent
   WireGuard/carrier/route/secret contracts; and
4. independent protocol and implementation review reports no unresolved
   Medium finding; and
5. the locked content SHA-256 is recorded before implementation continues.
