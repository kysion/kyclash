# KyClash Linux Peer v1 — locked minimum production contract

Status: source contract locked; live runtime not implemented or deployed

Date: 2026-07-23

This document locks the smallest secure Linux Peer boundary that can later
terminate KyClash carriers and forward the WireGuard overlay to explicitly
configured private site routes. The current deliverable is a strict,
compileable, fail-closed skeleton. It does not claim a running production
Peer, a connected Shenzhen site, or remote deployment.

## Runtime boundary

```text
KyClash macOS App
  -> QUIC, then WSS, then TCP
  -> TLS 1.3 server authentication
  -> KYNP framed WireGuard datagrams
  -> Linux Peer (unprivileged steady state)
  -> pre-provisioned kyclash0
  -> fixed site interface
  -> explicit private CIDRs only
```

The reusable implementation boundaries are:

- `internal/carrier`: QUIC, WSS and TCP acceptance plus KYNP stream framing;
- `internal/wgcarrier`: WireGuard device and carrier switchboard behavior;
- `internal/profile`: canonical transport names and order; and
- `internal/productionpeer`: the new public configuration, credential,
  lifecycle and readiness contract.

The loopback-only `labserver`, fixed two-VirtualMac `externalpeer`, and
client/dialer-oriented `userspace.Backend` remain test implementations. They
must not be started as, wrapped as, or reported as this production Peer.

## Public configuration

The only configuration location is:

```text
/etc/kyclash/network-peer-v1.json
```

The authoritative machine-readable contract is
[`network-sidecar/schemas/kyclash-linux-peer-v1.schema.json`](../../network-sidecar/schemas/kyclash-linux-peer-v1.schema.json).
The checked example uses TEST-NET and `.invalid` identities only:
[`network-sidecar/internal/productionpeer/testdata/valid-v1.json`](../../network-sidecar/internal/productionpeer/testdata/valid-v1.json).

The decoder is bounded to 64 KiB and 64 nested JSON levels, and rejects:

- unknown fields, trailing JSON values and duplicate keys at every depth;
- non-canonical, public, default, overlapping or tunnel-overlapping routes;
- wildcard, loopback or privileged listener binds;
- a listener order other than QUIC, WSS, TCP;
- TLS below 1.3 or a listener hostname different from `tls.server_name`;
- invalid, zero, duplicate or server-equal WireGuard public keys;
- non-host tunnel prefixes or address-family mismatches; and
- any attempt to select a TUN name, NAT mode, config path, credential path,
  credential name, private key, or live-listener option at runtime.

The `wireguard.clients` array authorizes between 1 and 32 identities so the
schema does not permanently encode a single named client. Version 1 still
requires `policy.max_active_clients = 1` and
`policy.max_active_carriers = 1`. It is a single-active-client service and
must not be described as multi-tenant.

## Identity and trust

`tls.trust_mode = system_roots` has one precise meaning: the macOS client
validates the Peer certificate using its operating-system trust roots and the
exact configured hostname. `tls.local_certificate_sha256` is a separate
Peer-local startup self-check of the leaf certificate DER. It is not a client
pin and does not replace system-root plus hostname verification.

WireGuard authenticates the inner client and server identities. Only public
keys belong in the JSON configuration. The server private key is checked
against `wireguard.server_public_key_base64` before the future live runtime
may become ready.

Private material is accepted only through the fixed systemd credential
directory:

```text
/run/credentials/net.kysion.kyclash.network-peer.service/
  tls-chain.pem
  tls-private-key.pem
  wireguard-private-key
```

No public JSON field, command-line argument, environment-selected path, log,
status object, or formatted error may contain those private values.
Credential reads open the fixed directory and fixed filename with
`O_NOFOLLOW`, require the expected owner, a non-writable trusted directory,
a root-owned regular file with no group/world permissions, and a bounded
non-empty size. Descriptor metadata and the directory entry's device/inode
identity must agree before and after the read. Any ambiguity clears already
loaded bytes and returns only the stable `credential unavailable` error.

The current command implements configuration checking only. The credential
provider and identity-material validation are compiled and tested, but are
not yet wired to a live listener.

## Forwarding and privilege

The fixed interface is `kyclash0` with MTU 1420. The Peer process must not
accept arbitrary commands or arbitrary interface/route input. A later,
separately reviewed Linux provisioner must create that exact TUN and any
required forwarding state before handing a typed lease to the unprivileged
Peer process.

Version 1 permits `return_path.mode = routed` only:

- site prefixes must be explicit private CIDRs;
- the site network must have a return route to the authorized WireGuard
  tunnel addresses through this Peer;
- default routes and public routes are forbidden; and
- SNAT, masquerade and exit-node behavior are out of scope.

This routed boundary can carry ordinary private IP services, including SSH,
only after the live Peer, site return path, service listener and firewall have
all been independently verified. The source skeleton is not evidence that
interactive SSH or any site endpoint is currently reachable.

## Lifecycle and fail-closed readiness

Startup order is fixed:

1. load and validate the fixed systemd credentials;
2. validate the pre-provisioned forwarding lease and exact route facts;
3. open the three listeners in QUIC, WSS, TCP order; and
4. publish `ready` only when all identity, forwarding and listener facts
   exactly match the decoded configuration.

Shutdown and failed startup close resources in reverse order:

1. carriers;
2. forwarding lease; and
3. identity material.

Cancellation, a forwarding-loss signal, a carrier-loss signal, mismatched
facts or cleanup failure converges to `stopped` or `failed_closed`; it never
falls back to a loopback lab service. Cleanup is bounded by
`policy.shutdown_grace_seconds`. `failed_closed` is terminal for the process:
an in-process retry cannot relabel unknown kernel or listener state as clean.

## Current executable surface

`kyclash-network-peer` currently accepts only:

```text
kyclash-network-peer --check-config
```

On Linux it securely opens the fixed root-owned configuration file and emits
only `KYCLASH_LINUX_PEER_CONFIG_OK` after strict validation. Live mode,
caller-selected paths, listener overrides and private-key arguments are
refused. Non-Linux execution is refused.

Before a production claim is allowed, a separate iteration must implement
the typed forwarder and carrier dependencies, wire the credential provider,
run under a locked systemd sandbox, and pass real Linux TUN, routed-return,
QUIC/WSS/TCP fallback, packet-loss, cancellation, restart, cleanup and
cross-host SSH tests. No production credentials or endpoints are stored in
this repository.
