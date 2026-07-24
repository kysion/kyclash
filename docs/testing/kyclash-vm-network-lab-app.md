# KyClash VM network lab App

This procedure belongs only to the disposable Apple-Silicon VirtualMac named
`kyclash-macos-lab-work`. It produces an unsigned `.app`; it does not build a
DMG/PKG, sign, notarize, publish, or activate production XPC/SMAppService.

The locked authority is
`docs/roadmap/kyclash-vm-network-lab-app-review-20260723.md`. The older
`vm_utun_lab` profile remains route-free and must not be used as private-route
evidence.

## Host build boundary

The host may compile artifacts and run source/contract tests only. Never run
the tagged harness, the App, Mihomo, or an utun/route helper on the host.

```sh
corepack pnpm macos:vm-network-lab:harness
corepack pnpm macos:production-vm:app -- \
  --lab-profile vm-network \
  --lab-public-root /absolute/reviewed/public/root \
  --sidecar /absolute/arm64/lab-sidecar
```

The App builder selects only `networking-vm-network-lab-app`, sets
`VITE_NETWORKING_VM_NETWORK_LAB=true`, disables both production and the
route-free VM-utun feature, creates only `KyClash.app`, and records source and
artifact provenance. The fixed repository Mihomo configuration is
`macos/route-helper/vm-network-lab-mihomo-config.json`; its required SHA-256 is
`2ad62e399c953f5298d8de22ee7d762277968f18e186c97d281cfdb67b10df5d`.

Stage the harness as
`/private/var/tmp/kyclash-vm-network-lab-stage/kyclash-vm-network-lab-harness`,
the pinned Mihomo executable as
`/private/var/tmp/kyclash-vm-network-lab-stage/mihomo`, and the exact config as
`/private/var/tmp/kyclash-vm-network-lab-stage/mihomo-config.json`. The harness
uses only these fixed runtime locations:

- App socket: `/var/run/net.kysion.kyclash.vm-network-lab.sock`
- root state: `/private/var/tmp/kyclash-vm-network-lab-root`
- route journal: `/private/var/tmp/kyclash-vm-network-lab-root/route-lease-v1.json`
- Mihomo controller: `/private/var/tmp/kyclash-vm-network-lab-root/mihomo.sock`

## Guest authorization and visible acceptance

SSH transport uses the VM-only public key. Starting the root harness requires
one visible Terminal `sudo` inside the guest. Do not use `sshpass`, `sudo -S`,
stdin password injection, Keychain password retrieval, or UI password
automation.

After the harness is visibly authorized, open the unsigned App and select
`KyClash Network (VM LAB · REAL UTUN · PRIVATE ROUTE · MIHOMO)`. One Connect
must show all of the following before the result can be accepted:

1. `runtime_mode=vm_network_lab`, `tunnel_kind=darwin_utun`, and one real
   KyClash-owned `utunN` distinct from Mihomo `utun4094`;
2. carrier health followed by the exact `10.88.0.2/32` route on that same
   KyClash utun—never route installation before health;
3. a successful typed private echo (`10.88.0.2:8080`) and authenticated Mihomo
   coexistence for QUIC, then WSS, then TCP;
4. break-before-make switching with one unchanged KyClash utun and route; and
5. `routes_installed`, `private_reachable`, and `mihomo_coexisting` visible in
   the App only after their typed harness proofs.

Disconnect and App EOF must first remove and positively inspect absence of the
owned `/32`, then stop the KyClash utun and Mihomo. Final evidence must show no
fixed socket, journal, child, controller, Mihomo `utun4094`/covering route, or
KyClash utun, while DNS, default route, and system proxy remain unchanged.
Missing inspection is not positive absence; ambiguous cleanup is a retained
recovery-only journal and a failed run.

This lab can prove visible core networking behavior in the disposable VM. It
does not close production signing/helper/Keychain gates or physical-Mac sleep
and network-switch acceptance.
