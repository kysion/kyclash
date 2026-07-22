# KyClash userspace lab App VM evidence

Date: 2026-07-23

Runtime target: `kyclash-macos-lab-work` (`VirtualMac2,1`, macOS 26.5.2,
arm64, guest user `supen`)

## Delivered App checkpoint

The explicit no-sign App profile was built with
`networking-userspace-lab-app`, copied to the guest as
`/Users/supen/KyClash-Lab-UI.app`, and launched in the guest Aqua session.
The visible KyClash Network page was selected and its Connect action was
pressed through the guest UI.

Guest process evidence:

```text
KyClash: /Users/supen/KyClash-Lab-UI.app/Contents/MacOS/clash-verge (pid 13160)
Mihomo:  /Users/supen/KyClash-Lab-UI.app/Contents/MacOS/verge-mihomo (pid 13167)
Lab sidecar: .../Contents/Resources/kyclash-network-sidecar-lab (pid 13304)
```

The UI reached the following state after the real Connect action:

```text
network_state=degraded_fallback
active_transport=tcp
sidecar_state=running
QUIC=passed
WSS=passed
TCP=passed
last_health=0 ms latency, 0 ms jitter, 0% loss
routes_installed=false
```

The guest-created screenshot and status record are retained outside Git under
`target/macos-vm-lab/evidence/userspace-lab-20260723/`.

```text
model=VirtualMac2,1
screenshot_mode=600
screenshot_sha256=970441b3e6ed0dd0d54d7588126f286312cb28e0c2e5e5474167010eb8b98a6b
```

## Scope and non-claims

This is an App-visible userspace loopback data-plane checkpoint. The lab
profile uses the bundled Go sidecar and a userspace WireGuard netstack. It
does not create a Darwin `utun`, install private routes, invoke the route
helper or tunnel broker, read Keychain, change DNS, or contact a production
endpoint. The displayed private CIDR is metadata only.

The separate root-required real-utun probe remains a manual guest-Terminal
test. It is intentionally waiting for the operator to type the administrator
password in the disposable VM; no password is passed through SSH or stored by
the host.
