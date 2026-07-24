# KyClash Shenzhen read-only acceptance

Status: acceptance contract only. No Shenzhen KyClash peer endpoint or public
trust bundle has been supplied, so this document does not authorize a tunnel
deployment or any remote mutation.

## Execution boundary

- The KyClash App and every data-plane probe run only in
  `kyclash-macos-lab-work`. The local host remains build/orchestration only.
- The remote side must already expose a reviewed KyClash peer/gateway and
  public trust material. Do not infer an endpoint from an SSH, PVE, ROS, K3s,
  database, Redis, MinIO, IPMI, or hypervisor management address.
- Tests are read-only: route lookup, ICMP reachability, TCP connect, and the
  fixed MinIO live-health GET. Do not log in to or mutate PVE, ROS, K3s,
  PostgreSQL, Redis, MinIO, IPMI/BMC, or ESXi.
- Never request, copy, print, or persist a password, token, private key, or
  raw credential. Public KyClash endpoint/trust material is still subject to
  the normal reviewed-input boundary.
- `10.68.72.1` is an obsolete ROS path and must not be introduced, selected,
  or used as a fallback. The recognized Shenzhen gateway toward
  `10.20.81.0/24` is `10.68.79.254`.

## Locked split routes

The initial Shenzhen profile must install only:

```text
10.68.72.0/21
10.20.81.0/24
```

It must not install or replace a default route. Optional database/Redis VIP
checks may add only these exact routes after explicit selection:

```text
10.68.64.30/32
10.68.64.31/32
```

Do not widen `10.68.64.0/…` merely to make a probe pass.

## Read-only probe matrix

All commands below are executed inside `kyclash-macos-lab-work` after the App
shows a healthy carrier and route ownership. Record exit status and redacted
timing only; do not record service banners or credentials.

1. Route ownership:
   - `/sbin/route -n get 10.68.79.203`
   - `/sbin/route -n get 10.20.81.101`
   - Both must select the exact KyClash utun. Neither may select the public
     default interface.
2. Shenzhen infrastructure reachability:
   - ICMP: `10.68.79.203`, `10.68.76.44`, `10.68.76.45`
   - TCP: `10.68.76.44:6443`, `10.68.76.42:5432`,
     `10.68.76.43:6379`
   - HTTP GET: `http://10.68.76.47:9000/minio/health/live`
3. IPMI/BMC reachability:
   - ICMP: `10.20.81.101` through `10.20.81.104`
   - TCP: ports `80`, `443`, and `623`, starting with `10.20.81.101` and
     expanding to `.102`–`.104` only after the first target passes.
4. Do not use `10.20.81.202` or `10.20.81.203` as first-pass acceptance
   targets; historical reachability there is not authoritative.

## Result classification

- `10.68.72.0/21` reachable through the KyClash utun: basic Shenzhen private
  networking passed.
- `10.20.81.101`–`.104` reachable through the same utun: the recognized
  Shenzhen ROS-Gateway/IPMI path passed.
- `10.68` passes but `10.20.81` fails: first verify that KyClash installed
  `10.20.81.0/24` on its owned utun and report a possible remote return/SNAT
  issue. Do not change ROS or widen routes.
- A public-default-path response, a host-only probe, or a probe before carrier
  health is not KyClash acceptance evidence.
