# KyClash Linux impaired-network lab

This lab covers the server/network portion that can be validated in an isolated
ARM64 Linux VM. It does not claim macOS PKG, Keychain, utun, route, sleep/wake,
or network-switch coverage.

## VM requirements

- Ubuntu Server ARM64 24.04 or newer in VMware Fusion, using NAT networking.
- 4 vCPU, 8 GiB RAM, and 30 GiB disk are sufficient for this lab.
- A disposable VM snapshot taken after installing Go 1.26.5, `iproute2`, and
  `nftables`.
- Run from the `network-sidecar` directory. No production endpoint or secret is
  needed; all certificates and ports are ephemeral and local to the test.

Install the operating-system tools:

```bash
sudo apt-get update
sudo apt-get install -y iproute2 nftables
```

Inspect the exact commands without mutation:

```bash
bash lab/linux/netem-lab.sh dry-run
```

Run inside the disposable VM:

```bash
mkdir -p build/linux-netem
sudo --preserve-env=PATH bash lab/linux/netem-lab.sh run \
  2>&1 | tee build/linux-netem/run.log
```

The harness is loopback-only by default. It applies one bounded `tc netem`
queue discipline and one isolated nftables table named `kyclash_lab`; an exit
trap removes both. A non-loopback interface is refused unless the operator sets
`KYCLASH_LAB_ALLOW_NON_LOOPBACK=YES` explicitly.

The same matrix runs on the repository's isolated Ubuntu ARM64 GitHub Actions
job. Its log and environment versions are retained for 14 days as CI evidence.

The matrix proves authenticated QUIC/WSS/TCP baseline exchange, records 20 QUIC
exchange outcomes under 40 ms ± 15 ms latency with 2% loss and 20 Mbit/s
shaping (requiring at least five successes), proves QUIC refusal
when UDP is blocked while authenticated WSS/TCP remain usable, and a sustained
10-second fragmented-QUIC benchmark. It does not yet prove the controller's
automatic fallback because the production sidecar command boundary remains
deliberately disabled pending macOS system gates.

## Loopback reliability soak

For a longer deterministic run, use the repository-owned in-process peers. This
does not require root and never touches routes, DNS, credentials, or external
endpoints:

```bash
KYCLASH_SOAK_ROUNDS=30 \
  KYCLASH_SOAK_OUTPUT=build/reliability-soak \
  bash lab/linux/reliability-soak.sh
```

Each round runs the authenticated carrier, userspace WireGuard, deterministic
impairment, replay/size-boundary, cancellation, and reconnect tests. The script
stops on the first failure and retains one log per round plus a summary. The
default of ten rounds is intentionally bounded for a disposable VM; increase
the round count only for an explicitly scheduled/manual soak. This evidence
does not close macOS sleep/wake, physical network switching, or a production
endpoint matrix.
