# KyClash network sidecar

This directory contains the isolated KyClash private-networking data plane. Its
locked implementation and security boundaries are documented in
`../docs/architecture/kyclash-network-runtime-v1.md`.

The sidecar is not yet bundled or enabled. Until its loopback, secret handling,
binary verification, and authorized macOS system tests pass, the application
continues to use only its feature-gated mock networking implementation.

## Verification

The sidecar uses Go 1.26.5. Its CI gate runs formatting, module verification,
race-enabled tests, `go vet`, two byte-for-byte reproducible builds, dependency
metadata extraction, and a license-aware CycloneDX SBOM. Dependencies are
pinned by `go.mod` and authenticated by `go.sum`; the generated binary, SHA-256,
dependency metadata, and SBOM are retained as CI evidence only and are not
published or bundled into KyClash yet.

The disposable Linux VM impaired-network matrix is documented in
[`lab/linux/README.md`](lab/linux/README.md). It covers the isolated network and
server-side subset only; macOS system lifecycle gates remain separate.

## Disposable macOS system-lab peer

`cmd/kyclash-networking-system-lab` and its `internal/systemlabpeer` package
are guest-only fixtures for the reviewed `networking-production-vm-lab`
candidate. They are standalone Go binaries, are not Tauri resources, and are
never used as the production sidecar. A run owns one userspace WireGuard
device, fixed numeric-loopback QUIC/WSS/TCP listeners, and dual-stack private
echo addresses. The peer publishes a strict redacted descriptor only after
all listeners are ready, persists its run-bound ports and identities in a
0600 manifest, and removes the descriptor on controller EOF, signal, or
parent re-parenting. The optional `--root-cert --leaf-cert --leaf-key` inputs
allow the disposable guest trust fixture to provide its exact short-lived
certificate chain; no production RootCAs or bootstrap API is changed.
