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
