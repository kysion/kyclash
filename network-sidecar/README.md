# KyClash network sidecar

This directory contains the isolated KyClash private-networking data plane. Its
locked implementation and security boundaries are documented in
`../docs/architecture/kyclash-network-runtime-v1.md`.

The sidecar is not yet bundled or enabled. Until its loopback, secret handling,
binary verification, and authorized macOS system tests pass, the application
continues to use only its feature-gated mock networking implementation.
