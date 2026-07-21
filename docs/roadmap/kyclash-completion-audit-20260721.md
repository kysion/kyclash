# KyClash completion audit — 2026-07-21

## Decision

All work permitted by the KyClash continuous-delivery authorization boundary is
complete. The locked architecture, isolated runtime proof, development UI,
credential boundary, release procedure, branding, documentation, CI, and
unsigned arm64 development PKG have passed their applicable source-level gates.

This is not a production-release declaration. The remaining gates require host
mutation, external infrastructure, or private signing credentials and therefore
need separate explicit authorization.

## Completed evidence

- The route transaction engine covers conflict refusal, rollback, restart
  recovery, idempotence, and fault injection without changing host routes.
- The Go sidecar implements authenticated bootstrap and IPC, WireGuard carrier
  adaptation, QUIC fragmentation/reassembly/replay protection, and authenticated
  WSS/TCP fallback boundaries.
- Entrypoint tests prove that rejected arguments, inherited environment state,
  malformed bootstrap input, and malformed IPC cannot enter process diagnostics;
  failure output is constant and attacker-controlled error chains are not
  formatted.
- An isolated userspace test proves WireGuard through fragmented QUIC in both
  directions without creating interfaces, routes, DNS changes, or external
  connections.
- The development-only macOS UI exposes lifecycle, health, routes, transport,
  errors, cancellation, and allowlisted diagnostic export through a mock command
  boundary. Production connect commands remain deliberately unavailable.
- The credential boundary uses fixed Keychain references and redacted,
  clear-on-drop secret material. Automated tests do not touch the host Keychain.
- The release workflow requires separate Application and Installer identities,
  notarization, stapling, validation, SBOM/provenance evidence, and rollback
  controls. Updater permissions remain disabled.
- The release pipeline cannot generate updater JSON or invoke updater publishing,
  the manual inherited updater workflow is absent, fixed-WebView2 overrides do
  not restore an inherited verification key, and a CI verifier locks these
  conditions together with both runtime update gates.
- Inherited scheduled/multi-platform publication and notification workflows are
  absent. The remaining release workflow is macOS arm64 only, defaults closed
  behind an explicit repository authorization variable and protected
  environment, and can create only a draft after all signing, notarization,
  stapling, Gatekeeper, checksum, and provenance checks succeed.
- Maintained README and issue intake surfaces identify KyClash, link only to the
  KyClash repository for releases and support, preserve explicit upstream
  attribution, and no longer advertise upstream packages, AutoBuild channels,
  funding, Telegram, or third-party promotions as KyClash resources.
- The current arm64 development PKG evidence is recorded in
  `docs/testing/kyclash-macos-arm64-pkg-20260721.md`. It is unsigned and must not
  be represented as a release artifact.
- The complete local gate passed on 2026-07-21: frontend typecheck/build/lint,
  localization and dead-code checks; 136 Rust library tests; two process-level
  sidecar tests; Clippy with all features and warnings denied; Go module
  verification, formatting, repeated race tests, and vet.
- The network-sidecar GitHub Actions run for security-hardening commit
  `eaf37d8d` completed successfully, superseding the four earlier successful
  runs through `f7cb07ad`.

## Authorization-dependent release gates

The following work is intentionally not executed under the current authority:

1. Mutate and restore real macOS routes on a disposable authorized host,
   including Mihomo coexistence, crash recovery, and conflict scenarios.
2. Test a reviewed compatible server endpoint under loss, jitter, UDP blocking,
   sustained load, suspend/resume, and network switching.
3. Integrate the production macOS utun and route adapters, then replace the mock
   command boundary only after the first two gates pass.
4. Exercise real Keychain create/read/delete and account lifecycle behavior on
   an authorized disposable account and host.
5. Import authorized Apple Developer Application and Installer identities plus
   App Store Connect notarization credentials, then produce and verify a signed,
   notarized, stapled PKG.
6. Run authorized fresh-install, upgrade, rollback, uninstall, forced-exit,
   service, system-proxy, TUN, and cleanup validation.
7. Provision a KyClash-owned update endpoint, public verification key, immutable
   artifacts, and rollback metadata before enabling the updater atomically.
8. Begin macOS x64 and later platforms only after the macOS arm64 MVP release
   gates above are closed.

## Resume rule

The project skill treats a request to continue through all stages as standing
authority for safe repository work. Future execution resumes automatically at
the first authorized item above; it does not require repeated “next step”
prompts. Credentials and real host or external-system mutations remain explicit
authorization boundaries.

## Authorization update — 2026-07-21

The user authorized continuation after this audit. The repository now contains
the feature-gated real route executor and fixed-scope lab harness documented in
`../testing/kyclash-macos-route-lab.md`. Read-only preflight rejected the current
development Mac as the mutation environment because it carries active split
routes and multiple tunnels and has no non-interactive elevation. Item 1 remains
open specifically for execution on a disposable macOS host; its source and
runbook preparation are complete.
