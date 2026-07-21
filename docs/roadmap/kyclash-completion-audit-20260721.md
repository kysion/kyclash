# KyClash completion audit — 2026-07-21

## Decision

All work permitted by the KyClash continuous-delivery authorization boundary is
complete. The locked architecture, isolated runtime proof, development UI,
credential boundary, release procedure, branding, documentation, CI, and
signed-but-unnotarized arm64 development PKG have passed their applicable
source-level gates.

This is not a production-release declaration. Continuation is authorized. Real
route and lifecycle gates still require disposable hosts, and impaired-network
validation requires a compatible isolated endpoint. Notarization is an optional
public-distribution enhancement rather than a current development blocker.

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
  optional notarization/stapling, SBOM/provenance evidence, and rollback
  controls. Updater permissions remain disabled pending the GitHub updater
  activation transaction.
- The release pipeline cannot generate updater JSON or invoke updater publishing,
  the manual inherited updater workflow is absent, fixed-WebView2 overrides do
  not restore an inherited verification key, and a CI verifier locks these
  conditions together with both runtime update gates.
- Inherited scheduled/multi-platform publication and notification workflows are
  absent. The remaining release workflow is macOS arm64 only, defaults closed
  behind an explicit repository authorization variable and protected
  environment, and can create only a draft after all signing, notarization,
  signature, checksum, and provenance checks succeed. Optional notarization and
  stapling evidence is required only when that enhancement is enabled.
- Maintained README and issue intake surfaces identify KyClash, link only to the
  KyClash repository for releases and support, preserve explicit upstream
  attribution, and no longer advertise upstream packages, AutoBuild channels,
  funding, Telegram, or third-party promotions as KyClash resources.
- The current arm64 development PKG evidence is recorded in
  `docs/testing/kyclash-macos-arm64-pkg-20260721.md`. Its Application and
  Installer signatures are valid, but it is unnotarized, unstapled, rejected by
  Gatekeeper, and must not be represented as a release artifact.
- GitHub Releases updater preparation is source-complete: its owned endpoint,
  inert build template, metadata schema/sample/validator, metadata builder,
  streaming signature verifier, rollback policy, and CI configuration names are
  documented in `../release/kyclash-github-updater-v1.md`. Runtime gates remain
  off and no Release has been created or endpoint activated.
- Dormant runtime update paths now validate the owned GitHub URL and strict
  KyClash metadata policy before download and cached-install refresh. Rejected
  metadata fails closed without being echoed into logs.
- The complete local gate passed on 2026-07-21: frontend typecheck/build/lint,
  localization and dead-code checks; 141 Rust all-feature library tests; two
  process-level sidecar tests; Clippy with all features and warnings denied; Go module
  verification, formatting, repeated race tests, and vet.
- The network-sidecar GitHub Actions run for security-hardening commit
  `eaf37d8d` completed successfully, superseding the four earlier sidecar CI
  runs. Later commits through `30ef92f1` did not change sidecar-scoped paths.

## Authorization-dependent release gates

The following work is intentionally not executed under the current authority:

1. Mutate and restore real macOS routes on a disposable authorized host,
   including Mihomo coexistence, crash recovery, and conflict scenarios.
2. Test a reviewed compatible server endpoint under loss, jitter, UDP blocking,
   sustained load, suspend/resume, and network switching.
3. Integrate the production macOS utun and route adapters, then replace the mock
   command boundary only after the first two gates pass.
4. Optionally exercise the manual destructive Keychain lifecycle test on a
   disposable account using only `net.kysion.kyclash.test`; this does not block
   other development.
5. Optionally notarize and staple a public-distribution candidate when the
   operator chooses to provide Apple notary credentials.
6. Run authorized fresh-install, upgrade, rollback, uninstall, forced-exit,
   service, system-proxy, TUN, and cleanup validation.
7. Provide the generated public verification key, signed immutable GitHub
   artifacts, retained rollback version, disposable-host lifecycle evidence,
   and separate authorization before atomic updater activation and publication.
8. Begin macOS x64 and later platforms only after the macOS arm64 MVP release
   gates above are closed.

## Current execution matrix

| Work item | Current state | Stops current source work? | Required external input |
| --- | --- | --- | --- |
| GitHub updater contract, templates, metadata and verification tools | Complete and default-off | No | None |
| GitHub updater activation and first metadata publication | Prepared, not authorized or enabled | Yes, for live updates only | Generated public key, protected private signing secret, retained rollback artifact, lifecycle evidence, and explicit publication/activation authorization |
| Developer ID internal arm64 PKG | Signed; unnotarized with Gatekeeper warning | No | None |
| Apple notarization and stapling | Optional enhancement | No | Notary credentials only if selected |
| Keychain destructive lifecycle | Manual/ignored and scoped to `net.kysion.kyclash.test` | No | Disposable macOS account when release evidence is desired |
| Real route mutation and crash recovery | Harness complete; execution pending | Yes, for production route adapter | Disposable macOS host with authorized elevation and recovery console |
| Impaired-network and sustained transport validation | Isolated POC complete; external matrix pending | Yes, for production data plane | Compatible isolated server and disposable client host |
| Install/upgrade/rollback/uninstall cleanup | Procedure prepared; execution pending | Yes, for general distribution | Disposable macOS lifecycle host and retained candidate/rollback artifacts |
| macOS x64 and later platforms | Deferred by locked platform order | Yes, for those platforms only | macOS arm64 MVP gates closed |

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

The authorized credential-lab source preparation is also complete. The
feature-gated fixed-service lifecycle harness and disposable-account procedure
are documented in `../testing/kyclash-macos-keychain-lab.md`. Its destructive
cycle remains manual because the available account is the daily-use development
account; this does not block updater or other source work.
