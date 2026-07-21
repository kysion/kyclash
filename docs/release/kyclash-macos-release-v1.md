# KyClash macOS Release Procedure v1

Status: Approved and locked; amended by the GitHub updater/no-store review

Date: 2026-07-21

## Current release state

KyClash application updates are disabled. The repository contains no updater
endpoint, updater public key, or frontend updater permission. The latest local
arm64 PKG has valid Developer ID Application and Installer signatures, but it
is not notarized or stapled and Gatekeeper rejects it. It remains a development
artifact. No artifact may be described as a KyClash release until every
required item below exists for the same commit and version.

KyClash does not target the Mac App Store. Notarization and stapling are
recommended public-distribution hardening, not a blocker for signed internal
test packages or preparation of the GitHub Releases updater path. Every
unnotarized package must retain an explicit Gatekeeper warning.

For the planned direct GitHub distribution, the operator selected notarization
and stapling so users do not need the Privacy & Security override. This choice
does not create an App Store listing or enter App Review. Local notarization may
use a validated `notarytool` Keychain profile through
`APPLE_NOTARY_KEYCHAIN_PROFILE`; CI continues to use its protected App Store
Connect API-key secrets. Exactly one credential mode is permitted. Apple ID
mode requires an app-specific password entered at `notarytool`'s secure prompt,
never the ordinary Apple Account password and never a repository variable.

## Required ownership

Before the first release, the operator must provide and explicitly authorize:

- a KyClash-controlled Apple Developer team and Developer ID Application and
  Installer identities;
- the KyClash-controlled `kysion/kyclash` GitHub Releases origin;
- an offline-held updater signing private key and repository-pinned public key;
- protected GitHub environments with reviewer approval for release secrets;
- immutable retention for the current and immediately previous installers,
  manifests, signatures, checksums, SBOMs, and provenance attestations.

The project must never reuse Clash Verge Rev endpoints, updater keys, Apple
identities, or release artifacts.

## Release candidate gates

For one immutable Git commit and version:

1. The working tree is clean and the commit is on `origin/main`.
2. Frontend, Rust, Go sidecar, format, lint, i18n, Knip, race, vet, and Clippy
   gates pass without exclusions added for the release.
3. Dependency locks, license-aware SBOMs, and vulnerability results are stored.
4. macOS arm64 and x64 app binaries and bundled sidecars are built from pinned
   inputs; architecture and bundle identifiers are verified.
5. Nested executables and the `.app` are signed with the authorized Application
   identity and strict `codesign` verification passes.
6. The final PKG is signed with the authorized Installer identity and
   `pkgutil --check-signature` reports the expected KyClash team.
7. When notarization is enabled for public distribution, the exact final PKG is
   submitted to Apple, accepted, stapled, and validated. Internal test packages
   may omit this optional enhancement only when clearly labelled unnotarized.
8. SHA-256, SBOM, dependency inventory, and GitHub artifact attestation refer to
   the exact PKG bytes selected for the authorized release.
9. Fresh install, authorized upgrade, uninstall, sleep/wake, network switch,
   forced-exit cleanup, Mihomo TUN coexistence, and rollback tests pass on
   disposable hosts.
10. A human release approver verifies visible KyClash branding, upstream
    attribution, release notes, known limitations, and the rollback target.

Any failed or missing gate stops publication. A local ad-hoc or unsigned result
cannot be promoted by renaming or manually uploading it.

## Updater enablement transaction

Updater support may be reintroduced only as one reviewed commit containing all
of the following:

- the KyClash GitHub Releases `latest.json` endpoint and pinned updater public key;
- frontend/backend capabilities limited to check, authenticated download, and
  verified install operations actually used by the UI;
- a signed manifest schema with version, platform/architecture, minimum
  supported version, immutable artifact URL, SHA-256, size, signature,
  publication time, rollout cohort, and rollback version;
- fail-closed tests for unknown algorithms/keys/schema, replayed or expired
  manifests, downgrade outside rollback mode, hash/signature mismatch, wrong
  architecture, unavailable rollback artifact, and interrupted install;
- an explicit user-visible update and recovery flow;
- a staged rollout starting with internal hosts and an operator kill switch.

The application and network sidecar use separate manifests, keys, rollout
controls, and compatibility ranges. Neither component may update the other
implicitly.

## Rollback policy

Before publication, retain one previously accepted, signed and
installation-tested version for every supported architecture. Record whether
each retained package is notarized and stapled. Trigger a
rollout halt and rollback review on any of these signals:

- signature, notarization, checksum, or provenance verification failure;
- install/launch failure above the approved threshold;
- route, DNS, system proxy, service, or tunnel state not restored after failure;
- credential exposure, crash loop, or remotely exploitable security issue;
- loss of private-network access without successful fallback;
- incompatible configuration migration without a verified reverse migration.

Rollback is an explicitly signed manifest pointing to the retained immutable
artifact. It is not an unsigned version downgrade. Configuration migrations
must be previewed, backed up, versioned, reversible, and restored before the old
binary is relaunched. If safe reversal is not proven, the update remains
disabled and recovery is manual from documented backups.

## Evidence retained per release

- commit, tag, source archive, toolchain versions, and dependency locks;
- complete gate logs and authorized-host lifecycle matrix;
- app/PKG signature identities and, when used, notarization submission and
  staple validation;
- artifact sizes and SHA-256 values, SBOMs, license inventory, and attestations;
- signed application/sidecar manifests and public keys used to verify them;
- release approval, rollout decisions, incident notes, and rollback evidence.

Signing, publication, updater activation, or external-host testing requires
explicit user authorization even though this procedure is locked. Notarization
is optional public-distribution hardening and requires credentials when chosen.
It has now been selected for the direct GitHub distribution candidate, while
remaining non-blocking for clearly labelled internal test packages.
