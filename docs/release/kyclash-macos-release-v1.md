# KyClash macOS Release Procedure v1

Status: Approved and locked; credentials and first release not authorized

Date: 2026-07-21

## Current release state

KyClash application updates are disabled. The repository contains no updater
endpoint, updater public key, or frontend updater permission. Local PKGs are
unsigned development artifacts. No artifact may be described as a KyClash
release until every required item below exists for the same commit and version.

## Required ownership

Before the first release, the operator must provide and explicitly authorize:

- a KyClash-controlled Apple Developer team and Developer ID Application and
  Installer identities;
- an App Store Connect notary API key restricted to the release workflow;
- a KyClash-controlled HTTPS download/update origin;
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
7. The exact final PKG is submitted to Apple, accepted, stapled, and validated.
8. SHA-256, SBOM, dependency inventory, and GitHub artifact attestation refer to
   the stapled PKG bytes that will be published.
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

- a KyClash HTTPS endpoint and pinned updater public key;
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

Before publication, retain one previously accepted, signed, notarized, stapled,
and installation-tested version for every supported architecture. Trigger a
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
- app/PKG signature identities, notarization submission result, and staple
  validation;
- artifact sizes and SHA-256 values, SBOMs, license inventory, and attestations;
- signed application/sidecar manifests and public keys used to verify them;
- release approval, rollout decisions, incident notes, and rollback evidence.

Signing, notarization, publication, updater activation, or external-host testing
requires explicit user authorization even though this procedure is locked.
