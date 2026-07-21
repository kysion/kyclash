# KyClash GitHub updater and no-store distribution review

Status: Approved and locked

Date: 2026-07-21

Supersedes only the notarization and updater-origin portions of:

- `kyclash-plan-review-20260721.md`
- `kyclash-implementation-plan.md`
- `../release/kyclash-macos-release-v1.md`

All networking, route ownership, transport, secret-storage, platform-order,
and single-site decisions remain unchanged.

## Distribution decision

KyClash does not target the Mac App Store. KyClash-owned GitHub Releases in
`kysion/kyclash` are the distribution origin for application installers and
Tauri updater metadata.

Developer ID Application and Installer signatures remain required for a
KyClash-distributed macOS package. Apple notarization and stapling are strongly
recommended public-distribution hardening, but they are not a stop condition
for internal no-store testing or preparation of the GitHub-owned update path.
An unnotarized package must be labelled clearly and must document that
Gatekeeper rejects normal launch or installation until the operator applies an
approved internal-test procedure.

## Updater ownership decision

The canonical stable metadata URL is:

`https://github.com/kysion/kyclash/releases/latest/download/latest.json`

The updater remains disabled in ordinary builds until one reviewed activation
change contains all of the following:

1. A KyClash-generated Tauri updater public key pinned in build configuration.
2. Signed updater artifacts and `latest.json` generated for the same immutable
   commit, version, platform, and architecture.
3. CI checks for repository ownership, HTTPS asset URLs, version consistency,
   artifact size and SHA-256, non-empty Tauri signature, and rollback metadata.
4. A protected release environment and explicit repository authorization
   variable. Private signing material is supplied only through CI secrets.
5. A tested staged rollout and rollback target. The first activation remains a
   separate user-authorized action and must not publish a GitHub Release as a
   side effect of repository preparation.

No Clash Verge Rev endpoint, key, manifest, artifact, or release channel may be
accepted. GitHub's HTTPS transport and artifact checksum are defense in depth;
the Tauri updater signature is the mandatory application authenticity check.

## Keychain validation decision

Automated tests continue to use the in-memory credential adapter. Destructive
macOS Keychain create/read/update/delete validation is a manual ignored test
using only the dedicated service `net.kysion.kyclash.test` and a fixed synthetic
account. A disposable account prevents a failed or mistaken lifecycle run from
polluting or deleting real login-Keychain entries.

Lack of a disposable account does not block other source development, updater
preparation, packaging, or non-destructive credential-boundary tests.

## Authorization boundary

This review authorizes source, test, documentation, local build, and inert CI
preparation. It does not authorize publishing a GitHub Release, enabling the
production updater endpoint, storing a private key in the repository, mutating
external infrastructure, or running destructive host tests.
