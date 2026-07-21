# KyClash GitHub Releases updater v1

Status: source preparation complete; production activation and publication disabled

Decision record: `../roadmap/kyclash-github-updater-review-20260721.md`

## Ownership and endpoint

The only approved application update origin is the KyClash repository:

`https://github.com/kysion/kyclash/releases/latest/download/latest.json`

The base Tauri configuration deliberately has no updater endpoint or public key,
creates no updater artifacts, grants no updater capability, and keeps both
frontend and backend runtime gates off. The committed build and least-privilege
macOS capability templates are inert. The build template becomes a temporary
override only after `KYCLASH_UPDATER_PUBLIC_KEY` is supplied to
`pnpm updater:prepare-config`; generated configuration stays under `target/`.
The capability template is copied into the application only during the future
atomic activation change.

This preparation does not enable updates and does not publish a GitHub Release.
Activation requires a separately reviewed and explicitly authorized commit.

## Artifact and metadata contract

The first allowed target is `darwin-aarch64-app`. Its updater artifact name is:

`KyClash_<version>_aarch64.app.tar.gz`

`latest.json` follows Tauri's static platform format and adds a `kyclash`
extension containing schema version, full source commit, rollback version,
channel, and a sample marker. Each platform record adds SHA-256 and byte size to
Tauri's required URL and signature. Tauri ignores the extension while retaining
the raw JSON for KyClash policy checks.

The schema is `kyclash-updater-metadata.schema.json`; the non-publishable sample
is `examples/latest.json`. `pnpm updater:metadata-sample-check` validates the
sample. Release validation omits `--sample` and additionally requires:

- `sample=false`;
- non-placeholder commit and SHA-256;
- `KYCLASH_RELEASE_VERSION` matching `version`;
- `KYCLASH_RELEASE_COMMIT` matching `source_commit`;
- only HTTPS assets owned by `kysion/kyclash`;
- the locked macOS arm64 platform and canonical asset filename.

`pnpm updater:build-metadata` assembles metadata from an existing updater
artifact and `.sig`, computes SHA-256 and size, and writes only below `target/`.
It does not sign or upload anything.

## Signature boundary

The Tauri private updater key is never stored in this repository. Tauri's signer
produces the updater artifact `.sig`; `kyclash-updater-verify` independently
streams the exact artifact through `minisign-verify` with the public key before
metadata is accepted:

```bash
pnpm updater:verify-signature -- \
  target/path/KyClash_2.5.4_aarch64.app.tar.gz \
  target/path/KyClash_2.5.4_aarch64.app.tar.gz.sig \
  target/credentials/kyclash-updater.pub
```

The signature embedded in `latest.json` is the base64 encoding of the complete
`.sig` file, matching Tauri updater v2. HTTPS, SHA-256, and GitHub artifact
attestation are defense in depth; none replaces this signature verification.

The dormant Rust updater also validates the complete KyClash extension before
download and again before installing cached bytes. It rejects unknown fields,
sample metadata, unknown schema/channel, non-KyClash URLs, mismatched announced
version/URL/signature, invalid commit or SHA-256 shapes, zero sizes, additional
platforms, and rollback versions that are not older than the candidate. Error
logging is constant and does not echo rejected metadata.

Because the existing silent updater caches verified bytes for installation on a
later launch, the cached artifact is verified a second time immediately before
installation using the pinned config public key and the freshly fetched owned
metadata signature. A missing key, malformed base64, altered cache, or signature
mismatch deletes the cache and fails closed.

## CI configuration names

Repository/environment variables (not secrets):

- `KYCLASH_MACOS_RELEASE_ENABLED`: permits the already protected draft build;
- `KYCLASH_UPDATER_ACTIVATION_ENABLED`: future atomic updater activation gate;
- `KYCLASH_NOTARIZATION_ENABLED`: optionally enables notarization/stapling;
- `KYCLASH_UPDATER_PUBLIC_KEY`: public minisign key used to build the override;
- `KYCLASH_ROLLBACK_VERSION`: retained installation-tested rollback version;
- `KYCLASH_UPDATE_CHANNEL`: `internal`, `candidate`, or `stable`.

Protected environment secrets, required only by the corresponding operation:

- `APPLE_CERTIFICATE`
- `APPLE_CERTIFICATE_PASSWORD`
- `APPLE_SIGNING_IDENTITY`
- `APPLE_INSTALLER_SIGNING_IDENTITY`
- `APPLE_TEAM_ID`
- `TAURI_SIGNING_PRIVATE_KEY`
- `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`
- optional `APPLE_NOTARY_KEY_BASE64`
- optional `APPLE_NOTARY_KEY_ID`
- optional `APPLE_NOTARY_ISSUER`

The standard GitHub-provided token is sufficient for an authorized workflow to
create its draft Release; no personal access token is part of this design.
Private keys and passwords must never be printed, committed, included in
metadata, passed as command arguments, or retained as workflow artifacts.

## Rollback and activation gates

Before updater activation:

1. Retain a previous signed, installation-tested GitHub Release asset and its
   metadata for the same architecture.
2. Verify the candidate artifact signature, SHA-256, size, source commit, version,
   architecture, and bundle identity.
3. Test fresh install, update, interrupted update, failed signature, failed hash,
   unavailable asset, downgrade refusal, and explicit rollback on disposable hosts.
4. Enable the endpoint, pinned public key, Tauri permissions, frontend/backend
   gates, signed artifact generation, metadata publication, and rollback policy
   in one reviewed change.
5. Start with `internal`, require an operator decision for `candidate` and
   `stable`, and preserve `KYCLASH_MACOS_RELEASE_ENABLED` plus the protected
   release environment. No workflow in the current repository activates this.

Notarization/stapling may be added to a public candidate by setting the optional
gate and credentials. Its absence must remain visible in release notes and
Gatekeeper guidance, but it does not prevent internal signed-package testing or
updater source preparation.
