# KyClash macOS arm64 PKG Evidence 2026-07-21

Status: historical Developer ID signed, Apple-notarized and stapled internal
candidate; notarization is optional for current GitHub/no-App-Store
distribution.

Source commit: `30ef92f1`

Artifact:

```text
target/aarch64-apple-darwin/release/bundle/pkg/KyClash_2.5.3_aarch64.pkg
```

Verification result:

- `CFBundleName`: `KyClash`
- `CFBundleDisplayName`: `KyClash`
- `CFBundleIdentifier`: `net.kysion.kyclash`
- main executable: Mach-O 64-bit arm64
- package size: 60,709,550 bytes
- Pre-staple SHA-256:
  `d98d082ca344ac7ff13a3e4c0cc5d6f2429675e7a46a9bf304cce4dc91c22aa3`
- Final stapled SHA-256:
  `760cd22bb2fcaf1062417d88cb2fa4e0989176e6f873bece5bada01f008ad38e`
- App signature: valid Developer ID Application signature with hardened runtime
- Installer signature: valid Developer ID Installer signature with trusted
  timestamp
- `codesign --verify --deep --strict`: passed
- `pkgutil --check-signature`: signed by an Apple-issued developer certificate
- Apple submission: `e568f45f-5b55-4dac-b068-89096d9949c1`, `Accepted`
- Notary log: `Ready for distribution`, no issues
- `xcrun stapler validate`: passed
- App and PKG Gatekeeper assessment: accepted as `Notarized Developer ID`

Build commands:

```bash
APPLE_SIGNING_IDENTITY='Developer ID Application: …' \
  corepack pnpm tauri build --target aarch64-apple-darwin --bundles app
APPLE_INSTALLER_SIGNING_IDENTITY='Developer ID Installer: …' \
  CI=true KYCLASH_NOTARIZATION_ENABLED=false \
  corepack pnpm macos:pkg aarch64-apple-darwin
```

The historical release build completed on Apple M5 after explicit signing
authorization; the Rust release build took 4 minutes 12 seconds. Existing
Application and Installer identities were used through the macOS Keychain
without exporting private material. Both signature layers pass their
cryptographic checks. The CI packaging path also passed with notarization
explicitly disabled, proving that signing remains mandatory while notarization
is optional. An unsigned/non-notarized internal build is expected to trigger a
Gatekeeper warning or quarantine handling; notarized evidence applies only to
the exact historical bytes identified above. This proves the signing/package
path, not general-distribution readiness for later bytes.

On macOS 26, `pkgbuild --component` exposes protected
`com.apple.provenance` extended attributes as AppleDouble entries in
`pkgutil --payload-files`. A clean temporary copy, `ditto --noextattr`,
`xattr -cr`, and `COPYFILE_DISABLE=1` were each checked and did not remove the
system-protected provenance representation. It is not a source-tree `._*` file.

Later on 2026-07-21, this package passed fresh installation and signature checks
in the disposable Virtualization.framework guest. After the operator selected
notarization for direct GitHub distribution, the signed PKG was submitted with
a local Keychain profile, accepted without issues, stapled, re-hashed, copied
back to the guest, and accepted there by Gatekeeper. Reinstalling the stapled
package over the internal build succeeded. No certificate, private key,
Apple-account password, or app-specific password was exported or stored in the
repository. No App Store record or GitHub Release was created.

## Current internal candidate after installed-resource permission fix

The historical notarized/stapled bytes above remain immutable evidence. A new
Developer ID-signed internal candidate was rebuilt from the source containing
commit `8bd179d1`; it was intentionally not submitted for notarization. Its
SHA-256 is
`b06d0c64bce8b50459875bf905ade2a244d17537f8a22e34ca270b008ed434f1`.

The first upgrade attempt exposed that the public sidecar trust manifest was
packaged as `root:wheel 0600`, which prevented a non-admin user from reading a
sealed application resource. The producer now enforces `0644` after writing
the manifest, including when an existing file previously had a restrictive
mode, and `scripts/verify-macos-package.mjs` rejects any package candidate that
does not contain exactly that mode.

The corrected candidate passed host package verification, upgrade installation
in the disposable Virtualization.framework guest, non-admin deep strict app
signature verification, exact trust-manifest/sidecar hash matching, nested
Team ID verification, and installed-app LaunchServices smoke from
`/Applications/KyClash.app`. No App Store record, GitHub Release, updater
activation, or production-network mutation occurred.

The historical notarized package was subsequently used as a rollback probe.
Although its installer transaction succeeded, the older app did not remain
running or restore the singleton listener and it predates the production
sidecar trust resource. It is therefore retained only as negative compatibility
evidence, not as an accepted rollback artifact. Reinstalling the corrected
current candidate restored non-admin deep signature verification and the live
installed application. A compatible retained rollback artifact remains an
open lifecycle requirement.

## Latest source candidate after `be3c9f39` — 2026-07-22

The current source commit `be3c9f39` was rebuilt with the authorized local
Developer ID identities after the production-networking and route-helper
changes were pushed. This is an internal GitHub/no-App-Store candidate; it is
Developer ID signed but intentionally not notarized or stapled.

Artifacts and hashes:

- App executable (`Contents/MacOS/clash-verge`):
  `adc83faefbac6a16a16bb64af15b8071db54907157b1e42578351c88ce74a40d`
- Nested network sidecar:
  `51a219f3481fdc3698a03768761f0557e2db3672c222b95746f370a7edadee6d`
- Nested route helper:
  `06aaa494e30d3bda31fc5b0c6fd33c90776c96d2e83e1b524b93386bc784c87e`
- PKG (`68512053` bytes):
  `0a95bb3933eb19625e555a9005b852a4c6511d4dd7d6aee1b67fa0dae0c17fb4`

`scripts/verify-macos-package.mjs aarch64-apple-darwin` passed for this exact
candidate: deep strict app signature, nested sidecar/helper signatures and
Team ID `RQUQ8Y3S9H`, trust-manifest hash, plist, and Developer ID Installer
signature with a trusted timestamp. Host LaunchServices then started the same
bundle with a visible `KyClash` window; the Mihomo control socket returned
`v1.19.29`. Gatekeeper/notarization remains a public-distribution enhancement,
not a current no-Store/GitHub internal-test stop condition.
