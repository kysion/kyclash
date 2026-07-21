# KyClash macOS arm64 PKG Evidence 2026-07-21

Status: Developer ID signed, Apple-notarized and stapled internal candidate

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

The current-source release build completed on Apple M5 after explicit signing
authorization; the Rust release build took 4 minutes 12 seconds. Existing
Application and Installer identities were used through the macOS Keychain
without exporting private material. Both signature layers pass their
cryptographic checks. The CI packaging path also passed with notarization
explicitly disabled, proving that signing remains mandatory while notarization
is optional. Gatekeeper correctly rejects both artifacts. This proves local
signing only, not general-distribution readiness.

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
