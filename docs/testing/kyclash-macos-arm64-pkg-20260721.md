# KyClash macOS arm64 PKG Evidence 2026-07-21

Status: Locally signed, unnotarized development artifact

Source commit: `7ae8d4a3`

Artifact:

```text
target/aarch64-apple-darwin/release/bundle/pkg/KyClash_2.5.3_aarch64.pkg
```

Verification result:

- `CFBundleName`: `KyClash`
- `CFBundleDisplayName`: `KyClash`
- `CFBundleIdentifier`: `net.kysion.kyclash`
- main executable: Mach-O 64-bit arm64
- package size: 60,702,393 bytes
- SHA-256: `019bf5f38f36aae6bb08eaa64631e8a3eb36a1e359ec586972e4cbb2e0710f63`
- App signature: valid Developer ID Application signature with hardened runtime
- Installer signature: valid Developer ID Installer signature with trusted
  timestamp
- `codesign --verify --deep --strict`: passed
- `pkgutil --check-signature`: signed by an Apple-issued developer certificate
- App and PKG Gatekeeper assessment: rejected as `Unnotarized Developer ID`
- `xcrun stapler validate`: no stapled ticket, as expected

Build commands:

```bash
APPLE_SIGNING_IDENTITY='Developer ID Application: …' \
  corepack pnpm tauri build --target aarch64-apple-darwin --bundles app
APPLE_INSTALLER_SIGNING_IDENTITY='Developer ID Installer: …' \
  corepack pnpm macos:pkg aarch64-apple-darwin
```

The current-source release build completed on Apple M5 after explicit signing
authorization. Existing Application and Installer identities were used through
the macOS Keychain without exporting private material. Both signature layers
pass their cryptographic checks. Notarization was not selected for this internal
test artifact, so Gatekeeper correctly rejects both artifacts. This proves local
signing only, not general-distribution readiness.

On macOS 26, `pkgbuild --component` exposes protected
`com.apple.provenance` extended attributes as AppleDouble entries in
`pkgutil --payload-files`. A clean temporary copy, `ditto --noextattr`,
`xattr -cr`, and `COPYFILE_DISABLE=1` were each checked and did not remove the
system-protected provenance representation. It is not a source-tree `._*` file.

No installation, system service change, notarization, stapling, upload, or
release action was performed. The only credential operation was the explicitly
authorized use of existing Application and Installer signing identities; no
certificate or private key was exported.
