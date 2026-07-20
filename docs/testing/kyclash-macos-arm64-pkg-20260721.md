# KyClash macOS arm64 PKG Evidence 2026-07-21

Status: Local unsigned development artifact

Source commit: `f7cb07ad`

Artifact:

```text
target/aarch64-apple-darwin/release/bundle/pkg/KyClash_2.5.3_aarch64.pkg
```

Verification result:

- `CFBundleName`: `KyClash`
- `CFBundleDisplayName`: `KyClash`
- `CFBundleIdentifier`: `net.kysion.kyclash`
- main executable: Mach-O 64-bit arm64
- package size: 61,388,300 bytes
- SHA-256: `d7ff858e0ed8d184e473e159678c309a21bc9d4ff8ca5300f9342c602f0bb1d9`
- `pkgutil --check-signature`: `Status: no signature`

Build commands:

```bash
corepack pnpm tauri build --target aarch64-apple-darwin
corepack pnpm macos:pkg aarch64-apple-darwin
```

The release build completed in 5 minutes 48 seconds on Apple M5. The resulting
app contains a linker ad-hoc signature only; strict bundle verification and the
installer signature gate correctly do not pass. This artifact demonstrates
current-source packaging, not release readiness.

On macOS 26, `pkgbuild --component` exposes protected
`com.apple.provenance` extended attributes as AppleDouble entries in
`pkgutil --payload-files`. A clean temporary copy, `ditto --noextattr`,
`xattr -cr`, and `COPYFILE_DISABLE=1` were each checked and did not remove the
system-protected provenance representation. It is not a source-tree `._*` file.

No installation, system service change, credential access, signing,
notarization, stapling, upload, or release action was performed.
