<h1 align="center">
  <img src="../src-tauri/icons/icon.png" alt="KyClash" width="128" />
  <br>
  KyClash
  <br>
</h1>

<h3 align="center">
A cross-platform proxy and private-network client derived from Clash Verge Rev.
</h3>

> [!IMPORTANT]
> **Upstream and derivative-work notice:** KyClash is developed by Kysion as a
> derivative of [Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev),
> which itself continues [Clash Verge](https://github.com/zzzgydi/clash-verge).
> KyClash is not an official release of either upstream project.

> **Compatibility identifiers:** The source currently retains names such as
> `clash-verge.exe`, `clash-verge-service`, selected Rust crate names, IPC
> identifiers, and legacy Windows cleanup keys. Renaming them prematurely could
> break installation, elevation, IPC, migration, or uninstall behavior. These
> internal identifiers do not connect KyClash to upstream release channels.
> The visible product, packages, bundle identifier, and release links belong to
> KyClash. Upstream attribution is retained under GPL-3.0-only.

Repository: [kysion/kyclash](https://github.com/kysion/kyclash)

<p align="center">
  Languages:
  <a href="../README.md">简体中文</a> ·
  <a href="./README_en.md">English</a>
</p>

## Preview

| Dark                                | Light                                 |
| ----------------------------------- | ------------------------------------- |
| ![Dark Preview](./preview_dark.png) | ![Light Preview](./preview_light.png) |

## Release status

KyClash does not yet have an official public release for end users. The current
repository can build a macOS arm64 PKG. The latest local evidence has valid
Developer ID Application and Installer signatures, but it is not notarized or
stapled and Gatekeeper rejects it. It remains a development artifact, not a
trusted release package. Application updates are disabled and do not use Clash
Verge Rev endpoints or signing keys.

The first public release must pass KyClash-owned application and installer
signing, installation lifecycle, rollback, and GitHub Releases ownership
review. Notarization and stapling are recommended public-distribution hardening
and must pass their checks whenever enabled. Once those gates close, packages will be published only through
[KyClash Releases](https://github.com/kysion/kyclash/releases) with checksums and
release evidence.

The locked platform order is macOS arm64, macOS x64, Windows x64, Windows arm64,
then Linux. This is an implementation plan, not a claim of current support.

Upstream documentation may be useful for retained proxy functionality, but
upstream downloads, update channels, and support promises do not apply to
KyClash.

## Features

- Rust and Tauri 2 desktop foundation
- Embedded [mihomo](https://github.com/MetaCubeX/mihomo) proxy core
- Theme, proxy-group, tray-icon, and CSS customization
- Profile management, Merge and Script enhancement, and syntax assistance
- System proxy, guard, and TUN controls inherited from the desktop baseline
- Visual node and rule editors
- WebDAV configuration backup and synchronization
- In-development KyClash private networking with WireGuard over QUIC and
  WSS/TCP fallback behind explicit safety gates

## Support

KyClash-specific documentation is still being prepared. Search or report issues
in [KyClash Issues](https://github.com/kysion/kyclash/issues). Do not install an
upstream package as though it were a KyClash build.

## Development

See [CONTRIBUTING.md](../CONTRIBUTING.md). After installing the Tauri
prerequisites:

```shell
pnpm install --frozen-lockfile
pnpm run prebuild
pnpm dev
```

## Acknowledgements

- [Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev): direct
  upstream of KyClash
- [Clash Verge](https://github.com/zzzgydi/clash-verge): upstream desktop client
- [Tauri](https://github.com/tauri-apps/tauri): desktop application framework
- [mihomo](https://github.com/MetaCubeX/mihomo): embedded proxy core
- [WireGuard](https://www.wireguard.com/): private-network tunnel protocol
- [Vite](https://github.com/vitejs/vite): frontend build tooling

## License

GPL-3.0-only. See the [license file](../LICENSE).
