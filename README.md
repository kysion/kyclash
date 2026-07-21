<h1 align="center">
  <img src="./src-tauri/icons/icon.png" alt="KyClash" width="128" />
  <br>
  KyClash
  <br>
</h1>

<h3 align="center">
基于 Clash Verge Rev 二次开发的跨平台代理与私有网络客户端。
</h3>

> [!IMPORTANT]
> **上游与二次开发说明：** KyClash 由 Kysion 团队基于
> [Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev)
> 进行二次开发；Clash Verge Rev 又延续自
> [Clash Verge](https://github.com/zzzgydi/clash-verge)。KyClash 并非上述上游项目的官方发行版。

> **兼容标识说明：** 为避免破坏既有安装、提权服务、IPC 和卸载迁移，源码中暂时保留
> `clash-verge.exe`、`clash-verge-service`、相关 Rust crate 名，以及 Windows 安装器清理旧
> `Clash Verge Rev` 注册表键的逻辑。这些内部或迁移标识不代表 KyClash 使用上游发布渠道；
> 用户可见产品名、安装包和发布链接均为 KyClash。
> 本项目继续遵循 GPL-3.0-only 许可证，并保留上游作者及依赖项目的署名。

项目仓库：[kysion/kyclash](https://github.com/kysion/kyclash)

<p align="center">
  Languages:
  <a href="./README.md">简体中文</a> ·
  <a href="./docs/README_en.md">English</a>
</p>

## Preview

| Dark                             | Light                             |
| -------------------------------- | --------------------------------- |
| ![预览](./docs/preview_dark.png) | ![预览](./docs/preview_light.png) |

## Release status

KyClash 尚未发布可供普通用户安装的正式版本。当前仓库能够构建 macOS arm64
PKG；最新本地证据已通过 Developer ID Application 与 Installer 签名，但尚未公证、
未 stapling，Gatekeeper 会拒绝，因此仍只能作为开发验证，不能视为可信发行包。
应用自动更新也保持禁用，不会使用 Clash Verge Rev 的更新源或密钥。

首个公开版本必须通过 KyClash 自有签名、公证、安装生命周期、回滚和更新源审阅。
发布后，安装包只会出现在
[KyClash Releases](https://github.com/kysion/kyclash/releases)，并附带校验和与发布证据。

当前平台实施顺序为 macOS arm64、macOS x64、Windows x64、Windows arm64，
再到 Linux；这表示开发计划，不表示这些平台已经发布。

上游 Clash Verge Rev 的使用文档可作为现有代理功能的参考，但其下载包、发布频道、
更新源和支持范围不代表 KyClash。

## Features

- 基于性能强劲的 Rust 和 Tauri 2 框架
- 内置[Clash.Meta(mihomo)](https://github.com/MetaCubeX/mihomo)内核，并支持切换 `Alpha` 版本内核。
- 简洁美观的用户界面，支持自定义主题颜色、代理组/托盘图标以及 `CSS Injection`。
- 配置文件管理和增强（Merge 和 Script），配置文件语法提示。
- 系统代理和守卫、`TUN(虚拟网卡)` 模式。
- 可视化节点和规则编辑
- WebDav 配置备份和同步

### FAQ

KyClash 专属文档仍在整理中。现阶段请在
[KyClash Issues](https://github.com/kysion/kyclash/issues) 检索或反馈问题；上游文档仅可作为
保留代理功能的参考，不能作为 KyClash 发布与支持承诺。

## Development

See [CONTRIBUTING.md](./CONTRIBUTING.md) for more details.

To run the development server, execute the following commands after all prerequisites for **Tauri** are installed:

```shell
pnpm i
pnpm run prebuild
pnpm dev
```

## Contributions

Issue and PR welcome!

## Acknowledgement

KyClash is directly derived from Clash Verge Rev and also retains the upstream
project acknowledgements:

- [clash-verge-rev/clash-verge-rev](https://github.com/clash-verge-rev/clash-verge-rev): KyClash 的直接上游项目。

- [zzzgydi/clash-verge](https://github.com/zzzgydi/clash-verge): A Clash GUI based on tauri. Supports Windows, macOS and Linux.
- [tauri-apps/tauri](https://github.com/tauri-apps/tauri): Build smaller, faster, and more secure desktop applications with a web frontend.
- [Dreamacro/clash](https://github.com/Dreamacro/clash): A rule-based tunnel in Go.
- [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo): A rule-based tunnel in Go.
- [Fndroid/clash_for_windows_pkg](https://github.com/Fndroid/clash_for_windows_pkg): A Windows/macOS GUI based on Clash.
- [vitejs/vite](https://github.com/vitejs/vite): Next generation frontend tooling. It's fast!

## License

GPL-3.0 License. See [License here](./LICENSE) for details.
