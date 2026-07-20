# KyClash Project Handoff - 2026-07-21

## 背景

用户希望基于 Clash Verge Rev 二次开发一个自有客户端，最终方向是 KyClash。

前期已确定的产品方向：
- 基于 Clash Verge Rev，而不是从零开发。
- 目标是做一个带 UI 的代理/组网客户端。
- 远期能力需要围绕 WireGuard 三层隧道、QUIC 主通道、WSS/TCP 备用通道做二次开发适配。
- 尽量减少普通用户额外安装第三方软件的成本。
- 当前阶段先完成项目落地、品牌重命名、macOS 构建验证和源码迁移。

## 组网二开目的背景

KyClash 不是单纯把 Clash Verge Rev 改名打包。更核心的目标是沉淀一个自有的跨端网络接入客户端，用来统一承载代理、私有组网、内网访问和跨区域出口调度。

用户前期讨论过的典型诉求：
- 希望本地 Mac、Windows、移动端等客户端能稳定访问私有网段，例如深圳、日本等 PVE/ROS/K3s 后面的业务网段。
- 希望在不频繁手工配置系统路由、不强依赖单独安装 WireGuard 客户端的情况下，通过一个带 UI 的客户端完成接入。
- 希望深圳和日本等多地 ROS/PVE 之间可以有更稳定的海外出口链路，主链路优先走 QUIC，异常时可降级到 WSS/TCP 或现有通道。
- 希望最终方案兼顾稳定、可观测、可灰度、可回滚，并能给普通用户提供尽量简单的配置入口。

当前技术方向的理解：
- WireGuard 三层隧道负责真正的私有网段互通和路由承载。
- QUIC 作为优先传输通道，用于改善跨区域链路的稳定性、抗抖动能力和连接恢复能力。
- WSS/TCP 作为备用通道，用于在 QUIC 不可用、UDP 受限或网络策略不稳定时兜底。
- Clash/mihomo 体系继续负责代理规则、订阅、策略组、DNS 分流、系统代理/TUN 等成熟能力。
- KyClash 的二开重点应放在 UI、配置模型、连接状态、路由下发、通道编排、健康检查、故障切换和日志诊断上，而不是重写底层代理核心。

为什么选择 Clash Verge Rev 作为基线：
- 已有成熟桌面 UI、系统托盘、配置管理、订阅管理、内核管理、TUN、DNS、规则模式等能力。
- Tauri 架构适合在 Rust 侧扩展本地服务、sidecar、系统权限、文件和网络控制能力。
- 前端可以相对低成本增加“组网/远程访问”页面、状态面板、节点健康检查和一键诊断。
- 比从零开发客户端更快，也更容易保留成熟代理客户端用户习惯。

阶段边界：
- 当前已经完成的是项目落地、品牌重命名、macOS arm64 构建验证和源码迁移。
- 当前还没有实现 WireGuard/QUIC/WSS 的正式运行时能力。
- 后续应先做 P0/P1 设计，不要直接改核心网络逻辑：先定义配置 schema、UI 原型、运行时边界、sidecar 方案、权限模型、日志和回滚策略。
- 任何涉及真实服务器、ROS、PVE、K3s、生产网络的联调，都必须由用户明确授权后再做。

## 当前项目位置

主开发目录已经迁移到 local-mac：

```text
/Volumes/CodeSpace/Kysion/kyclash
```

旧的 Mac 构建目录仍存在：

```text
/Users/supen/codex-builds/clash-verge-rev-mac-20260721/clash-verge-rev
```

Linux POC 工作区仍存在：

```text
/data/K3s/runtime/clash-verge-rev-poc-20260721/repos/clash-verge-rev
```

## 上游基线

上游项目：

```text
Clash Verge Rev
```

当前基线提交：

```text
304f5bade925811ba63be6537b39a2ef1191e669
```

项目版本：

```text
2.5.3
```

## 已完成事项

1. 已完成 Clash Verge Rev 源码拉取和基础构建验证。
2. 已完成 Linux deb-only 构建验证。
3. 已在 macOS arm64 上完成原始项目构建验证。
4. 已将用户可见品牌从 `Clash Verge` 改为 `KyClash`。
5. 已将 Tauri bundle identifier 改为：

```text
net.kysion.kyclash
```

6. 已更新 macOS plist/entitlements 中的 bundle id。
7. 已更新窗口标题、HTML title、Tauri productName、i18n 中可见的 `Clash Verge` 文案。
8. 已保留内部 Rust crate/service binary 名称，避免破坏上游 service IPC 和 sidecar 逻辑。
9. 已构建 macOS arm64 DMG：

```text
/data/K3s/runtime/clash-verge-rev-poc-20260721/artifacts/KyClash_2.5.3_aarch64.dmg
```

SHA256：

```text
620672464689763cba6560c54d2e9b864ab78ad706e51c8c2a7cdb76d76f1be0
```

10. 已确认 macOS app 信息：

```text
CFBundleName=KyClash
CFBundleDisplayName=KyClash
CFBundleIdentifier=net.kysion.kyclash
```

11. 已迁移项目到：

```text
/Volumes/CodeSpace/Kysion/kyclash
```

迁移时未复制旧的重型构建产物：

```text
node_modules
target
dist
.eslintcache
.DS_Store
```

12. 已在新目录完成验证：

```bash
corepack pnpm install --frozen-lockfile
corepack pnpm run typecheck
corepack pnpm run web:build
```

结果均通过。

13. 已确认新目录包含 macOS sidecar 和资源文件，例如：

```text
src-tauri/resources/Country.mmdb
src-tauri/resources/clash-verge-service
src-tauri/resources/clash-verge-service-install
src-tauri/resources/clash-verge-service-uninstall
src-tauri/resources/geoip.dat
src-tauri/resources/geosite.dat
src-tauri/resources/set_dns.sh
src-tauri/resources/unset_dns.sh
src-tauri/sidecar/verge-mihomo-aarch64-apple-darwin
src-tauri/sidecar/verge-mihomo-alpha-aarch64-apple-darwin
```

## 当前源码状态

`/Volumes/CodeSpace/Kysion/kyclash` 中保留了 KyClash 重命名改动。

当前改动是未提交状态，主要涉及：
- Tauri 配置
- macOS bundle 配置
- app title
- locale 文案
- Rust package metadata
- 用户目录命名相关逻辑

注意：目前只是完成品牌/路径层面的第一阶段重命名，并未开始实现 WireGuard/QUIC/WSS 组网能力。

## 重要报告

macOS 构建报告：

```text
/data/K3s/clash-verge-rev-mac-arm64-build-report-20260721.md
```

P0 方案与调研资料：

```text
/data/K3s/clash-verge-rev-remote-access-p0-report-20260721.md
/data/K3s/clash-verge-rev-remote-access-p0c-live-lab-runbook-20260721.md
```

## 接手建议

优先从 local-mac 的新项目目录继续：

```bash
ssh local-mac
cd /Volumes/CodeSpace/Kysion/kyclash
git status --short
corepack pnpm run typecheck
corepack pnpm run web:build
```

如果需要重新构建 macOS arm64 包，建议在 local-mac 上执行：

```bash
cd /Volumes/CodeSpace/Kysion/kyclash
corepack pnpm tauri build --target aarch64-apple-darwin
```

如果只需要继续开发，不需要先重新打包。

## 未完成事项

> 本节已由 `docs/roadmap/kyclash-plan-review-20260721.md` 和锁定版实施计划
> 取代；以下仅保留当前未完成摘要。

1. 尚未替换应用图标、托盘图标等品牌图形资产。
2. 当前工作区改动尚未建立正式 Git 基线并推送。
3. macOS PKG 已可复现，但正式发布仍缺签名、公证、stapling 和安装生命周期测试。
4. 版本化配置契约已经完成；WireGuard/QUIC/WSS 的真实运行时、UI 和系统集成尚未实现。
5. README 已整理；CHANGELOG 和正式发布说明尚未完成。
6. Windows 构建与 named-pipe/process 适配按锁定计划推迟到 macOS MVP 之后。

## 开发边界

- 不要输出或保存任何密码、token、私钥。
- 不要触碰生产服务器、PVE、ROS、K3s，除非用户明确要求。
- 当前任务是桌面客户端项目，不要混入 KT4、WSCTL、ZhipinAI 等业务项目。
- 继续开发时优先保持上游 Clash Verge Rev 的架构，不要大范围重构。
- 涉及品牌更名时要避免破坏 service IPC、sidecar、权限提升安装脚本。

## 给接手 AI 的当前任务

你现在接手的是 KyClash 项目。项目已经迁移到：

```text
/Volumes/CodeSpace/Kysion/kyclash
```

请先确认 `git status`、`pnpm typecheck`、`pnpm web:build`，然后根据用户下一步要求继续。
