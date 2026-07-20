## KyClash（未发布）

### 产品与发布安全

- 用户可见产品名、左上角标识、bundle identifier、安装包和仓库链接已迁移为 KyClash。
- README 明确说明 KyClash 基于 Clash Verge Rev 二次开发，并保留必要兼容标识的原因。
- 应用更新器保持禁用，已移除上游更新端点、验证密钥和前端更新权限。
- macOS 安装产物改为 PKG；本地 arm64 PKG 可复现，但仍是未签名开发产物。
- CI 发布流程要求 KyClash Installer 签名、Apple 公证、stapling 和验证后才允许上传。

### 私有网络 POC

- 锁定单站点、macOS 优先的 WireGuard + QUIC 主通道 + WSS/TCP 备用通道架构。
- 完成版本化配置/IPC、状态机、签名策略、凭据边界、脱敏诊断和开发状态页。
- 完成事务化私有路由、冲突拒绝、崩溃恢复、Mihomo TUN 共存策略和故障注入测试。
- 完成独立 Go sidecar 的帧协议、QUIC 分片/重组、TLS/WSS/TCP、`wireguard-go`
  custom Bind，以及真实 WireGuard-over-QUIC 的纯隔离组合测试。
- 生产连接命令、host utun/路由写入和真实服务端仍保持禁用；sidecar 尚未加入发行包。

### 尚未完成的正式发布门禁

- macOS Developer ID 签名、公证、stapling 与安装/升级/卸载生命周期测试。
- 经授权的真实路由、utun、睡眠/唤醒、网络切换和受损链路实验。
- KyClash 自有更新端点、签名密钥、回滚清单和分阶段发布。

## v2.5.3

### 🐞 修复问题

<details>
<summary><strong> ✨ 新增功能 </strong></summary>

</details>

<details>
<summary><strong> 🚀 优化改进 </strong></summary>

- TUN 模式设置也遵循 原始配置 < Merge 覆写 < Script 脚本 < GUI

</details>
