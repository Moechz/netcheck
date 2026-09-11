# 用户数据查阅、更正、删除途径说明
# User Data Access, Correction and Deletion

- 适用版本：NetCheck 1.2.54（应用 ID `netcheck`）
- 本文回答审核项 **C5**。所有数据都保存在您自己的 TOS 设备上，
  **查阅、更正、导出、删除均在本地完成，不需要向开发者提交任何申请**。

---

## 一、中文版

### 1. 数据位置一览

应用目录：`/usr/local/netcheck/`（App Center 可能映射到所选存储卷下的应用目录；
可用 `readlink -f /usr/local/netcheck` 确认实际路径）。

| 数据 | 文件/目录 |
|---|---|
| 账户（用户名、口令散列、恢复码散列） | `data/auth/users.json` |
| 登录会话 | `data/auth/sessions.json` |
| 应用设置（含保留期限） | `data/settings.json` |
| 诊断历史 | `data/diag-history/*.json` |
| 修复历史 | `data/fix-history.json` |
| 链路质量趋势 | `data/trends/*.json` |
| 告警历史 | `data/alerts/*.json` |
| 网络配置快照 | `data/snapshots/<snapshot_id>/` |
| 修复前备份 | `data/backups/<action>-<时间戳>/` |
| 应用日志 | `logs/app.log*` |
| 操作审计 / 特权通道审计 | `logs/operation-audit.jsonl*`、`logs/helper-audit.log` |
| 运行时令牌与套接字 | `/run/netcheck/token`、`/run/netcheck/helper.sock`、`/run/netcheck/bpf-traffic.sock` |

### 2. 查阅

- **界面**：历史（诊断/修复记录与下载）、快照（列表与差异对比）、设置（当前配置
  与保留期限）、关于（版本、合规材料）。
- **接口**：`GET /api/diag/history`、`GET /api/fix/history`、`GET /api/snapshots`、
  `GET /api/settings`、`GET /api/alerts`（经平台代理并可被审计）。
- **直接读取**：使用上表路径，例如
  `sudo cat /usr/local/netcheck/data/settings.json`；
  账户文件仅含散列与盐，不含明文口令，同样可查阅。

### 3. 导出

| 内容 | 界面 | 接口 |
|---|---|---|
| 诊断历史（JSON） | 历史 → 下载 | `GET /api/diag/history/export` |
| 修复历史（JSON） | 历史 → 下载 | `GET /api/fix/history/export` |
| 网络配置快照 | 快照 → 差异 | `GET /api/snapshots/{id}/diff` |
| 合规材料 | 关于 → 合规与政策 | `compliance/` 目录文件 |

命令行示例（无需界面）：

```bash
sudo tar czf /tmp/netcheck-data.tgz -C /usr/local/netcheck data logs
```

### 4. 更正

| 目标 | 途径 |
|---|---|
| 用户名 / 口令 | 设置 → 账户 → 修改用户名 / 修改密码 |
| 忘记口令 | 登录页「忘记密码」→ 使用初始化时的一次性恢复码重置（恢复码用后即换） |
| 网络参数与保留期限 | 设置页面（写入 `data/settings.json`，原子替换） |
| 网络配置回滚 | 快照 → 恢复（写入前自动备份，可再回滚） |

### 5. 删除

| 范围 | 界面/命令 |
|---|---|
| 单条诊断或修复记录 | 历史 → 删除 |
| 全部诊断与修复历史 | 历史 → 清空全部（`POST /api/history/clear`） |
| 单份快照 | 快照 → 删除（`data/snapshots/<id>/`） |
| 修复备份 | `sudo rm -rf /usr/local/netcheck/data/backups/*` |
| 审计与日志 | `sudo rm -f /usr/local/netcheck/logs/*` |
| 运行时令牌 | `sudo rm -f /run/netcheck/token`（重启后重新生成） |
| 全部应用数据（保留程序） | `sudo rm -rf /usr/local/netcheck/data /usr/local/netcheck/logs /run/netcheck` |
| 完整卸载并清除数据 | App Center 卸载时勾选「删除所有配置项」，或 `sudo dpkg --purge netcheck` |

`dpkg --purge netcheck` 会删除 `data/`（账户、历史、快照、备份、设置）、
`logs/`、`/usr/www/netcheck`、systemd 单元与运行时套接字；`netcheck` 系统账户由
平台策略保留（TOS 应用账户为平台级对象）。彻底移除系统账户：

```bash
sudo userdel netcheck 2>/dev/null || true
```

> 网络配置本身（`/etc/systemd/network/*.network`）属于 TOS 系统配置而非应用数据；
> 如需还原，请使用「快照 → 恢复」或 TOS 控制面板，应用不会自行删除系统文件。

### 6. 撤回同意 / 停止处理

- 关闭持续监控：设置 → 监控 → 关闭（停止写入 `data/trends/`）。
- 关闭报警：保持通知渠道为关闭状态。
- 停止特权通道：设置 → 修复模式改为「指引」，并
  `sudo systemctl disable --now netcheck-helper.service`。
- 停止全部处理：卸载应用（见上表）。

### 7. 响应时限与联系方式

由于所有操作均在本地完成，通常无需等待。如需开发者协助（例如理解文件含义或
迁移数据），请联系 **zhoucaven@163.com**，我们将在 **15 个工作日**内答复。

---

## 二、English version

All NetCheck data lives on your own TOS device under `/usr/local/netcheck/`
(`data/` and `logs/`; use `readlink -f /usr/local/netcheck` for the real path).
**Access, correction, export and deletion are local operations — no request to
the developer is needed.**

- **Access** — in the UI (History, Snapshots, Settings, About) or through
  `GET /api/diag/history`, `GET /api/fix/history`, `GET /api/snapshots`,
  `GET /api/settings`, `GET /api/alerts`, or by reading the files directly
  (`data/auth/users.json` holds hashes and salts only, never plaintext).
- **Export** — `GET /api/diag/history/export`, `GET /api/fix/history/export`,
  snapshot diffs, or `sudo tar czf /tmp/netcheck-data.tgz -C /usr/local/netcheck data logs`.
- **Correction** — Settings → Account (username/password; forgotten passwords
  are reset with the one-time recovery code), Settings page for all parameters
  and retention limits, Snapshot restore for network configuration.
- **Deletion** — per-record delete or "Clear All" in History
  (`POST /api/history/clear`), snapshot delete, `rm -rf data/backups/*`,
  `rm -f logs/*`, `rm -f /run/netcheck/token`, full
  `rm -rf data logs /run/netcheck`, or uninstall with "delete all
  configuration" / `dpkg --purge netcheck` (removes `data/`, `logs/`,
  `/usr/www/netcheck`, systemd units and runtime sockets; the platform-level
  `netcheck` system account can be removed with `sudo userdel netcheck`).
  Network configuration files under `/etc/systemd/network/` are TOS system
  configuration, not application data — restore them with Snapshot → Restore
  instead of deleting them.
- **Withdraw consent** — turn continuous monitoring off, keep alert channels
  disabled, switch repair mode to "guide" and
  `systemctl disable --now netcheck-helper.service`, or uninstall.
- **Contact** — zhoucaven@163.com, reply within 15 business days.
