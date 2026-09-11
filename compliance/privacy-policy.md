# NetCheck 隐私政策 / Privacy Policy

- 适用应用：NetCheck（应用 ID `netcheck`），TerraMaster TOS 7 应用
- 版本：1.2.54 · 生效日期：2026-09-11
- 数据控制者 / Developer & Publisher：Moechz（zhoucaven@163.com）
- 本政策同时随包分发（`/usr/local/netcheck/compliance/privacy-policy.md`），
  并可通过应用内「关于 → 合规与政策」以及
  https://github.com/Moechz/netcheck/tree/main/compliance 访问。

---

## 一、中文版

### 1. 总述

NetCheck 是一款**安装在您自己设备上的局域网网络诊断与修复工具**。它不提供
云端账号，不含广告、统计 SDK 或崩溃上报，**不会向开发者或任何第三方回传您的
数据**。所有账户、诊断结果、历史记录与日志均保存在您设备的本地磁盘上，由您
（设备管理员）完全控制。

### 2. 我们（应用）处理哪些数据

| 类别 | 具体内容 | 来源 |
|---|---|---|
| 本地账户凭据 | 用户名；口令的 PBKDF2-HMAC-SHA256（200,000 次迭代）散列与随机盐；一次性恢复码的散列 | 由您在首次初始化时设置 |
| 会话数据 | 登录会话令牌（随机 32 字节）、签发/过期时间 | 登录时生成 |
| 网络配置与状态 | 网卡名称/状态/速率、IP 地址、网关、DNS、MTU、路由、bond/OVS 拓扑、TOS 服务状态 | 从内核与本机 TOS 接口只读采集 |
| 诊断结果 | 35 项检查的状态、评分、问题描述与建议 | 诊断运行时生成 |
| 带宽测量结果 | 上/下行速率、时延、抖动、所用方法与目标端点 | 由您主动发起测速时生成 |
| 链路质量趋势 | 周期性采样的丢包率、RTT、接口字节计数 | 监控开启时生成 |
| 配置快照 | `/etc/systemd/network/*.network` 等网络配置文件的副本与元数据 | 修复前自动或您手动创建 |
| 修复备份与审计 | 修复动作、参数、结果、耗时、操作者、目标对象、回滚记录 | 执行修复时生成 |

**不处理的数据**：不读取、不索引、不上传您的任何文件内容、共享文件夹内容、
媒体库或个人文档；采集网络统计时不保存数据包载荷。

### 3. 数据存储位置与保存期限

所有数据都存储在应用目录 `/usr/local/netcheck/`（App Center 安装时可能映射到
所选存储卷下的应用目录）：

| 数据 | 路径 | 保存期限（默认） | 到期行为 |
|---|---|---|---|
| 账户与恢复码散列 | `data/auth/users.json`（权限 0600） | 直到您删除或卸载清除 | 无自动删除 |
| 会话 | `data/auth/sessions.json` | 24 小时 | 过期即失效，重新登录时清理 |
| 设置 | `data/settings.json` | 直到您修改或清除 | 无自动删除 |
| 诊断历史 | `data/diag-history/*.json` | 最近 50 份报告（可配置 `retention.diag_history`） | 滚动删除最旧记录 |
| 链路质量趋势 | `data/trends/*.json` | 30 天（`monitor.retain_days`） | 超过保留期的分片文件被删除 |
| 告警历史 | `data/alerts/*.json` | 90 天（`retention.alert_days`） | 超期清理 |
| 配置快照 | `data/snapshots/<id>/` | 最近 20 份（`snapshot.keep`） | 超出后删除最旧快照 |
| 修复备份 | `data/backups/<action>-<时间戳>/` | 直到您删除（可手动清理） | 无自动删除 |
| 应用日志 | `logs/app.log` | 10 MB × 5 份轮转；元数据保留 30 天（`retention.log_days`） | 按大小轮转覆盖 |
| 操作与修复审计 | `logs/operation-audit.jsonl`、`logs/helper-audit.log` | 10 MB × 5 份轮转；保留 90 天（`retention.operation_audit_days`） | 轮转覆盖 |
| 运行时文件 | `/run/netcheck/token`、`helper.sock`、`bpf-traffic.sock` | 进程生命周期（重启即重建） | 重启/卸载时删除 |

保存期限均在应用内可配置（设置页或 `data/settings.json` 的 `retention.*`），
不会超出上述默认值无限期保存。

### 4. 安全措施

- **最小权限**：主服务 `netcheck.service` 以专用非 root 账户 `netcheck` 运行；
  仅修复动作使用受控特权通道，且该通道以能力边界（capability bounding set）
  收窄，详见 `privileged-channel.md`。
- **凭据保护**：口令使用 PBKDF2-HMAC-SHA256（200,000 次迭代）+ 每账户随机盐，
  只存储散列；恢复码一次性使用并立即轮换；登录失败 5 次锁定 5 分钟，登录限速
  10 次/分钟；会话令牌 24 小时后失效。
- **本地通信**：后端仅监听 Unix 域套接字 `/var/api/netcheck.sock`（平台代理），
  不开放 TCP 端口；特权通道套接字 `0600`、目录 `0700`，并校验
  `SO_PEERCRED` 对端 UID + 启动令牌。
- **文件权限**：数据与日志目录归 `netcheck` 所有，主服务 `UMask=0027`，
  特权服务 `UMask=0077`；账户文件 `0600`，凭据目录 `0700`。
- **审计脱敏**：审计写入前按键名脱敏（`password`、`token`、`secret`、
  `session` 等一律替换为 `[REDACTED]`），日志抽样验证不含敏感信息。
- **修复可回滚**：写入前按 SHA-256 备份，失败自动回滚；所有动作记录审计。
- **传输安全**：仅使用 HTTPS/ICMP 等标准协议与外部端点通信；不使用明文口令
  传输，不在 URL 中携带凭据。

### 5. 第三方共享与数据出境

- 应用**不向开发者回传任何数据**，不包含遥测、崩溃上报、广告或第三方分析 SDK。
- 仅当您**主动**运行带宽测速、外部诊断或报警测试时，应用才会与
  `third-party-services.md` 中列明的第三方端点通信；这些通信只包含建立连接与
  测量所必需的报文（来源 IP、User-Agent `NetCheck/1.0` 等），不含您的账户、
  主机名、文件或历史记录。
- 外部测速端点通常位于您选择/自动选择的测速服务器所在国家或地区，属于跨境
  传输；**如您不希望发生任何跨境通信，可在设置中把 WAN 测速模式改为局域网
  iperf3 或自建 HTTP 端点，或不执行测速与外部诊断**（详见第 4 节）。
- 报警通道（邮件 SMTP / Webhook）仅在您填写并启用后生效，去向由您指定。

### 6. 您的权利与行使方式

您对自己的设备与数据拥有完全控制权：

- **查阅**：应用内「历史」「快照」「设置」「关于」页面，或直接读取上表路径文件。
- **更正**：「设置」页修改参数与保留期限；「账户」修改用户名/口令。
- **导出**：历史记录页面可下载 JSON 日志；网络配置快照支持差异查看。
- **删除**：历史记录单条删除/全部清空、删除快照、删除备份目录、卸载时清除。
- **撤回同意**：关闭监控、关闭报警通道、停止使用特权通道（`repair.mode=guide`）。

完整命令与界面路径见 `data-rights.md`。由于数据保存在您自己的设备上，**无需
向开发者提交申请**即可完成查阅、更正与删除；如需协助可通过 zhoucaven@163.com
联系，我们将在 15 个工作日内答复。

### 7. 儿童

本应用是面向 NAS 管理员的网络运维工具，不面向儿童，也不会有意收集儿童数据。

### 8. 政策变更

政策随版本更新，最新版本始终随包分发并在应用「关于 → 合规与政策」中展示；
重大变更会在应用内提示，并更新本文件顶部的版本号与生效日期。

---

## 二、English version

### 1. Summary

NetCheck is a **local network diagnosis and repair tool that runs on your own
TOS 7 device**. It has no cloud account, no advertising or analytics SDK, and
no crash reporting: **no data is ever sent back to the developer or to any
third party**. Accounts, diagnosis results, history and logs stay on your
device and are fully controlled by you (the device administrator).

### 2. Data the application processes

- **Local account credentials** — username, PBKDF2-HMAC-SHA256 (200,000
  iterations) password hash with a random per-account salt, and a one-time
  recovery-code hash that you set during first-run initialization.
- **Session data** — random session tokens with issue/expiry timestamps.
- **Network configuration and state** — interface names/state/speed, IP
  addresses, gateway, DNS, MTU, routes, bond/OVS topology, TOS service status
  (collected read-only from the kernel and local TOS APIs).
- **Diagnosis results** — status, score, findings and recommendations for 35
  checks. **Bandwidth results** — throughput, latency, jitter, method and
  target endpoint, produced only when you start a measurement.
- **Link-quality trends** — periodically sampled loss, RTT and interface byte
  counters while monitoring is enabled.
- **Configuration snapshots and repair backups/audit** — copies of
  `/etc/systemd/network/*.network` plus repair action, parameters, result,
  actor, target and rollback records.

**Not processed:** file contents, shared-folder content, media libraries or
personal documents are never read, indexed or uploaded; packet payloads are
never stored.

### 3. Storage location and retention

Everything is stored under the application directory `/usr/local/netcheck/`
(possibly mapped to a chosen volume by App Center).

| Data | Path | Default retention |
|---|---|---|
| Account & recovery-code hashes | `data/auth/users.json` (0600) | until deleted / purged |
| Sessions | `data/auth/sessions.json` | 24 hours |
| Settings | `data/settings.json` | until changed / purged |
| Diagnosis history | `data/diag-history/*.json` | last 50 reports (`retention.diag_history`) |
| Link-quality trends | `data/trends/*.json` | 30 days (`monitor.retain_days`) |
| Alert history | `data/alerts/*.json` | 90 days (`retention.alert_days`) |
| Snapshots | `data/snapshots/<id>/` | last 20 (`snapshot.keep`) |
| Repair backups | `data/backups/<action>-<ts>/` | until deleted manually |
| Application log | `logs/app.log` | 10 MB × 5 rotation; 30 days (`retention.log_days`) |
| Operation / helper audit | `logs/operation-audit.jsonl`, `logs/helper-audit.log` | 10 MB × 5 rotation; 90 days (`retention.operation_audit_days`) |
| Runtime files | `/run/netcheck/token`, `helper.sock`, `bpf-traffic.sock` | process lifetime |

All retention values are configurable in the Settings page or in
`data/settings.json` and never exceed the defaults above unintentionally.

### 4. Security measures

- **Least privilege** — the main backend runs as the dedicated non-root user
  `netcheck`; privileged work goes through one audited channel that is narrowed
  by a capability bounding set (see `privileged-channel.md`).
- **Credential protection** — PBKDF2-HMAC-SHA256 (200,000 iterations) with
  per-account salt; hashes only, never plaintext; single-use recovery code;
  5-failure lockout for 5 minutes; 10 logins/minute rate limit; 24-hour
  sessions.
- **Local-only transport** — the backend listens on a Unix domain socket
  (`/var/api/netcheck.sock`, platform-proxied); no TCP port is opened. The
  privileged socket is `0600` in a `0700` directory and is protected by
  `SO_PEERCRED` peer-UID checks plus a startup token.
- **File permissions** — data/log directories are owned by `netcheck`;
  `UMask=0027` (main) and `UMask=0077` (helper); account files `0600`.
- **Audit redaction** — audit entries redact `password`, `token`, `secret`,
  `session` and similar keys to `[REDACTED]` before writing.
- **Reversible repairs** — SHA-256-verified backups before every write, with
  automatic rollback and full audit.

### 5. Third-party sharing and cross-border transfer

The application sends nothing to the developer and embeds no telemetry,
analytics or advertising SDK. External communication happens **only when you
actively start it** (WAN speed test, external diagnosis, alert test) and only
with the endpoints listed in `third-party-services.md`; the exchanged data is
limited to what is technically required (source IP, `User-Agent NetCheck/1.0`).
Speed-test servers are located in the country/region you select (or the
auto-selected one), which may be outside your own country; **to avoid any
cross-border traffic, switch the WAN test mode to LAN iperf3 or your own HTTP
endpoint, or simply do not run a speed test.** Alert channels (SMTP/webhook)
only become active after you configure them.

### 6. Your rights

Access, correction, export and deletion are performed directly on your own
device — in the application UI, or by reading/removing the files listed above;
no request to the developer is required. See `data-rights.md` for exact paths
and commands. For assistance, contact zhoucaven@163.com (reply within 15
business days).

### 7. Children

NetCheck is a network operations tool for NAS administrators and is not
directed at children; no children's data is knowingly collected.

### 8. Changes

This policy is versioned with the application, shipped in the package, shown
under About → Compliance & Policies, and the version/date at the top is
updated on every material change.
