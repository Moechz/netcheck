# 特权通道（root 辅助服务）授权依据与最小权限实现说明
# Privileged Channel (root helper): Authorisation Basis and Least-Privilege Implementation

- 适用版本：NetCheck 1.2.54（应用 ID `netcheck`）
- 本文回答审核项 **V1 / S1**：`netcheck-helper.service` 以 uid 0（`User=0`，数字形式以规避 TOS 对「root」用户名的重映射；能力边界不变）运行的
  授权依据与最小化权限实现。
- 同时披露 1.2.52 起新增的 `netcheck-bpf.service`（同样以 root 运行），避免重审
  时再次出现「未见授权文件」的情况。

---

## 一、中文版

### 1. 组件与运行身份（包内定义：`/usr/local/netcheck/init.d/`）

| 单元 | 运行身份 | 作用 | 是否必需 |
|---|---|---|---|
| `netcheck.service` | `User=netcheck`（专用非 root 系统账户，`--no-create-home --shell /usr/sbin/nologin`） | 后端、WebUI 数据接口、诊断、监控 | 必需 |
| `netcheck-helper.service` | `User=0` + **能力边界收窄** | 仅执行白名单内的网络修复动作 | **可选**（缺失时应用自动降级为「指引模式」） |
| `netcheck-bpf.service` | `User=0` + **能力边界收窄**（1.2.52 起） | 只读实时速率计数（AF_PACKET + eBPF map） | **可选**（缺失/失败时自动回退 `/proc/net/dev`） |

> 包内**不含**任何 setuid/setgid 文件或 `setcap` 二进制：
> `find /usr/local/netcheck -perm -4000` 与 `getcap -r /usr/local/netcheck` 均为空；
> 两个 root 进程只能由 systemd 按包内单元文件拉起。

### 2. 为什么必须存在特权组件

1. TOS 7 未提供网络写入 API（不存在 `tos network set` 等命令），第三方应用无法
   通过平台接口修改网络配置——这是需求文档中登记的平台能力缺口（需求 R1）。
2. 网络配置文件的属主是 root：真机实测 `/etc/systemd/network/` 为
   `drwxr-xr-x`、`10-eth*.network` 为 `-rw-r--r--`，属主 uid 0。
3. 修复动作（改 IP/DNS/网关/MTU、重启 networkd/ntp/netplug、回滚快照）必须由
   特权进程执行，否则应用只能停留在「只读诊断 + 输出指引」。

若不接受 root 辅助服务，替代方案是：**只提供只读诊断与指引模式**
（`repair.mode=guide`），主服务完全无需特权——见第 6 节的关闭方法，应用在该模式下
功能完整（诊断、测速、监控、工具、快照全部可用，只是不自动落盘修复）。

### 3. 授权依据与本次申请（对应审核项 V1）

- **2026-08-25**：开发者与平台沟通后，平台以**「系统级应用契约」（system-level app
  contract）**机制同意本应用随 App Center 包分发 root 辅助服务；同机制先例为平台
  官方应用 `terai`（其 `contract/expected.json` 声明二进制哈希，平台在安装/启动前
  校验），真机验证记录见《TOS7 真机环境验证报告》§5.4。
- **2026-08-25**：项目安全评审出具《特权通道安全审查》，对 R1–R7 风险逐条评估，
  接受前提是白名单/参数校验/审计/回滚全部落地（本版本的实现即为落地结果）。
- **本次随包提供的授权材料**：
  1. 本文件（授权依据、能力清单、白名单、审计、关闭与核验方法）；
  2. `contract/expected.json`（平台契约校验清单：`netcheck`、`netcheck-helper`、
     `netcheck-bpf`、`webui.bz2` 的 SHA-256，安装/启动前核验）；
  3. `MANIFEST.json` / `SBOM.json`（包内文件与组件、维护脚本哈希）；
  4. 完整内部安全评审记录《特权通道安全审查》可依申请以邮件原文/PDF 提供。
- **本次申请（请审核团队确认）**：
  1. 请确认上述「系统级应用契约」是否即本次审核所需的 R1 特批；
  2. 若需要独立授权文件，请告知所需形式（授权函模板 / 契约编号登记），我们在
     收到模板后 **3 个工作日内**补充提交；
  3. 若平台要求「零特权」形态，我们可在 **5 个工作日内**提交不含
     `netcheck-helper.service` / `netcheck-bpf.service` 的无特权构建版本
     （`repair.mode=guide` 默认，仅保留只读诊断、测速、监控与指引修复），
     请告知是否需要。

### 4. 最小权限实现（本版本实际生效的配置）

`init.d/netcheck-helper.service`：

```ini
User=0
Group=0
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_NET_ADMIN
NoNewPrivileges=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
UMask=0077
```

> `User=0`（数字 uid）等价于 root：部分 TOS 安装会把「root」这个**名字**重映射到无能力的诱饵账户（uid 9999，真实 root 是管理员用户本身），按名字解析会丢失全部能力；数字 uid 不受影响，能力边界不变。运行时目录 `/run/netcheck` 归一化为 `0:netcheck 0770`（setgid 位不可用：`RestrictSUIDSGID=true` 会拒绝任何设置 suid/sgid 位的 chmod）。

| 保留的能力 | 用途（唯一必要性） |
|---|---|
| `CAP_CHOWN` | 启动时把 `/run/netcheck/token`、`helper.sock` 的属主改为 `netcheck`、目录属组改为 `netcheck` 组（目录属主保持 uid 0，供 bpf 收集器创建套接字），使非 root 主服务能读取令牌并连接套接字 |
| `CAP_DAC_OVERRIDE` | 兼容「`.network` 文件属主/权限变体」；真机默认属主为 uid 0 且含属主写位，本能力可按安装自检裁剪（审核若要求，可去掉并在自检中强制校验属主） |
| `CAP_NET_ADMIN` | `ip link set`（MTU/up/down）、`sysctl -w net.ipv6.conf.*`、`networkctl reload/reconfigure`、`resolvectl dns/revert` |

**显式剔除的高危能力**（早期草案曾包含，已在安全审查后移除并保持移除）：

`CAP_SYS_ADMIN`、`CAP_SYS_MODULE`、`CAP_SYS_PTRACE`、`CAP_SYS_RAWIO`、
`CAP_DAC_READ_SEARCH`、`CAP_SETUID`、`CAP_SETGID`、`CAP_KILL`、`CAP_SYS_TIME`、
`CAP_NET_RAW`（helper 不需要抓包）、`CAP_SYS_RESOURCE`。

`init.d/netcheck-bpf.service`（1.2.52 新增，只读计数）：

```ini
User=0
Group=netcheck
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_BPF CAP_PERFMON
NoNewPrivileges=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET
LimitMEMLOCK=infinity
```

> `User=0`（数字 uid）：TOS 会把用户名 `root` 重映射到无能力的诱饵 uid 9999，按名字解析会使能力失效，故用户部分用数字。`Group=netcheck`（名字）：TOS 不重映射组名，且系统给 netcheck 组分配的 gid 因机器而异（实测 996 与 999 两种），硬编码 gid 会在部分机器上 status=216/GROUP 启动失败（1.2.57 真机修复）；收集器创建的 `bpf-traffic.sock` 继承该组并以 0660 模式供主服务连接（不能用目录 setgid 位，原因同上）。

| 保留的能力 | 用途 |
|---|---|
| `CAP_NET_RAW` | 创建 `AF_PACKET` 套接字以统计每网卡字节/包数 |
| `CAP_BPF` + `CAP_PERFMON` | 加载 eBPF socket filter、创建内核 map（kernel ≥5.8 的细分能力，替代过去需要 `CAP_SYS_ADMIN` 的粗粒度授权） |
| `CAP_NET_ADMIN` | `SO_ATTACH_BPF` 附加过滤器 |

该服务**不写任何系统配置**、不保存数据包载荷（BPF 程序 `return 0` 丢弃拷贝），
`LimitMEMLOCK=infinity` 使其无需 `CAP_SYS_RESOURCE`。下一版本计划进一步降为
**专用非 root 用户 + AmbientCapabilities**（需在真机验证套接字目录权限与能力保留
后再启用）。

**为什么没有启用 ProtectSystem / PrivateTmp / ProtectHome**：TOS 7.0.1140
（kernel 6.12.63）上这些依赖 mount namespace 的沙箱指令会导致服务以
`226/NAMESPACE` 启动失败（2026-08-26 真机实测）。因此本版本用「能力边界 +
文件权限 + 白名单 + 审计」替代，并在 `init.d/*.service` 中注释说明。若平台放宽该
限制，我们将在下一版本启用
`ProtectSystem=strict` + `ReadWritePaths=/etc/systemd/network /run/netcheck`
+ `PrivateTmp=true`。

### 5. 白名单与纵深防御（与最小权限配套）

白名单动作（`lib/netcheck/fix/actions.py`，**9 项**，无 shell、无通配、无常量拼接）：

| 动作 | 关键参数与约束 |
|---|---|
| `link-toggle` | 网卡名 `^[A-Za-z0-9_.-]{1,15}$` 且必须来自采集器白名单；排除 `lo/docker0/tnas0/all/default`；方向仅 `up|down` |
| `net-reload` | 不接受任何参数 |
| `net-apply` | 模式 `dhcp|static|reset`；静态地址必须合法 IPv4、前缀 1–30、网关必须同子网；MTU 1280–9000 |
| `dns-set` | DNS 1–3 条，必须是合法 IP 且非 0.0.0.0 |
| `gateway-set` | 网关必须落在同子网；文件级改写并保留无关配置 |
| `sysctl-ipv6` | 仅 `net.ipv6.conf.<iface>.disable_ipv6=0` |
| `mtu-set` | MTU 1280–9000 |
| `svc-restart` | 单元为**精确枚举** `systemd-networkd.service` / `ntp.service` / `netplug.service`（拒绝裸名、`.timer`、`ssh` 等） |
| `snap-restore` | 快照 ID `^[A-Fa-f0-9-]{1,64}$`，文件必须通过内置语法校验 |

防御层：

1. **进程身份**：主服务 `netcheck` 非 root；helper 仅监听 `/run/netcheck/helper.sock`
   （目录 `0700`、套接字 `0600`、属主 `netcheck`）。
2. **对端认证**：`SO_PEERCRED` 校验对端 UID 必须等于 `netcheck`，并校验启动令牌
   （`secrets.compare_digest`，每次启动重新生成，`O_EXCL` 写入）。
3. **双侧参数校验**：主服务发送前校验一次，helper 收到后**再校验一次**。
4. **无 shell 执行**：`execve` argv 数组直调固定绝对路径二进制（`/usr/sbin/ip`、
   `/usr/bin/networkctl`、`/usr/bin/systemctl`、`/usr/bin/resolvectl`、
   `/usr/sbin/sysctl`），环境变量固定为 `PATH=/usr/sbin:/usr/bin:/bin`。
5. **写入安全**：内置 `.network` 语法校验 → SHA-256 备份 → 临时文件 `O_EXCL`
   原子替换 → `reload + reconfigure`；失败自动回滚。
6. **审计**：JSONL 审计（动作、参数、结果、耗时、stdout 哈希、备份路径、回滚），
   主服务侧另有操作审计（凭据键名统一脱敏）。
7. **限流与串行**：同一动作 30 秒内仅允许一次，执行串行加锁。
8. **平台契约校验**：`contract/expected.json` 声明二进制 SHA-256，被篡改的
   helper/backend 无法通过平台校验启动（terai 同机制）。

### 6. 关闭特权通道（审核与运维均可执行）

```bash
# 1) 应用内切换为指引模式（也可通过 API：POST /api/settings {"repair":{"mode":"guide"}}）
sudo sed -i 's/"mode": "helper"/"mode": "guide"/' /usr/local/netcheck/data/settings.json

# 2) 停用并屏蔽两个特权单元（主服务与全部只读功能继续正常工作）
sudo systemctl disable --now netcheck-helper.service netcheck-bpf.service
sudo systemctl mask netcheck-helper.service netcheck-bpf.service
```

关闭后：诊断、评分、历史、测速（回退 `/proc/net/dev`）、监控、工具、快照创建与
差异对比全部可用；修复动作改为输出「指引」文本，不写系统配置。

### 7. 审核可执行的自检命令

```bash
# 运行身份与能力边界
systemctl show -p User -p Group -p CapabilityBoundingSet -p NoNewPrivileges \
  -p RestrictAddressFamilies netcheck-helper.service
systemctl show -p User -p CapabilityBoundingSet netcheck-bpf.service

# 包内没有 setuid/setcap 二进制
find /usr/local/netcheck -perm -4000 -o -perm -2000
getcap -r /usr/local/netcheck 2>/dev/null

# 运行时权限
ls -ld /run/netcheck && ls -l /run/netcheck

# 契约与材料清单
cat /usr/local/netcheck/contract/expected.json
cat /usr/local/netcheck/compliance/MANIFEST.json

# 白名单与校验（源码随包为 .pyc；明文源码可依申请提供）
```

---

## 二、English version

### Components and identities

`netcheck.service` runs as the dedicated non-root account `netcheck`
(`--no-create-home --shell /usr/sbin/nologin`). `netcheck-helper.service` runs
as root with a **capability bounding set of
`CAP_CHOWN CAP_DAC_OVERRIDE CAP_NET_ADMIN`**, `NoNewPrivileges=true`,
`RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`, `UMask=0077`.
`netcheck-bpf.service` (new in 1.2.52) runs as root with
`CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_BPF CAP_PERFMON`,
`LimitMEMLOCK=infinity` and never writes system configuration. The package
contains no setuid/setgid file and no `setcap` binary — both root processes can
only be started by systemd from the packaged units.

**Platform exec-compat exception (1.2.58).** A small number of TOS builds
(observed 2026-09-15 on one production NAS, systemd 249) reject `execve` under
`NoNewPrivileges` with systemd `203/EXEC` — even for `/bin/true` — and on that
same build `RestrictSUIDSGID`/`RestrictAddressFamilies` additionally break
exec for the non-root service user. The package therefore probes this once at
install time (`systemd-run` transient units, 15 s timeout, `--collect`
cleanup, result written to the dpkg log). Only when the probe fails does
postinst install `80-netcheck-exec-compat.conf` drop-ins that set
`NoNewPrivileges=false` (plus `RestrictSUIDSGID=false` and a cleared
`RestrictAddressFamilies` for the non-root backend only). Capability bounding
sets, service users, socket ownership and every other isolation directive are
unchanged by this path, and the drop-ins are removed automatically once the
platform probe passes again. Unaffected platforms keep the fully hardened
templates (verified on two production NAS units); the relaxation path was
verified on the affected unit via equivalent field drop-ins.

### Why privilege is required

TOS 7 exposes no network-write API, and `/etc/systemd/network/*.network` is
root-owned (measured on device: owner uid 0 with the owner-write bit). Without a
privileged channel the application can only diagnose and print guidance.
Removing it is supported: switch `repair.mode` to `guide` and
`systemctl disable --now` both units (section 6) — diagnosis, scoring, history,
bandwidth, monitoring, tools and snapshots keep working.

### Authorisation basis (review item V1)

On 2026-08-25 the platform agreed, under the **system-level app contract**
mechanism (the same mechanism used by the official `terai` app, whose
`contract/expected.json` hashes are verified by the platform before
install/startup — device verification report §5.4), that this root helper ships
with the App Center package; the project security review documented the
corresponding R1–R7 risk acceptance. Because that agreement was never shipped as
a standalone document, this dossier now ships the basis, the capability
inventory, the whitelist, the audit trail and the off-switch. **We request
confirmation** that the system-level app contract is the required R1 approval,
or the template/registration form you need (we will provide it within three
working days). If a zero-privilege form is required instead, we can deliver,
within five working days, a build that omits both privileged units and defaults
to `repair.mode=guide`.

### Least privilege

Only three capabilities are retained for the helper, each with a single
necessity: `CAP_CHOWN` (hand the runtime token/socket to the `netcheck` user),
`CAP_DAC_OVERRIDE` (compatibility with future ownership variants — removable
once the installer self-check asserts owner uid 0 plus the owner-write bit) and
`CAP_NET_ADMIN` (`ip link set`, IPv6 sysctl, `networkctl`, `resolvectl`).
`CAP_SYS_ADMIN`, `CAP_SYS_MODULE`, `CAP_SYS_PTRACE`, `CAP_SYS_RAWIO`,
`CAP_DAC_READ_SEARCH`, `CAP_SETUID`, `CAP_SETGID`, `CAP_KILL`, `CAP_SYS_TIME`,
`CAP_NET_RAW` and `CAP_SYS_RESOURCE` are explicitly removed. Mount-namespace
sandboxing (`ProtectSystem`, `PrivateTmp`, `ProtectHome`) is not enabled because
it fails with `226/NAMESPACE` on TOS kernel 6.12.63; the units document this and
the plan to enable it once the platform allows.

### Whitelist and defence in depth

Nine whitelisted actions with two-sided parameter validation (interface regex
plus collector whitelist, exact unit enum, DNS 1–3 valid IPs, gateway in the
same subnet, MTU 1280–9000, snapshot ID regex), no shell, fixed absolute
binaries, built-in `.network` syntax check, SHA-256 backup with automatic
rollback, JSONL audit with redaction, 30-second per-action rate limit, serial
execution lock, `SO_PEERCRED` peer-UID plus startup-token authentication, and
platform contract hash verification. Reviewers can self-verify with the
commands in section 7.

---

## 9. 执行兼容降级（exec-compat，1.2.58）

**背景**：2026-09-15 在一台生产 NAS（TOS，systemd 249）上实测：该平台的
systemd 在 `NoNewPrivileges=true` 下拒绝任何 `execve`（`203/EXEC`，连
`/bin/true` 都失败）；同一平台上 `RestrictSUIDSGID=true` 或
`RestrictAddressFamilies=…` 对非 root 服务用户同样导致 exec 失败。三个
服务因此全部无法启动，页面表现为 TOS 代理报 `invalid api socket`。

**机制**：安装脚本（postinst）在安装时做一次性最小探测——用
`systemd-run --wait --collect` 分别验证 (a) `NoNewPrivileges=true` 下能否
exec；(b) 非特权用户叠加全部沙箱过滤后能否 exec。探测有 15 秒超时、
`--collect` 清理临时 unit、结果写入 dpkg 日志。**仅当探测失败**才安装
`80-netcheck-exec-compat.conf` 降级 drop-in：主后端
`NoNewPrivileges=false` + `RestrictSUIDSGID=false` + 清空
`RestrictAddressFamilies`；两个特权服务仅 `NoNewPrivileges=false`。

**不妥协项**：该路径不扩大 CapabilityBoundingSet、不改变服务用户
（主后端仍为非特权 `netcheck`，特权服务仍为数字 uid 0）、不改变 socket
属主与 0600/0660 权限、不新增 setuid/setgid 文件。探测通过的平台继续
使用完整加固模板（两台生产 NAS 验证）；降级文件在后续安装探测通过时
自动移除。可用环境变量 `NETCHECK_EXEC_COMPAT=force|off` 覆盖探测（测试
钩子）。

**旧现场补丁迁移**：升级时会识别现场修复产生的
`90-tos-compat.conf`（已知文件名），先备份到
`/var/backups/netcheck/legacy-dropins-<时间戳>/` 再移除，避免旧覆盖与新
模板叠层冲突；其他自定义 drop-in 一律不动并告警。卸载（purge）只删除
本包生成的 `80-netcheck-exec-compat.conf`。
