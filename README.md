# NetCheck — Network Diagnostics & Repair for TOS 7

![Release](https://img.shields.io/badge/release-0.0.1%20beta-2E8B52) ![TOS](https://img.shields.io/badge/platform-TerraMaster%20TOS%207-1877f2) ![Languages](https://img.shields.io/badge/i18n-23%20languages-0d9488)

**NetCheck** is a network health application for TerraMaster NAS running **TOS 7**. It diagnoses connectivity problems from the TOS web UI, explains what broke and where, and walks you through safe repairs — no SSH required.

**NetCheck** 是一款运行在 **TerraMaster TOS 7** 上的网络健康应用：在网页端即可完成网络体检、故障定位与安全修复，无需 SSH 登录命令行。

---

## ✨ Features · 功能亮点

### One-click full diagnosis · 一键全量诊断
Nine check groups cover the whole path from cable to cloud: **Link layer · IPv4 · Routing · DNS · IPv6 · Internet · TOS services · Transport**. Every item reports **Pass / Warn / Fail** with measured values and human-readable reasons — from cable errors to DNS hijacking, clock skew to SMB multichannel.

九组检查覆盖从网线到云端的完整链路：链路层、IPv4、路由、DNS、IPv6、互联网、TOS 服务、传输性能。每项给出通过/警告/失败结论、实测值与通俗解释——网线错误、DNS 劫持、时钟偏移、SMB 多通道等 130+ 种诊断消息。

### Guided repair wizard · 引导式修复向导
Fix broken settings through a four-step wizard: **back up configuration → apply fix → verify connectivity → record history**. Every repair is reversible with pre-fix snapshots.

四步向导安全修复：备份配置 → 执行修复 → 验证连通 → 写入历史。每次修复前自动创建快照，随时可回滚。

### Interface inspector · 网卡体检
All physical, OVS bridge, virtual, tunnel, and Docker interfaces in one table — state, speed, duplex, driver, MTU, error counters, and bearer relationships.

物理口、OVS 桥、虚拟口、隧道、Docker 网桥一览：状态、速率、双工、驱动、MTU、错误计数与承载关系。

### Monitoring & alerts · 监控与告警
Gateway RTT and packet-loss trends (1/7/30 days), continuous background sampling, and an alert history that tells you *when* the network was bad, not just that it was.

网关延迟与丢包趋势（1/7/30 天）、后台持续采样、告警历史——不只告诉你网络坏了，还告诉你什么时候坏的。

### Security exposure scan · 安全面自检
Firewall status, listening-port exposure with risk levels, and remote-tunnel state — find that SSH port bound to `0.0.0.0` before someone else does.

防火墙状态、监听端口暴露面与风险等级、远程隧道状态——在别人之前发现绑定在 `0.0.0.0` 上的高危端口。

### Targeted tools · 针对性工具
Device discovery with IP-conflict detection · TCP/UDP port check · traceroute breakpoint hunting · local-vs-public DNS comparison.

设备发现（IP 冲突检测）、TCP/UDP 端口探测、traceroute 断点定位、本地与公共 DNS 结果对比。

### Config snapshots & history · 快照与历史
Version your network configuration with notes, diff before/after, and restore in one click. Diagnosis and repair history keeps scores, actions, and downloadable reports.

网络配置版本管理（备注/对比/一键还原），诊断与修复历史保留分数、动作与可下载报告。

### Truly international · 真正的国际化
**23 languages** including English, 简体中文, 繁體中文, Deutsch, Français, 日本語, 한국어, Русский — and full **right-to-left layout** for العربية and עברית. Light & dark themes included.

23 种语言（含简繁中文、英、德、法、日、韩、俄等），阿拉伯语与希伯来语支持完整 RTL 排版，浅色/深色双主题。

---

## 📦 Install · 安装

**Requirements**: TerraMaster NAS with TOS 7 · x86_64 or aarch64

Download the package matching your NAS architecture from [Releases](https://github.com/Moechz/netcheck/releases) or the table below, verify the checksum, and install with TOS package tools:

```bash
curl -LO https://github.com/Moechz/netcheck/releases/download/netcheck_0.0.1_beta/netcheck_1.2.50_x86_64.deb
shasum -a 256 -c netcheck_1.2.50_x86_64.deb.sha256   # optional integrity check
sudo dpkg -i netcheck_1.2.50_x86_64.deb
```

After installation, open NetCheck from the TOS desktop and create the admin account on first launch.

安装后在 TOS 桌面打开 NetCheck，首次启动创建管理员账号即可使用。

## Current release: 1.2.50

| Architecture | Package | SHA-256 |
|---|---|---|
| x86_64 | [netcheck_1.2.50_x86_64.deb](raw/main/netcheck_1.2.50_x86_64.deb) | `131c8d4d0b509d93dcce1391748d7a78afb5fd93e96cd907b725577c67623991` |
| aarch64 | [netcheck_1.2.50_aarch64.deb](raw/main/netcheck_1.2.50_aarch64.deb) | `c01a7ee36a26c3fb1aae12801657aa46b00c127e3e159bf848828f1c7ce0c5da` |

## Verify

```bash
shasum -a 256 -c netcheck_1.2.50_x86_64.deb.sha256
shasum -a 256 -c netcheck_1.2.50_aarch64.deb.sha256
```

## Highlights

- L1 source protection: minified frontend and bytecode-only backend in packages
- Arabic and Hebrew language packs with full right-to-left layout
- RTL topbar brand pinned left away from TOS window controls

---

Source code is maintained in [Moechz/TOS-netcheck](https://github.com/Moechz/TOS-netcheck).
