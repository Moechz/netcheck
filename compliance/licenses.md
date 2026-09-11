# 开源许可证与依赖许可声明
# Open-Source Licenses and Dependency Notices

- 适用版本：NetCheck 1.2.54（应用 ID `netcheck`）
- 本文回答审核项 **C3**。许可证全文随包分发于
  `/usr/local/netcheck/compliance/licenses/`，应用本体许可证为
  `/usr/local/netcheck/LICENSE`，版权与第三方声明为
  `/usr/local/netcheck/NOTICE`（包内同时提供 `/usr/share/doc/netcheck/copyright`）。

---

## 一、中文版

### 1. 应用本体

| 组件 | 许可证 | 版权 |
|---|---|---|
| NetCheck（Python 后端、WebUI、Go 采集器、eBPF 源码、构建脚本、文档） | **Apache-2.0** | Copyright 2026 Moechz <zhoucaven@163.com> |

Apache-2.0 全文见 `LICENSE`（本目录同名文件即包内 `/usr/local/netcheck/LICENSE`）。

### 2. 运行时随包分发的第三方组件

`bin/netcheck-bpf`（Go 静态链接，依赖已 vendor 于 `bpfcollector/vendor/`）：

| 组件 | 版本 | 许可证 | 声明文件 |
|---|---|---|---|
| github.com/cilium/ebpf | v0.15.0 | MIT | `licenses/cilium-ebpf-MIT.txt` |
| golang.org/x/sys | v0.15.0 | BSD-3-Clause | `licenses/golang-x-sys-BSD-3-Clause.txt` |
| golang.org/x/exp | 2023-02-24 快照 | BSD-3-Clause | `licenses/golang-x-exp-BSD-3-Clause.txt` |
| cilium/ebpf 示例头文件（`bpfcollector/_headers/`，编译进 eBPF 对象） | 随 cilium/ebpf v0.15.0 | BSD-2-Clause | `licenses/cilium-ebpf-examples-headers-BSD-2-Clause.txt` |

`bin/netcheck-bpf` 以 `-trimpath -ldflags='-s -w -buildid='` 构建，未修改上游源码，
未添加任何 copyleft 组件；组合后的二进制仅包含 Apache-2.0 / MIT / BSD-2 / BSD-3
四种宽松许可证代码。

### 3. 运行时使用的系统组件（未随包分发、未修改）

| 组件 | 许可证 | 说明 |
|---|---|---|
| Python 3.10 标准库 | PSF-2.0 | 后端全部逻辑仅使用标准库（`http.server`、`socket`、`hashlib` 等） |
| systemd / systemd-networkd / networkctl / resolvectl | LGPL-2.1-or-later | 以命令行与 D-Bus 方式调用，未链接、未修改、未分发 |
| iproute2（`ip`、`ss`）、`ping`、`traceroute`、`dig`、`ntpq`、`iperf3`（可选）、`ethtool`、`pgrep` 等 | GPL-2.0 / 各自许可 | 仅以独立进程方式调用（execve，无 shell），未链接、未修改、未分发 |
| Linux 内核（AF_PACKET、BPF、/proc、/sys） | GPL-2.0 | 使用内核公开 UAPI，未分发内核代码；eBPF 程序为独立加载的 BPF 字节码，内核要求其自身 license 字段仅用于兼容性声明（源码为 Apache-2.0 项目文件） |

> 说明：以上系统组件由 TOS 系统提供，应用不复制、不打包、不修改它们的文件；
> 若审核需要确认「GPL 传染性」，结论是**它们全部以独立进程/系统调用边界交互，
> 不构成衍生作品**。

### 4. 仅构建期使用（不随包分发）

| 工具 | 许可证 | 用途 |
|---|---|---|
| javascript-obfuscator 5.6.0 | BSD-2-Clause | 前端 JS 压缩混淆（L2 保护） |
| terser 5.51.2 | BSD-2-Clause | 备用 JS 压缩 |
| Node.js 18+ | MIT | 前端检查/构建脚本 |
| Go toolchain 1.23+ | BSD-3-Clause | 构建 `netcheck-bpf` |
| clang / LLVM、libbpf 头文件 | Apache-2.0 WITH LLVM-exception / BSD-2-Clause OR LGPL-2.1 | 仅在 Linux 上重新生成 `_bpf/traffic.bpf.o`（常规构建使用仓库内已提交的 .o） |

### 5. 参考实现与可选依赖

| 项 | 许可证 | 说明 |
|---|---|---|
| sivel/speedtest-cli | Apache-2.0 | 带宽测速的**思路参考**（服务器列表解析与分段传输流程）；NetCheck 使用自有实现（`lib/netcheck/bandwidth/ookla.py`），并在此声明归属以避免歧义 |
| `requests`（可选） | Apache-2.0 | **不随包分发**。仅当运维人员自行放入 `<app_root>/depends/` 时被本地加载使用 |
| Speedtest.net / Ookla 名称与端点 | 商标与使用条款 | 仅在用户主动测速时访问其公开端点，未分发其软件、未使用其商标作为产品名（界面显示为「Ookla 兼容模式」） |

### 6. 无 copyleft 捆绑声明

包内**不含** GPL / LGPL / AGPL / SSPL / BUSL 许可的代码、库或二进制；唯一的
copyleft 交互发生在与 TOS 系统组件（systemd、iproute2 等）的进程边界上。

---

## 二、English version

- **NetCheck itself** — Apache-2.0, Copyright 2026 Moechz
  <zhoucaven@163.com>. Full text shipped as `LICENSE`.
- **Third-party components redistributed inside `bin/netcheck-bpf`** —
  github.com/cilium/ebpf v0.15.0 (MIT), golang.org/x/sys v0.15.0
  (BSD-3-Clause), golang.org/x/exp (BSD-3-Clause), and the cilium/ebpf example
  headers under `bpfcollector/_headers/` (BSD-2-Clause) compiled into the eBPF
  object. Vendored, unmodified, permissively licensed only. Full texts are in
  `licenses/`.
- **System components used but not redistributed** — the Python 3.10 standard
  library (PSF-2.0) is the only runtime dependency; systemd/networkctl/
  resolvectl (LGPL-2.1-or-later), iproute2, ping, traceroute, dig, ntpq, the
  optional iperf3 and ethtool (GPL-2.0 or their own licenses) are invoked as
  separate processes over execve/D-Bus and are neither linked, modified nor
  distributed. The kernel (AF_PACKET, BPF, /proc, /sys) is used through public
  UAPI only.
- **Build-only tools (not shipped)** — javascript-obfuscator 5.6.0 (BSD-2),
  terser (BSD-2), Node.js (MIT), Go toolchain (BSD-3), clang/LLVM
  (Apache-2.0 WITH LLVM-exception) and libbpf headers (BSD-2 OR LGPL-2.1),
  the latter only when regenerating the eBPF object on Linux.
- **Reference implementations / optional dependencies** — sivel/speedtest-cli
  (Apache-2.0) is credited as the conceptual reference for the bandwidth test
  flow; NetCheck uses its own implementation. The optional `requests` module
  (Apache-2.0) is never shipped and only used if an operator places it under
  `<app_root>/depends/`.
- **No copyleft is bundled**: the package contains no GPL/LGPL/AGPL/SSPL/BUSL
  code, library or binary.
