# 供应链与构建来源说明（含 .deb 维护脚本）
# Supply Chain, Build Provenance and Debian Maintainer Scripts

- 适用版本：NetCheck 1.2.54（应用 ID `netcheck`）
- 本文回答审核项 **S8 / S9（可选补充）**：`.deb`、维护脚本与仓库来源说明。

---

## 一、中文版

### 1. 仓库与来源

| 用途 | 仓库 | 可见性 |
|---|---|---|
| 开发仓库（全部源码、设计文档、测试、构建脚本） | `Moechz/TOS-netcheck-pv` | 私有（开发期） |
| 发布仓库（.deb 产物、版本表、合规材料副本） | `Moechz/netcheck` | 公开：https://github.com/Moechz/netcheck |
| 合规材料（本目录） | `Moechz/netcheck/compliance/` | 公开 URL，可直接下载比对 |

应用的全部二进制均由上述开发仓库在受控构建机上生成，无第三方预编译产物：
`bin/netcheck`、`bin/netcheck-helper` 是包内 Python 入口脚本，`bin/netcheck-bpf`
由 `bpfcollector/`（Go，依赖全部 vendor 于仓库内）编译而来，`webui.bz2` 由
`webui/` 打包而来。

> 审核如需**明文源码**（后端 `.py`、前端未混淆 `.js`、eBPF `.bpf.c`），可通过
> zhoucaven@163.com 索取：我们提供只读仓库访问或源码压缩包（含构建脚本），
> 用于平台侧静态审计，作为「L1/L2 保护」与「可审计性」的平衡。

### 2. 构建环境与命令（可复现）

```bash
# 环境：macOS/Linux 均可；Python 3.10（目标设备版本，用于生成兼容 .pyc）、
#       Node 18+（前端检查与压缩）、Go 1.23+（可选，vendor 已就绪）
#       dpkg-deb（Linux 可选；无 dpkg-deb 时使用内置 GNU deb 写入器）

cd netcheck
./build.sh x86_64      # 产出 netcheck_1.2.54_x86_64.deb + .sha256
./build.sh aarch64     # 产出 netcheck_1.2.54_aarch64.deb + .sha256
```

`build.sh` 的 8 个强制步骤：

1. Python 全量编译检查（`compileall`）；
2. WebUI 语法、i18n 键一致性、API 客户端、剪贴板、布局、导航图标检查（Node）；
3. Go/eBPF 采集器构建（无 Go 工具链时使用仓库内已提交的 `bin/netcheck-bpf`）；
4. 行尾检查（禁止 CRLF）；
5. TOS 元数据校验（`config.ini` / `DEBIAN/control` / `version.json` 版本一致、
   14 种官方语言、图标 512×512 等）；
6. 主服务必须为非 root（`User=netcheck`）且使用官方路径；
7. 契约（`contract/expected.json`）与 `webui.bz2` 生成、合规材料（本目录）打包、
   SBOM 与 MANIFEST 生成；
8. Debian 打包与结构校验（成员顺序、`./` 前缀布局、架构、md5sums、必需文件、
   许可证与合规材料存在性）。

**确定性处理**：包内所有条目 `mtime=0`、`uid/gid=0`、`uname/gname=root`；
排除 `.DS_Store`/`__pycache__`；`bin/netcheck-bpf` 使用
`-trimpath -ldflags='-s -w -buildid='`；后端 `lib/` 以 Python 3.10 `compileall -b`
生成 `.pyc` 后删除 `.py`（L1 源码保护），前端 JS 经 javascript-obfuscator 处理
（L2）。上述工具版本记录于 SBOM 的 `metadata.tools`。

### 3. .deb 维护脚本（S8/S9 核验对象）

四个脚本位于包的 control 成员中，可直接抽取核验：

```bash
dpkg-deb -e netcheck_1.2.54_x86_64.deb /tmp/netcheck-control
ls -l /tmp/netcheck-control      # control md5sums preinst postinst prerm postrm
sha256sum /tmp/netcheck-control/postinst /tmp/netcheck-control/prerm \
          /tmp/netcheck-control/postrm /tmp/netcheck-control/preinst
```

| 脚本 | 行为摘要（仅使用幂等命令，无网络访问、无脚本下载） |
|---|---|
| `preinst` | 空操作（`exit 0`）。刻意保持最小：即使专用账户尚未创建，dpkg 也能完成解包 |
| `postinst` | ① 创建系统账户/组 `netcheck`（`--no-create-home --shell /usr/sbin/nologin`）；② 创建 `data/`（`data/auth` 权限 0700）与 `logs/` 并 `chown netcheck`；③ 处理 TOS 的 `/var/api`（符号链接目标、ACL 或组回退）；④ 解包 `webui.bz2` → `webui/`；⑤ 注册 `/usr/www/netcheck` 符号链接；⑥ 安装三个 systemd 单元 → `daemon-reload` → `enable` → `restart` |
| `prerm` | `systemctl stop` 并 `disable` 三个单元 |
| `postrm` | 移除 `/usr/www/netcheck`；`purge` 时额外删除 `data/`、`logs/`、`/run/netcheck`、三个单元文件并 `daemon-reload`（普通 `remove` 保留数据，便于升级/重装） |

脚本的 SHA-256 与字节数同时记录在包内 `compliance/MANIFEST.json`，便于逐版本比对；
脚本不进行任何网络下载、不执行 `curl|bash`、不修改与自身无关的目录。

### 4. 包结构

```
netcheck_1.2.54_<arch>.deb
├── debian-binary
├── control.tar.gz   → control, md5sums, preinst, postinst, prerm, postrm
└── data.tar.gz      → ./usr/local/netcheck/
                        ├── bin/{netcheck,netcheck-helper,netcheck-bpf}
                        ├── lib/netcheck/**.pyc
                        ├── webui.bz2（含 compliance/*.html）
                        ├── init.d/*.service
                        ├── config.ini, netcheck.lang, version.json
                        ├── contract/expected.json
                        ├── compliance/{README,privacy-policy,third-party-services,
                        │               data-rights,licenses,privileged-channel,
                        │               supply-chain}.md, MANIFEST.json, SBOM.json,
                        │               licenses/*, LICENSE, NOTICE
                        ├── LICENSE, NOTICE
                        └── images/icons/netcheck.svg
                      → ./usr/share/doc/netcheck/copyright
```

### 5. 独立复核命令

```bash
sha256sum -c netcheck_1.2.54_x86_64.deb.sha256
dpkg-deb -I netcheck_1.2.54_x86_64.deb          # control 字段与版本
dpkg-deb -c netcheck_1.2.54_x86_64.deb | head   # 文件清单与权限
dpkg-deb -e netcheck_1.2.54_x86_64.deb /tmp/nc  # 维护脚本
python3 - <<'PY'                                # 契约哈希比对（安装后）
import json,hashlib,pathlib
c=json.load(open('/usr/local/netcheck/contract/expected.json'))
for name,key in (('bin/netcheck','backend_binary_sha256'),
                 ('bin/netcheck-helper','helper_binary_sha256'),
                 ('bin/netcheck-bpf','bpf_collector_binary_sha256'),
                 ('webui.bz2','webui_bz2_sha256')):
    p=pathlib.Path('/usr/local/netcheck')/name
    print(name, hashlib.sha256(p.read_bytes()).hexdigest()==c[key])
PY
```

### 6. SBOM

`compliance/SBOM.json` 为 CycloneDX 1.5 风格的最小软件物料清单，列出应用本体
（Apache-2.0）与全部随包/构建期组件及其 SPDX 许可证标识；`MANIFEST.json` 列出
每个合规文件与维护脚本的 SHA-256、契约哈希与构建信息。

---

## 二、English version

Development happens in the private repository `Moechz/TOS-netcheck-pv`; release
artifacts and compliance material are published at
https://github.com/Moechz/netcheck. Every binary in the package is built from
that source on a controlled build host — nothing is precompiled by a third
party: `bin/netcheck`/`bin/netcheck-helper` are the Python entry points,
`bin/netcheck-bpf` comes from `bpfcollector/` (Go, fully vendored), and
`webui.bz2` is packaged from `webui/`. Plaintext source (`.py`, unobfuscated
`.js`, `.bpf.c`) is available on request for platform-side static review.

Build: `./build.sh x86_64` and `./build.sh aarch64`, with the eight mandatory
stages listed above (compile checks, WebUI/i18n checks, Go build, CRLF check,
TOS metadata validation, non-root service check, contract/webui/compliance/SBOM
generation, packaging validation). Staging is deterministic (`mtime=0`,
`uid/gid=0`, root names, no `.DS_Store`/`__pycache__`, `-trimpath -s -w
-buildid=`); `lib/` ships as Python 3.10 `.pyc` files and the frontend JS is
obfuscated, with tool versions recorded in the SBOM.

The four Debian maintainer scripts are inside the control member and can be
extracted with `dpkg-deb -e`; their SHA-256 and sizes are recorded in
`compliance/MANIFEST.json`. `preinst` is a no-op; `postinst` creates the
non-root `netcheck` account, prepares data/log directories and the TOS
`/var/api` ACL, unpacks `webui.bz2`, links `/usr/www/netcheck` and registers the
three systemd units; `prerm` stops and disables them; `postrm` removes
`/usr/www/netcheck` and, on `purge`, all application data, logs, runtime
sockets and unit files. No maintainer script downloads anything or touches
unrelated paths. Verification commands and the CycloneDX-style `SBOM.json` /
`MANIFEST.json` are provided in sections 5 and 6.
