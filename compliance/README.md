# NetCheck 合规与材料索引（Compliance Dossier）

本目录是 NetCheck 面向 TOS 应用上架审核（通用模板2）提交的合规材料集合。
它同时存在于三个位置，内容完全一致：

| 位置 | 路径 / URL |
|---|---|
| 安装包内 | `/usr/local/netcheck/compliance/`（本目录原样打包） |
| 应用界面 | 关于 → 合规与政策（`/netcheck/compliance/index.html`，由本目录 Markdown 生成） |
| 公开可访问 URL | https://github.com/Moechz/netcheck/tree/main/compliance |

应用：NetCheck（应用 ID `netcheck`）· 开发者/发布者：Moechz · 版本：1.2.54
联系邮箱：zhoucaven@163.com

## 材料清单与审核项对应关系

| 审核项 | 要求 | 提供的材料 |
|---|---|---|
| V1 / S1 | root 辅助服务 R1 特批/授权文件，或最小化权限实现 | [`privileged-channel.md`](privileged-channel.md)（授权依据、能力最小化清单、白名单、审计、降级与关闭方法、平台核验命令） |
| C2 | 隐私政策（保存期限、用户权利、安全措施、第三方共享、删除途径） | [`privacy-policy.md`](privacy-policy.md) |
| C3 | 开源许可证及依赖许可声明 | [`licenses.md`](licenses.md)、`LICENSE`、`NOTICE`、`licenses/`（各许可证全文） |
| C4 | 第三方服务/API 说明（数据去向、传输地域、共享情况） | [`third-party-services.md`](third-party-services.md) |
| C5 | 用户数据查阅、更正、删除途径 | [`data-rights.md`](data-rights.md) |
| S8 / S9（可选） | .deb、维护脚本、供应链来源说明 | [`supply-chain.md`](supply-chain.md)、`MANIFEST.json`、`SBOM.json` |

## 离线核验

安装后在设备上可直接核验这些材料，无需联网：

```bash
# 材料清单与哈希（与发布包一一对应）
cat /usr/local/netcheck/compliance/MANIFEST.json

# 组件清单（SBOM）
cat /usr/local/netcheck/compliance/SBOM.json

# 许可证全文
ls /usr/local/netcheck/compliance/licenses/
cat /usr/local/netcheck/LICENSE
```

`MANIFEST.json` 由构建流程生成，包含包内每个合规文件的 SHA-256、契约哈希
（`contract/expected.json` 的二进制哈希）、.deb 维护脚本（`preinst/postinst/prerm/postrm`）
的 SHA-256 与字节数，供审核逐项比对。

## 语言

`privacy-policy.md`、`third-party-services.md`、`data-rights.md`、
`privileged-channel.md`、`supply-chain.md` 均为中英双语（每篇先中文、后英文）。
`licenses.md`/`NOTICE` 的许可证全文按原许可证语言（英文）提供。
