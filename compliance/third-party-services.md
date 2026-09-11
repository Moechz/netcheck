# 第三方服务 / 外部端点与数据去向说明
# Third-Party Services, External Endpoints and Data Flows

- 适用版本：NetCheck 1.2.54（应用 ID `netcheck`）
- 本文回答审核项 **C4**：带宽测速是否调用 ookla / iperf3 等外部服务，数据去向、
  传输地域与共享情况。
- 结论先行：**NetCheck 不自带、不调用 Ookla 官方 CLI/SDK，也不捆绑 iperf3
  二进制或任何第三方测速服务账号**；它使用自己的 HTTPS/ICMP 网络栈与公开端点
  通信，全部外部通信都由您在界面上主动触发，且不会向开发者回传任何数据。

---

## 一、中文版

### 1. 带宽测速（WAN）

| 模式 | 使用的程序/端点 | 协议与端口 | 数据去向 | 触发方式 |
|---|---|---|---|---|
| Ookla 兼容模式（默认，`bandwidth.wan_mode=ookla`） | `https://www.speedtest.net/speedtest-config.php`、`https://www.speedtest.net/speedtest-servers-static.php`（获取服务器列表）；随后与**所选测速服务器**进行 `/speedtest/random{N}x{N}.jpg` 下载与 `/speedtest/upload.php` 上传 | HTTPS/HTTP 80/443 | Speedtest.net（Ookla）公开端点 + 第三方测速服务器 | 仅当您点击「开始测速」 |
| 内置回退端点（服务器列表不可用时） | `https://speed.cloudflare.com`、`https://speed.hetzner.de` | HTTPS 443 | Cloudflare / Hetzner 公共测速端点 | 同上，且仅在获取不到列表时 |
| 自建 HTTP 端点 | 您在设置中填写的 URL（`bandwidth.http_speed_endpoint`） | HTTPS/HTTP | 由您指定的服务器 | 仅当您点击「开始测速」 |
| 局域网 iperf3 | 系统 `iperf3`（**仅在设备上已安装时可用，未随包分发**） | TCP 5201（可配置） | 您在界面上填写的局域网目标 | 仅当您点击「开始测速」 |
| iperf3 服务端模式 | 本机 `iperf3 -s` 监听 5201，等待您自己的客户端连接 | TCP 5201 | 无外部去向，仅接受您发起的连接 | 仅当您点击「启动服务端」 |

说明：

- Ookla 兼容模式是**自行实现的 HTTP 客户端**（Apache-2.0 代码），只使用公开的
  端点协议；不包含、不调用 Ookla 官方 CLI/SDK，不注册 Ookla 账号。
- 请求中携带的信息仅为协议必需项：来源 IP、`User-Agent: NetCheck/1.0`、
  测速用的随机数据块；**不包含**您的账户、主机名、NAS 文件、诊断历史或任何
  个人标识。
- 为避免误报，应用在启动测试前会用一次 UDP `connect(8.8.8.8:80)` 做**路由
  选择**，该调用不发送任何报文。

### 2. 网络诊断产生的外部通信

| 检查项 | 端点 | 协议 | 说明 |
|---|---|---|---|
| 公网连通性（IPv4） | `223.5.5.5`（AliDNS）、`8.8.8.8`（Google DNS） | ICMP Echo | 仅测量丢包与时延 |
| 公网连通性（IPv6） | `2400:3200::1`（AliDNS IPv6） | ICMP/HTTPS | 仅测量可达性 |
| HTTPS 可达性 | `https://www.baidu.com` | HTTPS 443 | 一次 HEAD/GET 探针 |
| DNS 对比（工具） | `223.5.5.5`、`119.29.29.29`、`8.8.8.8` | DNS 53 | 查询 `www.baidu.com` 的 A 记录，用于检测劫持 |
| 代理检查 | 经您配置的代理访问 `http://example.com`（示例目标） | HTTP | 验证代理是否可用 |
| TOS 平台端点 | `https://app.terra-master.com`（应用市场）、`https://download3.terra-master.com`、`https://dl.terra-master.com`（升级） | HTTPS 443 | 检查 TOS 自身服务可达性 |
| NTP | 本机 `ntp.service`/`ntpd`（`ntpq -c peers/rv`） | 本地查询 | 应用不直接连接 NTP 服务器，上游由 TOS 配置 |
| 局域网设备发现 | 本地 IPv4 子网（ARP 表 + ping 扫描） | ARP/ICMP | **仅在您的局域网内**，不外发 |
| TOS 状态 | 本机 TOS 接口（TNAS.online / DDNS / 防火墙状态） | 本地 Unix/HTTP | 只读查询，不联外网 |

上述目标均可在设置中修改（`diag.ping_public_ips`、`diag.public_probe_urls`、
`diag.ipv6_targets`、`diag.tos_endpoints`、`diag.dns_probe_domain`）。

### 3. 报警通道

| 通道 | 去向 | 触发 |
|---|---|---|
| TOS 系统通知 | 本机 TOS 平台 | 默认关闭，需您显式开启 |
| 邮件（SMTP） | 您填写的 SMTP 服务器与收件人 | 默认关闭，需您填写并启用 |
| Webhook | 您填写的 URL | 默认关闭，需您填写并启用 |

告警内容仅包含事件类型、接口、阈值与实际值，不含凭据（凭据在写日志前统一脱敏）。

### 4. 传输地域与共享情况

- **传输地域**：由目标端点决定。测速服务器由应用按地理位置自动选择，也可由您
  手动指定；因此可能位于您所在国家/地区之外，属于跨境传输。ICMP/DNS 探针指向
  您配置的公共地址（默认含中国境内 AliDNS 与美国 Google DNS）。
- **共享情况**：应用不与任何第三方共享数据，也不向其提供账户或历史信息；端点上
  「看到」的仅是您的公网出口 IP 与前述协议必需字段，其处理规则适用各端点的
  隐私政策。开发者不接收、不存储任何上述数据。
- **不开启即不发生**：不点击测速、不运行外部诊断时，应用不会主动与外部端点
  通信；后台监控只使用本地内核统计与本机 ping。

### 5. 如何完全关闭外部通信

1. 设置 → 带宽测速 → WAN 模式选择「局域网 iperf3」或「自建 HTTP 端点」（若均
   不可用则不要执行 WAN 测速）；
2. 不运行「诊断」与「工具」中的外部检查项（或把探针地址改为内网地址）；
3. 关闭报警通道（保持默认关闭）；
4. 关闭持续监控（设置 → 监控 → 关闭），此时应用只在你打开界面时读取本地状态。

---

## 二、English version

**NetCheck does not bundle, invoke or require the official Ookla CLI/SDK, does
not bundle the iperf3 binary, and holds no third-party speed-test account.**
Bandwidth testing is implemented with the application's own HTTP client
(Apache-2.0 code) talking to public endpoints, and `iperf3` is used only if the
operator has already installed it on the device.

### 1. WAN bandwidth measurement

| Mode | Endpoints | Protocol/Port | Trigger |
|---|---|---|---|
| Ookla-compatible (default) | `speedtest.net/speedtest-config.php`, `/speedtest-servers-static.php`, then download `/speedtest/random{N}x{N}.jpg` and upload `/speedtest/upload.php` on the **selected** test server | HTTP/HTTPS 80/443 | only when you press Start |
| Built-in fallback | `speed.cloudflare.com`, `speed.hetzner.de` | HTTPS 443 | only if the server list is unavailable |
| Custom HTTP endpoint | the URL you configure | HTTP/HTTPS | only when you press Start |
| LAN iperf3 | system `iperf3` if installed (not shipped) | TCP 5201 | only when you press Start |
| iperf3 server mode | local `iperf3 -s` on 5201 | TCP 5201 | only when you press Start Server |

Only protocol-required fields leave the device (source IP, `User-Agent:
NetCheck/1.0`, random test payloads). No account, hostname, file, history or
personal identifier is transmitted. A UDP `connect(8.8.8.8:80)` is performed
for route selection only and sends no packet.

### 2. Diagnostic endpoints

ICMP to `223.5.5.5` and `8.8.8.8`; ICMP/HTTPS to `2400:3200::1`; one HTTPS
probe to `https://www.baidu.com`; DNS queries to `223.5.5.5`,
`119.29.29.29`, `8.8.8.8` for the configured probe domain; HTTP proxy check
against `http://example.com` through your proxy; HTTPS reachability to TOS
platform endpoints `app.terra-master.com`, `download3.terra-master.com`,
`dl.terra-master.com`; NTP state read locally from `ntp.service` via `ntpq`
(upstream servers are configured by TOS, not by NetCheck); LAN device
discovery stays inside your local subnet (ARP + ICMP). All targets are
configurable.

### 3. Alert channels

TOS notification (off by default), SMTP (your server), webhook (your URL) —
all off until you configure them; payloads contain event type, interface,
threshold and measured value only.

### 4. Regions and sharing

Transfer region follows the endpoint: speed-test servers may be outside your
country (cross-border), and the default ICMP/DNS probes resolve to AliDNS
(China) and Google DNS (US). The application shares no data with any third
party, and the developer receives and stores nothing. If you never start a
speed test or an external check, no external traffic is generated — background
monitoring uses local kernel counters and local ping only.

### 5. How to disable external traffic completely

Switch WAN mode to LAN iperf3 or a self-hosted HTTP endpoint (or do not run WAN
tests), avoid external diagnostic items (or point probes at internal
addresses), keep alert channels disabled, and turn continuous monitoring off.
