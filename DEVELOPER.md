# NetCheck Developer Guide

## Prerequisites

- Python 3.10+ (TOS 7 uses 3.10.12)
- Node.js 18+ (for JS syntax checks and i18n tooling only; NOT required at runtime)
- Go 1.23+ (builds `netcheck-bpf`; dependencies are vendored)
- clang/libbpf development headers (only when regenerating `_bpf/traffic.bpf.o` on Linux)
- dpkg-deb (optional; Linux/CI uses it, macOS falls back to the built-in GNU deb writer)
- curl (for smoke tests)

## Project Structure

```
netcheck/
├── bin/
│   ├── netcheck              # Backend entry point (Python, shebang #!/usr/bin/python3)
│   ├── netcheck-helper       # Privileged repair helper (root + capability bounding set; see compliance/privileged-channel.md)
│   └── netcheck-bpf          # Go/eBPF traffic collector (root; AF_PACKET + BPF map)
├── bpfcollector/
│   ├── main.go               # Loads BPF, opens AF_PACKET sockets, serves snapshots
│   ├── socket_linux.go       # SO_ATTACH_BPF and per-interface AF_PACKET setup
│   ├── internal/collector/   # Map polling and rx/tx bps calculation
│   └── _bpf/traffic.bpf.c    # eBPF socket filter source (compiled CO-RE-free object)
├── lib/netcheck/
│   ├── app.py                # HTTP server over Unix socket + endpoint registration
│   ├── router.py             # Route table + middleware (auth → rate_limit → dispatch)
│   ├── config.py             # settings.json (defaults, atomic write, thread-safe)
│   ├── auth.py               # PBKDF2 accounts, sessions, recovery codes, lockout
│   ├── audit.py              # Operation audit trail (F45, JSONL + redaction)
│   ├── logging_setup.py      # Structured JSON logging with rotation
│   ├── collectors/
│   │   ├── sysprobe.py       # Whitelisted command runner (no shell, execve only)
│   │   └── nic.py            # NIC collector (dual OVS/direct architecture)
│   ├── diag/
│   │   ├── engine.py         # Two-stage scheduler (ABC local → DEFGHI external)
│   │   ├── report.py         # Weighted health score, issues aggregation
│   │   ├── history.py        # F19 persistence (daily shards, rolling retention)
│   │   └── checkers/         # 35 checkers across 9 groups (A-I)
│   ├── fix/
│   │   ├── actions.py        # Whitelist definitions + two-sided parameter validation
│   │   ├── helper_client.py  # Unix-socket client for the privileged helper
│   │   └── engine.py         # FixEngine pipeline (precheck → backup → execute → verify)
│   ├── helper/
│   │   ├── server.py         # Helper: SO_PEERCRED + token auth, backup/rollback
│   │   └── network_template.py  # .network rendering + built-in syntax check
│   ├── bandwidth/
│   │   ├── iperf3.py         # Server/client session, log parsing, per-segment JSON
│   │   ├── ookla.py          # Embedded speedtest (live → cache → builtin fallback)
│   │   ├── service.py        # Singleton lock, job lifecycle, history
│   │   ├── traffic.py        # /proc/net/dev fallback sampler → rx/tx bps
│   │   └── bpf_client.py     # Unix-socket client for the Go/eBPF collector
│   ├── monitor/
│   │   ├── sampler.py        # Link-quality periodic sampling (F26)
│   │   └── alerts.py         # Threshold rules, throttle, webhook (F27)
│   ├── tools/
│   │   ├── devices.py        # LAN discovery: ARP + ping sweep (F28)
│   │   ├── portcheck.py      # TCP/UDP probing (F29)
│   │   ├── traceroute.py     # Path analysis with breakpoint (F30)
│   │   ├── dnscompare.py     # Local vs public DNS (F31)
│   │   └── security.py       # Firewall, exposure, tunnel (F33-F34)
│   └── snapshot.py           # Config snapshots + network reset (F23-F24)
├── webui/
│   ├── index.html            # SPA shell
│   └── assets/
│       ├── styles.css        # Light/dark theme (CSS variables)
│       ├── i18n.js           # 21 languages, browser-language resolution
│       ├── api.js            # Unified API client (Bearer auth)
│       └── app.js            # Hash router + all views
├── init.d/
│   ├── netcheck.service      # Main service (User=netcheck)
│   ├── netcheck-helper.service  # Privileged helper (User=root, 3 capabilities, R1 dossier shipped)
│   └── netcheck-bpf.service    # Go/eBPF collector (User=root, 4 capabilities, read-only counters)
├── DEBIAN/                   # dpkg control scripts (preinst/postinst/prerm/postrm)
├── compliance/              # 上架审核合规材料（隐私政策/第三方服务/数据权利/许可/特权通道/供应链 + SBOM）
├── webui/compliance/         # 由 compliance/*.md 生成的页面（随 webui.bz2 分发，关于页入口）
├── tools/build_deb.py        # Official staging, deterministic fallback deb writer, package validator
├── tools/build_compliance.py # Markdown dossier -> webui/compliance/*.html（单一来源）
├── tools/patch_compliance_i18n.js # 把 about.compliance* 键写入 23 个语言包（幂等）
├── tools/make_release_bundle.py   # 组装 release/<version>/ 送审包（deb+维护脚本+契约+材料+校验）
├── build.sh                  # Compliance build (metadata, i18n, contract, package checks)
├── config.ini               # TOS App Center metadata (strict JSON)
├── netcheck.lang             # Official 14-language INI-style metadata
└── tests/                    # 404 automated unit and smoke checks
```

## Running Tests

```bash
cd netcheck/

# All unit tests (no external dependencies)
python3 tests/test_nic_collector.py    # 34 - dual-architecture fixture tests
python3 tests/test_diag.py             # 64 - checker three-branch + score matrix
python3 tests/test_tos_services.py     # 16 - TNAS.online/DDNS/proxy status bridge
python3 tests/test_fix_engine.py       # 45 - helper dispatch, targeted DNS/Gateway/NTP verification, backup/rollback
python3 tests/test_bandwidth.py        # 29 - parsers, mutex, ookla fallback, BPF protocol
cd bpfcollector && go test ./... && cd ..  # BPF collector rate and protocol tests
python3 tests/test_auth_security.py    # 22 - recovery code, lockout, rate limit
python3 tests/test_monitor.py          # 14 - sampler, alert thresholds
python3 tests/test_snapshot.py         #  9 - create/list/diff/prune
python3 tests/test_tools.py            # 13 - port check, traceroute, security
node tests/test_i18n.js                # 50 - language resolution, key parity, and audit
node tests/test_api_client.js          # 14 - TOS proxy CSRF and response handling
node tests/test_clipboard.js           # 11 - Clipboard API and HTTP fallback
node tests/test_layout.js              # 85 - brand header, scrolling, hit-area, toast, login data loading, diagnosis status/button, interface state, hostname, developer metadata, guidance modal, repair inputs, NTP pending, and expandable About layout
node tests/test_nav_icons.js           # 6 - sidebar SVG size, style, and accessibility consistency

# Smoke test (starts a local server on a temp Unix socket)
bash tests/smoke_test.sh               # 38 - full API lifecycle

# E2E test (requires a browser; starts a local proxy server)
python3 tests/serve_e2e.py /tmp/netcheck.sock 8765
# Then open http://127.0.0.1:8765 in a browser
```

## Building

```bash
cd netcheck/
./build.sh x86_64    # or aarch64
# Output: netcheck_<version>_x86_64.deb + .sha256（如 netcheck_1.2.1_x86_64.deb）
```

Build steps (all must pass):

1. Python compile check
2. WebUI JS syntax and i18n checks
3. Go/eBPF collector build
4. LF line-ending check
5. TOS metadata validation (`publisher`, iframe/path exclusions, IDs, icon, versions)
6. Main-service non-root and official `/usr/local/netcheck` path check
7. Compliance page rendering (`compliance/*.md` -> `webui/compliance/*.html`), R1 contract
   generation (SHA-256 manifest), `webui.bz2` creation, compliance dossier + SBOM +
   `MANIFEST.json` staging (dossier, licenses, SBOM, maintainer-script hashes, contract copy)
8. Debian package staging, build, and structural validation

The package payload is staged exactly as required by TerraMaster's current single-package template. The application icon is an SVG named after `config.ini.id`, stored under `images/icons/`, and uses the officially recommended `0 0 512 512` viewBox on a transparent canvas:

```text
DEBIAN/
usr/local/netcheck/
```

`postinst` extracts `webui.bz2` into `/usr/local/netcheck/webui/` and registers `/usr/www/netcheck` as a symlink to that directory. This makes direct `dpkg -i` and App Center deployment expose the same frontend path.

On Linux, the builder calls `dpkg-deb --root-owner-group --build`. On macOS, it writes the GNU ar format directly; this deliberately avoids BSD `ar`, whose output is not suitable for Debian package installation. The builder validates member order, control/data paths, architecture, versions, publisher, service user, icon, and checksums.

## Deploying to TOS

```bash
# On a TOS 7 device:
scp netcheck_<version>_x86_64.deb root@<device>:/tmp/
ssh root@<device>
dpkg -i /tmp/netcheck_<version>_x86_64.deb

# Or via TOS App Center:
# App Center → Manual Install → select .deb
```

## Compliance material (store review)

`compliance/` is the single source for everything the app-store review asks for
(V1/S1, C2-C8, S8/S9): `privileged-channel.md` (R1 authorisation dossier and the
least-privilege capability list), `privacy-policy.md`, `third-party-services.md`,
`data-rights.md`, `licenses.md` + `licenses/`, `supply-chain.md`, `LICENSE`,
`NOTICE`. The build renders each document into `webui/compliance/*.html`
(bilingual, reachable from About → 合规与政策) and stages the Markdown originals
into the package under `/usr/local/netcheck/compliance/` together with
`SBOM.json` and `MANIFEST.json` (file hashes, contract copy, service users and
maintainer-script hashes). `tests/test_compliance.py` and `tests/test_packaging.py`
fail the build if any of it drifts.

Least privilege is enforced by the units and checked at build time: the main
service stays `User=netcheck`, while the two root units declare an explicit
`CapabilityBoundingSet` plus `NoNewPrivileges=true`
(`netcheck-helper.service`: `CAP_CHOWN CAP_DAC_OVERRIDE CAP_NET_ADMIN`;
`netcheck-bpf.service`: `CAP_NET_ADMIN CAP_NET_RAW CAP_BPF CAP_PERFMON`).
Mount-namespace sandboxing cannot be enabled yet (226/NAMESPACE on TOS 6.12.63,
see Known Limitations).

## Review submission bundle

```bash
./build.sh x86_64 && ./build.sh aarch64
python3 tools/make_release_bundle.py          # -> release/<version>/
```

The bundle contains both debs and checksums, `MANIFEST.<arch>.json` (package
SHA-256 + every packaged file hash + contract), `maintainer-scripts/` as shipped
in the `control` member, `contract/expected.json`, the compliance dossier, and
`SHA256SUMS`. It is assembled by reading the built debs back, so it cannot drift
from the payload. The reply letter for the review team is kept next to the repo
root as `REVIEW_REPLY_<version>.md`.

## Key Design Decisions

| Decision | Reason |
|---|---|
| Vanilla JS (no framework) | Requirements §7.1.6 lightweight alternative; zero dependencies, offline |
| `X-Csrf-Token` request header | Required by the TOS WebUI Internal Open proxy for authenticated browser sessions |
| Legacy `execCommand("copy")` fallback | TOS HTTP consoles/iframes may not expose the asynchronous Clipboard API |
| `/var/api` ACL for `netcheck` | Some TOS installations create the admin-owned proxy directory as 0755; the service remains non-root |
| Go + eBPF socket filter for realtime traffic | Counters stay in a kernel BPF map; the filter returns 0 so packet payloads are discarded before copying to Go |
| `/proc/net/dev` fallback | `/api/realtime` remains available if BPF loading or the collector socket is unavailable |
| Platform-proxy path normalization | Real-device verified: TOS may preserve `/v2/proxy/netcheck/` when forwarding to the Unix backend |
| Unix socket (no TCP port) | TOS iframe platform proxy standard; no port conflicts |
| Two-sided parameter validation | FixEngine validates before sending; helper re-validates on receipt |
| `reload + reconfigure` sequence | M1-measured: `networkctl reload` alone doesn't reconfigure running interfaces |
| Built-in .network syntax check | TOS 7.0.1140 has no `networkd-analyze` (device-verified) |
| One-time recovery code | PBKDF2-hashed, rotated on use; no email dependency on NAS |

## Known Limitations

- `arping -D` requires `CAP_NET_RAW` (unavailable to non-root); IP conflict check degrades to `ip neigh` heuristic
- `ss -p` shows no process names for non-root users; exposure list shows "unknown"
- `ProtectSystem=strict` causes 226/NAMESPACE on TOS kernel 6.12.63; removed from unit files
- The deb payload uses the official canonical path `/usr/local/netcheck/`; TOS App Center may expose or map the installed application under its selected storage volume without changing the package layout
