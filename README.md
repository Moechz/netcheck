# NetCheck — Network Diagnostics & Repair for TOS 7

![Release](https://img.shields.io/badge/release-0.0.1%20beta-2E8B52) ![TOS](https://img.shields.io/badge/platform-TerraMaster%20TOS%207-1877f2) ![Languages](https://img.shields.io/badge/i18n-23%20languages-0d9488)

**NetCheck** is a network health application for TerraMaster NAS running **TOS 7**. It diagnoses connectivity problems from the TOS web UI, explains what broke and where, and walks you through safe repairs — no SSH required.

---

## ✨ Features

### One-click full diagnosis
Nine check groups cover the whole path from cable to cloud: **Link layer · IPv4 · Routing · DNS · IPv6 · Internet · TOS services · Transport**. Every item reports **Pass / Warn / Fail** with measured values and human-readable reasons — from cable errors to DNS hijacking, clock skew to SMB multichannel.

### Guided repair wizard
Fix broken settings through a four-step wizard: **back up configuration → apply fix → verify connectivity → record history**. Every repair is reversible with pre-fix snapshots.

### Interface inspector
All physical, OVS bridge, virtual, tunnel, and Docker interfaces in one table — state, speed, duplex, driver, MTU, error counters, and bearer relationships.

### Monitoring & alerts
Gateway RTT and packet-loss trends (1/7/30 days), continuous background sampling, and an alert history that tells you *when* the network was bad, not just that it was.

### Security exposure scan
Firewall status, listening-port exposure with risk levels, and remote-tunnel state — find that SSH port bound to `0.0.0.0` before someone else does.

### Targeted tools
Device discovery with IP-conflict detection · TCP/UDP port check · traceroute breakpoint hunting · local-vs-public DNS comparison.

### Config snapshots & history
Version your network configuration with notes, diff before/after, and restore in one click. Diagnosis and repair history keeps scores, actions, and downloadable reports.

### Truly international
**23 languages** including English, Chinese, German, French, Japanese, Korean, and Russian — with full right-to-left layout for Arabic and Hebrew. Light & dark themes included.

---

## 📦 Install

**Requirements**: TerraMaster NAS with TOS 7 · x86_64 or aarch64

Download the package matching your NAS architecture from [Releases](https://github.com/Moechz/netcheck/releases) or the table below, verify the checksum, and install with TOS package tools:

```bash
curl -LO https://github.com/Moechz/netcheck/releases/download/v1.2.51/netcheck_1.2.51_x86_64.deb
shasum -a 256 -c netcheck_1.2.51_x86_64.deb.sha256   # optional integrity check
sudo dpkg -i netcheck_1.2.51_x86_64.deb
```

After installation, open NetCheck from the TOS desktop and create the admin account on first launch.

## Current release: 1.2.51

| Architecture | Package | SHA-256 |
|---|---|---|
| x86_64 | [netcheck_1.2.51_x86_64.deb](raw/main/netcheck_1.2.51_x86_64.deb) | `1107603e570f2e45995e95cc975be1e787c12e44e0054ebd69aeebd8da75d616` |
| aarch64 | [netcheck_1.2.51_aarch64.deb](raw/main/netcheck_1.2.51_aarch64.deb) | `afa9038ed07bb55b61a558bcad2fc13b98b2534411f61c387537b99bfb74d407` |

## Verify

```bash
shasum -a 256 -c netcheck_1.2.51_x86_64.deb.sha256
shasum -a 256 -c netcheck_1.2.51_aarch64.deb.sha256
```

## Highlights

- L2 source protection: obfuscated frontend (control-flow flattening and string encryption) and bytecode-only backend
- Arabic and Hebrew language packs with full right-to-left layout
- RTL topbar brand pinned left away from TOS window controls

---

Source code is maintained in [Moechz/TOS-netcheck](https://github.com/Moechz/TOS-netcheck).
