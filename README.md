# NetCheck Debian Packages

This repository publishes manually installable NetCheck packages for TerraMaster TOS 7.

## Current release: 1.2.49

| Architecture | Package | SHA-256 |
|---|---|---|
| x86_64 | [netcheck_1.2.49_x86_64.deb](raw/main/netcheck_1.2.49_x86_64.deb) | `1fb46e1f62ceb646000f21aa6d1f68c7ebbe2a1b2cc65c2a0380ae0ca423bfb3` |
| aarch64 | [netcheck_1.2.49_aarch64.deb](raw/main/netcheck_1.2.49_aarch64.deb) | `09751ba422eb59cce9aa63561812019697890a6200120b4bcdf8ba3ee5281540` |

## Verify

```bash
shasum -a 256 -c netcheck_1.2.49_x86_64.deb.sha256
shasum -a 256 -c netcheck_1.2.49_aarch64.deb.sha256
```

## Highlights

- Arabic and Hebrew language packs with full right-to-left layout
- RTL topbar brand pinned left away from TOS window controls

## Install

Install the package matching your NAS architecture with TOS package installation tools, or:

```bash
sudo dpkg -i netcheck_1.2.49_x86_64.deb
```

Source code is maintained in [Moechz/TOS-netcheck](https://github.com/Moechz/TOS-netcheck).
