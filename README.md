# NetCheck Debian Packages

This repository publishes manually installable NetCheck packages for TerraMaster TOS 7.

## Current release: 1.2.48

| Architecture | Package | SHA-256 |
|---|---|---|
| x86_64 | [netcheck_1.2.48_x86_64.deb](raw/main/netcheck_1.2.48_x86_64.deb) | `39bb188841c614791396014d38f2c58acb5667fba349d7850a4225b119401674` |
| aarch64 | [netcheck_1.2.48_aarch64.deb](raw/main/netcheck_1.2.48_aarch64.deb) | `3c60dfa6eb9b25c9bd9d9f6e668685f4eed304a7aa32bb7d801606963619e243` |

## Verify

```bash
shasum -a 256 -c netcheck_1.2.48_x86_64.deb.sha256
shasum -a 256 -c netcheck_1.2.48_aarch64.deb.sha256
```

## Highlights

- Arabic and Hebrew language packs with full right-to-left layout
- RTL topbar brand pinned left away from TOS window controls

## Install

Install the package matching your NAS architecture with TOS package installation tools, or:

```bash
sudo dpkg -i netcheck_1.2.48_x86_64.deb
```

Source code is maintained in [Moechz/TOS-netcheck](https://github.com/Moechz/TOS-netcheck).
