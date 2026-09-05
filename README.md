# NetCheck Debian Packages

This repository publishes manually installable NetCheck packages for TerraMaster TOS 7.

## Current release: 1.2.47

| Architecture | Package | SHA-256 |
|---|---|---|
| x86_64 | [netcheck_1.2.47_x86_64.deb](raw/main/netcheck_1.2.47_x86_64.deb) | `da6b8b8536b9831bf35484d37516023085b7b8f8c75d79ffe38e23dbe365dcf3` |
| aarch64 | [netcheck_1.2.47_aarch64.deb](raw/main/netcheck_1.2.47_aarch64.deb) | `71ee712613251a4e2015dbed2a9a4f66ee8b896e93e4d3155c228be85621f816` |

## Verify

```bash
shasum -a 256 -c netcheck_1.2.47_x86_64.deb.sha256
shasum -a 256 -c netcheck_1.2.47_aarch64.deb.sha256
```

## Highlights

- Arabic and Hebrew language packs with full right-to-left layout

## Install

Install the package matching your NAS architecture with TOS package installation tools, or:

```bash
sudo dpkg -i netcheck_1.2.47_x86_64.deb
```

Source code is maintained in [Moechz/TOS-netcheck](https://github.com/Moechz/TOS-netcheck).
