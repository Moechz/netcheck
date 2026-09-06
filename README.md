# NetCheck Debian Packages

This repository publishes manually installable NetCheck packages for TerraMaster TOS 7.

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

## Install

Install the package matching your NAS architecture with TOS package installation tools, or:

```bash
sudo dpkg -i netcheck_1.2.50_x86_64.deb
```

Source code is maintained in [Moechz/TOS-netcheck](https://github.com/Moechz/TOS-netcheck).
