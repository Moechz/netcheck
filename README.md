# NetCheck Debian Packages

This repository publishes manually installable NetCheck packages for TerraMaster TOS 7.

## Current release: 1.2.46

| Architecture | Package | SHA-256 |
|---|---|---|
| x86_64 | [netcheck_1.2.46_x86_64.deb](raw/main/netcheck_1.2.46_x86_64.deb) | `d665ca89fa6849d3aee9fb706014208052af2c6d3b551d16960ed3da7e439b46` |
| aarch64 | [netcheck_1.2.46_aarch64.deb](raw/main/netcheck_1.2.46_aarch64.deb) | `f7407a7f262e574f74401668561f8cf4b85afc0f292f0b6e87c9574eeeccf516` |

## Verify

```bash
shasum -a 256 -c netcheck_1.2.46_x86_64.deb.sha256
shasum -a 256 -c netcheck_1.2.46_aarch64.deb.sha256
```

## Install

Install the package matching your NAS architecture with TOS package installation tools, or:

```bash
sudo dpkg -i netcheck_1.2.46_x86_64.deb
```

Source code is maintained in [Moechz/TOS-netcheck](https://github.com/Moechz/TOS-netcheck).
