# NetCheck 1.2.54 — review submission bundle

对应上架审核回复所需材料（V1/S1、C2–C8、S8/S9）。
Materials requested by the app review team; see `compliance/README.md`
inside the package (`/usr/local/netcheck/compliance/`) and at
https://github.com/Moechz/netcheck/tree/main/compliance

## Contents

| File | Purpose |
|---|---|
| `netcheck_1.2.54_x86_64.deb` | installed payload for amd64 |
| `netcheck_1.2.54_aarch64.deb` | installed payload for arm64 |
| `MANIFEST.<arch>.json` | package SHA-256 + every packaged file hash + contract |
| `maintainer-scripts/` | preinst / postinst / prerm / postrm as shipped |
| `contract/expected.json` | platform integrity manifest (binary + webui hashes) |
| `compliance/` | privacy policy, third-party services, data rights, licenses, privileged channel, supply chain, SBOM |
| `SHA256SUMS` | checksums of every file in this bundle |

## Verify

```bash
sha256sum -c SHA256SUMS
sha256sum -c netcheck_1.2.54_x86_64.deb.sha256
dpkg-deb -e netcheck_1.2.54_x86_64.deb /tmp/netcheck-control   # maintainer scripts
dpkg-deb -x netcheck_1.2.54_x86_64.deb /tmp/netcheck-payload   # installed payload
```
