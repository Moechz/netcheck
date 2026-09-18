#!/usr/bin/env python3
"""Assemble the review submission bundle for the built .deb packages.

Output: release/<version>/ containing both architectures, their checksums, the
Debian maintainer scripts, the platform contract, the compliance dossier
extracted from the package, per-architecture manifests and a reviewer index.
Everything is read back from the built .deb files so the bundle cannot drift
from the shipped payload.

Usage: python3 tools/make_release_bundle.py [version]
"""
from __future__ import annotations

import bz2
import hashlib
import importlib.util
import io
import json
import shutil
import sys
import tarfile
from pathlib import Path
from typing import Dict

ROOT = Path(__file__).resolve().parent.parent
BUILDER = ROOT / "tools/build_deb.py"


def load_builder():
    spec = importlib.util.spec_from_file_location("netcheck_build_deb", BUILDER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_member(archive: Dict[str, bytes], tar_name: str, inner: str) -> bytes:
    with tarfile.open(fileobj=io.BytesIO(archive[tar_name]), mode="r:gz") as bundle:
        stream = bundle.extractfile(inner)
        if stream is None:
            raise ValueError(f"{inner} missing from {tar_name}")
        return stream.read()


def build(version: str) -> Path:
    builder = load_builder()
    out = ROOT / "release" / version
    if out.exists():
        shutil.rmtree(out)
    (out / "maintainer-scripts").mkdir(parents=True)
    (out / "contract").mkdir()
    (out / "compliance").mkdir()

    index_lines = [
        f"# NetCheck {version} — review submission bundle",
        "",
        "对应上架审核回复所需材料（V1/S1、C2–C8、S8/S9）。",
        "Materials requested by the app review team; see `compliance/README.md`",
        "inside the package (`/usr/local/netcheck/compliance/`) and at",
        "https://github.com/Moechz/netcheck/tree/main/compliance",
        "",
        "## Contents",
        "",
        "| File | Purpose |",
        "|---|---|",
    ]
    checksums = []
    manifests = {}
    for deb_arch in ("amd64", "arm64"):
        legacy = {"amd64": "x86_64", "arm64": "aarch64"}[deb_arch]
        deb = ROOT / f"netcheck_{version}_{deb_arch}.deb"
        if not deb.is_file():
            deb = ROOT / f"netcheck_{version}_{legacy}.deb"
        if not deb.is_file():
            raise SystemExit(
                f"missing package: netcheck_{version}_{deb_arch}.deb (run ./build.sh {deb_arch})")
        members = builder.extract_ar_members(deb)
        control = members["control.tar.gz"]
        data = members["data.tar.gz"]

        # maintainer scripts (identical for both architectures) - audit item S8/S9
        if not (out / "maintainer-scripts" / "postinst").exists():
            for script in ("preinst", "postinst", "prerm", "postrm"):
                body = read_member(members, "control.tar.gz", f"./{script}")
                (out / "maintainer-scripts" / script).write_bytes(body)
                (out / "maintainer-scripts" / script).chmod(0o755)
            (out / "contract" / "expected.json").write_bytes(
                read_member(members, "data.tar.gz",
                            "./usr/local/netcheck/contract/expected.json"))
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as bundle:
                for member in bundle.getmembers():
                    name = member.name
                    if not member.isfile():
                        continue
                    if name.startswith("./usr/local/netcheck/compliance/"):
                        relative = name[len("./usr/local/netcheck/compliance/"):]
                        if not relative:
                            continue
                        target = out / "compliance" / relative
                        target.parent.mkdir(parents=True, exist_ok=True)
                        stream = bundle.extractfile(member)
                        assert stream is not None
                        target.write_bytes(stream.read())
                for extra in ("LICENSE", "NOTICE"):
                    stream = bundle.extractfile(f"./usr/local/netcheck/{extra}")
                    if stream is not None:
                        (out / extra).write_bytes(stream.read())

        shutil.copy2(deb, out / deb.name)
        shutil.copy2(deb.with_suffix(".deb.sha256"), out / f"{deb.name}.sha256")
        package_sha = sha256(deb)
        assert package_sha in (out / f"{deb.name}.sha256").read_text(encoding="utf-8")

        manifest = json.loads(
            read_member(members, "data.tar.gz",
                        "./usr/local/netcheck/compliance/MANIFEST.json"))
        manifest["package"] = {
            "file": deb.name,
            "sha256": package_sha,
            "bytes": deb.stat().st_size,
            "architecture": manifest["deb_architecture"],
            "verified_by": "sha256sum -c " + f"{deb.name}.sha256",
        }
        manifests[deb_arch] = manifest
        (out / f"MANIFEST.{deb_arch}.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=False) + "\n",
            encoding="utf-8")
        checksums.append(f"{package_sha}  {deb.name}")
        index_lines.append(
            f"| `{deb.name}` | installed payload for {manifest['deb_architecture']} |")

    index_lines += [
        "| `MANIFEST.<arch>.json` | package SHA-256 + every packaged file hash + contract |",
        "| `maintainer-scripts/` | preinst / postinst / prerm / postrm as shipped |",
        "| `contract/expected.json` | platform integrity manifest (binary + webui hashes) |",
        "| `compliance/` | privacy policy, third-party services, data rights, licenses, privileged channel, supply chain, SBOM |",
        "| `SHA256SUMS` | checksums of every file in this bundle |",
        "",
        "## Verify",
        "",
        "```bash",
        "sha256sum -c SHA256SUMS",
        "sha256sum -c netcheck_%s_amd64.deb.sha256" % version,
        "dpkg-deb -e netcheck_%s_amd64.deb /tmp/netcheck-control   # maintainer scripts" % version,
        "dpkg-deb -x netcheck_%s_amd64.deb /tmp/netcheck-payload   # installed payload" % version,
        "```",
        "",
    ]
    (out / "README.md").write_text("\n".join(index_lines), encoding="utf-8")

    script_sums = []
    for script in sorted((out / "maintainer-scripts").iterdir()):
        script_sums.append(f"{sha256(script)}  {script.relative_to(out).as_posix()}")
    (out / "maintainer-scripts" / "SHA256SUMS").write_text(
        "\n".join(script_sums) + "\n", encoding="utf-8")

    entries = []
    for path in sorted(out.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            entries.append(f"{sha256(path)}  {path.relative_to(out).as_posix()}")
    (out / "SHA256SUMS").write_text("\n".join(entries) + "\n", encoding="utf-8")

    (out / "review-response.json").write_text(
        json.dumps({
            "version": version,
            "review_items": manifests["amd64"]["review_items"],
            "notes": manifests["amd64"]["note"],
            "contact": manifests["amd64"]["contact"],
        }, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"release bundle: {out.relative_to(ROOT)}")
    for path in sorted(out.rglob("*")):
        print("  " + path.relative_to(out).as_posix())
    return out


def main() -> int:
    version = sys.argv[1] if len(sys.argv) > 1 else json.loads(
        (ROOT / "version.json").read_text(encoding="utf-8"))["version"]
    build(str(version))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
