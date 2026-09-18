#!/usr/bin/env python3
"""Publish a NetCheck version to the public artifact repo and create its Release.

Usage
-----
  python3 tools/github_release.py inspect
  python3 tools/github_release.py publish [--version 1.2.54] [--repo Moechz/netcheck]
                                          [--prerelease] [--dry-run]

What `publish` does (all through the GitHub REST API, token read from
~/.config/netcheck-gh-token - the token value is never printed):

  1. collects the built packages, the compliance dossier and the release
     metadata (`release/<version>/`) from the working tree;
  2. regenerates README.md from the published one (version, hashes, compliance
     section);
  3. writes one commit to the repo tree that updates those files and drops the
     previous version's packages (their Release keeps the assets);
  4. creates the `v<version>` tag + Release and uploads the four .deb assets;
  5. verifies the result by downloading every asset anonymously and comparing
     SHA-256.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import string
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
TOKEN_PATH = Path.home() / ".config" / "netcheck-gh-token"
API = "https://api.github.com"
UPLOADS = "https://uploads.github.com"
DEFAULT_REPO = "Moechz/netcheck"
ARCHES = ("amd64", "arm64")
# Pre-1.2.56-relabel artefacts used the kernel-style names; accept them when
# collecting local files so older trees can still be re-published.
LEGACY_ARCH = {"amd64": "x86_64", "arm64": "aarch64"}


def local_artifact(version: str, arch: str, suffix: str = ".deb") -> Path:
    """Resolve netcheck_<v>_<arch><suffix> preferring the Debian architecture
    name, falling back to the legacy kernel-style name."""
    for name in (arch, LEGACY_ARCH[arch]):
        candidate = ROOT / f"netcheck_{version}_{name}{suffix}"
        if candidate.is_file():
            return candidate
    return ROOT / f"netcheck_{version}_{arch}{suffix}"

COMPLIANCE_SECTION = """
---

## 🔐 Compliance & policies

Privacy policy, third-party service and data-flow disclosure, open-source
licence notices, user data access/correction/deletion paths, the privileged
channel (R1) authorisation dossier and the software bill of materials ship with
every package under `/usr/local/netcheck/compliance/`, and are published here:

- [Privacy policy](compliance/privacy-policy.md)
- [Third-party services & data flows](compliance/third-party-services.md)
- [Data access, correction and deletion](compliance/data-rights.md)
- [Licences & dependencies](compliance/licenses.md)
- [Privileged channel (root helper) authorisation & least privilege](compliance/privileged-channel.md)
- [Supply chain & build provenance](compliance/supply-chain.md)
- [Software bill of materials](compliance/SBOM.json)
"""

RELEASE_NOTES = """## NetCheck {version}

{summary}

### Packages

| File | For NAS with | CPU family |
|---|---|---|
| `netcheck_{version}_amd64.deb` | Intel / AMD 64-bit models | amd64 (= x86-64) |
| `netcheck_{version}_arm64.deb` | ARM 64-bit models | arm64 (= aarch64) |

**Which one do I need?** Run `dpkg --print-architecture` over SSH (or check the
CPU in TOS Control Panel > System Status): the output (`amd64` or `arm64`)
is exactly the suffix of the package you should install.

### Verify

```bash
shasum -a 256 -c netcheck_{version}_amd64.deb.sha256
sudo dpkg -i netcheck_{version}_amd64.deb
```

### Compliance material submitted with this version

- `compliance/` — privacy policy, third-party services, data rights, licences, privileged-channel (R1)
  dossier, supply chain and SBOM (also shipped inside the package)
- `release/{version}/` — per-architecture `MANIFEST.*.json` (package SHA-256 plus every packaged file
  hash), the Debian maintainer scripts as shipped, the platform contract and `SHA256SUMS`

---

## NetCheck {version}（中文摘要）

{summary_zh}

### 合规材料（随包分发）

- `compliance/`：隐私政策、第三方服务与数据去向、数据权利、开源许可、特权通道（R1）授权说明、
  供应链与 SBOM；
- `release/{version}/`：双架构 `MANIFEST.*.json`（包 SHA-256 + 包内每个文件哈希）、随包维护脚本、
  平台契约与 `SHA256SUMS`。

**校验 / Verify**

```bash
shasum -a 256 -c netcheck_{version}_amd64.deb.sha256
shasum -a 256 -c netcheck_{version}_arm64.deb.sha256
```

**怎么选包？** SSH 执行 `dpkg --print-architecture`，输出 `amd64`（Intel/AMD 机型）就下 amd64 包，输出 `arm64`（ARM 机型）就下 arm64 包；也可在 TOS 控制面板 > 系统状态查看 CPU 型号。
"""

SUMMARY_EN = (
    "Compliance release for the TOS app-store review: ships the complete compliance dossier "
    "(privacy policy, open-source licences and dependency notices, third-party service and data-flow "
    "disclosure, user data access/correction/deletion paths, supply-chain provenance, SBOM) both inside "
    "the package and in this repository, and tightens the privileged services to a minimal capability "
    "set - `netcheck-helper.service` keeps only CAP_CHOWN, CAP_DAC_OVERRIDE and CAP_NET_ADMIN, "
    "`netcheck-bpf.service` only CAP_NET_ADMIN, CAP_NET_RAW, CAP_BPF and CAP_PERFMON, both with "
    "NoNewPrivileges=true. No functional change for users; the privileged channel can be disabled with "
    "`repair.mode=guide`."
)
SUMMARY_ZH = (
    "面向 TOS 应用上架审核的合规版本：随包（并在本仓库）提供完整合规材料（隐私政策、开源许可与依赖声明、"
    "第三方服务与数据去向、用户数据查阅/更正/删除途径、供应链来源、SBOM），并将特权服务收紧到最小能力集——"
    "`netcheck-helper.service` 仅保留 CAP_CHOWN / CAP_DAC_OVERRIDE / CAP_NET_ADMIN，"
    "`netcheck-bpf.service` 仅保留 CAP_NET_ADMIN / CAP_NET_RAW / CAP_BPF / CAP_PERFMON，均启用 "
    "NoNewPrivileges。对用户功能无影响；特权通道可通过 `repair.mode=guide` 关闭。"
)


def token() -> str:
    if not TOKEN_PATH.is_file():
        raise SystemExit(f"missing GitHub token file: {TOKEN_PATH}")
    value = TOKEN_PATH.read_text(encoding="utf-8").strip()
    if not value:
        raise SystemExit(f"empty GitHub token file: {TOKEN_PATH}")
    return value


def api(method: str, url: str, payload: Optional[dict] = None, *, raw: bytes = None,
        content_type: str = "application/json", auth: bool = True,
        attempts: int = 4) -> Tuple[int, bytes]:
    """Call the API with retries: the link to GitHub is occasionally flaky."""
    data = None
    if raw is not None:
        data = raw
    elif payload is not None:
        data = json.dumps(payload).encode("utf-8")
    last_error = ""
    for attempt in range(1, attempts + 1):
        request = urllib.request.Request(url, data=data, method=method)
        if raw is not None:
            request.add_header("Content-Type", content_type)
        elif data is not None:
            request.add_header("Content-Type", "application/json")
        request.add_header("Accept", "application/vnd.github+json")
        request.add_header("X-GitHub-Api-Version", "2022-11-28")
        request.add_header("User-Agent", "netcheck-release-tool")
        request.add_header("Connection", "close")
        if auth:
            request.add_header("Authorization", f"Bearer {token()}")
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", "replace")
            # "400 malformed" from api.github.com/git/blobs is occasionally a
            # transient gateway hiccup (observed 2026-09: same body re-POSTs fine)
            transient = error.code in (429, 500, 502, 503, 504) or (
                error.code == 400 and "malformed request" in body
                and "/git/blobs" in url)
            if transient and attempt < attempts:
                last_error = f"HTTP {error.code}: {body[:200]}"
            else:
                raise SystemExit(
                    f"HTTP {error.code} for {method} {url}: {body[:400]}") from error
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as error:
            last_error = f"{type(error).__name__}: {error}"
            if attempt >= attempts:
                raise SystemExit(
                    f"network error for {method} {url}: {last_error}") from error
        delay = 2 ** attempt
        print(f"  retry {attempt}/{attempts - 1} after {last_error} "
              f"(waiting {delay}s)")
        time.sleep(delay)
    raise SystemExit(f"unreachable: {last_error}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def blob(repo: str, path: Path) -> str:
    status, body = api("POST", f"{API}/repos/{repo}/git/blobs", {
        "content": base64.b64encode(path.read_bytes()).decode("ascii"),
        "encoding": "base64",
    })
    assert status == 201, status
    return json.loads(body)["sha"]


def render_readme(current: str, version: str, old_to_new: Dict[str, str],
                  hashes: Dict[str, str]) -> str:
    """Render the public README from tools/templates/README.public.md.

    The template is the single source for the published README (badge, install
    snippet, version table, compliance links); the published README is only
    used as a fallback when the template is missing.
    """
    template_path = ROOT / "tools" / "templates" / "README.public.md"
    if template_path.is_file():
        template = string.Template(template_path.read_text(encoding="utf-8"))
        return template.safe_substitute(version=version, sha_amd64=hashes["amd64"],
                                        sha_arm64=hashes["arm64"])
    text = current
    for old, new in sorted(old_to_new.items()):
        text = text.replace(old, new)
    if "Compliance & policies" not in text:
        text = text.rstrip("\n") + "\n" + COMPLIANCE_SECTION
    return text


def bpf_src_files() -> Dict[str, Path]:
    """Repo-relative path -> local file for the Go/eBPF collector source.

    Kept for the tarball builder; the repo tree uses app_source_files().
    """
    src_root = ROOT / "bpfcollector"
    files: Dict[str, Path] = {}
    for path in sorted(src_root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(src_root)
        if rel.parts[0] == "vendor" or path.name == ".DS_Store":
            continue
        files[f"bpfcollector/{rel.as_posix()}"] = path
    if "bpfcollector/main.go" not in files or "bpfcollector/_bpf/traffic.bpf.c" not in files:
        raise SystemExit("bpfcollector source incomplete (main.go / traffic.bpf.c missing)")
    return files


# Full application source mirror published for auditability (review V6,
# 2026-09-18: the rule covers every executable artefact, including the Python
# backend bytecode - so the tree mirrors everything that builds the deb).
_SOURCE_EXCLUDE_DIRS = {
    "release", "__pycache__", "node_modules", ".git", "vendor",
    "webui/compliance",  # generated by tools/build_compliance.py
}
_SOURCE_EXCLUDE_NAMES = {".DS_Store"}
# .o kept: bpfcollector/_bpf/traffic.bpf.o is committed so the Go build
# needs no clang (see bpfcollector/README.md)
_SOURCE_EXCLUDE_SUFFIXES = {".deb", ".sha256", ".pyc", ".bz2", ".log"}
_SOURCE_EXCLUDE_EXACT = {
    # build artefacts / ELF binaries (source of bin/netcheck-bpf is bpfcollector/)
    "bin/netcheck-bpf",
}


def app_source_files() -> Dict[str, Path]:
    files: Dict[str, Path] = {}
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT).as_posix()
        parts = rel.split("/")
        if any(d in _SOURCE_EXCLUDE_DIRS for d in parts[:-1]):
            continue
        if path.name in _SOURCE_EXCLUDE_NAMES:
            continue
        if path.suffix in _SOURCE_EXCLUDE_SUFFIXES:
            continue
        if rel in _SOURCE_EXCLUDE_EXACT:
            continue
        if path.name.startswith("REVIEW_"):  # internal review correspondence
            continue
        if path.name.startswith("netcheck_") and path.suffix == ".gz":
            continue  # generated source-snapshot artefacts
        files[rel] = path
    for required in ("lib/netcheck/app.py", "webui/index.html",
                     "bpfcollector/main.go", "DEBIAN/postinst", "build.sh"):
        if required not in files:
            raise SystemExit(f"source mirror incomplete: {required} missing")
    return files


def make_src_tarball(version: str) -> Path:
    """Full application source snapshot pinned to this release (asset)."""
    import tarfile, io
    out = ROOT / f"netcheck_{version}_src.tar.gz"
    entries = app_source_files()
    with tarfile.open(out, "w:gz") as tar:
        for rel, path in sorted(entries.items()):
            info = tarfile.TarInfo(f"netcheck-src/{rel}")
            data = path.read_bytes()
            info.size = len(data)
            info.mtime = 0
            info.uid = info.gid = 0
            info.mode = 0o755 if path.suffix == ".sh" or rel == "build.sh" else 0o644
            info.uname = info.gname = "root"
            tar.addfile(info, io.BytesIO(data))
    sidecar = ROOT / f"netcheck_{version}_src.tar.gz.sha256"
    sidecar.write_text(f"{sha256(out)}  {out.name}\n", encoding="utf-8")
    print(f"  built {out.name} ({out.stat().st_size:,} B, {len(entries)} files)")
    return out


def collect(version: str) -> Dict[str, Path]:
    """Return repo-relative path -> local file for the new commit."""
    files: Dict[str, Path] = {}
    for arch in ARCHES:
        deb = local_artifact(version, arch)
        checksum = local_artifact(version, arch, ".deb.sha256")
        for path in (deb, checksum):
            if not path.is_file():
                raise SystemExit(f"missing artifact: {path} (run ./build.sh {arch})")
        files[deb.name] = deb
        files[checksum.name] = checksum
    compliance = ROOT / "compliance"
    for path in sorted(compliance.rglob("*")):
        if path.is_file() and path.name not in {".DS_Store", "MANIFEST.json", "SBOM.json"}:
            files[path.relative_to(ROOT).as_posix()] = path
    bundle = ROOT / "release" / version
    # SBOM and per-build MANIFEST are generated by the build and published from
    # the release bundle (they contain hashes of the built package).
    for name in ("SBOM.json", "MANIFEST.json"):
        source = bundle / "compliance" / name
        if not source.is_file():
            raise SystemExit(
                f"missing {name} in {bundle}/compliance "
                f"(run ./build.sh <arch> and tools/make_release_bundle.py first)")
        files[f"compliance/{name}"] = source
    for path in sorted(bundle.rglob("*")):
        if not path.is_file():
            continue
        if path.name in {"SHA256SUMS", "README.public.md"} or path.suffix == ".deb":
            continue
        if path.name.endswith(".deb.sha256"):
            continue
        relative = path.relative_to(bundle).as_posix()
        # The canonical dossier lives at the repo root; the bundle's nested copy
        # is only for the emailed release archive.
        if relative.startswith("compliance/"):
            continue
        files[f"release/{version}/{relative}"] = path
    # Auditable FULL application source (review item V6: every executable
    # artefact incl. the Python backend must have readable source).
    files.update(app_source_files())
    return files


def cmd_inspect(repo: str) -> int:
    status, body = api("GET", f"{API}/repos/{repo}/git/trees/main?recursive=1")
    tree = json.loads(body)["tree"]
    print(f"repo {repo}: {len(tree)} entries")
    for entry in tree:
        print(f"  {entry['type']:4} {entry.get('size', ''):>9} {entry['path']}")
    status, body = api("GET", f"{API}/repos/{repo}/releases?per_page=5")
    for release in json.loads(body):
        print(f"  release {release['tag_name']} '{release['name']}' "
              f"prerelease={release['prerelease']} "
              f"assets={[a['name'] for a in release['assets']]}")
    return 0


def cmd_publish(args) -> int:
    repo = args.repo
    version = args.version or json.loads(read(ROOT / "version.json"))["version"]
    status, body = api("GET", f"{API}/repos/{repo}/git/refs/heads/main")
    head = json.loads(body)["object"]["sha"]
    status, body = api("GET", f"{API}/repos/{repo}/git/commits/{head}")
    base_tree = json.loads(body)["tree"]["sha"]
    status, body = api("GET", f"{API}/repos/{repo}/git/trees/{base_tree}?recursive=1")
    current = {entry["path"]: entry for entry in json.loads(body)["tree"]}

    previous = ""
    for path in current:
        match = re.match(r"netcheck_([0-9.]+)_(x86_64|aarch64|amd64|arm64)\.deb$", path)
        if match and match.group(1) != version:
            previous = match.group(1)
    new_hashes = {arch: sha256(local_artifact(version, arch)) for arch in ARCHES}
    old_to_new = {}
    if previous and previous != version:
        for arch in ARCHES:
            previous_checksum = local_artifact(previous, arch, ".deb.sha256")
            if previous_checksum.is_file():
                old_to_new[read(previous_checksum).split()[0]] = new_hashes[arch]
    files = collect(version)
    readme_now = ""
    if "README.md" in current:
        status, body = api("GET", f"{API}/repos/{repo}/contents/README.md?ref=main")
        readme_now = base64.b64decode(json.loads(body)["content"]).decode("utf-8")
    files["README.md"] = None  # rendered below
    readme_new = render_readme(readme_now, version, old_to_new, new_hashes)

    print(f"publish {version} to {repo} (previous={previous or 'none'}, "
          f"{len([f for f in files.values() if f])} files)")
    if args.dry_run:
        for name, path in sorted(files.items()):
            if path:
                print(f"  + {name} ({path.stat().st_size:,} B)")
        if previous and previous != version:
            for path in sorted(current):
                if re.match(rf"netcheck_{previous}_", path):
                    print(f"  - {path}")
        print("  ~ README.md (rendered)")
        return 0

    entries: List[dict] = []
    for name, path in sorted(files.items()):
        if path is None:
            continue  # README.md is rendered and uploaded separately below
        entries.append({"path": name, "mode": "100644", "type": "blob",
                        "sha": blob(repo, path)})
    # README: render into the working tree then upload that exact content.
    rendered = ROOT / "release" / version / "README.public.md"
    rendered.parent.mkdir(parents=True, exist_ok=True)
    rendered.write_text(readme_new, encoding="utf-8")
    entries.append({"path": "README.md", "mode": "100644", "type": "blob",
                    "sha": blob(repo, rendered)})
    for path in sorted(current):
        # Drop every package file of any other version, and any legacy-named
        # (x86_64/aarch64) file of this version, plus stale release/<v>/ entries.
        is_pkg = re.match(r"netcheck_[0-9.]+_(x86_64|aarch64|amd64|arm64)\.deb(\.sha256)?$", path)
        in_version_dir = path.startswith(f"release/{version}/")
        if (is_pkg or in_version_dir) and path not in files:
            entries.append({"path": path, "mode": "100644", "type": "blob", "sha": None})

    status, body = api("POST", f"{API}/repos/{repo}/git/trees",
                       {"base_tree": base_tree, "tree": entries})
    tree_sha = json.loads(body)["sha"]
    status, body = api("POST", f"{API}/repos/{repo}/git/commits", {
        "message": f"release: publish NetCheck {version} packages and compliance material",
        "tree": tree_sha,
        "parents": [head],
    })
    commit_sha = json.loads(body)["sha"]
    api("PATCH", f"{API}/repos/{repo}/git/refs/heads/main", {
        "sha": commit_sha, "force": False})
    print(f"commit {commit_sha[:10]} pushed to {repo}@main")

    notes = RELEASE_NOTES.format(version=version, summary=SUMMARY_EN, summary_zh=SUMMARY_ZH,
                                 sha_amd64=new_hashes["amd64"], sha_arm64=new_hashes["arm64"])
    try:
        status, body = api("GET", f"{API}/repos/{repo}/releases/tags/v{version}")
        release = json.loads(body)
        existing = {asset["name"] for asset in release["assets"]}
        expected = {f"netcheck_{version}_{arch}{sfx}"
                    for arch in ARCHES for sfx in (".deb", ".deb.sha256")}
        expected |= {f"netcheck_{version}_src.tar.gz",
                     f"netcheck_{version}_src.tar.gz.sha256"}
        for asset in release["assets"]:
            if asset["name"] not in expected:
                api("DELETE", f"{API}/repos/{repo}/releases/assets/{asset['id']}")
                existing.discard(asset["name"])
                print(f"  deleted stale asset {asset['name']}")
        api("PATCH", f"{API}/repos/{repo}/releases/{release['id']}",
            {"name": f"NetCheck {version}", "body": notes,
             "prerelease": bool(args.prerelease)})
        print(f"release {release['tag_name']} already existed - notes refreshed")
    except SystemExit:
        status, body = api("POST", f"{API}/repos/{repo}/releases", {
            "tag_name": f"v{version}",
            "target_commitish": commit_sha,
            "name": f"NetCheck {version}",
            "body": notes,
            "draft": False,
            "prerelease": bool(args.prerelease),
        })
        release = json.loads(body)
        existing = set()
        print(f"release {release['tag_name']} created ({release['html_url']})")

    for arch in ARCHES:
        for suffix in (".deb", ".deb.sha256"):
            path = local_artifact(version, arch, suffix)
            if path.name in existing:
                print(f"  asset {path.name} already uploaded - skipped")
                continue
            status, body = api(
                "POST",
                f"{UPLOADS}/repos/{repo}/releases/{release['id']}/assets?name={path.name}",
                raw=path.read_bytes(), content_type="application/octet-stream")
            print(f"  uploaded {path.name} ({path.stat().st_size:,} B)")

    # Auditable source snapshot (V6): same file set that lands in the repo tree.
    make_src_tarball(version)
    for name in (f"netcheck_{version}_src.tar.gz",
                 f"netcheck_{version}_src.tar.gz.sha256"):
        if name in existing:
            print(f"  asset {name} already uploaded - skipped")
            continue
        path = ROOT / name
        status, body = api(
            "POST",
            f"{UPLOADS}/repos/{repo}/releases/{release['id']}/assets?name={name}",
            raw=path.read_bytes(), content_type="application/octet-stream")
        print(f"  uploaded {name} ({path.stat().st_size:,} B)")

    # Anonymous verification: no Authorization header on purpose.
    for arch in ARCHES:
        name = local_artifact(version, arch).name
        expected = sha256(ROOT / name)
        url = f"https://github.com/{repo}/releases/download/v{version}/{name}"
        status, data = api("GET", url, auth=False)
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            raise SystemExit(f"asset verification failed for {name}: {actual} != {expected}")
        print(f"  verified anonymous download {name} ({len(data):,} B, sha256 ok)")
    name = f"netcheck_{version}_src.tar.gz"
    status, data = api("GET", f"https://github.com/{repo}/releases/download/v{version}/{name}", auth=False)
    actual = hashlib.sha256(data).hexdigest()
    if actual != sha256(ROOT / name):
        raise SystemExit(f"asset verification failed for {name}")
    print(f"  verified anonymous download {name} ({len(data):,} B, sha256 ok)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    inspect = sub.add_parser("inspect")
    inspect.add_argument("--repo", default=DEFAULT_REPO)
    publish = sub.add_parser("publish")
    publish.add_argument("--version")
    publish.add_argument("--repo", default=DEFAULT_REPO)
    publish.add_argument("--prerelease", action="store_true")
    publish.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if args.command == "inspect":
        return cmd_inspect(args.repo)
    return cmd_publish(args)


if __name__ == "__main__":
    sys.exit(main())
