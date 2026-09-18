#!/usr/bin/env python3
"""Build a TOS 7 single-package .deb on macOS, Linux, or CI."""
from __future__ import annotations

import argparse
import bz2
import configparser
import gzip
import hashlib
import io
import re
import json
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Iterable, List


ROOT = Path(__file__).resolve().parent.parent
APP_ID = "netcheck"
PLATFORM_ARCH = {"x86_64": "amd64", "aarch64": "arm64"}
# Accept the Debian architecture names as aliases on the CLI as well, so the
# build command matches the published artefact names (netcheck_<v>_amd64.deb).
PLATFORM_ALIASES = {"amd64": "x86_64", "arm64": "aarch64"}
EXCLUDED_NAMES = {".DS_Store", "__pycache__"}
ICON_PATH = ROOT / "images/icons/netcheck.svg"
COMPLIANCE_DIR = ROOT / "compliance"
# Markdown dossier shipped in the package (review items C2-C8, S8/S9) and
# rendered into webui/compliance/*.html by tools/build_compliance.py.
COMPLIANCE_DOCS = (
    "README.md", "privacy-policy.md", "third-party-services.md", "data-rights.md",
    "licenses.md", "privileged-channel.md", "supply-chain.md",
)
COPYRIGHT_HEADER = """Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: NetCheck (TOS 7 network diagnosis & repair)
Source: https://github.com/Moechz/netcheck

Files: *
Copyright: 2026 Moechz
License: Apache-2.0
 Licensed under the Apache License, Version 2.0. The full license text is
 shipped inside the application at /usr/local/netcheck/LICENSE and
 /usr/local/netcheck/compliance/LICENSE.

Files: usr/local/netcheck/bin/netcheck-bpf
Copyright: 2017 Nathan Sweet; 2018, 2019 Cloudflare; 2019 Authors of Cilium;
 2009 The Go Authors; 2026 Moechz
License: MIT and BSD-3-Clause and Apache-2.0
 Statically linked Go binary. Bundled components: github.com/cilium/ebpf
 (MIT), golang.org/x/sys and golang.org/x/exp (BSD-3-Clause), and the
 NetCheck Go/eBPF collector (Apache-2.0). Full license texts are shipped in
 /usr/local/netcheck/compliance/licenses/.

Files: usr/local/netcheck/compliance/*
Copyright: 2026 Moechz
License: Apache-2.0
 Compliance dossier: privacy policy, third-party service disclosure, data
 rights, license notices, privileged-channel authorisation dossier, supply
 chain notes, CycloneDX-style SBOM and file manifest.
"""
ICON_VIEWBOX = "0 0 512 512"
ICON_SIZE = "512"
REQUIRED_LANGUAGES = {
    "en-us", "zh-cn", "zh-hk", "fr-fr", "de-de", "it-it", "es-es",
    "hu-hu", "ja-jp", "ko-kr", "pl-pl", "ru-ru", "tr-tr", "pt-pt",
}
REQUIRED_LANG_FIELDS = {"name", "auth", "descript"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_config() -> Dict[str, object]:
    with (ROOT / "config.ini").open(encoding="utf-8") as stream:
        return json.load(stream)


def read_control() -> Dict[str, str]:
    fields: Dict[str, str] = {}
    with (ROOT / "DEBIAN/control").open(encoding="utf-8") as stream:
        for raw in stream:
            if ": " in raw:
                key, value = raw.rstrip("\n").split(": ", 1)
                fields[key] = value
    return fields


def parse_lang(content: str) -> Dict[str, Dict[str, str]]:
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.read_string(content)
    languages: Dict[str, Dict[str, str]] = {}
    for section in parser.sections():
        values: Dict[str, str] = {}
        for key, raw_value in parser.items(section):
            value = raw_value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
                value = value[1:-1]
            values[key] = value
        languages[section] = values
    return languages


def read_lang() -> Dict[str, Dict[str, str]]:
    return parse_lang((ROOT / f"{APP_ID}.lang").read_text(encoding="utf-8"))


def validate_icon() -> None:
    """Validate the SVG against TerraMaster's application icon specification."""
    if not ICON_PATH.is_file():
        raise ValueError("icon images/icons/netcheck.svg is missing")
    try:
        root = ET.parse(ICON_PATH).getroot()
    except ET.ParseError as error:
        raise ValueError(f"application icon is not valid XML: {error}") from error
    if root.tag.rsplit("}", 1)[-1] != "svg":
        raise ValueError("application icon root element must be <svg>")
    if root.attrib.get("viewBox") != ICON_VIEWBOX:
        raise ValueError(f"application icon viewBox must be {ICON_VIEWBOX}")
    if root.attrib.get("width") != ICON_SIZE or root.attrib.get("height") != ICON_SIZE:
        raise ValueError("application icon width and height must both be 512")


def validate_metadata(
    config: Dict[str, object],
    control: Dict[str, str],
    languages: Dict[str, Dict[str, str]],
) -> None:
    required = {
        "id", "icon", "publisher", "exec", "version", "recommend", "beta",
        "low_version", "category", "depend", "relation", "platform",
        "application_type", "system_id", "package", "user",
    }
    missing = sorted(required - set(config))
    if missing:
        raise ValueError(f"config.ini is missing required fields: {missing}")
    if config["id"] != APP_ID:
        raise ValueError("config.ini id must be netcheck")
    if config["package"] != control.get("Package"):
        raise ValueError("config.ini package and DEBIAN/control Package differ")
    if config["version"] != control.get("Version"):
        raise ValueError("version differs between config.ini and control")
    if config["system_id"] != APP_ID:
        raise ValueError("config.ini system_id must be netcheck")
    if "type" in config and "open_path" in config:
        raise ValueError("config.ini type and open_path are mutually exclusive")
    if config.get("type") == "iframe" and config.get("path") != f"/{APP_ID}/":
        raise ValueError("iframe path must be /netcheck/")
    if config["application_type"] != "deb":
        raise ValueError("application_type must be deb")
    missing_languages = sorted(REQUIRED_LANGUAGES - set(languages))
    if missing_languages:
        raise ValueError(f"language file is missing languages: {missing_languages}")
    for language, fields in languages.items():
        missing_fields = sorted(REQUIRED_LANG_FIELDS - set(fields))
        if missing_fields:
            raise ValueError(
                f"language {language} is missing fields: {missing_fields}"
            )
        if not all(fields[field] for field in REQUIRED_LANG_FIELDS):
            raise ValueError(f"language {language} has empty required fields")
    expected_icon = f"/images/icons/{APP_ID}.svg"
    if config.get("icon") != expected_icon:
        raise ValueError(f"config.ini icon must be {expected_icon}")
    if ICON_PATH.name != f"{APP_ID}.svg":
        raise ValueError("application icon filename must match config.ini id")
    validate_icon()


def normalized_mode(path: Path, is_script: bool = False) -> int:
    mode = stat.S_IMODE(path.stat().st_mode)
    if path.is_dir():
        return 0o755
    if is_script or mode & 0o111:
        return 0o755
    return 0o644


def copy_file(source: Path, target: Path, mode: int | None = None) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(mode if mode is not None else normalized_mode(source))


def copy_tree(source: Path, target: Path) -> None:
    if not source.exists():
        return
    target.mkdir(parents=True, exist_ok=True)
    for item in sorted(source.iterdir()):
        if item.name in EXCLUDED_NAMES or item.suffix in {".pyc", ".pyo"}:
            continue
        destination = target / item.name
        if item.is_dir():
            copy_tree(item, destination)
            destination.chmod(0o755)
        elif item.is_file():
            copy_file(item, destination)
        else:
            raise ValueError(f"unsupported package entry: {item}")


def webui_cache_key() -> str:
    """Unique per-build cache key: version + build_time from version.json."""
    meta = json.loads((ROOT / "version.json").read_text(encoding="utf-8"))
    build = str(meta.get("build_time", "")).replace(":", "").replace("-", "")[:15]
    return f"{meta['version']}-{build}" if build else str(meta["version"])


def write_webui_archive() -> None:
    """Create the fixed-name frontend archive with only runtime files."""
    archive = ROOT / "webui.bz2"
    cache_key = webui_cache_key()
    with tarfile.open(archive, "w:bz2", format=tarfile.GNU_FORMAT) as bundle:
        added_directories = set()

        def add_directory(name: str) -> None:
            if name in added_directories:
                return
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            bundle.addfile(info)
            added_directories.add(name)

        source = ROOT / "webui"
        wanted: List[Path] = [source / "index.html"]
        wanted.extend(sorted((source / "assets").rglob("*")))
        # Compliance pages are generated from compliance/*.md by
        # tools/build_compliance.py (single source of truth).
        wanted.extend(sorted((source / "compliance").rglob("*")))
        for path in wanted:
            if not path.is_file() or path.name in EXCLUDED_NAMES:
                continue
            relative = path.relative_to(source).as_posix()
            if path.parent != source:
                parent = path.parent
                while parent != source:
                    add_directory(parent.relative_to(source).as_posix())
                    parent = parent.parent
            data = path.read_bytes()
            if path.suffix == ".js":
                data = minify_js_bytes(path.name, data)
            if path.name == "index.html":
                # Rewrite asset cache keys so every build gets a unique URL
                # even when the app version stays the same.
                html = data.decode("utf-8")
                html = re.sub(r"\?v=[^\s\"']+", f"?v={cache_key}", html)
                data = html.encode("utf-8")
            info = tarfile.TarInfo(relative)
            info.size = len(data)
            info.mode = normalized_mode(path)
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            bundle.addfile(info, io.BytesIO(data))


def minify_js_bytes(name: str, data: bytes) -> bytes:
    """L2 保护：javascript-obfuscator 深度混淆（仅作用于打包内容，源文件不动）。

    逻辑代码（app/api/clipboard）：控制流扁平化 + base64 字符串数组 +
    标识符十六进制化 + 字符串拆分 + 对象键转换。
    i18n.js 以翻译字符串为主（约 600KB），全量加密会令包体膨胀数倍，
    故采用轻量档：仅压缩 + 标识符混淆。
    """
    import json as _json
    import subprocess
    import tempfile
    options = {
        "compact": True,
        "identifierNamesGenerator": "hexadecimal",
        "selfDefending": False,
        "sourceMap": False,
    }
    if name != "i18n.js":
        options.update({
            "stringArray": True,
            "stringArrayEncoding": ["base64"],
            "stringArrayThreshold": 0.75,
            "controlFlowFlattening": True,
            "controlFlowFlatteningThreshold": 0.5,
            "deadCodeInjection": False,
            "splitStrings": True,
            "splitStringsChunkLength": 8,
            "transformObjectKeys": True,
        })
    with tempfile.TemporaryDirectory(prefix="nc-obf-") as tmp:
        src = Path(tmp) / "in.js"
        out = Path(tmp) / "out.js"
        cfg = Path(tmp) / "options.json"
        src.write_bytes(data)
        cfg.write_text(_json.dumps(options), encoding="utf-8")
        result = subprocess.run(
            ["javascript-obfuscator", str(src), "--config", str(cfg),
             "--output", str(out)],
            capture_output=True, text=True)
        if result.returncode != 0 or not out.exists() or out.stat().st_size == 0:
            raise RuntimeError(f"obfuscator failed for {name}: {result.stderr[:300]}")
        return out.read_bytes()


def compile_lib_bytecode(staging: Path) -> None:
    """Ship plain .py sources (review V6, 1.2.60): auditable code is required
    in the package. The legacy adjacent-.pyc strip (L1) was removed - Python 3
    imports .py directly (SourcelessFileLoader was only needed when .py was
    absent); the read-only lib dir simply skips __pycache__ caching."""
    return


def write_contract(version: str) -> None:
    contract = {
        "backend_binary_sha256": sha256(ROOT / "bin/netcheck"),
        "helper_binary_sha256": sha256(ROOT / "bin/netcheck-helper"),
        "bpf_collector_binary_sha256": sha256(ROOT / "bin/netcheck-bpf"),
        "version": version,
        "webui_bz2_sha256": sha256(ROOT / "webui.bz2"),
    }
    target = ROOT / "contract/expected.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(contract, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def render_compliance_pages() -> None:
    """Render the Markdown dossier into webui/compliance/*.html (single source)."""
    import importlib.util
    module_path = ROOT / "tools/build_compliance.py"
    spec = importlib.util.spec_from_file_location("netcheck_build_compliance", module_path)
    if spec is None or spec.loader is None:
        raise ValueError("tools/build_compliance.py is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if {name for name, _, _ in module.DOCUMENTS} != set(COMPLIANCE_DOCS):
        raise ValueError("build_compliance document list differs from COMPLIANCE_DOCS")
    module.build(COMPLIANCE_DIR, ROOT / "webui" / "compliance")


def build_sbom(version: str, platform: str) -> Dict[str, object]:
    """Minimal CycloneDX 1.5 inventory of everything relevant to the package."""
    meta = json.loads((ROOT / "version.json").read_text(encoding="utf-8"))
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": str(meta.get("build_time", "")),
            "component": {
                "type": "application",
                "bom-ref": f"netcheck@{version}",
                "name": "NetCheck",
                "version": version,
                "author": "Moechz",
                "supplier": {"name": "Moechz", "url": "https://github.com/Moechz/netcheck"},
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "properties": [
                    {"name": "platform", "value": platform},
                    {"name": "package", "value": "deb"},
                    {"name": "tos.minimum", "value": "TOS 7.0"},
                ],
            },
            "tools": [
                {"vendor": "OpenJS", "name": "javascript-obfuscator", "version": "5.6.0"},
                {"vendor": "OpenJS", "name": "terser", "version": "5.51.2"},
                {"vendor": "Python", "name": "CPython", "version": "3.10"},
                {"vendor": "Google", "name": "Go", "version": "1.23"},
            ],
        },
        "components": [
            {
                "type": "library", "bom-ref": "pkg:golang/github.com/cilium/ebpf@v0.15.0",
                "name": "github.com/cilium/ebpf", "version": "v0.15.0",
                "scope": "required",
                "licenses": [{"license": {"id": "MIT"}}],
                "properties": [
                    {"name": "bundled", "value": "true"},
                    {"name": "bundled-in", "value": "usr/local/netcheck/bin/netcheck-bpf"},
                    {"name": "vendor-path", "value": "bpfcollector/vendor/github.com/cilium/ebpf"},
                ],
            },
            {
                "type": "library", "bom-ref": "pkg:golang/golang.org/x/sys@v0.15.0",
                "name": "golang.org/x/sys", "version": "v0.15.0", "scope": "required",
                "licenses": [{"license": {"id": "BSD-3-Clause"}}],
                "properties": [
                    {"name": "bundled", "value": "true"},
                    {"name": "bundled-in", "value": "usr/local/netcheck/bin/netcheck-bpf"},
                ],
            },
            {
                "type": "library",
                "bom-ref": "pkg:golang/golang.org/x/exp@20230224",
                "name": "golang.org/x/exp", "version": "v0.0.0-20230224173230-c95f2b4c22f2",
                "scope": "required",
                "licenses": [{"license": {"id": "BSD-3-Clause"}}],
                "properties": [
                    {"name": "bundled", "value": "true"},
                    {"name": "bundled-in", "value": "usr/local/netcheck/bin/netcheck-bpf"},
                ],
            },
            {
                "type": "library", "bom-ref": "netcheck-ebpf-header-set",
                "name": "cilium/ebpf example headers", "version": "v0.15.0",
                "scope": "required",
                "licenses": [{"license": {"id": "BSD-2-Clause"}}],
                "properties": [
                    {"name": "bundled", "value": "true"},
                    {"name": "path", "value": "bpfcollector/_headers"},
                    {"name": "note", "value": "compiled into the eBPF object inside bin/netcheck-bpf"},
                ],
            },
            {
                "type": "library", "bom-ref": "python-runtime",
                "name": "CPython standard library", "version": "3.10",
                "scope": "required",
                "licenses": [{"license": {"id": "PSF-2.0"}}],
                "properties": [
                    {"name": "bundled", "value": "false"},
                    {"name": "note", "value": "provided by TOS; no third-party Python package is shipped"},
                ],
            },
            {
                "type": "library", "bom-ref": "sivel-speedtest-cli",
                "name": "sivel/speedtest-cli",
                "scope": "optional",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "properties": [
                    {"name": "bundled", "value": "false"},
                    {"name": "note", "value": "conceptual reference for the bandwidth flow; NetCheck ships its own implementation"},
                ],
            },
        ],
    }


def build_compliance_manifest(version: str, platform: str, app_dir: Path) -> Dict[str, object]:
    """Hash inventory for the compliance dossier, services and maintainer scripts."""
    def digest(path: Path) -> Dict[str, object]:
        return {"sha256": sha256(path), "bytes": path.stat().st_size}

    files: Dict[str, object] = {}
    for path in sorted((app_dir / "compliance").rglob("*")):
        if path.is_file() and path.name != "MANIFEST.json":
            files[path.relative_to(app_dir).as_posix()] = digest(path)
    for name in ("LICENSE", "NOTICE", "config.ini", "version.json", f"{APP_ID}.lang"):
        candidate = app_dir / name
        if candidate.is_file():
            files[name] = digest(candidate)

    docs = {name: digest(COMPLIANCE_DIR / name) for name in COMPLIANCE_DOCS}
    licenses = {
        path.name: digest(path)
        for path in sorted((COMPLIANCE_DIR / "licenses").glob("*")) if path.is_file()
    }
    services = {}
    for name in ("netcheck.service", "netcheck-helper.service", "netcheck-bpf.service"):
        unit = ROOT / "init.d" / name
        unit_text = unit.read_text(encoding="utf-8")
        user = next((line.split("=", 1)[1].strip()
                     for line in unit_text.splitlines()
                     if line.startswith("User=")), "")
        services[name] = {"sha256": sha256(unit), "user": user,
                          "install_path": f"/etc/systemd/system/{name}"}
    maintainer = {
        name: digest(ROOT / "DEBIAN" / name)
        for name in ("preinst", "postinst", "prerm", "postrm")
    }
    return {
        "app": APP_ID,
        "version": version,
        "platform": platform,
        "deb_architecture": PLATFORM_ARCH[platform],
        "install_root": f"/usr/local/{APP_ID}",
        "compliance_dir": f"/usr/local/{APP_ID}/compliance",
        "public_docs": "https://github.com/Moechz/netcheck/tree/main/compliance",
        "contact": "https://github.com/Moechz/netcheck/issues",
        "generated_by": "tools/build_deb.py",
        "note": ("Hashes are computed after bytecode compilation, before tar creation; "
                 "verify with sha256sum against the installed files. The package-level "
                 "SHA-256 is published in the release bundle and in the .deb.sha256 file."),
        "dossier_docs": docs,
        "licenses": licenses,
        "packaged_files": files,
        "contract": json.loads((ROOT / "contract/expected.json").read_text(encoding="utf-8")),
        "service_units": services,
        "maintainer_scripts": maintainer,
        "review_items": {
            "V1/S1": "compliance/privileged-channel.md",
            "C2": "compliance/privacy-policy.md",
            "C3": "compliance/licenses.md + LICENSE + NOTICE + compliance/licenses/",
            "C4": "compliance/third-party-services.md",
            "C5": "compliance/data-rights.md",
            "S8/S9": "compliance/supply-chain.md + maintainer_scripts",
        },
    }


def stage_package(platform: str, config: Dict[str, object], control: Dict[str, str]) -> Path:
    staging = Path(tempfile.mkdtemp(prefix="netcheck-deb-"))
    app_dir = staging / "usr/local" / APP_ID
    debian_dir = staging / "DEBIAN"
    app_dir.mkdir(parents=True)
    debian_dir.mkdir()

    staged_config = dict(config)
    staged_config["platform"] = platform
    staged_control = dict(control)
    staged_control["Architecture"] = PLATFORM_ARCH[platform]
    (app_dir / "config.ini").write_text(
        json.dumps(staged_config, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    copy_file(ROOT / f"{APP_ID}.lang", app_dir / f"{APP_ID}.lang")
    copy_file(ROOT / "version.json", app_dir / "version.json")
    copy_tree(ROOT / "bin", app_dir / "bin")
    copy_tree(ROOT / "lib", app_dir / "lib")
    copy_tree(ROOT / "images", app_dir / "images")
    copy_tree(ROOT / "init.d", app_dir / "init.d")
    copy_tree(ROOT / "contract", app_dir / "contract")
    copy_file(ROOT / "webui.bz2", app_dir / "webui.bz2")

    # Compliance dossier (review items C2-C8, S8/S9) + license material.
    if not COMPLIANCE_DIR.is_dir():
        raise ValueError("compliance/ dossier is missing")
    copy_tree(COMPLIANCE_DIR, app_dir / "compliance")
    copy_file(COMPLIANCE_DIR / "LICENSE", app_dir / "LICENSE")
    copy_file(COMPLIANCE_DIR / "NOTICE", app_dir / "NOTICE")
    doc_dir = staging / "usr/share/doc" / APP_ID
    doc_dir.mkdir(parents=True, exist_ok=True)
    (doc_dir / "copyright").write_text(
        COPYRIGHT_HEADER + "\n" + (COMPLIANCE_DIR / "NOTICE").read_text(encoding="utf-8"),
        encoding="utf-8")

    control_lines = [f"{key}: {value}" for key, value in staged_control.items()]
    (debian_dir / "control").write_text("\n".join(control_lines) + "\n", encoding="utf-8")
    for script in ("preinst", "postinst", "prerm", "postrm"):
        copy_file(ROOT / "DEBIAN" / script, debian_dir / script, 0o755)

    compile_lib_bytecode(staging)  # no-op since 1.2.60: plain .py ships (V6)

    # SBOM + compliance file manifest describe exactly what ships in the package.
    (app_dir / "compliance" / "SBOM.json").write_text(
        json.dumps(build_sbom(str(config["version"]), platform), indent=2,
                   ensure_ascii=False, sort_keys=False) + "\n", encoding="utf-8")
    (app_dir / "compliance" / "MANIFEST.json").write_text(
        json.dumps(build_compliance_manifest(str(config["version"]), platform, app_dir),
                   indent=2, ensure_ascii=False, sort_keys=False) + "\n",
        encoding="utf-8")

    hashes: List[str] = []
    for path in sorted(app_dir.rglob("*")):
        if path.is_file():
            digest = hashlib.md5(path.read_bytes()).hexdigest()
            hashes.append(f"{digest}  {path.relative_to(staging).as_posix()}")
    (debian_dir / "md5sums").write_text("\n".join(hashes) + "\n", encoding="utf-8")
    (debian_dir / "md5sums").chmod(0o644)
    return staging


def make_tar_bytes(root: Path, members: Iterable[Path]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as bundle:
        added_directories: set[str] = set()

        def add_directory(name: str) -> None:
            # Debian's dpkg-deb emits a root entry and prefixes every tar
            # member with "./". Keep that exact shape in the macOS fallback;
            # pathlib would otherwise normalize "./control" to "control".
            if name in added_directories:
                return
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            bundle.addfile(info)
            added_directories.add(name)

        add_directory("./")
        for path in sorted(members, key=lambda item: item.relative_to(root).as_posix()):
            parts = path.relative_to(root).parts
            relative = "./" + "/".join(parts)
            for depth in range(1, len(parts)):
                add_directory("./" + "/".join(parts[:depth]) + "/")
            if path.is_dir():
                add_directory(relative + "/")
                continue
            if not path.is_file():
                raise ValueError(f"unsupported tar member: {path}")
            data = path.read_bytes()
            if path.suffix == ".js":
                data = minify_js_bytes(path.name, data)
            if path.name == "index.html":
                # Rewrite asset cache keys so every build gets a unique URL
                # even when the app version stays the same.
                html = data.decode("utf-8")
                html = re.sub(r"\?v=[^\s\"']+", f"?v={cache_key}", html)
                data = html.encode("utf-8")
            info = tarfile.TarInfo(relative)
            info.size = len(data)
            info.mode = normalized_mode(path)
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            bundle.addfile(info, io.BytesIO(data))
    return raw.getvalue()


def compressed_tar(root: Path, members: Iterable[Path]) -> bytes:
    return gzip.compress(make_tar_bytes(root, members), compresslevel=9, mtime=0)


def gnu_ar_member(name: str, data: bytes) -> bytes:
    if len(name) > 15:
        raise ValueError(f"GNU ar member name is too long: {name}")
    size = len(data)
    header = (
        f"{name:<16}{0:<12}{0:<6}{0:<6}{0o100644:<8o}{size:<10}`\n"
    ).encode("ascii")
    if len(header) != 60:
        raise AssertionError("invalid GNU ar header length")
    return header + data + (b"\n" if size % 2 else b"")


def write_python_deb(staging: Path, output: Path) -> None:
    control_members = [path for path in (staging / "DEBIAN").iterdir() if path.is_file()]
    data_members = [
        path
        for path in staging.rglob("*")
        if path.is_file() and path.relative_to(staging).parts[0] != "DEBIAN"
    ]
    with output.open("wb") as stream:
        stream.write(b"!<arch>\n")
        stream.write(gnu_ar_member("debian-binary", b"2.0\n"))
        stream.write(
            gnu_ar_member(
                "control.tar.gz", compressed_tar(staging / "DEBIAN", control_members)
            )
        )
        stream.write(gnu_ar_member("data.tar.gz", compressed_tar(staging, data_members)))


def run_dpkg_deb(staging: Path, output: Path) -> None:
    command = [
        "dpkg-deb",
        "--root-owner-group",
        "--compression=gzip",
        "--build",
        str(staging),
        str(output),
    ]
    result = subprocess.run(command, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(f"dpkg-deb failed: {result.stderr.strip()}")


def extract_ar_members(path: Path) -> Dict[str, bytes]:
    data = path.read_bytes()
    if data[:8] != b"!<arch>\n":
        raise ValueError("not an ar archive")
    offset = 8
    members: Dict[str, bytes] = {}
    while offset < len(data):
        header = data[offset:offset + 60]
        if len(header) != 60 or header[58:59] != b"`":
            raise ValueError("invalid or non-GNU ar member header")
        name = header[:16].decode("ascii").rstrip(" ")
        size = int(header[48:58].decode("ascii").rstrip())
        offset += 60
        members[name.rstrip("/")] = data[offset:offset + size]
        offset += size + (size % 2)
    return members


def validate_package(path: Path, platform: str) -> None:
    members = extract_ar_members(path)
    if list(members) != ["debian-binary", "control.tar.gz", "data.tar.gz"]:
        raise ValueError(f"invalid deb member order: {list(members)}")
    if members["debian-binary"] != b"2.0\n":
        raise ValueError("unsupported Debian package version")

    control_files: Dict[str, bytes] = {}
    data_files: Dict[str, bytes] = {}
    archives = (
        ("control.tar.gz", control_files),
        ("data.tar.gz", data_files),
    )
    for archive_name, target in archives:
        with tarfile.open(fileobj=io.BytesIO(members[archive_name]), mode="r:gz") as bundle:
            for member in bundle.getmembers():
                if member.isfile():
                    stream = bundle.extractfile(member)
                    if stream is not None:
                        clean_name = member.name
                        if clean_name.startswith("./"):
                            clean_name = clean_name[2:]
                        target[clean_name] = stream.read()

    required_control = {"control", "md5sums", "preinst", "postinst", "prerm", "postrm"}
    if required_control - set(control_files):
        raise ValueError(f"control archive is missing: {required_control - set(control_files)}")
    for script in sorted(required_control - {"control", "md5sums"}):
        if control_files[script] != (ROOT / "DEBIAN" / script).read_bytes():
            raise ValueError(f"packaged {script} differs from DEBIAN/{script}")
    required_data = {
        "usr/local/netcheck/config.ini",
        "usr/local/netcheck/netcheck.lang",
        "usr/local/netcheck/bin/netcheck",
        "usr/local/netcheck/bin/netcheck-helper",
        "usr/local/netcheck/images/icons/netcheck.svg",
        "usr/local/netcheck/init.d/netcheck.service",
        "usr/local/netcheck/init.d/netcheck-helper.service",
        "usr/local/netcheck/webui.bz2",
    }
    if required_data - set(data_files):
        raise ValueError(f"data archive is missing: {required_data - set(data_files)}")

    # Compliance material must be present in the package (review items C2-C8, S8/S9).
    required_compliance = {
        "usr/local/netcheck/LICENSE",
        "usr/local/netcheck/NOTICE",
        "usr/local/netcheck/compliance/SBOM.json",
        "usr/local/netcheck/compliance/MANIFEST.json",
        "usr/share/doc/netcheck/copyright",
    }
    required_compliance |= {
        f"usr/local/netcheck/compliance/{name}" for name in COMPLIANCE_DOCS
    }
    if required_compliance - set(data_files):
        raise ValueError(
            f"compliance material is missing: {sorted(required_compliance - set(data_files))}")
    for name in ("cilium-ebpf-MIT.txt", "golang-x-sys-BSD-3-Clause.txt",
                 "golang-x-exp-BSD-3-Clause.txt",
                 "cilium-ebpf-examples-headers-BSD-2-Clause.txt"):
        if f"usr/local/netcheck/compliance/licenses/{name}" not in data_files:
            raise ValueError(f"license text is missing: {name}")
    if "Apache License" not in data_files["usr/local/netcheck/LICENSE"].decode("utf-8"):
        raise ValueError("packaged LICENSE is not the Apache-2.0 text")
    for name in COMPLIANCE_DOCS:
        body = data_files[f"usr/local/netcheck/compliance/{name}"].decode("utf-8")
        if len(body) < 1200 or "## " not in body:
            raise ValueError(f"compliance document looks truncated: {name}")
    manifest = json.loads(
        data_files["usr/local/netcheck/compliance/MANIFEST.json"].decode("utf-8"))
    for key in ("dossier_docs", "licenses", "contract", "service_units",
                "maintainer_scripts", "review_items"):
        if key not in manifest:
            raise ValueError(f"compliance MANIFEST.json is missing: {key}")
    if set(manifest["dossier_docs"]) != set(COMPLIANCE_DOCS):
        raise ValueError("compliance MANIFEST.json dossier list mismatch")
    for script in ("preinst", "postinst", "prerm", "postrm"):
        entry = manifest["maintainer_scripts"].get(script)
        if not entry or entry.get("sha256") != sha256(ROOT / "DEBIAN" / script):
            raise ValueError(f"compliance MANIFEST.json has a stale {script} hash")
    contracted = json.loads(
        data_files["usr/local/netcheck/contract/expected.json"].decode("utf-8"))
    if manifest["contract"] != contracted:
        raise ValueError("compliance MANIFEST.json contract copy differs from the package")
    sbom = json.loads(data_files["usr/local/netcheck/compliance/SBOM.json"].decode("utf-8"))
    if sbom.get("bomFormat") != "CycloneDX" or len(sbom.get("components", [])) < 5:
        raise ValueError("compliance SBOM.json is incomplete")

    # Least-privilege service units (audit item V1/S1): the root units must ship
    # with an explicit capability bounding set and NoNewPrivileges.
    helper_unit = data_files["usr/local/netcheck/init.d/netcheck-helper.service"].decode("utf-8")
    if "CapabilityBoundingSet=" not in helper_unit or "NoNewPrivileges=true" not in helper_unit:
        raise ValueError("helper unit is missing the least-privilege capability set")
    if "CAP_SYS_ADMIN" in helper_unit.split("CapabilityBoundingSet=")[1].split("\n")[0]:
        raise ValueError("helper unit must not grant CAP_SYS_ADMIN")
    bpf_unit = data_files["usr/local/netcheck/init.d/netcheck-bpf.service"].decode("utf-8")
    if "CapabilityBoundingSet=" not in bpf_unit or "NoNewPrivileges=true" not in bpf_unit:
        raise ValueError("BPF collector unit is missing the least-privilege capability set")
    main_unit = data_files["usr/local/netcheck/init.d/netcheck.service"].decode("utf-8")
    if "RestrictAddressFamilies=" not in main_unit or "NoNewPrivileges=true" not in main_unit:
        raise ValueError("main service unit lost its hardening directives")

    # The unpacked frontend must expose the generated compliance pages.
    with tarfile.open(fileobj=io.BytesIO(bz2.decompress(
            data_files["usr/local/netcheck/webui.bz2"])), mode="r:") as frontend:
        ui_names = frontend.getnames()
    if "compliance/index.html" not in ui_names:
        raise ValueError("webui archive is missing the generated compliance index")
    for name in COMPLIANCE_DOCS:
        if f"compliance/{name[:-3]}.html" not in ui_names:
            raise ValueError(f"webui archive is missing compliance/{name[:-3]}.html")

    if any(name == ".DS_Store" or name.endswith("/.DS_Store") for name in data_files):
        raise ValueError(".DS_Store leaked into package")

    staged_config = json.loads(data_files["usr/local/netcheck/config.ini"])
    control_fields: Dict[str, str] = {}
    for line in control_files["control"].decode("utf-8").splitlines():
        if ": " in line:
            key, value = line.split(": ", 1)
            control_fields[key] = value
    version = str(staged_config["version"])
    if staged_config.get("platform") != platform:
        raise ValueError("staged config platform does not match build platform")
    if not staged_config.get("publisher"):
        raise ValueError("staged config publisher is empty")
    if control_fields.get("Version") != version:
        raise ValueError("staged control version mismatch")
    if control_fields.get("Architecture") != PLATFORM_ARCH[platform]:
        raise ValueError("staged control architecture mismatch")

    lang = parse_lang(data_files["usr/local/netcheck/netcheck.lang"].decode("utf-8"))
    missing_languages = sorted(REQUIRED_LANGUAGES - set(lang))
    if missing_languages:
        raise ValueError(f"staged language file is missing languages: {missing_languages}")
    for language, fields in lang.items():
        missing_fields = sorted(REQUIRED_LANG_FIELDS - set(fields))
        if missing_fields or not all(fields[field] for field in REQUIRED_LANG_FIELDS):
            raise ValueError(f"staged language {language} is incomplete")
    service = data_files["usr/local/netcheck/init.d/netcheck.service"].decode("utf-8")
    if "\nUser=netcheck\n" not in service or "/usr/local/netcheck/bin/netcheck" not in service:
        raise ValueError("main service is not the official non-root /usr/local service")
    if "usr/local/netcheck/init.d/netcheck-bpf.service" not in data_files:
        raise ValueError("BPF collector service is missing")
    bpf_service = data_files["usr/local/netcheck/init.d/netcheck-bpf.service"].decode("utf-8")
    if "ExecStart=/usr/local/netcheck/bin/netcheck-bpf" not in bpf_service:
        raise ValueError("BPF collector service has an invalid ExecStart")


def build(platform: str) -> Path:
    platform = PLATFORM_ALIASES.get(platform, platform)  # amd64 -> x86_64, arm64 -> aarch64
    if platform not in PLATFORM_ARCH:
        raise ValueError(f"unsupported platform: {platform}")
    config = read_config()
    control = read_control()
    languages = read_lang()
    validate_metadata(config, control, languages)
    version = str(config["version"])

    render_compliance_pages()
    write_webui_archive()
    write_contract(version)
    staging = stage_package(platform, config, control)
    # output name uses the Debian architecture (amd64/arm64) so the filename
    # always matches the package's Architecture: field and the output of
    # `dpkg --print-architecture` on the target machine
    output = ROOT / f"netcheck_{version}_{PLATFORM_ARCH[platform]}.deb"
    try:
        if shutil.which("dpkg-deb"):
            run_dpkg_deb(staging, output)
        else:
            write_python_deb(staging, output)
        validate_package(output, platform)
        output.chmod(0o644)
        checksum = f"{sha256(output)}  {output.name}\n"
        (ROOT / f"{output.name}.sha256").write_text(checksum, encoding="utf-8")
        return output
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("platform", nargs="?",
                        choices=sorted(PLATFORM_ARCH) + sorted(PLATFORM_ALIASES),
                        default="x86_64")
    args = parser.parse_args()
    try:
        output = build(args.platform)
    except Exception as error:
        print(f"BUILD FAIL: {error}", file=sys.stderr)
        return 1
    print(f"BUILD OK: {output}")
    print(f"  size: {output.stat().st_size:,} bytes")
    print(f"  sha256: {sha256(output)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
