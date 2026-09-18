#!/usr/bin/env python3
"""TOS 7 packaging contract tests."""
from __future__ import annotations

import hashlib
import gzip
import io
import importlib.util
import json
import tarfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = ROOT / "tools/build_deb.py"

def load_builder():
    spec = importlib.util.spec_from_file_location("netcheck_build_deb", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module

def test() -> None:
    builder = load_builder()
    version = json.loads((ROOT / "version.json").read_text(encoding="utf-8"))
    assert version["developer"] == "Moechz"
    package = builder.build("x86_64")
    members = builder.extract_ar_members(package)
    assert list(members) == ["debian-binary", "control.tar.gz", "data.tar.gz"]

    control = {}
    data = {}
    for archive_name, target in (
        ("control.tar.gz", control),
        ("data.tar.gz", data),
    ):
        with tarfile.open(fileobj=io.BytesIO(members[archive_name]), mode="r:gz") as bundle:
            names = [member.name for member in bundle.getmembers()]
            assert names[0] in {".", "./"}
            assert all(
                name in {".", "./"} or name.startswith("./")
                for name in names
            ), "TOS requires dpkg-deb's ./-prefixed tar layout"
            if archive_name == "data.tar.gz":
                assert any(
                    name.rstrip("/") == "./usr/local/netcheck"
                    for name in names
                )
            for member in bundle.getmembers():
                if not member.isfile():
                    continue
                name = member.name[2:] if member.name.startswith("./") else member.name
                stream = bundle.extractfile(member)
                assert stream is not None
                target[name] = (stream.read(), member.mode)

        raw_tar = gzip.decompress(members[archive_name])
        raw_names = []
        offset = 0
        while offset < len(raw_tar):
            name = raw_tar[offset:offset + 100].split(b"\0", 1)[0]
            if not name:
                break
            raw_names.append(name)
            size_field = raw_tar[offset + 124:offset + 136].split(b"\0", 1)[0].strip()
            member_size = int(size_field, 8)
            offset += 512 + ((member_size + 511) // 512) * 512
        assert raw_names[0] == b"./"
        assert all(name.startswith(b"./") for name in raw_names)

    assert {"control", "md5sums", "postinst", "prerm", "postrm"} <= set(control)
    config = json.loads(data["usr/local/netcheck/config.ini"][0])
    language = builder.parse_lang(
        data["usr/local/netcheck/netcheck.lang"][0].decode("utf-8")
    )
    assert config["id"] == config["package"] == config["system_id"] == "netcheck"
    assert config["publisher"] == "Moechz"
    assert config["type"] == "iframe" and config["path"] == "/netcheck/"
    assert config["icon"] == "/images/icons/netcheck.svg"
    assert "open_path" not in config
    assert config["platform"] == "x86_64"
    assert set(builder.REQUIRED_LANGUAGES) <= set(language)
    for lang_name, fields in language.items():
        assert {"name", "auth", "descript"} <= set(fields)
        assert all(fields[field] for field in ("name", "auth", "descript"))

    control_fields = {}
    for line in control["control"][0].decode().splitlines():
        if ": " in line:
            key, value = line.split(": ", 1)
            control_fields[key] = value
    assert control_fields["Package"] == "netcheck"
    assert control_fields["Version"] == str(config["version"])
    assert control_fields["Architecture"] == "amd64"
    icon_svg = ET.fromstring(
        data["usr/local/netcheck/images/icons/netcheck.svg"][0].decode("utf-8")
    )
    assert icon_svg.tag.rsplit("}", 1)[-1] == "svg"
    assert icon_svg.attrib["width"] == icon_svg.attrib["height"] == "512"
    assert icon_svg.attrib["viewBox"] == "0 0 512 512"

    required = {
        "usr/local/netcheck/bin/netcheck": 0o755,
        "usr/local/netcheck/bin/netcheck-helper": 0o755,
        "usr/local/netcheck/images/icons/netcheck.svg": 0o644,
        "usr/local/netcheck/init.d/netcheck.service": 0o644,
        "usr/local/netcheck/init.d/netcheck-bpf.service": 0o644,
        "usr/local/netcheck/webui.bz2": 0o644,
    }
    for name, mode in required.items():
        assert data[name][1] == mode

    for script in ("postinst", "prerm", "postrm"):
        assert control[script][1] == 0o755

    service = data["usr/local/netcheck/init.d/netcheck.service"][0].decode()
    assert "\nUser=netcheck\n" in service
    assert "ExecStart=/usr/local/netcheck/bin/netcheck" in service
    bpf_service = data["usr/local/netcheck/init.d/netcheck-bpf.service"][0].decode()
    assert "ExecStart=/usr/local/netcheck/bin/netcheck-bpf" in bpf_service
    assert "usr/local/netcheck/bin/netcheck-bpf" in data
    assert "/Volume1/@apps/netcheck" not in service

    postinst = control["postinst"][0].decode()
    postrm = control["postrm"][0].decode()
    assert 'tar -xjf "$APP_DIR/webui.bz2" -C "$APP_DIR/webui"' in postinst
    assert 'ln -sfn "$APP_DIR/webui" "/usr/www/${APPID}"' in postinst
    assert 'setfacl -m "u:${APPID}:rwx" /var/api' in postinst
    assert 'chgrp "${APPID}" /var/api' in postinst
    assert 'rm -f /usr/www/netcheck' in postrm
    assert 'rm -rf "${APP_DIR}/data"' in postrm and 'rm -rf "${APP_DIR}/logs"' in postrm

    # ---- compliance dossier (review items C2-C8, S8/S9) ----
    required_compliance = {
        "usr/local/netcheck/LICENSE",
        "usr/local/netcheck/NOTICE",
        "usr/local/netcheck/compliance/README.md",
        "usr/local/netcheck/compliance/privacy-policy.md",
        "usr/local/netcheck/compliance/third-party-services.md",
        "usr/local/netcheck/compliance/data-rights.md",
        "usr/local/netcheck/compliance/licenses.md",
        "usr/local/netcheck/compliance/privileged-channel.md",
        "usr/local/netcheck/compliance/supply-chain.md",
        "usr/local/netcheck/compliance/SBOM.json",
        "usr/local/netcheck/compliance/MANIFEST.json",
        "usr/local/netcheck/compliance/licenses/cilium-ebpf-MIT.txt",
        "usr/local/netcheck/compliance/licenses/golang-x-sys-BSD-3-Clause.txt",
        "usr/share/doc/netcheck/copyright",
    }
    assert required_compliance <= set(data), sorted(required_compliance - set(data))
    assert "Apache License" in data["usr/local/netcheck/LICENSE"][0].decode("utf-8")
    assert "usr/share/doc/netcheck/copyright" in data
    copyright_text = data["usr/share/doc/netcheck/copyright"][0].decode("utf-8")
    assert "License: Apache-2.0" in copyright_text and "BSD-3-Clause" in copyright_text

    manifest = json.loads(data["usr/local/netcheck/compliance/MANIFEST.json"][0])
    for script in ("preinst", "postinst", "prerm", "postrm"):
        assert manifest["maintainer_scripts"][script]["sha256"] == hashlib.sha256(
            control[script][0]).hexdigest(), f"MANIFEST hash mismatch: {script}"
    assert manifest["maintainer_scripts"]["postinst"]["bytes"] == len(control["postinst"][0])
    assert manifest["service_units"]["netcheck-helper.service"]["user"] == "0"
    assert manifest["service_units"]["netcheck-bpf.service"]["user"] == "0"
    assert manifest["service_units"]["netcheck.service"]["user"] == "netcheck"
    contract = json.loads(data["usr/local/netcheck/contract/expected.json"][0])
    assert manifest["contract"] == contract
    assert manifest["review_items"]["C2"] == "compliance/privacy-policy.md"
    assert set(manifest["dossier_docs"]) == {
        name for name in manifest["dossier_docs"] if name.endswith(".md")}
    for name, entry in manifest["dossier_docs"].items():
        assert entry["sha256"] == hashlib.sha256(
            (ROOT / "compliance" / name).read_bytes()).hexdigest()
    sbom = json.loads(data["usr/local/netcheck/compliance/SBOM.json"][0])
    assert sbom["bomFormat"] == "CycloneDX" and sbom["specVersion"] == "1.5"
    sppx = {component["licenses"][0]["license"]["id"] for component in sbom["components"]}
    assert {"MIT", "BSD-3-Clause", "BSD-2-Clause", "Apache-2.0"} <= sppx
    assert any(component["name"] == "github.com/cilium/ebpf"
               for component in sbom["components"])

    # ---- least privilege (review item V1/S1) ----
    helper_unit = data["usr/local/netcheck/init.d/netcheck-helper.service"][0].decode()
    assert "CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_NET_ADMIN" in helper_unit
    assert "NoNewPrivileges=true" in helper_unit
    assert "RestrictAddressFamilies=" in helper_unit
    assert "CAP_SYS_ADMIN" not in helper_unit.split("CapabilityBoundingSet=")[1].split("\n")[0]
    bpf_unit = data["usr/local/netcheck/init.d/netcheck-bpf.service"][0].decode()
    assert "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_BPF CAP_PERFMON" in bpf_unit
    assert "LimitMEMLOCK=infinity" in bpf_unit and "NoNewPrivileges=true" in bpf_unit
    assert "NoNewPrivileges=true" in service and "RestrictAddressFamilies=" in service

    assert not any(name.endswith("/.DS_Store") for name in data)
    assert not any("/data/" in name for name in data)

    md5_lines = control["md5sums"][0].decode().splitlines()
    assert md5_lines
    for line in md5_lines:
        digest, name = line.split("  ", 1)
        assert digest == hashlib.md5(data[name][0]).hexdigest()

    with tarfile.open(ROOT / "webui.bz2", "r:bz2") as frontend:
        names = frontend.getnames()
        index = frontend.extractfile("index.html").read().decode("utf-8")
    assert names.count("assets") == 1
    assert "index.html" in names and "assets/app.js" in names
    for asset in ("styles.css", "i18n.js", "api.js", "clipboard.js", "app.js"):
        assert f"assets/{asset}?v={version['version']}-" in index
    assert ".DS_Store" not in names
    assert "compliance/index.html" in names, "compliance pages must ship in webui.bz2"
    for page in ("privacy-policy", "third-party-services", "data-rights", "licenses",
                 "privileged-channel", "supply-chain", "README"):
        assert f"compliance/{page}.html" in names, f"missing compliance page: {page}"
    with tarfile.open(ROOT / "webui.bz2", "r:bz2") as frontend:
        privacy_page = frontend.extractfile("compliance/privacy-policy.html").read().decode("utf-8")
        index_page = frontend.extractfile("compliance/index.html").read().decode("utf-8")
    assert 'id="block-zh"' in privacy_page and 'id="block-en" hidden' in privacy_page
    assert 'id="lang-zh"' in privacy_page
    assert "github.com/Moechz/netcheck/tree/main/compliance" in index_page
    # V6 可审计性断言（1.2.60 起）：包内 Python 以明文 .py 随包（store 审核要求
    # 可读源码；.pyc-only 曾被判"不可审计字节码"驳回）；前端 JS 必须为压缩混淆版
    lib_py = [n for n in data if n.startswith("usr/local/netcheck/lib/") and n.endswith(".py")]
    assert lib_py, "plain .py sources must ship in the package (review V6)"
    lib_pyc = [n for n in data if n.startswith("usr/local/netcheck/lib/") and n.endswith(".pyc")]
    assert not lib_pyc, f"stale adjacent .pyc leaked: {lib_pyc[:3]}"
    # S05：生命周期由应用中心管理，unit 模板不得携带 Restart=
    for unit_name in ("netcheck.service", "netcheck-helper.service",
                      "netcheck-bpf.service"):
        unit = data[f"usr/local/netcheck/init.d/{unit_name}"][0].decode()
        active = "\n".join(l for l in unit.splitlines()
                            if l.strip() and not l.lstrip().startswith(("#", ";")))
        assert "Restart=" not in active, f"S05 violation: Restart= in {unit_name}"
        assert "RestartSec=" not in active, f"S05 violation: RestartSec= in {unit_name}"
    import bz2 as _bz2
    with tarfile.open(fileobj=io.BytesIO(_bz2.decompress(data["usr/local/netcheck/webui.bz2"][0]))) as ui:
        app_js = ui.extractfile("assets/app.js").read().decode("utf-8")
    assert "function checkName(check)" not in app_js, "app.js is not minified (source leaked)"
    assert "\n  " not in app_js[:4000], "app.js retains readable indentation"
    assert app_js.count("\n") < 60, "app.js should be minified to few lines"
    print(f"PASS packaging.l1_protected (py={len(lib_pyc)}, app.js={len(app_js)}B)")

if __name__ == "__main__":
    test()
    print("PASS packaging.official_layout")
    print("RESULT: 1 passed, 0 failed")
