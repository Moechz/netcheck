#!/usr/bin/env python3
"""Compliance dossier tests: Markdown rendering + audit-item coverage.

Review items covered here: C2 (privacy policy), C3 (licenses), C4 (third-party
services), C5 (data access/correction/deletion), V1/S1 (privileged channel
authorisation and least privilege) and S8/S9 (supply chain / maintainer scripts).
"""
from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COMPLIANCE = ROOT / "compliance"
BUILDER = ROOT / "tools/build_compliance.py"

passed = 0
failed = 0


def check(name: str, expected, actual) -> None:
    global passed, failed
    if expected == actual:
        passed += 1
        print(f"PASS {name}")
    else:
        failed += 1
        print(f"FAIL {name}: expected={expected!r} actual={actual!r}")


def check_true(name: str, condition: bool, detail: str = "") -> None:
    check(name, True, bool(condition) if condition else detail or False)


def load_builder():
    spec = importlib.util.spec_from_file_location("netcheck_build_compliance", BUILDER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def read(name: str) -> str:
    return (COMPLIANCE / name).read_text(encoding="utf-8")


def test_markdown_renderer(builder) -> None:
    markdown = "\n".join([
        "# Title",
        "",
        "Paragraph with **bold**, `code` and a [link](https://example.com).",
        "",
        "- first item",
        "  wrapped continuation",
        "- second `item`",
        "",
        "| A | B |",
        "| --- | --- |",
        "| 1 | 2 |",
        "",
        "```bash",
        "echo hi",
        "```",
        "",
        "> note",
        "",
        "1. one",
        "2. two",
    ])
    html = builder.render_markdown(markdown)
    check_true("md.heading", '<h1 id="title">Title</h1>' in html, html[:120])
    check_true("md.bold", "<strong>bold</strong>" in html)
    check_true("md.code_span", "<code>code</code>" in html)
    check_true("md.link", '<a href="https://example.com">link</a>' in html)
    check_true("md.list_lazy_continuation",
               "<li>first item wrapped continuation</li>" in html, html)
    check_true("md.table", "<th>A</th><th>B</th>" in html and "<td>1</td>" in html)
    check_true("md.code_fence", "<pre><code>echo hi</code></pre>" in html)
    check_true("md.blockquote", "<blockquote>note</blockquote>" in html)
    check_true("md.ordered", "<ol><li>one</li><li>two</li></ol>" in html)
    check_true("md.escapes_html", "&lt;script&gt;" in builder.render_markdown("<script>"))
    check("md.deterministic", html, builder.render_markdown(markdown))


def test_documents() -> None:
    docs = {
        "README.md": ["V1 / S1", "C2", "C3", "C4", "C5", "S8 / S9"],
        "privacy-policy.md": ["保存期限", "您的权利", "安全措施", "第三方共享", "删除",
                              "retention", "Security measures", "Third-party sharing"],
        "third-party-services.md": ["ookla", "iperf3", "speedtest.net", "传输地域",
                                    "共享", "cross-border"],
        "data-rights.md": ["查阅", "更正", "删除", "dpkg --purge", "Access",
                           "Correction", "Deletion"],
        "licenses.md": ["Apache-2.0", "MIT", "BSD-3-Clause", "BSD-2-Clause",
                        "copyleft", "无 copyleft"],
        "privileged-channel.md": ["R1", "CapabilityBoundingSet", "CAP_NET_ADMIN",
                                  "CAP_CHOWN", "CAP_SYS_ADMIN", "白名单", "Least privilege"],
        "supply-chain.md": ["postinst", "prerm", "postrm", "preinst", "SBOM",
                            "Moechz/TOS-netcheck-pv"],
    }
    for name, needles in docs.items():
        body = read(name)
        check_true(f"doc.exists.{name}", (COMPLIANCE / name).is_file())
        for needle in needles:
            check_true(f"doc.{name}.mentions[{needle}]", needle in body)
    check_true("doc.privacy.bilingual", "## 一、中文版" in read("privacy-policy.md")
               and "## 二、English version" in read("privacy-policy.md"))
    check_true("doc.privileged.request", "本次申请" in read("privileged-channel.md"))


def test_licenses_shipped() -> None:
    required = {
        "LICENSE": "Apache License",
        "NOTICE": "third-party",
        "licenses/cilium-ebpf-MIT.txt": "MIT License",
        "licenses/golang-x-sys-BSD-3-Clause.txt": "Redistribution and use",
        "licenses/golang-x-exp-BSD-3-Clause.txt": "Redistribution and use",
        "licenses/cilium-ebpf-examples-headers-BSD-2-Clause.txt": "Redistribution and use",
    }
    for relative, needle in required.items():
        path = COMPLIANCE / relative
        check_true(f"licenses.shipped.{relative}", path.is_file() and needle in
                   path.read_text(encoding="utf-8", errors="replace"))


def test_generated_pages(builder, tmp: Path) -> None:
    pages = builder.build(builder.SOURCE_DIR, tmp)
    names = {page.name for page in pages}
    check_true("pages.index", "index.html" in names)
    for filename, _, _ in builder.DOCUMENTS:
        check_true(f"pages.{filename}", filename[:-3] + ".html" in names)
    privacy = (tmp / "privacy-policy.html").read_text(encoding="utf-8")
    check_true("pages.language_switch", 'id="lang-zh"' in privacy and 'id="lang-en"' in privacy)
    check_true("pages.bilingual_blocks", 'id="block-zh"' in privacy and 'id="block-en" hidden' in privacy)
    check_true("pages.self_contained", "<style>" in privacy and "http-equiv" not in privacy)
    check_true("pages.no_external_assets", not re.search(r'<(script|link)[^>]+src="http', privacy))
    index = (tmp / "index.html").read_text(encoding="utf-8")
    check_true("pages.index_links", index.count('class="card"') >= len(builder.DOCUMENTS))
    check_true("pages.index_public_url", "github.com/Moechz/netcheck/tree/main/compliance" in index)

    # The checked-in pages must match the Markdown sources exactly.
    for page in pages:
        target = builder.OUTPUT_DIR / page.name
        check("pages.in_sync." + page.name, page.read_text(encoding="utf-8"),
              target.read_text(encoding="utf-8") if target.is_file() else "")


def test_service_units() -> None:
    helper = (ROOT / "init.d/netcheck-helper.service").read_text(encoding="utf-8")
    bpf = (ROOT / "init.d/netcheck-bpf.service").read_text(encoding="utf-8")
    main = (ROOT / "init.d/netcheck.service").read_text(encoding="utf-8")
    check_true("unit.helper.capabilities",
               "CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_NET_ADMIN" in helper)
    check_true("unit.helper.no_sys_admin", "CAP_SYS_ADMIN" not in helper.split(
        "CapabilityBoundingSet=")[1].split("\n")[0])
    check_true("unit.helper.nnp", "NoNewPrivileges=true" in helper)
    check_true("unit.helper.address_families", "RestrictAddressFamilies=" in helper)
    check_true("unit.bpf.capabilities",
               "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_BPF CAP_PERFMON" in bpf)
    check_true("unit.bpf.memlock", "LimitMEMLOCK=infinity" in bpf)
    check_true("unit.main.non_root", "\nUser=netcheck\n" in main)
    check_true("unit.main.hardened",
               "NoNewPrivileges=true" in main and "RestrictAddressFamilies=" in main)
    for unit in ("netcheck.service", "netcheck-helper.service", "netcheck-bpf.service"):
        check_true(f"unit.{unit}.namespace_note",
                   "NAMESPACE" in (ROOT / "init.d" / unit).read_text(encoding="utf-8"))
    postrm = (ROOT / "DEBIAN/postrm").read_text(encoding="utf-8")
    check_true("postrm.purge_data", 'rm -rf "${APP_DIR}/data"' in postrm
               and 'rm -rf "${APP_DIR}/logs"' in postrm)


def main() -> int:
    import tempfile
    builder = load_builder()
    test_markdown_renderer(builder)
    test_documents()
    test_licenses_shipped()
    test_service_units()
    with tempfile.TemporaryDirectory(prefix="nc-compliance-") as tmp:
        test_generated_pages(builder, Path(tmp))
    print(f"\nRESULT: {passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
