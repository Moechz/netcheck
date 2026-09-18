#!/usr/bin/env python3
"""Render the compliance Markdown dossier into self-contained WebUI pages.

Sources  : compliance/*.md            (single source of truth, shipped in the .deb)
Output   : webui/compliance/*.html    (bundled into webui.bz2 for the app UI)

The converter intentionally supports only the Markdown subset used by the
dossier (headings, paragraphs, lists, tables, fenced code, blockquotes, rules,
inline code/bold/links) so that the output stays deterministic and dependency
free. Each page carries a 中文/English switch because the source documents are
bilingual (the first English heading splits the two halves).
"""
from __future__ import annotations

import argparse
import html
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple

ROOT = Path(__file__).resolve().parent.parent
SOURCE_DIR = ROOT / "compliance"
OUTPUT_DIR = ROOT / "webui" / "compliance"

# Document order on the landing page: (markdown file, title, one-line purpose)
DOCUMENTS: List[Tuple[str, str, str]] = [
    ("README.md", "材料索引 / Dossier Index", "审核项与材料对照表 / Review-item mapping"),
    ("privileged-channel.md", "特权通道授权与最小权限 / Privileged Channel",
     "V1·S1：root 辅助服务的授权依据、能力清单与关闭方法"),
    ("privacy-policy.md", "隐私政策 / Privacy Policy",
     "C2：处理的数据、保存期限、安全措施、第三方共享、删除途径"),
    ("third-party-services.md", "第三方服务与数据去向 / Third-Party Services",
     "C4：ookla/iperf3 等外部调用、传输地域与共享情况"),
    ("data-rights.md", "用户数据权利 / Data Access, Correction, Deletion",
     "C5：查阅、更正、导出、删除的确切途径与命令"),
    ("licenses.md", "开源许可与依赖声明 / Licenses & Dependencies",
     "C3：应用与第三方组件许可证、无 copyleft 捆绑声明"),
    ("supply-chain.md", "供应链与维护脚本 / Supply Chain",
     "S8·S9：仓库来源、构建复现、.deb 维护脚本与 SBOM"),
]

_CSS = """
:root{--bg:#0f1713;--card:#16211b;--fg:#e8f2ec;--dim:#a7b8ae;--acc:#6fc258;--bd:#27392f}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
 font:15px/1.75 -apple-system,"PingFang SC","Microsoft YaHei",Segoe UI,Roboto,Helvetica,Arial,sans-serif}
header{position:sticky;top:0;z-index:5;display:flex;gap:12px;align-items:center;justify-content:space-between;
 padding:14px 22px;background:rgba(15,23,19,.94);border-bottom:1px solid var(--bd);backdrop-filter:blur(6px)}
header a{color:var(--fg);text-decoration:none;font-weight:600}
header .sub{color:var(--dim);font-size:13px}
main{max-width:960px;margin:0 auto;padding:22px 22px 60px}
.langbar{display:flex;gap:8px;margin:0 0 18px}
.langbar button{cursor:pointer;border:1px solid var(--bd);background:var(--card);color:var(--dim);
 border-radius:8px;padding:6px 14px;font-size:13px}
.langbar button[aria-pressed="true"]{background:var(--acc);border-color:var(--acc);color:#0d1a10;font-weight:600}
h1{font-size:24px;line-height:1.35;margin:6px 0 18px}
h2{font-size:19px;margin:28px 0 10px;padding-top:14px;border-top:1px solid var(--bd)}
h3{font-size:16px;margin:22px 0 8px}
h4{font-size:14px;margin:18px 0 6px;color:var(--dim)}
p{margin:10px 0}
ul,ol{margin:10px 0 10px 22px;padding:0}
li{margin:4px 0}
code{background:#0b120e;border:1px solid var(--bd);border-radius:5px;padding:1px 5px;font-size:13px}
pre{background:#0b120e;border:1px solid var(--bd);border-radius:10px;padding:14px;overflow:auto}
pre code{background:none;border:0;padding:0;font-size:12.5px;line-height:1.6}
blockquote{margin:12px 0;padding:8px 14px;border-left:3px solid var(--acc);background:var(--card);color:var(--dim)}
table{border-collapse:collapse;width:100%;margin:14px 0;font-size:13.5px;display:block;overflow-x:auto}
th,td{border:1px solid var(--bd);padding:8px 10px;text-align:left;vertical-align:top}
th{background:var(--card);font-weight:600;white-space:nowrap}
a{color:var(--acc)}
hr{border:0;border-top:1px solid var(--bd);margin:24px 0}
.cards{display:grid;gap:12px;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));margin:18px 0}
.card{display:block;background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:14px 16px;
 text-decoration:none;color:var(--fg)}
.card b{display:block;font-size:15px;margin-bottom:6px}
.card span{display:block;color:var(--dim);font-size:13px}
.toc{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:12px 16px;margin:18px 0}
.toc b{display:block;margin-bottom:6px;font-size:13px;color:var(--dim)}
.toc a{display:block;font-size:13.5px;text-decoration:none;margin:3px 0}
footer{color:var(--dim);font-size:12.5px;border-top:1px solid var(--bd);margin-top:34px;padding-top:14px}
[hidden]{display:none}
"""

_TOGGLE_JS = """
(function(){
  var zh=document.getElementById('lang-zh'),en=document.getElementById('lang-en');
  if(!zh||!en)return;
  function apply(lang){
    document.documentElement.setAttribute('data-lang',lang);
    var showZh=lang!=='en';
    document.getElementById('block-zh').hidden=!showZh;
    document.getElementById('block-en').hidden=showZh;
    zh.setAttribute('aria-pressed',String(showZh));
    en.setAttribute('aria-pressed',String(!showZh));
  }
  zh.addEventListener('click',function(){apply('zh');});
  en.addEventListener('click',function(){apply('en');});
  var q=(location.search.match(/[?&]lang=(\\w+)/)||[])[1];
  apply(q==='en'?'en':'zh');
})();
"""


def _slug(text: str) -> str:
    slug = re.sub(r"[^0-9a-z\u4e00-\u9fff]+", "-", text.lower()).strip("-")
    return slug or "section"


_CODE_RE = re.compile(r"`([^`]+)`")
_LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)")
_BOLD_RE = re.compile(r"\*\*([^*]+)\*\*")


def inline(text: str) -> str:
    """Escape and render the inline Markdown subset used by the dossier."""
    out = html.escape(text, quote=False)
    spans: List[str] = []

    def stash(match: "re.Match[str]") -> str:
        spans.append(f"<code>{match.group(1)}</code>")
        return f"\x00{len(spans) - 1}\x00"

    out = _CODE_RE.sub(stash, out)
    out = _LINK_RE.sub(lambda m: f'<a href="{m.group(2)}">{m.group(1)}</a>', out)
    out = _BOLD_RE.sub(lambda m: f"<strong>{m.group(1)}</strong>", out)
    for index, span in enumerate(spans):
        out = out.replace(f"\x00{index}\x00", span)
    return out


def _table_row(line: str) -> List[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


_BLOCK_START_RE = re.compile(r"^(#{1,6}\s|```|>|-{3,}$|\||[-*]\s|\d+\.\s)")


def _starts_block(line: str) -> bool:
    """True when a line begins a new Markdown block (ends lazy list continuation)."""
    return bool(_BLOCK_START_RE.match(line))


def render_markdown(text: str) -> str:
    """Convert the dossier Markdown subset into HTML (deterministic)."""
    lines = text.replace("\r\n", "\n").split("\n")
    html_parts: List[str] = []
    paragraph: List[str] = []
    index = 0

    def flush_paragraph() -> None:
        if paragraph:
            html_parts.append("<p>" + inline(" ".join(paragraph).strip()) + "</p>")
            paragraph.clear()

    while index < len(lines):
        line = lines[index]
        stripped = line.strip()

        if stripped.startswith("```"):
            flush_paragraph()
            index += 1
            block: List[str] = []
            while index < len(lines) and not lines[index].strip().startswith("```"):
                block.append(lines[index])
                index += 1
            index += 1
            html_parts.append("<pre><code>" + html.escape("\n".join(block)) + "</code></pre>")
            continue

        if not stripped:
            flush_paragraph()
            index += 1
            continue

        if re.fullmatch(r"-{3,}", stripped):
            flush_paragraph()
            html_parts.append("<hr>")
            index += 1
            continue

        heading = re.match(r"(#{1,6})\s+(.*)$", stripped)
        if heading:
            flush_paragraph()
            level = len(heading.group(1))
            title = heading.group(2).strip()
            html_parts.append(
                f'<h{level} id="{_slug(title)}">{inline(title)}</h{level}>')
            index += 1
            continue

        if (stripped.startswith("|") and index + 1 < len(lines)
                and re.fullmatch(r"\|[\s:|-]+\|", lines[index + 1].strip())):
            flush_paragraph()
            header = _table_row(stripped)
            index += 2
            rows: List[List[str]] = []
            while index < len(lines) and lines[index].strip().startswith("|"):
                rows.append(_table_row(lines[index]))
                index += 1
            table = ["<table><thead><tr>"]
            table += [f"<th>{inline(cell)}</th>" for cell in header]
            table.append("</tr></thead><tbody>")
            for row in rows:
                table.append("<tr>" + "".join(
                    f"<td>{inline(cell)}</td>" for cell in row) + "</tr>")
            table.append("</tbody></table>")
            html_parts.append("".join(table))
            continue

        if stripped.startswith(">"):
            flush_paragraph()
            quote: List[str] = []
            while index < len(lines) and lines[index].strip().startswith(">"):
                quote.append(lines[index].strip().lstrip(">").strip())
                index += 1
            html_parts.append("<blockquote>" + inline(" ".join(quote)) + "</blockquote>")
            continue

        ordered = re.match(r"\d+\.\s+(.*)$", stripped)
        if stripped.startswith("- ") or stripped.startswith("* ") or ordered:
            flush_paragraph()
            tag = "ol" if ordered else "ul"
            items: List[str] = []
            while index < len(lines):
                current = lines[index]
                current_stripped = current.strip()
                match = (re.match(r"\d+\.\s+(.*)$", current_stripped) if ordered
                         else re.match(r"[-*]\s+(.*)$", current_stripped))
                if match:
                    items.append(match.group(1))
                    index += 1
                    continue
                # Lazy continuation: wrapped lines belong to the previous item.
                if not current_stripped or _starts_block(current_stripped) or not items:
                    break
                items[-1] = items[-1] + " " + current_stripped
                index += 1
            html_parts.append(
                f"<{tag}>" + "".join(f"<li>{inline(item)}</li>" for item in items)
                + f"</{tag}>")
            continue

        paragraph.append(stripped)
        index += 1

    flush_paragraph()
    return "\n".join(html_parts)


def split_languages(body_html: str) -> Tuple[str, str]:
    """Split rendered HTML into (zh, en) halves at the first English heading."""
    marker = re.search(r'<h2 id="[^"]*">[^<]*(english|二、english)[^<]*</h2>',
                       body_html, re.IGNORECASE)
    if not marker:
        return body_html, ""
    return body_html[:marker.start()], body_html[marker.start():]


def page(title: str, body: str, *, has_english: bool, depth: int = 0) -> str:
    prefix = "../" * depth
    back = (f'<a href="{prefix}index.html">← 材料索引 / Dossier index</a>'
            if depth else '<span class="sub">NetCheck · Compliance &amp; Policies</span>')
    if has_english:
        zh, en = split_languages(body)
        blocks = (f'<section id="block-zh">{zh}</section>'
                  f'<section id="block-en" hidden>{en}</section>')
        bar = ('<div class="langbar">'
               '<button id="lang-zh" type="button" aria-pressed="true">中文</button>'
               '<button id="lang-en" type="button" aria-pressed="false">English</button>'
               '</div>')
        script = f"<script>{_TOGGLE_JS}</script>"
    else:
        blocks, bar, script = f'<section id="block-zh">{body}</section>', "", ""
    return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{html.escape(title)} · NetCheck</title>
<style>{_CSS}</style></head>
<body>
<header><a href="{prefix}index.html">NetCheck 合规与政策</a>{back}</header>
<main>{bar}{blocks}
<footer>NetCheck (netcheck) · Developer/Publisher: Moechz · TerraMaster TOS 7 ·
github.com/Moechz/netcheck · 本页由 compliance/ 目录下的 Markdown 直接生成，与安装包内容一致。</footer>
</main>{script}</body></html>
"""


def _toc(body_html: str) -> str:
    items = re.findall(r'<h2 id="([^"]+)">([^<]+)</h2>', body_html)
    if len(items) < 3:
        return ""
    links = "".join(f'<a href="#{anchor}">{html.escape(text)}</a>' for anchor, text in items)
    return f'<div class="toc"><b>目录 / Contents</b>{links}</div>'


def build(source_dir: Path = SOURCE_DIR, output_dir: Path = OUTPUT_DIR) -> List[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []
    cards: List[str] = []

    for filename, title, purpose in DOCUMENTS:
        source = source_dir / filename
        if not source.is_file():
            raise FileNotFoundError(f"compliance document missing: {source}")
        markdown = source.read_text(encoding="utf-8")
        body = render_markdown(markdown)
        has_english = bool(re.search(r'<h2 id="[^"]*">[^<]*english',
                                     body, re.IGNORECASE))
        body = _toc(body) + body
        target = output_dir / (filename[:-3] + ".html")
        target.write_text(page(title, body, has_english=has_english),
                          encoding="utf-8")
        written.append(target)
        cards.append(f'<a class="card" href="{target.name}"><b>{html.escape(title)}</b>'
                     f'<span>{html.escape(purpose)}</span></a>')

    index_body = (
        "<h1>合规与政策 / Compliance &amp; Policies</h1>"
        "<p>本页材料由安装包内的 <code>compliance/</code> 目录生成，与 "
        "<code>/usr/local/netcheck/compliance/</code> 中的文件逐字节一致，"
        "同时发布于 "
        '<a href="https://github.com/Moechz/netcheck/tree/main/compliance">'
        "github.com/Moechz/netcheck</a>。</p>"
        '<div class="cards">' + "".join(cards) + "</div>"
        "<p>联系渠道 / Contact: <a href=\"https://github.com/Moechz/netcheck/issues\">github.com/Moechz/netcheck/issues</a></p>"
    )
    index_path = output_dir / "index.html"
    index_path.write_text(page("合规与政策 / Compliance & Policies", index_body,
                               has_english=False), encoding="utf-8")
    written.insert(0, index_path)
    return written


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default=str(SOURCE_DIR))
    parser.add_argument("--output", default=str(OUTPUT_DIR))
    parser.add_argument("--check", action="store_true",
                        help="fail if the generated pages are not up to date")
    args = parser.parse_args()
    try:
        if args.check:
            expected = {path.name: path.read_text(encoding="utf-8")
                        for path in build(Path(args.source), Path(args.output))}
            stale = []
            for name, content in expected.items():
                target = Path(args.output) / name
                if not target.is_file() or target.read_text(encoding="utf-8") != content:
                    stale.append(name)
            if stale:
                print(f"COMPLIANCE FAIL: stale generated pages: {stale}", file=sys.stderr)
                return 1
            print(f"compliance pages up to date ({len(expected)} files)")
            return 0
        written = build(Path(args.source), Path(args.output))
    except Exception as error:  # noqa: BLE001 - CLI boundary
        print(f"COMPLIANCE FAIL: {error}", file=sys.stderr)
        return 1
    print(f"compliance: {len(written)} pages -> {Path(args.output).relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
