#!/bin/bash
# Build a TOS 7 single-package .deb with official staging and preflight checks.
# Usage: ./build.sh [x86_64|aarch64|amd64|arm64]   (amd64=x86_64, arm64=aarch64)
# Output artefacts use the Debian architecture names: netcheck_<v>_amd64.deb / netcheck_<v>_arm64.deb
set -euo pipefail

PLATFORM="${1:-x86_64}"
case "$PLATFORM" in
  amd64)  PLATFORM=x86_64 ;;
  arm64)  PLATFORM=aarch64 ;;
esac
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

fail() {
    echo "BUILD FAIL: $*" >&2
    exit 1
}

echo "== [1/8] Python compile check =="
PYTHONPYCACHEPREFIX="${TMPDIR:-/tmp}/netcheck-pycache" \
    python3 -m compileall -q lib tools || fail "compileall"

echo "== [2/8] WebUI syntax and i18n checks =="
if command -v node >/dev/null 2>&1; then
    for js in webui/assets/*.js; do
        node --check "$js" || fail "JS syntax: $js"
    done
    node webui/tools/check_i18n.js || fail "i18n key parity"
    node tests/test_i18n.js || fail "i18n resolution"
    node tests/test_api_client.js || fail "API client"
    node tests/test_clipboard.js || fail "clipboard"
    node tests/test_layout.js || fail "layout"
    node tests/test_nav_icons.js || fail "navigation icons"
else
    echo "  SKIP: node not installed (CI runs these checks)"
fi

echo "== [2b/8] Compliance dossier render =="
python3 tools/build_compliance.py || fail "compliance page generation"
python3 tools/build_compliance.py --check || fail "compliance pages are stale"
for doc in privacy-policy third-party-services data-rights licenses privileged-channel supply-chain; do
    [ -s "compliance/${doc}.md" ] || fail "compliance/${doc}.md is missing"
    [ -s "webui/compliance/${doc}.html" ] || fail "webui/compliance/${doc}.html is missing"
done
[ -s compliance/LICENSE ] || fail "compliance/LICENSE is missing"
[ -s compliance/NOTICE ] || fail "compliance/NOTICE is missing"

echo "== [3/8] Go/eBPF collector build =="
case "$PLATFORM" in
  x86_64)  WANT_ELF="x86-64" ;;
  aarch64) WANT_ELF="aarch64" ;;
esac
check_bpf_arch() {
    local got
    got="$(file bin/netcheck-bpf 2>/dev/null || true)"
    case "$got" in
      *"$WANT_ELF"*) return 0 ;;
      *) fail "bin/netcheck-bpf architecture mismatch (want $WANT_ELF): $got" ;;
    esac
}
if [ -n "${NETCHECK_GO:-}" ]; then
    NETCHECK_GO="${NETCHECK_GO}" tools/build_bpf_collector.sh "$PLATFORM" \
        || fail "Go BPF collector"
elif command -v go >/dev/null 2>&1; then
    tools/build_bpf_collector.sh "$PLATFORM" || fail "Go BPF collector"
else
    [ -s bin/netcheck-bpf ] || fail "Go toolchain not found and bin/netcheck-bpf is missing"
    echo "  SKIP: using prebuilt bin/netcheck-bpf"
fi
check_bpf_arch

echo "== [4/8] Line-ending check =="
if grep -rl $'\r' --include='*.sh' --include='*.py' --include='*.ini' \
        --include='*.lang' --include='*.service' --include='*.conf' . \
        | grep -v '/\.git/' | grep -q .; then
    fail "CRLF files found"
fi

echo "== [5/8] TOS metadata validation =="
python3 - <<'PY' || exit 1
import configparser
import json
import xml.etree.ElementTree as ET
from pathlib import Path

config = json.loads(Path("config.ini").read_text(encoding="utf-8"))
version = json.loads(Path("version.json").read_text(encoding="utf-8"))["version"]
control = {}
for line in Path("DEBIAN/control").read_text(encoding="utf-8").splitlines():
    if ": " in line:
        key, value = line.split(": ", 1)
        control[key] = value

lang_text = Path("netcheck.lang").read_text(encoding="utf-8")
assert not lang_text.startswith(chr(0xfeff)), "netcheck.lang must be UTF-8 without BOM"
lang_parser = configparser.ConfigParser(interpolation=None, strict=True)
lang_parser.read_string(lang_text)

assert config["id"] == "netcheck"
assert config["publisher"], "config.ini publisher is required"
assert config["type"] == "iframe" and config["path"] == "/netcheck/"
assert "open_path" not in config, "type and open_path are mutually exclusive"
assert config["package"] == control["Package"] == "netcheck"
assert config["system_id"] == "netcheck"
assert config["version"] == control["Version"] == version
assert config["application_type"] == "deb"
assert config["icon"] == "/images/icons/netcheck.svg", "icon path is invalid"
icon_path = Path(config["icon"].lstrip("/"))
assert icon_path.is_file(), "icon is missing"
icon_root = ET.parse(icon_path).getroot()
assert icon_root.tag.rsplit("}", 1)[-1] == "svg", "icon must be an SVG"
assert icon_root.attrib.get("viewBox") == "0 0 512 512", "icon viewBox must be 0 0 512 512"
assert icon_root.attrib.get("width") == icon_root.attrib.get("height") == "512", "icon must declare 512x512"
assert Path("init.d/netcheck.service").is_file()
assert Path("init.d/netcheck-helper.service").is_file()
assert Path("init.d/netcheck-bpf.service").is_file()
assert Path("bin/netcheck-bpf").is_file()
assert Path("webui/index.html").is_file()

required_langs = {
    "en-us", "zh-cn", "zh-hk", "fr-fr", "de-de", "it-it", "es-es", "hu-hu",
    "ja-jp", "ko-kr", "pl-pl", "ru-ru", "tr-tr", "pt-pt",
}
missing = required_langs - set(lang_parser.sections())
assert not missing, f"missing official languages: {sorted(missing)}"
for language in required_langs:
    for field in ("name", "auth", "descript"):
        value = lang_parser.get(language, field).strip().strip('"')
        assert value, f"{language}.{field} must not be empty"
print(f"  metadata OK: netcheck v{version}, publisher={config['publisher']}")
PY

echo "== [6/8] Non-root main service and least-privilege check =="
grep -q '^User=netcheck$' init.d/netcheck.service || fail "main service must run as netcheck"
grep -q '^ExecStart=/usr/local/netcheck/bin/netcheck$' init.d/netcheck.service \
    || fail "main service must use the official /usr/local path"
grep -q '^NoNewPrivileges=true$' init.d/netcheck.service \
    || fail "main service must keep NoNewPrivileges=true"
grep -q '^RestrictAddressFamilies=' init.d/netcheck.service \
    || fail "main service must restrict address families"
for unit in netcheck-helper netcheck-bpf; do
    # uid 0（数字形式）≡ root：TOS 部分安装会把名字 "root" 重映射到无能力的诱饵账户
    grep -q '^User=0$' "init.d/${unit}.service" || fail "${unit} must run as uid 0 (numeric, remap-safe)"
    grep -q '^CapabilityBoundingSet=' "init.d/${unit}.service" \
        || fail "${unit} must declare a capability bounding set"
    grep -q '^NoNewPrivileges=true$' "init.d/${unit}.service" \
        || fail "${unit} must set NoNewPrivileges=true"
    case "$(grep '^CapabilityBoundingSet=' "init.d/${unit}.service")" in
        *CAP_SYS_ADMIN*) fail "${unit} must not grant CAP_SYS_ADMIN" ;;
    esac
done
grep -q '^CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_NET_ADMIN$' \
    init.d/netcheck-helper.service || fail "helper capability set changed unexpectedly"

echo "== [7/8] Stage and package =="
python3 tools/build_deb.py "$PLATFORM" || fail "Deb builder"

echo "== [8/8] Output =="
VERSION=$(python3 -c "import json;print(json.load(open('version.json'))['version'])") \
    || fail "read version.json"
case "$PLATFORM" in
  x86_64)  DEB_ARCH="amd64" ;;
  aarch64) DEB_ARCH="arm64" ;;
esac
OUT="netcheck_${VERSION}_${DEB_ARCH}.deb"
[ -s "$OUT" ] || fail "package was not created"
[ -s "$OUT.sha256" ] || fail "checksum was not created"
shasum -a 256 -c "$OUT.sha256" || fail "checksum verification"

echo
echo "BUILD OK: $OUT ($(du -h "$OUT" | cut -f1))"
echo "Installed payload: /usr/local/netcheck/"
