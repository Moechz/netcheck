""".network content generation + built-in syntax self-check.

No networkd-analyze on TOS 7.0.1140 (device-verified 2026-08-25), so the
built-in parser is primary. Values never contain section/key separators.
"""
from __future__ import annotations
import re
from typing import Any, Dict, List, Optional

SECTION_WHITELIST = {"Match", "Network", "Route", "Link", "DHCPv4", "DHCPv6"}
KEY_WHITELIST = {
    "Match": {"Name", "MACAddress", "Type"},
    "Network": {"DHCP", "Address", "DNS", "LinkLocalAddressing", "IPv6AcceptRA"},
    "Route": {"Destination", "Gateway", "Metric"},
    "Link": {"MTUBytes"},
    "DHCPv4": {"ClientIdentifier", "RouteMetric"},
    "DHCPv6": {"RouteMetric"},
}
_VALUE_FORBIDDEN = set("[];#\n\r")


def render_net_apply(iface: str, mode: str, ipv4: str = "", prefix: int = 24,
                     gateway: str = "", dns: Optional[List[str]] = None,
                     mtu: Optional[int] = None,
                     keep: Optional[Dict[str, Any]] = None) -> str:
    """Render a 10-<iface>.network body per the security-review template."""
    lines: List[str] = ["[Match]", f"Name={iface}", "", "[Network]"]
    if mode in ("dhcp", "reset"):
        lines.append("DHCP=ipv4")
        lines.append("LinkLocalAddressing=ipv6")
    else:  # static
        lines.append("DHCP=no")
        lines.append(f"Address={ipv4}/{prefix}")
        if dns:
            lines.append("DNS=" + " ".join(dns))
        lines.append("LinkLocalAddressing=ipv6")
    lines.append("")
    if mode == "static" and gateway:
        lines += ["[Route]", "Destination=0.0.0.0/0", f"Gateway={gateway}", ""]
    if mtu:
        lines += ["[Link]", f"MTUBytes={mtu}", ""]
    return "\n".join(lines).rstrip() + "\n"


def syntax_check(text: str) -> List[str]:
    """Built-in parser (primary on TOS: no networkd-analyze). Returns errors."""
    errors: List[str] = []
    section: Optional[str] = None
    for ln, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            if section not in SECTION_WHITELIST:
                errors.append(f"line {ln}: unknown section [{section}]")
            continue
        if section is None:
            errors.append(f"line {ln}: key outside any section")
            continue
        if "=" not in line:
            errors.append(f"line {ln}: not key=value")
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if section in KEY_WHITELIST and key not in KEY_WHITELIST[section]:
            errors.append(f"line {ln}: key {key!r} not allowed in [{section}]")
        if any(ch in _VALUE_FORBIDDEN for ch in value):
            errors.append(f"line {ln}: forbidden characters in value of {key}")
    return errors
