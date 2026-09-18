"""Shared checker helpers: ping loss, curl classification, gates."""
from __future__ import annotations
import ipaddress
import os
import re
import time
from typing import Optional, Tuple

CURL_ERR = {6: "dns_failure", 7: "connect_failure", 28: "timeout", 60: "cert_failure"}


def ping_loss(probe, target: str, count: int = 2, wait: int = 2,
              ipv6: bool = False) -> Optional[int]:
    """Return loss percentage 0-100, or None when ping is unavailable."""
    argv = ["ping"] + (["-6"] if ipv6 else []) + ["-c", str(count), "-W", str(wait), target]
    r = probe(argv, timeout=count * wait + 3)
    if r.rc != 0 and "received" not in r.stdout and "received" not in r.stderr:
        return None
    m = re.search(r"(\d+) received", r.stdout) or re.search(r"(\d+) received", r.stderr)
    got = int(m.group(1)) if m else 0
    return int((count - got) * 100.0 / count)


def https_probe(probe, url: str, timeout: int = 5) -> Tuple[str, Optional[int]]:
    """curl classification: (ok|http_error|class, code)."""
    r = probe(["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
               "-m", str(timeout), url], timeout=timeout + 2)
    if r.rc == 0:
        code = int(r.stdout.strip() or 0)
        return ("ok" if 200 <= code < 400 else "http_error"), code
    return CURL_ERR.get(r.rc, "unknown"), None


def same_subnet(ip_a: str, prefix_a: int, ip_b: str) -> bool:
    try:
        a = ipaddress.ip_interface(f"{ip_a}/{prefix_a}")
        b = ipaddress.ip_address(ip_b)
        return b in a.network
    except ValueError:
        return False


def gate_ipv6(ctx: dict) -> bool:
    nics = ctx.get("nics") or {}
    return any(i.get("ipv6") for i in nics.get("interfaces", []))


def v6_service_present(nics: dict) -> bool:
    """True when the LAN actually provides IPv6 (any global address or v6 route).

    Takes the collector's nics dict (the same shape as ``self.nics`` in a
    checker). Routers without IPv6 service never send RA/DHCPv6; on such LANs
    a link-local-only host cannot obtain global configuration regardless of
    any local repair, so the IPv6 checks report N/A instead of an unfixable
    fail (M3 device finding).
    """
    if nics.get("_routes6"):
        return True
    return any(a.get("scope") == "global"
               for i in nics.get("interfaces", []) for a in i.get("ipv6", []))


def gate_bond(ctx: dict) -> bool:
    nics = ctx.get("nics") or {}
    return any(i.get("type") == "bond" for i in nics.get("interfaces", []))
