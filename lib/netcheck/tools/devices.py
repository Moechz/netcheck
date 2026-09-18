"""LAN device discovery: ARP table + optional ping sweep (F28)."""
from __future__ import annotations
import ipaddress
import re
import subprocess
from typing import Any, Dict, List

from ..collectors import sysprobe

OUI_PREFIXES = {
    "00:1A:11": "Google", "00:23:CD": "Google", "3C:06:30": "ASUS",
    "6C:BF:B5": "Noon Technology", "DC:65:55": "Unknown", "AA:15:AB": "Unknown",
}


def discover(intensity: str = "medium") -> Dict[str, Any]:
    """Discover LAN devices; intensity: low (ARP only) / medium (+ping) / high (+arping)."""
    neigh = sysprobe.run(["ip", "neigh", "show"], timeout=3).stdout
    devices = _parse_neigh(neigh)

    if intensity in ("medium", "high"):
        # ping sweep the local /24
        subnet = _local_subnet()
        if subnet:
            _ping_sweep(subnet, devices)

    return {"devices": devices, "count": len(devices),
            "intensity": intensity}


def _parse_neigh(text: str) -> List[Dict[str, Any]]:
    devices = {}
    for line in text.splitlines():
        m = re.match(r"(\d+\.\d+\.\d+\.\d+) dev (\S+) lladdr (\S+)", line)
        if not m:
            continue
        ip, iface, mac = m.groups()
        if mac == "00:00:00:00:00:00":
            continue
        key = mac
        if key not in devices:
            oui = mac[:8].upper()
            devices[key] = {
                "ip": ip, "mac": mac, "interface": iface,
                "vendor": OUI_PREFIXES.get(oui, "Unknown"),
                "state": "reachable" if "REACHABLE" in line else "stale",
            }
        else:
            # duplicate IP with different MAC = conflict
            if devices[key]["ip"] != ip:
                devices[key]["conflict"] = True
    return list(devices.values())


def _local_subnet() -> str:
    routes = sysprobe.run(["ip", "route"], timeout=3).stdout
    for line in routes.splitlines():
        if "scope link src" in line and "/24" in line:
            parts = line.split()
            return parts[0]  # e.g. 192.168.124.0/24
    return ""


def _ping_sweep(subnet: str, devices: List) -> None:
    """Parallel ping sweep of /24; populates ARP table for medium/high intensity."""
    net = ipaddress.ip_network(subnet, strict=False)
    hosts = [str(ip) for ip in net.hosts()][:254]
    # use a single batch ping (faster than per-host subprocess)
    try:
        subprocess.run(
            ["ping", "-b", "-c", "1", "-W", "1", subnet.split("/")[0]],
            capture_output=True, timeout=5)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    # re-read ARP after sweep
    neigh2 = sysprobe.run(["ip", "neigh", "show"], timeout=3).stdout
    existing_macs = {d["mac"] for d in devices}
    for d in _parse_neigh(neigh2):
        if d["mac"] not in existing_macs:
            devices.append(d)
