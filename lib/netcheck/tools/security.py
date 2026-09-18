"""Security self-check: firewall, listening ports, tunnel (F33-F34)."""
from __future__ import annotations
import re
from typing import Any, Dict, List

from ..collectors import sysprobe

HIGH_RISK = {22: "SSH", 23: "Telnet", 445: "SMB", 3389: "RDP",
             5900: "VNC", 6379: "Redis", 27017: "MongoDB"}


def check_security() -> Dict[str, Any]:
    """Run all security checks: firewall, exposure, tunnel."""
    return {
        "firewall": _check_firewall(),
        "exposure": _check_exposure(),
        "tunnel": _check_tunnel(),
    }


def _check_firewall() -> Dict[str, Any]:
    cli = sysprobe.run(["tos", "firewall", "status"], timeout=3)
    match = re.search(r"Firewall\s+Status\s+(\w+)", cli.stdout, re.IGNORECASE)
    if match:
        enabled = match.group(1).lower() in ("enabled", "active", "on", "true")
        return {"active": enabled, "service": "tos-firewall",
                "source": "tos-cli"}
    r = sysprobe.run(["systemctl", "is-active", "ufw"], timeout=2)
    active = r.stdout.strip() == "active"
    r2 = sysprobe.run(["systemctl", "is-active", "firewalld"], timeout=2)
    active2 = r2.stdout.strip() == "active"
    return {"active": active or active2,
            "service": "ufw" if active else "firewalld" if active2 else "none"}


def _check_exposure() -> Dict[str, Any]:
    r = sysprobe.run(["ss", "-ltn"], timeout=3)
    ports = []
    for line in r.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[3]
        addr, _, port_str = local.rpartition(":")
        try:
            port = int(port_str)
        except ValueError:
            continue
        binding = "0.0.0.0" if addr in ("0.0.0.0", "*") or ":" in addr else addr
        risk = HIGH_RISK.get(port, "")
        ports.append({
            "port": port, "binding": binding,
            "risk": "high" if port in HIGH_RISK and binding == "0.0.0.0" else
                    "medium" if port in HIGH_RISK else "low",
            "service": risk or "unknown",
            # process names unavailable to non-root (device-verified)
            "process": "unknown",
        })
    exposed = [p for p in ports if p["binding"] == "0.0.0.0"]
    high = [p for p in exposed if p["risk"] == "high"]
    score = max(0, 100 - len(high) * 20 - max(0, len(exposed) - len(high)) * 5)
    return {"ports": ports, "exposed_count": len(exposed),
            "high_risk_count": len(high), "score": score}


def _check_tunnel() -> Dict[str, Any]:
    r = sysprobe.run(["ip", "addr", "show", "tnas0"], timeout=3)
    up = "state UP" in r.stdout or "UNKNOWN" in r.stdout
    has_ip = bool(re.search(r"inet \d+\.", r.stdout))
    return {"interface": "tnas0", "up": up, "has_ip": has_ip,
            "status": "connected" if up and has_ip else
                      "disconnected" if not up else "no_ip"}
