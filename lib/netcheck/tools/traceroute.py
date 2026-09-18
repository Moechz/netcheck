"""Traceroute path analysis with breakpoint detection (F30)."""
from __future__ import annotations
import re
from typing import Any, Dict, List

from ..collectors import sysprobe


def run_traceroute(target: str, max_hops: int = 30) -> Dict[str, Any]:
    """Run traceroute and parse hops; detect the failing hop."""
    r = sysprobe.run(["traceroute", "-n", "-m", str(max_hops), "-w", "2", target],
                     timeout=max_hops * 3 + 10)
    hops = _parse_traceroute(r.stdout)
    breakpoint = _find_breakpoint(hops)
    return {"target": target, "hops": hops, "breakpoint": breakpoint,
            "hop_count": len(hops)}


def _parse_traceroute(text: str) -> List[Dict[str, Any]]:
    hops = []
    for line in text.splitlines():
        m = re.match(r"\s*(\d+)\s+(\S+)\s+([\d.]+)\s+ms", line)
        if m:
            hop_num, ip, rtt = int(m.group(1)), m.group(2), float(m.group(3))
            if hops and hops[-1]["hop"] == hop_num:
                hops[-1]["rtts"].append(rtt)
            else:
                hops.append({"hop": hop_num, "ip": ip, "rtts": [rtt],
                             "timeout": False})
            continue
        m2 = re.match(r"\s*(\d+)\s+\*", line)
        if m2:
            hops.append({"hop": int(m2.group(1)), "ip": "*",
                         "rtts": [], "timeout": True})
    return hops


def _find_breakpoint(hops: List) -> Dict[str, Any]:
    """Find the first hop where the path breaks (consecutive timeouts)."""
    consecutive_timeouts = 0
    for hop in hops:
        if hop.get("timeout"):
            consecutive_timeouts += 1
            if consecutive_timeouts >= 3:
                attribution = _attribute(hop["hop"])
                return {"hop": hop["hop"], "reason": "3 consecutive timeouts",
                        "attribution": attribution}
        else:
            consecutive_timeouts = 0
    return None


def _attribute(hop: int) -> str:
    if hop == 1:
        return "local (this device)"
    if hop == 2:
        return "gateway/switch"
    if hop <= 5:
        return "ISP backbone"
    return "remote/target"
