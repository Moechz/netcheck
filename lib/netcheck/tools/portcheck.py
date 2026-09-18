"""TCP/UDP port connectivity probing (F29)."""
from __future__ import annotations
import socket
import time
from typing import Any, Dict, List


def check_port(host: str, port: int, proto: str = "tcp",
               timeout: float = 3.0) -> Dict[str, Any]:
    """Probe a single port; returns reachability + RTT."""
    t0 = time.monotonic()
    result = {"host": host, "port": port, "proto": proto,
              "reachable": False, "rtt_ms": None, "error": ""}
    try:
        if proto == "tcp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.close()
            result["reachable"] = True
        else:  # udp
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(b"\x00", (host, port))
            try:
                data, _ = sock.recvfrom(1024)
                result["reachable"] = True
            except socket.timeout:
                # UDP timeout is ambiguous (could be open with no response)
                result["reachable"] = None
                result["error"] = "no response (may be open)"
            sock.close()
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        result["error"] = str(e)[:100]
    result["rtt_ms"] = round((time.monotonic() - t0) * 1000, 1)
    return result


def check_ports(targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Batch port check; each target: {host, port, proto?}."""
    return [check_port(t["host"], int(t["port"]), t.get("proto", "tcp"))
            for t in targets[:20]]  # limit to 20 per request
