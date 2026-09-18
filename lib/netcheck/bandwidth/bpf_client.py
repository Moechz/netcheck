"""Unix-socket client for the Go/eBPF traffic collector."""
from __future__ import annotations
import json
import socket
from typing import Dict


class BpfTrafficClient:
    """Minimal HTTP/1.0 client; avoids a third-party Unix HTTP dependency."""

    def __init__(self, path: str = "/run/netcheck/bpf-traffic.sock",
                 timeout: float = 0.35):
        self.path = path
        self.timeout = timeout

    def snapshot(self, iface: str = "") -> Dict:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            sock.connect(self.path)
            request = ("GET /snapshot HTTP/1.0\r\n"
                       "Host: netcheck-bpf\r\n"
                       "Connection: close\r\n\r\n")
            sock.sendall(request.encode("ascii"))
            response = b""
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                response += chunk
                if len(response) > 1024 * 1024:
                    raise ValueError("BPF response too large")

        header, _, body = response.partition(b"\r\n\r\n")
        lines = header.split(b"\r\n", 1)
        if not lines or not lines[0].startswith(b"HTTP/"):
            raise ValueError("invalid BPF response")
        try:
            status = int(lines[0].split()[1])
        except (IndexError, ValueError) as exc:
            raise ValueError("invalid BPF status") from exc
        if status != 200:
            raise ValueError(f"BPF status {status}")

        payload = json.loads(body.decode("utf-8"))
        interfaces = payload.get("interfaces", {})
        if not isinstance(interfaces, dict):
            raise ValueError("invalid BPF interfaces")
        if iface:
            interfaces = {iface: interfaces.get(iface, {})}
        payload["interfaces"] = interfaces
        return payload
