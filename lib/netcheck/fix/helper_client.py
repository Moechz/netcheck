"""Main-service client for the privileged helper (SO_PEERCRED passes implicitly)."""
from __future__ import annotations
import json
import os
import socket
from typing import Any, Dict, Optional


class HelperClient:
    E_UNAVAILABLE = {"ok": False, "rc": 3001, "stdout": "", "err": "helper unavailable"}

    def __init__(self, sock_path: str = "/run/netcheck/helper.sock",
                 token_path: str = "/run/netcheck/token", timeout: float = 45.0):
        self.sock_path = sock_path
        self.token_path = token_path
        self.timeout = timeout

    def _read_token(self) -> Optional[str]:
        try:
            with open(self.token_path, encoding="ascii") as f:
                return f.read().strip()
        except OSError:
            return None

    def call(self, action: str, params: Dict[str, Any]) -> Dict[str, Any]:
        token = self._read_token()
        if token is None:
            return dict(self.E_UNAVAILABLE)
        payload = json.dumps({"action": action, "params": params, "token": token})
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect(self.sock_path)
                s.sendall(payload.encode("utf-8"))
                chunks = b""
                while True:
                    data = s.recv(65536)
                    if not data:
                        break
                    chunks += data
                    try:
                        return json.loads(chunks.decode("utf-8"))
                    except ValueError:
                        continue
        except (OSError, ValueError):
            return dict(self.E_UNAVAILABLE)
        return dict(self.E_UNAVAILABLE)
