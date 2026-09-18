#!/usr/bin/env python3
"""E2E dev server: serves webui/ statically and proxies /v2/proxy/netcheck/*
to the backend Unix socket (mirrors the TOS nginx platform proxy locally).

Usage: python3 tests/serve_e2e.py <unix_socket> [http_port]
"""
import http.client
import json
import os
import secrets
import socket
import sys
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

SOCK = sys.argv[1] if len(sys.argv) > 1 else "/tmp/netcheck-smoke/netcheck.sock"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8765
BIND = os.environ.get("NETCHECK_E2E_BIND", "127.0.0.1")
WEBUI = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "webui")
CSRF_TOKEN = secrets.token_hex(32)
TOS_ONLINE_CODE = int(os.environ.get("NETCHECK_E2E_TNAS_CODE", "0"))
MONITOR_SAMPLE_DELAY_MS = int(os.environ.get("NETCHECK_E2E_MONITOR_DELAY_MS", "0"))


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost")
        self.unix_path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(self.unix_path)
        self.sock = s


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=WEBUI, **kw)

    def _proxy(self):
        if self.headers.get("X-Csrf-Token") != CSRF_TOKEN:
            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path.replace("/v2/proxy/netcheck", "", 1) == "/api/monitor/sample":
            time.sleep(MONITOR_SAMPLE_DELAY_MS / 1000.0)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        conn = UnixConnection(SOCK)
        conn.request(self.command, self.path.replace("/v2/proxy/netcheck", "", 1),
                     body=body, headers={k: v for k, v in self.headers.items()
                                         if k.lower() in ("content-type", "authorization",
                                                          "cookie", "host",
                                                          "x-forwarded-host",
                                                          "x-forwarded-proto")})
        resp = conn.getresponse()
        data = resp.read()
        if self.path.replace("/v2/proxy/netcheck", "", 1) == "/api/interfaces":
            payload = json.loads(data)
            interfaces = payload.get("data", {}).get("interfaces", [])
            # macOS development hosts may expose no Linux-compatible collector
            # interfaces. Keep the browser contract test deterministic.
            if not any(item.get("type") == "physical" for item in interfaces):
                payload["data"]["interfaces"] = [{
                    "name": "lo", "type": "loopback", "operstate": "unknown",
                    "speed_mbps": None, "mode": "none", "mac": "00:00:00:00:00:00",
                    "ipv4": [{"addr": "127.0.0.1"}], "ipv6": [], "is_primary": False,
                }, {
                    "name": "e2e0", "type": "physical", "operstate": "up",
                    "speed_mbps": 1000, "mode": "dhcp", "mac": "02:00:00:00:00:01",
                    "ipv4": [{"addr": "192.0.2.10"}], "ipv6": [], "is_primary": True,
                }, {
                    "name": "e2e1", "type": "physical", "operstate": "down",
                    "speed_mbps": None, "mode": "none", "mac": "02:00:00:00:00:02",
                    "ipv4": [], "ipv6": [], "is_primary": False,
                }]
                payload["data"]["hostname"] = "netcheck-e2e"
                data = json.dumps(payload).encode("utf-8")
        elif self.path.replace("/v2/proxy/netcheck", "", 1).startswith("/api/diag/report"):
            payload = json.loads(data)
            report = payload.get("data", {}).get("report")
            if report:
                for item in report.get("groups", {}).get("A", []):
                    if item.get("id") == "link-state":
                        item["status"] = "pass"
                        item["fixable"] = None
                        item["detail"] = {
                            "actual": "1 up, 1 down (e2e1=down)",
                            "expected": "up or unconnected",
                            "reason": "unconnected physical ports are informational only",
                        }
                summary = report.get("summary", {})
                if summary:
                    summary["na"] = max(0, summary.get("na", 0) - 1)
                    summary["pass"] = summary.get("pass", 0) + 1
                report["issues"] = [item for item in report.get("issues", [])
                                    if item.get("id") != "link-state"]
                report["fixable"] = [item for item in report.get("fixable", [])
                                     if item != "link-state"]
                payload["data"]["report"] = report
                data = json.dumps(payload).encode("utf-8")
        elif self.path.replace("/v2/proxy/netcheck", "", 1).startswith("/api/monitor/link-quality"):
            payload = json.loads(data)
            samples = payload.get("data", {}).get("samples") or []
            if not samples or not any(
                isinstance(sample.get("gw_rtt_ms"), (int, float))
                for sample in samples
            ):
                now = time.time()
                offsets = [3, 0, 2, 1, 5, 4, 7, 6]
                payload["data"]["samples"] = [
                    {"ts": now - index * 1800, "gw_loss_pct": 0,
                     "gw_rtt_ms": 5 + index * 2}
                    for index in offsets
                ]
                data = json.dumps(payload).encode("utf-8")
        self.send_response(resp.status)
        self.send_header("Content-Type", resp.getheader("Content-Type", "application/json"))
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _tos_status(self):
        if self.headers.get("X-Csrf-Token") != CSRF_TOKEN:
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/v2/srv/online2/status":
            payload = {"data": {
                "code": TOS_ONLINE_CODE,
                "connect_status": 2 if TOS_ONLINE_CODE else 0,
                "tnasid": "e2e", "user": "secret@example.com",
                "ipv4": "100.82.0.2/22"
            }, "code_num": 0, "code": True}
        elif self.path == "/v2/ddns/":
            payload = {"data": {"records": [{
                "id": 1, "enabled": True, "provider_name": "Example",
                "host_name": "example.example", "user": "secret",
                "last_update_result": "updated", "v6_last_update_result": "",
            }]}, "code_num": 0, "code": True}
        else:
            self.send_error(404)
            return
        data = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in ("/v2/srv/online2/status", "/v2/ddns/"):
            self._tos_status()
        if self.path.startswith("/v2/proxy/netcheck/"):
            self._proxy()
        else:
            super().do_GET()

    def do_POST(self):
        if self.path.startswith("/v2/proxy/netcheck/"):
            self._proxy()
        else:
            self.send_error(404)

    def end_headers(self):
        self.send_header(
            "Set-Cookie",
            f"X-Csrf-Token={CSRF_TOKEN}; Path=/; SameSite=Lax",
        )
        super().end_headers()

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    print(f"E2E server: http://{BIND}:{PORT} (webui={WEBUI}, CSRF proxy->unix:{SOCK})")
    ThreadingHTTPServer((BIND, PORT), Handler).serve_forever()
