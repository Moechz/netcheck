"""Embedded Ookla speedtest logic (simplified sivel/speedtest-cli approach).

requests is lazy-loaded from the bundled depends/ directory when present;
a session object is injectable for tests. Server list: live -> cache (7d) ->
built-in fallback (design 5.1).
"""
from __future__ import annotations
import json
import os
import statistics
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Optional, Tuple

CONFIG_URL = "https://www.speedtest.net/speedtest-config.php"
SERVERS_URL = "https://www.speedtest.net/speedtest-servers-static.php"
BUILTIN_SERVERS = [
    {"id": "builtin-1", "name": "Fallback A", "host": "https://speed.cloudflare.com"},
    {"id": "builtin-2", "name": "Fallback B", "host": "https://speed.hetzner.de"},
]
SIZES_KB = [350, 500, 750, 1000, 1500, 2000, 2500, 3000, 3500, 4000]


class SpeedtestError(Exception):
    pass


class Speedtest:
    """All network I/O goes through self.session (injectable for tests)."""

    def __init__(self, session: Optional[Any] = None, cache_path: str = "",
                 timeout: int = 10):
        self._session = session
        self.timeout = timeout
        self.cache_path = cache_path

    @property
    def session(self):
        if self._session is not None:
            return self._session
        # lazy-load bundled requests (design 5.2)
        import sys
        app_root = os.environ.get("NETCHECK_ROOT", "")
        depends = os.path.join(app_root, "depends")
        if os.path.isdir(depends) and depends not in sys.path:
            sys.path.insert(0, depends)
        import requests  # noqa: PLC0415 - lazy by design
        self._session = requests.Session()
        self._session.headers["User-Agent"] = "NetCheck/1.0"
        return self._session

    # ---------------- server list ----------------
    def get_servers(self) -> Tuple[List[Dict[str, Any]], str]:
        """Returns (servers, source) where source is live|cache|builtin."""
        try:
            r = self.session.get(SERVERS_URL, timeout=self.timeout)
            servers = self._parse_server_list(r.text)
            if servers and self.cache_path:
                os.makedirs(os.path.dirname(self.cache_path) or ".", exist_ok=True)
                with open(self.cache_path, "w", encoding="utf-8") as f:
                    json.dump({"ts": time.time(), "servers": servers}, f)
            if servers:
                return servers, "live"
        except Exception:  # noqa: BLE001 - fall through to cache
            pass
        # cache (7-day TTL)
        if self.cache_path and os.path.exists(self.cache_path):
            try:
                with open(self.cache_path, encoding="utf-8") as f:
                    data = json.load(f)
                if time.time() - data.get("ts", 0) < 7 * 86400 and data.get("servers"):
                    return data["servers"], "cache"
            except (OSError, ValueError):
                pass
        return BUILTIN_SERVERS, "builtin"

    @staticmethod
    def _parse_server_list(xml: str) -> List[Dict[str, Any]]:
        import re
        servers = []
        for m in re.finditer(
                r'<server url="([^"]+)"(?:[^>]*lat="([^"]*)")?[^>]*name="([^"]*)"',
                xml):
            url = m.group(1)
            servers.append({"id": url, "name": m.group(3) or url,
                            "host": url.rsplit("/", 1)[0]})
            if len(servers) >= 30:
                break
        return servers

    def best_server(self, servers: List[Dict[str, Any]],
                    limit: int = 8) -> Tuple[Dict[str, Any], float]:
        """Probe latency.txt concurrently; pick the lowest median latency."""
        if not servers:
            raise SpeedtestError("no servers")

        def probe(srv):
            try:
                t0 = time.monotonic()
                self.session.get(srv["host"] + "/latency.txt",
                                 timeout=self.timeout)
                return srv, (time.monotonic() - t0) * 1000
            except Exception:  # noqa: BLE001
                return srv, None

        with ThreadPoolExecutor(max_workers=4) as ex:
            scored = list(ex.map(probe, servers[:limit]))
        candidates = [(s, ms) for s, ms in scored if ms is not None]
        if not candidates:
            # cannot probe (e.g. offline) - use the first with a note
            return servers[0], -1.0
        candidates.sort(key=lambda t: t[1])
        return candidates[0]

    # ---------------- download / upload ----------------
    def download(self, server: Dict[str, Any]) -> float:
        results = []

        def fetch(i: int) -> Optional[float]:
            size = SIZES_KB[i % len(SIZES_KB)]
            url = f"{server['host']}/speedtest/random{size}x{size}.jpg"
            try:
                t0 = time.monotonic()
                r = self.session.get(url + f"?nc={time.time()}{i}",
                                     timeout=self.timeout)
                dur = time.monotonic() - t0
                if dur <= 0:
                    return None
                return len(r.content) * 8 / dur / 1e6
            except Exception:  # noqa: BLE001
                return None

        with ThreadPoolExecutor(max_workers=4) as ex:
            for mbps in ex.map(fetch, range(len(SIZES_KB))):
                if mbps:
                    results.append(mbps)
        if not results:
            raise SpeedtestError("download failed")
        return max(results)

    def upload(self, server: Dict[str, Any], loops: int = 8,
               chunk: bytes = b"x" * 100_000) -> float:
        last = 0.0

        def post_once(_: int) -> Optional[float]:
            try:
                t0 = time.monotonic()
                self.session.post(server["host"] + "/speedtest/upload.php",
                                  data=chunk, timeout=self.timeout)
                dur = time.monotonic() - t0
                return len(chunk) * 8 / dur / 1e6 if dur > 0 else None
            except Exception:  # noqa: BLE001
                return None

        with ThreadPoolExecutor(max_workers=4) as ex:
            for mbps in ex.map(post_once, range(loops)):
                if mbps:
                    last = mbps
        if last <= 0:
            raise SpeedtestError("upload failed")
        return last

    def ping_median(self, server: Dict[str, Any], count: int = 10) -> float:
        times = []
        for _ in range(count):
            try:
                t0 = time.monotonic()
                self.session.get(server["host"] + "/latency.txt",
                                 timeout=self.timeout)
                times.append((time.monotonic() - t0) * 1000)
            except Exception:  # noqa: BLE001
                continue
        return statistics.median(times) if times else -1.0


def run_ookla(session=None, cache_path: str = "") -> Dict[str, Any]:
    st = Speedtest(session=session, cache_path=cache_path)
    servers, source = st.get_servers()
    best, probe_ms = st.best_server(servers)
    latency = st.ping_median(best) if probe_ms >= 0 else probe_ms
    down = st.download(best)
    up = st.upload(best)
    return {"download_mbps": round(down, 2), "upload_mbps": round(up, 2),
            "latency_ms": round(latency, 1),
            "server": {"id": best.get("id"), "name": best.get("name"),
                       "host": best.get("host")},
            "conditions": {"method": "ookla",
                           "note": ["results affected by server load",
                                    f"server list source: {source}"]}}
