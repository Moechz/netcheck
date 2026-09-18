"""Real-time traffic sampler: /proc/net/dev once per second -> bps per iface."""
from __future__ import annotations
import os
import threading
import time
from typing import Callable, Dict


def parse_proc_net_dev(text: str) -> Dict[str, Dict[str, int]]:
    out: Dict[str, Dict[str, int]] = {}
    for line in text.splitlines()[2:]:
        if ":" not in line:
            continue
        name, _, rest = line.partition(":")
        fields = rest.split()
        if len(fields) < 16:
            continue
        try:
            out[name.strip()] = {
                "rx_bytes": int(fields[0]), "rx_packets": int(fields[1]),
                "rx_errs": int(fields[2]), "rx_drop": int(fields[3]),
                "tx_bytes": int(fields[8]), "tx_packets": int(fields[9]),
                "tx_errs": int(fields[10]), "tx_drop": int(fields[11]),
            }
        except ValueError:
            continue
    return out


class TrafficSampler:
    """Background thread sampling /proc/net/dev; read_fn injectable for tests."""

    def __init__(self, interval: float = 1.0, read_fn: Callable[[], str] = None):
        self.interval = interval
        self._read = read_fn or (lambda: _read_proc())
        self._lock = threading.Lock()
        self.traffic: Dict[str, Dict[str, float]] = {}
        self._prev: Dict[str, Dict[str, int]] = {}
        self._prev_ts = 0.0
        self._stop = threading.Event()
        self._thread = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="nc-traffic")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            self.tick()

    def tick(self) -> None:
        cur = parse_proc_net_dev(self._read())
        now = time.monotonic()
        with self._lock:
            for iface, c in cur.items():
                prev = self._prev.get(iface)
                if prev and now > self._prev_ts > 0:
                    dt = now - self._prev_ts
                    entry = dict(c)
                    entry["rx_bps"] = max(0, c["rx_bytes"] - prev["rx_bytes"]) / dt
                    entry["tx_bps"] = max(0, c["tx_bytes"] - prev["tx_bytes"]) / dt
                else:
                    entry = dict(c, rx_bps=0.0, tx_bps=0.0)
                self.traffic[iface] = entry
            self._prev = cur
            self._prev_ts = now

    def snapshot(self, iface: str = "") -> Dict[str, Dict[str, float]]:
        with self._lock:
            if iface:
                return {iface: dict(self.traffic.get(iface, {}))}
            return {k: dict(v) for k, v in self.traffic.items()}


def _read_proc() -> str:
    try:
        with open("/proc/net/dev", encoding="ascii", errors="replace") as f:
            return f.read()
    except OSError:
        return ""
