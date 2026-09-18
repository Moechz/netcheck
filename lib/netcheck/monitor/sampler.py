"""Link-quality periodic sampler (F26): gateway/public ping, error deltas.

Samples every N minutes (default 5), stores daily shards in data/trends/,
computes rolling statistics for 7/30-day views.
"""
from __future__ import annotations
import json
import os
import threading
import time
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional

from ..collectors import sysprobe


def ping_loss(probe, target: str, count: int = 3, wait: int = 2) -> Optional[float]:
    r = probe(["ping", "-c", str(count), "-W", str(wait), target],
              timeout=count * wait + 3)
    if r.rc != 0 and "received" not in r.stdout:
        return None
    import re
    m = re.search(r"(\d+) received", r.stdout)
    got = int(m.group(1)) if m else 0
    return (count - got) * 100.0 / count


def ping_rtt(probe, target: str, count: int = 3, wait: int = 2) -> Optional[float]:
    r = probe(["ping", "-c", str(count), "-W", str(wait), target],
              timeout=count * wait + 3)
    import re
    m = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", r.stdout)
    return float(m.group(2)) if m else None


class LinkSampler:
    """Background thread sampling link quality; probe injectable for tests."""

    def __init__(self, data_dir: str, config, probe=None, interval_min: int = 5):
        self.data_dir = os.path.join(data_dir, "trends")
        os.makedirs(self.data_dir, exist_ok=True)
        self.config = config
        self._probe = probe or sysprobe.run
        self.interval = interval_min * 60
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._prev_errors: Dict[str, int] = {}

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="nc-monitor")
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=2.0)

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def _loop(self):
        while not self._stop.wait(self.interval):
            try:
                self.sample()
            except Exception:  # noqa: BLE001
                pass

    def gateway(self) -> str:
        out = self._probe(["ip", "route"], timeout=3).stdout
        for line in out.splitlines():
            if line.startswith("default"):
                parts = line.split()
                try:
                    return parts[parts.index("via") + 1]
                except (ValueError, IndexError):
                    pass
        return ""

    def sample(self) -> Dict[str, Any]:
        gw = self.gateway()
        entry: Dict[str, Any] = {"ts": time.time()}
        if gw:
            entry["gw_loss_pct"] = ping_loss(self._probe, gw)
            entry["gw_rtt_ms"] = ping_rtt(self._probe, gw)
        pub = (self.config.get("diag.ping_public_ips") or ["223.5.5.5"])[0]
        entry["pub_loss_pct"] = ping_loss(self._probe, pub)
        entry["pub_rtt_ms"] = ping_rtt(self._probe, pub)
        # error deltas from /proc/net/dev
        traffic = self._read_proc_dev()
        entry["errors"] = {}
        for iface, stats in traffic.items():
            total = stats.get("rx_errs", 0) + stats.get("tx_drop", 0)
            prev = self._prev_errors.get(iface, total)
            entry["errors"][iface] = total - prev
            self._prev_errors[iface] = total
        self._append(entry)
        return entry

    @staticmethod
    def _read_proc_dev() -> Dict[str, Dict[str, int]]:
        out: Dict[str, Dict[str, int]] = {}
        try:
            with open("/proc/net/dev", encoding="ascii", errors="replace") as f:
                for line in f.readlines()[2:]:
                    if ":" not in line:
                        continue
                    name, _, rest = line.partition(":")
                    fields = rest.split()
                    if len(fields) >= 12:
                        out[name.strip()] = {
                            "rx_errs": int(fields[2]), "tx_drop": int(fields[11])}
        except OSError:
            pass
        return out

    def _append(self, entry: Dict[str, Any]):
        shard = datetime.now().strftime("%Y-%m-%d")
        path = os.path.join(self.data_dir, f"{shard}.json")
        items = []
        try:
            with open(path, encoding="utf-8") as f:
                items = json.load(f)
        except (OSError, ValueError):
            pass
        items.append(entry)
        with open(path + ".tmp", "w", encoding="utf-8") as f:
            json.dump(items, f)
        os.replace(path + ".tmp", path)
        self._prune()

    def _prune(self):
        retain = int(self.config.get("monitor.retain_days", 30))
        cutoff = datetime.now() - timedelta(days=retain)
        for fname in os.listdir(self.data_dir):
            if fname.endswith(".json"):
                try:
                    d = datetime.strptime(fname[:-5], "%Y-%m-%d")
                    if d < cutoff:
                        os.unlink(os.path.join(self.data_dir, fname))
                except ValueError:
                    pass

    def query(self, days: int = 7) -> List[Dict[str, Any]]:
        """Return samples from the last N days (newest first)."""
        cutoff = time.time() - days * 86400
        items: List[Dict[str, Any]] = []
        for fname in sorted(os.listdir(self.data_dir), reverse=True):
            if not fname.endswith(".json"):
                continue
            try:
                with open(os.path.join(self.data_dir, fname), encoding="utf-8") as f:
                    for e in json.load(f):
                        if e.get("ts", 0) >= cutoff:
                            items.append(e)
            except (OSError, ValueError):
                continue
        # Daily shards are visited newest-first, but each shard is append-only
        # and therefore oldest-first. Sort the merged result to restore the API
        # contract; otherwise clients that take "the first N" get a mixture of
        # days instead of the newest N samples.
        items.sort(key=lambda entry: entry.get("ts") or 0, reverse=True)
        return items
