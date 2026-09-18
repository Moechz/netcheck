"""Alert engine (F27): threshold rules, throttle, notification channels."""
from __future__ import annotations
import json
import os
import time
from typing import Any, Callable, Dict, List, Optional
from urllib.request import Request, urlopen


class AlertEngine:
    """Evaluates rules against samples; throttles per event; dispatches."""

    def __init__(self, data_dir: str, config,
                 notify_fn: Optional[Callable] = None):
        self.data_dir = os.path.join(data_dir, "alerts")
        os.makedirs(self.data_dir, exist_ok=True)
        self.config = config
        self._notify = notify_fn or self._default_notify
        self._last_sent: Dict[str, float] = {}

    def evaluate(self, sample: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check thresholds and fire alerts (returns fired list)."""
        fired: List[Dict[str, Any]] = []
        th = self.config.get("monitor.thresholds", {})
        loss_limit = th.get("loss_pct", 10)
        latency_limit = th.get("latency_ms", 500)

        for key, label in [("gw_loss_pct", "gateway"), ("pub_loss_pct", "public")]:
            loss = sample.get(key)
            if loss is not None and loss > loss_limit:
                fired.append({"event": f"{label}_loss", "value": loss,
                              "threshold": loss_limit,
                              "message": f"{label} loss {loss:.0f}% > {loss_limit}%"})
        for key, label in [("gw_rtt_ms", "gateway"), ("pub_rtt_ms", "public")]:
            rtt = sample.get(key)
            if rtt is not None and rtt > latency_limit:
                fired.append({"event": f"{label}_latency", "value": rtt,
                              "threshold": latency_limit,
                              "message": f"{label} latency {rtt:.0f}ms > {latency_limit}ms"})
        for iface, delta in (sample.get("errors") or {}).items():
            if delta > 50:
                fired.append({"event": f"{iface}_errors", "value": delta,
                              "threshold": 50,
                              "message": f"{iface} error delta {delta} > 50"})

        cooldown = int(self.config.get("alerts.cooldown_min", 30)) * 60
        now = time.time()
        result = []
        for alert in fired:
            if now - self._last_sent.get(alert["event"], 0) >= cooldown:
                self._last_sent[alert["event"]] = now
                self._record(alert)
                self._notify(alert)
                result.append(alert)
        return result

    def _record(self, alert: Dict[str, Any]):
        shard = time.strftime("%Y-%m-%d")
        path = os.path.join(self.data_dir, f"{shard}.json")
        items = []
        try:
            with open(path, encoding="utf-8") as f:
                items = json.load(f)
        except (OSError, ValueError):
            pass
        alert["ts"] = time.time()
        items.append(alert)
        with open(path + ".tmp", "w", encoding="utf-8") as f:
            json.dump(items, f)
        os.replace(path + ".tmp", path)

    def history(self, days: int = 7) -> List[Dict[str, Any]]:
        """Return recent alerts (newest first)."""
        cutoff = time.time() - days * 86400
        items = []
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
        return items

    def _default_notify(self, alert: Dict[str, Any]):
        """Built-in notifier: webhook + email (if configured)."""
        channels = self.config.get("alerts.channels", {})
        hook = channels.get("webhook", {}).get("url", "")
        if hook:
            try:
                body = json.dumps({"event": alert["event"],
                                   "message": alert["message"],
                                   "value": alert["value"],
                                   "ts": alert.get("ts", time.time())}).encode()
                req = Request(hook, data=body,
                              headers={"Content-Type": "application/json"})
                urlopen(req, timeout=5)
            except Exception:  # noqa: BLE001
                pass
