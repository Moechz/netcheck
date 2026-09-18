"""settings.json load/save with defaults, atomic write and lock (Technical Design 5.1)."""
from __future__ import annotations
import copy
import json
import os
import tempfile
import threading
from typing import Any, Dict

DEFAULTS: Dict[str, Any] = {
    "language": "system",            # system | zh-CN | ... (21)
    "theme": "system",               # system | light | dark
    "auto_diag": {"enabled": False, "interval_hours": 12},
    "diag": {
        "timeout_sec": 5,
        "ping_public_ips": ["223.5.5.5", "8.8.8.8"],
        "public_probe_urls": ["https://www.baidu.com"],
        "tos_endpoints": [
            "https://app.terra-master.com",
            "https://download3.terra-master.com",
            "https://dl.terra-master.com",
        ],
        "tos_status_timeout_sec": 2.0,
        "ipv6_targets": ["2400:3200::1"],
        "dns_probe_domain": "www.baidu.com",
        "loss_threshold_pct": 20,
        "resolve_slow_ms": 2000,
        "time_offset_sec": 300,
        "ntp_verify_timeout_sec": 18,
        "ipv6_verify_timeout_sec": 15,
        "mtu_probe_sec": 4,
        "expected_mtu": None,
        "error_delta_threshold": 10,
        "conn_timewait_warn": 30000,
        "conn_timewait_fail": 50000,
        "port_usage_warn_pct": 80,
        "port_usage_fail_pct": 95,
        "bond_throughput_ratio": 0.7,
    },
    "bandwidth": {
        "wan_mode": "ookla", "http_speed_endpoint": "",
        "iperf3_port": 5201, "streams": 4, "duration_sec": 10,
        "smb_share_path": "", "smb_file_size_mb": 1024,
        "server_idle_timeout_sec": 300, "server_max_lifetime_sec": 3600,
        "udp_enabled": False, "udp_bandwidth": "100M", "upload_size_mb": 64,
        "rounds": {"http": 3, "iperf3": 1, "ookla": 1, "smb": 1},
        "wan_plan_mbps": None,
    },
    "monitor": {
        "enabled": True, "interval_min": 5, "retain_days": 30,
        "thresholds": {"loss_pct": 10, "latency_ms": 500},
    },
    "alerts": {
        "channels": {
            "tos_notify": False,
            "email": {"smtp": "", "from": "", "to": ""},
            "webhook": {"url": "", "template": "generic"},
        },
        "cooldown_min": 30,
    },
    # helper is the v1.0 default after the R1 contract approval (2026-08-25)
    "repair": {"mode": "helper", "require_admin": True, "confirm_dialog": True,
               "dns_servers": ["223.5.5.5", "119.29.29.29"]},
    "snapshot": {"auto_before_fix": True, "daily": False, "keep": 20},
    "scan": {"intensity": "medium"},
    "retention": {"diag_history": 50, "log_days": 30, "alert_days": 90,
                  "bandwidth_history": 100, "operation_audit_days": 90},
}


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Merge loaded settings over defaults; unknown keys preserved (backward compatible)."""
    out = copy.deepcopy(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


class Config:
    """Thread-safe settings store backed by settings.json (atomic write)."""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self._data: Dict[str, Any] = {}
        self.load()

    def load(self) -> None:
        with self._lock:
            loaded: Dict[str, Any] = {}
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
            except (OSError, ValueError):
                loaded = {}
            self._data = _deep_merge(DEFAULTS, loaded)

    def get(self, dotted_key: str = "", default: Any = None) -> Any:
        with self._lock:
            node: Any = self._data
            if not dotted_key:
                return copy.deepcopy(node)
            for part in dotted_key.split("."):
                if not isinstance(node, dict) or part not in node:
                    return default
                node = node[part]
            return copy.deepcopy(node)

    def set(self, dotted_key: str, value: Any) -> None:
        with self._lock:
            node = self._data
            parts = dotted_key.split(".")
            for part in parts[:-1]:
                node = node.setdefault(part, {})
            node[parts[-1]] = value
            self._save_locked()

    def update(self, partial: Dict[str, Any]) -> None:
        with self._lock:
            self._data = _deep_merge(self._data, partial)
            self._save_locked()

    def _save_locked(self) -> None:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".settings-", dir=os.path.dirname(self.path) or ".")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self._data, f, ensure_ascii=False, indent=2, sort_keys=True)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
