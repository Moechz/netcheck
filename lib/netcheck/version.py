"""Version info sourced from the packaged version.json (F41)."""
from __future__ import annotations
import json
import os
import platform

_FALLBACK = {"version": "0.0.0", "arch": "", "build_time": "", "channel": "stable"}


def load_version(app_root: str) -> dict:
    path = os.path.join(app_root, "version.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        data = {}
    data.setdefault("version", _FALLBACK["version"])
    data.setdefault("arch", platform.machine() or "unknown")
    data.setdefault("build_time", _FALLBACK["build_time"])
    data.setdefault("channel", _FALLBACK["channel"])
    return data
