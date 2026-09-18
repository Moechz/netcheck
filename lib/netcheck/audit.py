"""User operation audit trail (F45): append-only JSONL with rotation and redaction."""
from __future__ import annotations
import json
import os
import time
from typing import Any, Dict, Optional

# Never logged, regardless of caller input (F45 redaction rules)
_FORBIDDEN_KEYS = {"password", "old_password", "new_password", "token", "secret",
                   "credentials", "auth", "session", "cookie"}


def redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: ("[REDACTED]" if k.lower() in _FORBIDDEN_KEYS else redact(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


class OperationAudit:
    """Append-only operation audit (logs/operation-audit.jsonl, admin-readable only)."""

    def __init__(self, path: str, max_bytes: int = 10 * 1024 * 1024, keep: int = 5):
        self.path = path
        self.max_bytes = max_bytes
        self.keep = keep
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def record(self, actor: str, action: str, result: str,
               target: str = "", req_id: str = "", tos_user: str = "",
               detail: Optional[Dict[str, Any]] = None, dur_ms: int = 0) -> None:
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "evt": "op",
            "actor": actor,
            "tos_user": tos_user or "",
            "action": action,
            "target": target,
            "result": result,
            "req_id": req_id,
            "detail": redact(detail or {}),
            "dur_ms": dur_ms,
        }
        self._rotate_if_needed()
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def _rotate_if_needed(self) -> None:
        try:
            if os.path.getsize(self.path) < self.max_bytes:
                return
        except OSError:
            return
        for i in range(self.keep - 1, 0, -1):
            src = f"{self.path}.{i}"
            if os.path.exists(src):
                os.replace(src, f"{self.path}.{i + 1}")
        os.replace(self.path, f"{self.path}.1")
