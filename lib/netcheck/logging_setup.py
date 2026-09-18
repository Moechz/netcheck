"""Structured JSON-lines logging with size rotation (logs/app.log, 10MB x N)."""
from __future__ import annotations
import json
import logging
import logging.handlers
import os
import time
from typing import Optional

_TS_FMT = "%Y-%m-%dT%H:%M:%S%z"


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": time.strftime(_TS_FMT, time.localtime(record.created)),
            "lvl": record.levelname,
            "mod": record.name,
            "evt": record.getMessage(),
        }
        for key in ("req_id", "result", "dur_ms", "detail"):
            val = getattr(record, key, None)
            if val is not None:
                entry[key] = val
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)[:2000]
        return json.dumps(entry, ensure_ascii=False)


def setup_logging(log_dir: str, level: str = "INFO",
                  max_bytes: int = 10 * 1024 * 1024, backup_count: int = 5) -> logging.Logger:
    """Configure the app logger writing JSON lines with rotation. Idempotent."""
    os.makedirs(log_dir, exist_ok=True)
    logger = logging.getLogger("netcheck")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False
    if getattr(logger, "_nc_configured", False):
        return logger
    handler = logging.handlers.RotatingFileHandler(
        os.path.join(log_dir, "app.log"), maxBytes=max_bytes, backupCount=backup_count)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger._nc_configured = True  # type: ignore[attr-defined]
    return logger


def log_event(logger: logging.Logger, event: str, level: int = logging.INFO, **fields: object) -> None:
    logger.log(level, event, extra=fields)
