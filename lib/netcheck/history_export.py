"""Standalone history exporters for support-friendly per-record downloads."""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, List


def _digest(record: Dict[str, Any]) -> str:
    canonical = json.dumps(record, ensure_ascii=False, sort_keys=True,
                           separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _payload(record: Dict[str, Any], record_type: str, log: List[Dict[str, Any]],
             version: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "app_name": version.get("app_name", "NetCheck"),
        "version": version.get("version", ""),
        "export_format": 1,
        "type": record_type,
        "exported_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "record": record,
        "log": log,
        "record_sha256": _digest(record),
    }


def diagnosis_export(report: Dict[str, Any],
                     version: Dict[str, Any]) -> Dict[str, Any]:
    """Return a diagnosis record and its persisted (or legacy-derived) event log."""
    log = report.get("log")
    if not isinstance(log, list):
        # Reports created before v1.2.32 did not duplicate check results into a
        # log array. Derive the same event shape from their persisted groups.
        log = []
        for group, checks in (report.get("groups") or {}).items():
            for check in checks:
                detail = check.get("detail") or {}
                log.append({
                    "ts": report.get("started_at"),
                    "event": "check.result",
                    "group": group,
                    "check_id": check.get("id"),
                    "status": check.get("status"),
                    "detail": detail,
                })
    return _payload(report, "diagnosis", log, version)


def repair_export(record: Dict[str, Any],
                  version: Dict[str, Any]) -> Dict[str, Any]:
    """Return a repair record and its persisted (or legacy-derived) event log."""
    log = record.get("log")
    if not isinstance(log, list):
        # Old repair entries persisted the request, helper result, and verification
        # fields, but not an explicit event array. Keep those records downloadable.
        result = record.get("result") or {}
        log = [
            {
                "ts": record.get("ts"),
                "event": "repair.request",
                "check_id": record.get("check_id"),
                "action": record.get("action"),
                "params": record.get("params", {}),
            },
            {
                "ts": record.get("ts"),
                "event": "repair.execute",
                "ok": result.get("ok", record.get("ok")),
                "rc": result.get("rc"),
                "stdout": result.get("stdout", ""),
                "stderr": result.get("stderr", ""),
                "duration_ms": record.get("dur_ms"),
            },
        ]
        verification = record.get("verified") or record.get("verification_observed")
        if verification:
            log.append({
                "ts": record.get("ts"),
                "event": "repair.verify",
                "checks": verification,
                "pending": bool(record.get("verified_pending")),
                "ok": record.get("verified_ok", record.get("ok")),
            })
    return _payload(record, "repair", log, version)
