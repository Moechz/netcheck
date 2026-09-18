#!/usr/bin/env python3
"""History deletion and clear-all unit tests."""
from __future__ import annotations

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from netcheck.diag.history import DiagHistory
from netcheck.diag.report import build_report
from netcheck.fix.engine import FixEngine
from netcheck.history_export import diagnosis_export, repair_export


PASS = 0
FAIL = 0


def check(name: str, expected, actual) -> None:
    global PASS, FAIL
    if expected == actual:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name}: expected={expected!r} got={actual!r}")


class FakeConfig:
    def get(self, key: str, default=None):
        return default


with tempfile.TemporaryDirectory(prefix="nc-history-test-") as root:
    diag = DiagHistory(os.path.join(root, "diag-history"), keep=10)
    report = build_report([
        {"id": "link-state", "group": "A", "status": "pass", "fixable": None,
         "detail": {"reason": "ok", "actual": "up", "expected": "up"}},
        {"id": "dns-reachable", "group": "D", "status": "fail", "fixable": "fix-dns",
         "detail": {"reason": "dns unreachable", "actual": "timeout", "expected": "reachable"}},
    ], "job-export", 1780000000, 1250)
    check("diag.report_log_persisted", 2, len(report.get("log", [])))
    diag.append(report)
    exported = diagnosis_export(report, {"app_name": "NetCheck", "version": "test"})
    check("diag.export_type", "diagnosis", exported.get("type"))
    check("diag.export_log", 2, len(exported.get("log", [])))
    check("diag.export_checksum", True,
          len(exported.get("record_sha256", "")) == 64)
    for index in range(3):
        diag.append({"job_id": f"job-{index}", "score": 100 - index,
                     "level": "healthy", "summary": {}})
    check("diag.delete", True, diag.delete("job-1"))
    check("diag.delete_missing", False, diag.delete("job-1"))
    check("diag.remaining_newest_first", "job-2 job-0 job-export",
          " ".join(item["job_id"] for item in diag.list(page_size=20)["items"]))
    check("diag.clear", 3, diag.clear())
    check("diag.empty", 0, diag.list()["total"])
    check("diag.shards_removed", [], os.listdir(diag.dir))

    fix_path = os.path.join(root, "fix-history.json")
    legacy = {"items": [
        {"ts": "2026-08-30T10:00:00+0800", "check_id": "dns-reachable",
         "action": "dns-set", "params": {}, "result": {"ok": True},
         "dur_ms": 10, "ok": True},
        {"ts": "2026-08-30T10:01:00+0800", "check_id": "gateway-reach",
         "action": "gateway-set", "params": {}, "result": {"ok": True},
         "dur_ms": 12, "ok": True},
    ]}
    with open(fix_path, "w", encoding="utf-8") as stream:
        json.dump(legacy, stream)
    engine = FixEngine(FakeConfig(), history_path=fix_path)
    viewed = engine.history()
    check("fix.legacy_ids", True,
          all(item.get("record_id", "").startswith("legacy-fix-") for item in viewed))
    check("fix.legacy_delete", True, engine.delete(viewed[1]["record_id"]))
    check("fix.legacy_remaining", 1, len(engine.history()))
    legacy_export = repair_export(viewed[0], {"app_name": "NetCheck", "version": "test"})
    check("fix.legacy_export_events", True,
          [item["event"] for item in legacy_export["log"]] ==
          ["repair.request", "repair.execute"])
    engine._append_history({"record_id": "fix-unit-test",
                            "ts": "2026-08-30T10:02:00+0800",
                            "check_id": "ntp-server", "action": "svc-restart",
                            "params": {}, "result": {"ok": True}, "dur_ms": 5,
                            "ok": True})
    persisted = engine.history()[-1]
    check("fix.persistent_id", "fix-unit-test", persisted.get("record_id"))
    check("fix.persistent_delete", True, engine.delete(persisted["record_id"]))
    check("fix.clear", 1, engine.clear())
    with open(fix_path, encoding="utf-8") as stream:
        check("fix.clear_format", {"items": []}, json.load(stream))


print()
print(f"RESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
