"""Diagnosis history persistence (F19): daily JSON shards, rolling retention.

Design (diagnostic checks 5.3): reports append to data/diag-history/YYYY-MM-DD.json;
retention.diag_history (default 50) drops the oldest reports across shards.
"""
from __future__ import annotations
import glob
import json
import os
import threading
import time
from typing import Any, Dict, List, Optional


class DiagHistory:
    def __init__(self, history_dir: str, keep: int = 50):
        self.dir = history_dir
        self.keep = max(1, keep)
        self._lock = threading.Lock()
        os.makedirs(self.dir, exist_ok=True)

    # ---------------- write ----------------
    def append(self, report: Dict[str, Any]) -> None:
        with self._lock:
            shard = time.strftime("%Y-%m-%d")
            path = os.path.join(self.dir, f"{shard}.json")
            items = self._read_shard(path)
            items.append(report)
            self._write_shard(path, items)
            self._prune()

    def delete(self, job_id: str) -> bool:
        """Delete one report by job ID; return whether it was found."""
        if not isinstance(job_id, str) or not job_id:
            return False
        with self._lock:
            for path, items in self._all_shards():
                kept = [item for item in items if item.get("job_id") != job_id]
                if len(kept) == len(items):
                    continue
                if kept:
                    self._write_shard(path, kept)
                else:
                    os.unlink(path)
                return True
            return False

    def clear(self) -> int:
        """Delete all diagnosis shards and return the removed record count."""
        with self._lock:
            paths = glob.glob(os.path.join(self.dir, "*.json"))
            count = sum(len(self._read_shard(path)) for path in paths)
            for path in paths:
                os.unlink(path)
            return count

    @staticmethod
    def _write_shard(path: str, items: List[Dict[str, Any]]) -> None:
        with open(path + ".tmp", "w", encoding="utf-8") as stream:
            json.dump(items, stream, ensure_ascii=False)
        os.replace(path + ".tmp", path)

    def _prune(self) -> None:
        """Keep only the newest self.keep reports across all shards (oldest first)."""
        shards = self._all_shards()
        total = sum(len(s[1]) for s in shards)
        if total <= self.keep:
            return
        excess = total - self.keep
        for path, items in shards:  # oldest date first
            if excess <= 0:
                break
            drop = min(excess, len(items))
            items = items[drop:]
            excess -= drop
            if items:
                self._write_shard(path, items)
            else:
                os.unlink(path)

    # ---------------- read ----------------
    def _all_shards(self) -> List[Any]:
        out = []
        for path in sorted(glob.glob(os.path.join(self.dir, "*.json"))):
            items = self._read_shard(path)
            if items:
                out.append((path, items))
        return out

    @staticmethod
    def _read_shard(path: str) -> List[Dict[str, Any]]:
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except (OSError, ValueError):
            return []

    def list(self, page: int = 1, page_size: int = 20,
             detail: bool = False) -> Dict[str, Any]:
        items = [r for _, shard in self._all_shards() for r in shard]
        items.reverse()  # newest first
        total = len(items)
        start = max(0, (page - 1) * page_size)
        slice_ = items[start:start + page_size]
        if not detail:
            slice_ = [{k: r.get(k) for k in
                       ("job_id", "started_at", "score", "level",
                        "duration_ms", "summary")} for r in slice_]
        return {"total": total, "page": page, "page_size": page_size,
                "items": slice_}

    def get(self, job_id: str) -> Optional[Dict[str, Any]]:
        for _, shard in self._all_shards():
            for r in shard:
                if r.get("job_id") == job_id:
                    return r
        return None
