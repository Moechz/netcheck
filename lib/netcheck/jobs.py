"""Async job registry & state machine (idle -> running -> done/failed/stopped)."""
from __future__ import annotations
import threading
import time
import uuid
from typing import Any, Callable, Dict, Optional


class Job:
    def __init__(self, jtype: str):
        self.id = f"job-{uuid.uuid4().hex[:12]}"
        self.type = jtype
        self.state = "running"
        self.created_at = time.time()
        self.finished_at: Optional[float] = None
        self.progress: Dict[str, Any] = {"phase": "starting", "percent": 0}
        self.result: Any = None
        self.error: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.id, "type": self.type, "state": self.state,
            "created_at": self.created_at,
            "finished_at": self.finished_at,
            "progress": self.progress,
            "result": self.result, "error": self.error,
        }


class JobManager:
    """Tracks in-process async jobs; long tasks register a stop callback."""

    def __init__(self, max_tracked: int = 100):
        self._lock = threading.Lock()
        self._jobs: Dict[str, Job] = {}
        self._stop_fns: Dict[str, Callable[[], None]] = {}
        self._max = max_tracked

    def create(self, jtype: str, runner: Callable[[Job], None],
               stop_fn: Optional[Callable[[], None]] = None) -> Job:
        job = Job(jtype)
        with self._lock:
            if len(self._jobs) >= self._max:  # prune oldest finished
                finished = [j for j in self._jobs.values() if j.state != "running"]
                for j in finished[: len(finished) - self._max + 1]:
                    self._jobs.pop(j.id, None)
            self._jobs[job.id] = job
            if stop_fn:
                self._stop_fns[job.id] = stop_fn

        def wrap() -> None:
            try:
                runner(job)
                if job.state == "running":
                    job.state = "done"
            except Exception as exc:  # noqa: BLE001 - job boundary
                job.state = "failed"
                job.error = {"code": 5000, "message": f"{type(exc).__name__}: {exc}"}
            finally:
                job.finished_at = time.time()
                with self._lock:
                    self._stop_fns.pop(job.id, None)

        threading.Thread(target=wrap, daemon=True, name=f"nc-{job.id}").start()
        return job

    def get(self, job_id: str) -> Optional[Job]:
        with self._lock:
            return self._jobs.get(job_id)

    def stop(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            fn = self._stop_fns.get(job_id)
        if not job or job.state != "running":
            return False
        if fn:
            try:
                fn()
            except Exception:  # noqa: BLE001
                pass
        job.state = "stopped"
        job.finished_at = time.time()
        return True
