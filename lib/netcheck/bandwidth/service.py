"""Bandwidth service: WAN/LAN mutual exclusion, job lifecycle, history (design 2)."""
from __future__ import annotations
import json
import os
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional

from . import iperf3, ookla


class Busy(Exception):
    def __init__(self, active: Dict[str, Any]):
        super().__init__("task running")
        self.active = active


class BandwidthSvc:
    """Single active task OR server session (F18); process-in-process lock."""

    def __init__(self, config, data_dir: str,
                 run_client_fn=iperf3.run_client,
                 ookla_fn=ookla.run_ookla,
                 http_fn: Optional[Callable] = None,
                 smb_fn: Optional[Callable] = None):
        self.config = config
        self.data_dir = data_dir
        self.history_path = os.path.join(data_dir, "bandwidth-history.json")
        self._run_client = run_client_fn
        self._ookla = ookla_fn
        self._http = http_fn
        self._smb = smb_fn
        self._guard = threading.Lock()
        self._active: Optional[Dict[str, Any]] = None
        self._last_done: Optional[Dict[str, Any]] = None
        self._jobs: Dict[str, Dict[str, Any]] = {}
        self._server_session: Optional[iperf3.ServerSession] = None
        self._monitor: Optional[threading.Thread] = None

    # ---------------- lock ----------------
    def _try_acquire(self, who: Dict[str, Any]) -> bool:
        with self._guard:
            if self._active is not None:
                return False
            self._active = who
            return True

    def _release(self, token: Any) -> None:
        with self._guard:
            if self._active is token or self._active == token:
                self._active = None

    # ---------------- server session (mode A) ----------------
    def server_start(self) -> Dict[str, Any]:
        port = self.config.get("bandwidth.iperf3_port", 5201)
        log_path = os.path.join(self.data_dir, "iperf3-server.log")
        session = iperf3.ServerSession(
            port, log_path,
            idle_timeout=self.config.get("bandwidth.server_idle_timeout_sec", 300),
            max_lifetime=self.config.get("bandwidth.server_max_lifetime_sec", 3600))
        who = {"type": "lan", "mode": "server", "session": session}
        if not self._try_acquire(who):
            raise Busy(self._public_active())
        try:
            if iperf3.port_busy(port):
                raise ValueError("port_in_use")
            session.start()
        except Exception:
            self._release(who)
            raise
        self._server_session = session
        self._start_monitor()
        pri_ip = self._primary_ip()
        return {"session_id": session.id, "port": port,
                "started_at": session.started_at,
                "auto_stop_sec": session.idle_timeout,
                "guide": self._guide(pri_ip, port)}

    @staticmethod
    def _guide(ip: str, port: int) -> List[str]:
        return [
            f"Test NAS download (PC -> NAS): iperf3 -c {ip} -p {port} -t 10 -P 4",
            f"Test NAS upload (NAS -> PC):   iperf3 -c {ip} -p {port} -t 10 -P 4 -R",
            f"UDP jitter:                    iperf3 -c {ip} -p {port} -u -b 100M -t 5",
            "This page summarizes automatically; the server stops after 5 minutes idle.",
        ]

    def server_stop(self, reason: str = "user") -> Dict[str, Any]:
        with self._guard:
            session = self._server_session
        if not session:
            return {"error": "no_server_session"}
        summary = session.stop(reason)
        self._release({"type": "lan", "mode": "server"})
        self._append_history({"id": f"srv-{uuid.uuid4().hex[:8]}", "type": "lan",
                              "mode": "server", "started_at": session.started_at,
                              "finished_at": time.time(),
                              "summary": summary, "state": session.state})
        self._server_session = None
        return {"session_id": session.id, "stopped_at": time.time(),
                "reason": reason, "summary": summary}

    def _start_monitor(self) -> None:
        if self._monitor and self._monitor.is_alive():
            return
        def loop():
            while True:
                time.sleep(5)
                with self._guard:
                    session = self._server_session
                if not session:
                    return
                session.poll_realtime()
                expired = session.expired()
                if expired:
                    self.server_stop(expired)
                    return
        self._monitor = threading.Thread(target=loop, daemon=True, name="nc-bw-mon")
        self._monitor.start()

    # ---------------- job API (start/stop/status) ----------------
    def start(self, btype: str, mode: str, params: Dict[str, Any]) -> Dict[str, Any]:
        btype = "wan" if btype == "wan" else "lan"
        if mode not in ("ookla", "http", "client", "smb", "server"):
            raise ValueError("invalid mode")
        if mode == "server":
            return self.server_start()
        job = {"job_id": f"bw-{uuid.uuid4().hex[:12]}", "type": btype, "mode": mode,
               "params": {k: v for k, v in params.items() if k != "smb" or True},
               "state": "running", "started_at": time.time(),
               "progress": {"phase": "precheck", "percent": 0}, "result": None,
               "error": None}
        who = {"type": btype, "mode": mode, "job": job}
        if not self._try_acquire(who):
            raise Busy(self._public_active())
        threading.Thread(target=self._run_job, args=(job,), daemon=True,
                         name=f"nc-{job['job_id']}").start()
        return {"job_id": job["job_id"], "type": btype, "mode": mode,
                "started_at": job["started_at"],
                "eta_sec": self._eta(mode, job["params"])}

    def stop(self) -> Dict[str, Any]:
        with self._guard:
            active = self._active
        if not active:
            return {"error": "no_active_task"}
        if active.get("mode") == "server":
            return self.server_stop("user")
        job = active.get("job", {})
        job["state"] = "stopped"
        partial = job.get("result") or {}
        self._release(active)
        return {"job_id": job.get("job_id"), "stopped_at": time.time(),
                "partial": partial or None}

    def status(self) -> Dict[str, Any]:
        with self._guard:
            active = self._active
        out: Dict[str, Any] = {"state": "idle"}
        if not active and self._last_done:
            out["state"] = self._last_done["state"]
            out["job_id"] = self._last_done["job_id"]
            out["result"] = self._last_done.get("result")
            out["error"] = self._last_done.get("error")
            return out
        if active:
            out["state"] = "running"
            out.update(self._public_active())
            session = active.get("session")
            if session:
                out["realtime"] = session.poll_realtime()
                out["guide"] = self._guide(self._primary_ip(), session.port)
            job = active.get("job")
            if job:
                out["job_id"] = job["job_id"]
                out["progress"] = job["progress"]
            if active.get("job", {}).get("state") in ("done", "failed", "stopped"):
                out["state"] = active["job"]["state"]
                out["result"] = active["job"]["result"]
        return out

    def _public_active(self) -> Dict[str, Any]:
        active = self._active or {}
        out = {"type": active.get("type"), "mode": active.get("mode")}
        job = active.get("job")
        if job:
            out["job_id"] = job["job_id"]
        return out

    # ---------------- job runner ----------------
    def _eta(self, mode: str, params: Dict[str, Any]) -> int:
        duration = int(params.get("duration", self.config.get(
            "bandwidth.duration_sec", 10)))
        return {"ookla": 60, "http": 45, "client": duration * 2 + 25,
                "smb": 120}.get(mode, 60)

    def _run_job(self, job: Dict[str, Any]) -> None:
        token = self._active
        try:
            job["progress"] = {"phase": "measuring", "percent": 40}
            p = job["params"]
            mode = job["mode"]
            if mode == "client":
                result = self._run_client(
                    p.get("target", ""), int(p.get("port", 5201)),
                    int(p.get("duration", 10)), int(p.get("streams", 4)),
                    bool(p.get("udp")), p.get("udp_bandwidth", "100M"))
            elif mode == "ookla":
                result = self._ookla(cache_path=os.path.join(
                    self.data_dir, "speedtest-servers.json"))
            elif mode == "http" and self._http:
                result = self._http(p)
            elif mode == "smb" and self._smb:
                result = self._smb(p)
            else:
                result = {"ok": False, "code": 1002, "err": f"mode {mode} unavailable"}
            job["progress"] = {"phase": "aggregating", "percent": 90}
            if job["state"] == "stopped":
                return
            ok = bool(result.get("ok", result.get("download_mbps") is not None))
            result.setdefault("conditions", {"method": mode})
            self._annotate(result)
            job["result"] = result
            job["state"] = "done" if ok else "failed"
            job["error"] = None if ok else {"code": result.get("code", 5000),
                                            "message": result.get("err", "")}
            job["finished_at"] = time.time()
            self._append_history({k: job[k] for k in
                                  ("id", "type", "mode", "started_at",
                                   "finished_at", "result", "state", "error")
                                  if k in job} | {"id": job["job_id"]})
        except Exception as exc:  # noqa: BLE001
            job["state"] = "failed"
            job["error"] = {"code": 5000, "message": str(exc)}
            job["finished_at"] = time.time()
        finally:
            job["progress"] = {"phase": "done", "percent": 100}
            self._last_done = job
            self._release(token)

    def _annotate(self, result: Dict[str, Any]) -> None:
        notes = result.setdefault("conditions", {}).setdefault("note", [])
        if "ookla" in str(result.get("conditions", {}).get("method", "")):
            notes.append("results affected by speed-test server load")

    def _primary_ip(self) -> str:
        try:
            import socket as s
            with s.socket(s.AF_INET, s.SOCK_DGRAM) as sock:
                sock.connect(("8.8.8.8", 80))
                return sock.getsockname()[0]
        except OSError:
            return "<NAS_IP>"

    # ---------------- history ----------------
    def history(self) -> Dict[str, Any]:
        try:
            with open(self.history_path, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return {"version": 1, "latest": {}, "items": []}

    def _append_history(self, item: Dict[str, Any]) -> None:
        data = self.history()
        items: List[Dict[str, Any]] = data.get("items", [])
        items.append(item)
        keep = int(self.config.get("retention.bandwidth_history", 100))
        items = items[-keep:]
        latest = data.get("latest", {})
        if item.get("type") in ("wan", "lan") and item.get("state") == "done":
            latest[item["type"]] = item.get("id")
        os.makedirs(os.path.dirname(self.history_path) or ".", exist_ok=True)
        tmp = self.history_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"version": 1, "latest": latest, "items": items},
                      f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.history_path)
