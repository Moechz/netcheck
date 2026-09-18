"""HTTP server over Unix socket (/var/api/netcheck.sock) + endpoint registration.

Endpoints (M2 skeleton): /health, /api/version, /api/auth/*, /api/settings,
/api/jobs/{id} (async plumbing). Diagnosis/bandwidth engines register in later
milestones through the same Router.
"""
from __future__ import annotations
import json
import os
import platform
import signal
import socket
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict
from urllib.parse import parse_qs, urlsplit

from .audit import OperationAudit
from .auth import ERR_LOCKED, AuthService
from .collectors.nic import NicCollector
from .diag import run_diag
from .diag.history import DiagHistory
from .diag.report import build_report
from .bandwidth.service import BandwidthSvc, Busy
from .bandwidth.bpf_client import BpfTrafficClient
from .monitor.alerts import AlertEngine
from .snapshot import SnapshotService
from .tools.devices import discover
from .tools.dnscompare import compare as dns_compare
from .tools.portcheck import check_ports
from .tools.security import check_security
from .tools.traceroute import run_traceroute
from .monitor.sampler import LinkSampler
from .bandwidth.traffic import TrafficSampler
from .fix.engine import FixEngine, GUIDE
from .diag.engine import registry as diag_registry
from .diag.tos_services import collect_current_status
from .history_export import diagnosis_export, repair_export
from .config import Config
from .jobs import JobManager
from .logging_setup import log_event, setup_logging
from .router import E_BAD_REQUEST, E_INTERNAL, E_OK, E_UNAUTHORIZED, Request, Response, Router
from .version import load_version

MAX_BODY = 1024 * 1024  # 1 MB
APP_ID = "netcheck"


class UnixHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, sock_path: str, handler: type, mode: int = 0o660):
        self.sock_path = sock_path
        self._mode = mode
        # clear stale socket
        try:
            if os.path.exists(sock_path):
                st = os.stat(sock_path)
                if stat_is_socket(st):
                    os.unlink(sock_path)
                else:
                    raise RuntimeError(f"{sock_path} exists and is not a socket")
        except OSError:
            pass
        super().__init__(sock_path, handler)
        os.chmod(sock_path, mode)

    def server_bind(self) -> None:  # noqa: D102 - unix socket bind
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.bind(self.sock_path)

    def server_close(self) -> None:  # noqa: D102
        super().server_close()
        try:
            os.unlink(self.sock_path)
        except OSError:
            pass

    def finish_request(self, request, client_address):  # client_address unused for AF_UNIX
        super().finish_request(request, ("local", 0))


def stat_is_socket(st: os.stat_result) -> bool:
    import stat
    return stat.S_ISSOCK(st.st_mode)


def normalized_arch() -> str:
    machine = platform.machine().lower()
    if machine in ("amd64", "x86_64"):
        return "x86_64"
    if machine in ("arm64", "aarch64"):
        return "aarch64"
    return machine or "unknown"


def normalize_platform_path(path: str, app_id: str = APP_ID) -> str:
    """Normalize route shapes emitted by different TOS platform proxy modes.

    TOS may forward the public proxy path unchanged, or use one of the app/path
    combinations documented in the WebUI Internal Open specification. Keep the
    canonical backend routes small while accepting those compatible prefixes.
    """
    if not path.startswith("/"):
        return path
    segments = path.split("/")
    if (len(segments) >= 4 and segments[1] == "v2"
            and segments[2] in {"proxy", "proxy2"} and segments[3] == app_id):
        del segments[1:4]
    elif len(segments) >= 2 and segments[1] == app_id:
        del segments[1]
    # Handle <config.ini.path>/<app_id>/<api_name> after a proxy prefix.
    if len(segments) >= 2 and segments[1] == app_id:
        del segments[1]
    return "/".join(segments) or "/"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "NetCheck/1.2.60"
    router: Router = None  # type: ignore[assignment]
    logger = None

    # silence default stderr logging; we log structured ourselves
    def log_message(self, fmt: str, *args: Any) -> None:
        pass

    def _read_body(self) -> Any:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        if length > MAX_BODY:
            raise ValueError("body too large")
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise ValueError("invalid JSON body")

    def _handle(self, method: str) -> None:
        logger = self.logger
        try:
            parts = urlsplit(self.path)
            query = {k: v[-1] for k, v in parse_qs(parts.query).items()}
            headers = {k.lower(): v for k, v in self.headers.items()}
            body = self._read_body() if method == "POST" else {}
            route_path = normalize_platform_path(parts.path)
            resp = self.router.dispatch(method, route_path, query, headers, body)
        except ValueError as exc:
            resp = Response.err(E_BAD_REQUEST, str(exc), 400)
        except Exception as exc:  # noqa: BLE001
            if logger:
                logger.exception("handler_error")
            resp = Response.err(E_INTERNAL, f"internal error: {type(exc).__name__}", 500)
        payload = json.dumps({"code": resp.code, "message": resp.message,
                              "data": resp.data}, ensure_ascii=False).encode("utf-8")
        try:
            self.send_response(resp.http_status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self) -> None:  # noqa: N802
        self._handle("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._handle("POST")


# ----------------------------------------------------------------------------
# Endpoint registration
# ----------------------------------------------------------------------------
def build_router(app_root: str, data_dir: str, log_dir: str) -> Router:
    logger = setup_logging(log_dir)
    config = Config(os.path.join(data_dir, "settings.json"))
    auth = AuthService(os.path.join(data_dir, "auth"))
    collector = NicCollector()
    bandwidth = BandwidthSvc(config, data_dir)
    traffic = TrafficSampler(interval=1.0)
    bpf_traffic = BpfTrafficClient(
        os.environ.get("NETCHECK_BPF_SOCK", "/run/netcheck/bpf-traffic.sock"))
    traffic.start()
    link_sampler = LinkSampler(data_dir, config,
                               interval_min=int(config.get("monitor.interval_min", 5)))
    if config.get("monitor.enabled", True):
        link_sampler.start()
    alert_engine = AlertEngine(data_dir, config)
    snapshots = SnapshotService(data_dir,
                                keep=int(config.get("snapshot.keep", 20)))
    diag_history = DiagHistory(os.path.join(data_dir, "diag-history"),
                               keep=int(config.get("retention.diag_history", 50)))

    def run_single_check(check_id: str) -> str:
        cls = diag_registry().get(check_id)
        if cls is None:
            return "fail"
        try:
            checker = cls({"cfg": config.get("diag"), "nics": collector.get()})
            return checker.evaluate(checker.collect()).status
        except Exception:  # noqa: BLE001 - repair verification boundary
            return "fail"

    fix_engine = FixEngine(
        config,
        history_path=os.path.join(data_dir, "fix-history.json"),
        collector=collector,
        run_check_fn=run_single_check,
        audit_fn=lambda **kw: audit_op(Request("POST", "/api/fix", {}, {}, {},
                                               kw.get("req_id", "")), kw.get("action", "fix"),
                                       kw.get("result", ""), target=kw.get("target", ""),
                                       detail=kw.get("detail")))
    audit = OperationAudit(os.path.join(log_dir, "operation-audit.jsonl"))
    jobs = JobManager()
    version = load_version(app_root)

    def apply_monitor_enabled(enabled: bool) -> bool:
        """Apply the persistent continuous-monitoring switch to the live sampler."""
        if enabled:
            link_sampler.start()
        else:
            link_sampler.stop()
        return link_sampler.is_running()

    def audit_op(req: Request, action: str, result: str, target: str = "",
                 detail: Dict[str, Any] = None, dur_ms: int = 0) -> None:
        audit.record(actor=req.actor, action=action, result=result, target=target,
                     req_id=req.req_id, detail=detail, dur_ms=dur_ms)

    router = Router({"logger": logger, "config": config, "auth": auth,
                     "audit": audit, "jobs": jobs, "version": version,
                     "collector": collector,
                     "data_dir": data_dir, "log_dir": log_dir, "app_root": app_root})

    # ---------- health (no auth) ----------
    @router.add("GET", "/health")
    def health(req: Request) -> Response:
        return Response.ok({"status": "ok", "version": version["version"],
                            "time": __import__("time").strftime("%Y-%m-%dT%H:%M:%S%z")})

    @router.add("GET", "/api/version")
    def api_version(req: Request) -> Response:
        payload = dict(version)
        payload.setdefault("arch", normalized_arch())
        return Response.ok(payload)

    # ---------- auth ----------
    @router.add("POST", "/api/auth/setup")
    def auth_setup(req: Request) -> Response:
        if auth.is_initialized():
            audit_op(req, "auth.setup", "rejected", detail={"reason": "already_initialized"})
            return Response.err(E_BAD_REQUEST, "already initialized", 400)
        ok, reason, recovery_code = auth.setup(req.body.get("username", ""),
                                               req.body.get("password", ""))
        audit_op(req, "auth.setup", "ok" if ok else "rejected",
                 detail={"reason": reason})
        if not ok:
            return Response.err(E_BAD_REQUEST, reason, 400)
        # recovery_code is returned exactly once, never stored in plaintext
        return Response.ok({"username": auth.username(),
                            "recovery_code": recovery_code})

    @router.add("POST", "/api/auth/login")
    def auth_login(req: Request) -> Response:
        token, info = auth.login(req.body.get("username", ""),
                                 req.body.get("password", ""))
        reason = info.get("reason", "")
        audit_op(req, "auth.login", "ok" if token else "rejected",
                 detail={"reason": reason})
        if not token:
            status = 401 if reason in (ERR_LOCKED, "bad_credentials") else 429
            data = {k: v for k, v in info.items() if k != "reason"}
            code = E_UNAUTHORIZED if status == 401 else 1003
            return Response(code, reason, data, status)
        return Response.ok({"token": token, "expires_in": 24 * 3600,
                            "username": auth.username()})

    @router.add("POST", "/api/auth/logout")
    def auth_logout(req: Request) -> Response:
        header = req.headers.get("authorization", "")
        token = header[7:].strip() if header.lower().startswith("bearer ") else ""
        auth.logout(token)
        audit_op(req, "auth.logout", "ok")
        return Response.ok({"logged_out": True})

    @router.add("GET", "/api/auth/status")
    def auth_status(req: Request) -> Response:
        header = req.headers.get("authorization", "")
        token = header[7:].strip() if header.lower().startswith("bearer ") else ""
        authenticated = auth.check_session(token)
        data = {"initialized": auth.is_initialized(), "authenticated": authenticated}
        if authenticated:
            data.update({"username": auth.username(),
                         "repair_mode": config.get("repair.mode")})
        return Response.ok(data)

    @router.add("POST", "/api/auth/change-password")
    def change_password(req: Request) -> Response:
        ok, reason = auth.change_password(req.body.get("old_password", ""),
                                          req.body.get("new_password", ""))
        audit_op(req, "auth.change_password", "ok" if ok else "rejected",
                 detail={"reason": reason})
        if not ok:
            return Response.err(E_BAD_REQUEST, reason, 400)
        return Response.ok({"changed": True})

    @router.add("POST", "/api/auth/change-username")
    def change_username(req: Request) -> Response:
        ok, reason = auth.change_username(req.body.get("password", ""),
                                          req.body.get("new_username", ""))
        audit_op(req, "auth.change_username", "ok" if ok else "rejected",
                 detail={"reason": reason})
        if not ok:
            return Response.err(E_BAD_REQUEST, reason, 400)
        return Response.ok({"username": auth.username()})

    @router.add("POST", "/api/auth/recover")
    def auth_recover(req: Request) -> Response:
        ok, out = auth.recover(req.body.get("username", ""),
                               req.body.get("recovery_code", ""),
                               req.body.get("new_password", ""))
        audit_op(req, "auth.recover", "ok" if ok else "rejected",
                 detail={"reason": out})
        if not ok:
            status = 401 if out in (ERR_LOCKED, "bad_credentials") else 400
            return Response.err(E_UNAUTHORIZED if status == 401 else 1002,
                                out, status)
        # a fresh recovery code is issued; shown exactly once
        return Response.ok({"username": req.body.get("username", ""),
                            "recovery_code": out})

    # ---------- settings ----------
    @router.add("GET", "/api/settings")
    def get_settings(req: Request) -> Response:
        return Response.ok(config.get())

    @router.add("POST", "/api/settings")
    def post_settings(req: Request) -> Response:
        if not isinstance(req.body, dict) or not req.body:
            return Response.err(E_BAD_REQUEST, "settings object required", 400)
        config.update(req.body)
        if "monitor" in req.body and "enabled" in (req.body.get("monitor") or {}):
            apply_monitor_enabled(bool(config.get("monitor.enabled", True)))
        audit_op(req, "settings.write", "ok", detail={"keys": sorted(req.body.keys())[:20]})
        return Response.ok(config.get())

    # ---------- interfaces & status ----------
    @router.add("GET", "/api/interfaces")
    def interfaces(req: Request) -> Response:
        snap = collector.get()
        # internal route tables are not part of the public schema
        public = {k: v for k, v in snap.items() if not k.startswith("_")}
        public["hostname"] = socket.gethostname()
        return Response.ok(public)

    @router.add("GET", "/api/status")
    def status(req: Request) -> Response:
        snap = collector.get()
        pri = next((i for i in snap["interfaces"] if i.get("is_primary")), None)
        return Response.ok({
            "arch": snap["arch"], "updated_at": snap["updated_at"],
            "hostname": socket.gethostname(),
            "primary": {k: pri[k] for k in ("name", "type", "operstate",
                                            "ipv4", "ipv6", "gateway", "mode")
                        } if pri else None,
            "interface_count": len(snap["interfaces"]),
            "online": bool(pri),
        })

    # ---------- diagnosis ----------
    @router.add("POST", "/api/diag/run")
    def diag_run(req: Request) -> Response:
        cfg = config.get("diag")
        tos_headers = {key: req.headers.get(key, "")
                       for key in ("cookie", "host", "x-forwarded-host",
                                   "x-forwarded-proto")}

        def runner(job):
            runtime_cfg = dict(cfg)
            runtime_cfg["_tos_services"] = collect_current_status(
                tos_headers, timeout=float(cfg.get("tos_status_timeout_sec", 2.0))
            )
            results = run_diag(runtime_cfg, collector=collector)
            report = build_report([r.to_dict() for r in results], job.id,
                                  job.created_at, 0)
            report["duration_ms"] = round((__import__("time").time() - job.created_at) * 1000, 1)
            report["req_id"] = req.req_id
            report["operator"] = req.actor
            job.progress = {"phase": "done", "percent": 100}
            job.result = report
            try:
                diag_history.append(report)  # F19 persistence
            except OSError:
                logger.exception("diag_history_append_failed")

        job = jobs.create("diagnosis", runner)
        audit_op(req, "diag.run", "ok", target=job.id)
        return Response.ok({"job_id": job.id})

    @router.add("GET", "/api/diag/history")
    def diag_history_ep(req: Request) -> Response:
        page = int(req.query.get("page", "1") or 1)
        return Response.ok(diag_history.list(page=page,
                                             detail=req.query.get("detail") == "1"))

    @router.add("POST", "/api/diag/history/delete")
    def diag_history_delete(req: Request) -> Response:
        job_id = req.body.get("job_id", "")
        if not isinstance(job_id, str) or not job_id:
            return Response.err(E_BAD_REQUEST, "job_id required")
        deleted = diag_history.delete(job_id)
        audit_op(req, "history.delete", "ok" if deleted else "error",
                 target=job_id, detail={"type": "diagnosis"})
        if not deleted:
            return Response.err(E_BAD_REQUEST, "history record not found", 404)
        return Response.ok({"deleted": True})

    @router.add("GET", "/api/diag/history/export")
    def diag_history_export(req: Request) -> Response:
        job_id = req.query.get("job_id", "")
        if not job_id:
            return Response.err(E_BAD_REQUEST, "job_id required")
        report = diag_history.get(job_id)
        audit_op(req, "history.export", "ok" if report else "error",
                 target=job_id, detail={"type": "diagnosis"})
        if not report:
            return Response.err(E_BAD_REQUEST, "history record not found", 404)
        return Response.ok(diagnosis_export(report, version))

    @router.add("GET", "/api/diag/report")
    def diag_report(req: Request) -> Response:
        job_id = req.query.get("job_id", "")
        job = jobs.get(job_id)
        if not job or job.type != "diagnosis":
            return Response.err(E_BAD_REQUEST, "job not found", 404)
        if job.state == "running":
            return Response.ok({"state": "running", "progress": job.progress})
        return Response.ok({"state": job.state, "report": job.result,
                            "error": job.error})

    # ---------- bandwidth (F14-F18) ----------
    @router.add("POST", "/api/bandwidth/start")
    def bw_start(req: Request) -> Response:
        btype = req.body.get("type", "lan")
        mode = req.body.get("mode", "")
        params = {k: v for k, v in req.body.items()
                  if k not in ("type", "mode")}
        try:
            out = bandwidth.start(btype, mode, params)
        except Busy as exc:
            return Response.err(2001, "a bandwidth task is already running",
                                {"active": exc.active})
        except ValueError as exc:
            return Response.err(1002, str(exc))
        audit_op(req, "bandwidth.start", "ok",
                 target=out.get("job_id", "server"),
                 detail={"type": btype, "mode": mode})
        return Response.ok(out)

    @router.add("POST", "/api/bandwidth/server")
    def bw_server(req: Request) -> Response:
        action = req.body.get("action", "")
        if action == "start":
            try:
                out = bandwidth.server_start()
            except Busy as exc:
                return Response.err(2001, "a bandwidth task is already running",
                                    {"active": exc.active})
            except ValueError as exc:
                return Response.err(1002, str(exc))
            except RuntimeError as exc:
                return Response.err(5000, str(exc))
            audit_op(req, "bandwidth.server", "ok", target=out.get("session_id", ""))
            return Response.ok(out)
        if action == "stop":
            out = bandwidth.server_stop("user")
            audit_op(req, "bandwidth.server", "ok", target="stop")
            return Response.ok(out)
        return Response.err(1002, "action must be start|stop")

    @router.add("POST", "/api/bandwidth/stop")
    def bw_stop(req: Request) -> Response:
        out = bandwidth.stop()
        audit_op(req, "bandwidth.stop", "ok")
        return Response.ok(out)

    @router.add("GET", "/api/bandwidth/status")
    def bw_status(req: Request) -> Response:
        out = bandwidth.status()
        out["history_latest"] = bandwidth.history().get("latest", {})
        return Response.ok(out)

    @router.add("GET", "/api/realtime")
    def realtime(req: Request) -> Response:
        iface = req.query.get("iface", "")
        try:
            snap = bpf_traffic.snapshot(iface)
            return Response.ok({"source": "bpf", "bpf_available": True,
                                "interfaces": snap.get("interfaces", {}),
                                "ts": snap.get("ts", "")})
        except (OSError, ValueError, KeyError):
            snap = traffic.snapshot(iface)
            return Response.ok({"source": "procfs", "bpf_available": False,
                                "interfaces": snap,
                                "ts": __import__("time").strftime("%Y-%m-%dT%H:%M:%S%z")})

    # ---------- monitor & alerts (F26-F27) ----------
    @router.add("GET", "/api/monitor/link-quality")
    def monitor_quality(req: Request) -> Response:
        days = int(req.query.get("range", "7").rstrip("d") or 7)
        return Response.ok({"days": days, "samples": link_sampler.query(days),
                            "enabled": bool(config.get("monitor.enabled", True)),
                            "interval_min": int(config.get("monitor.interval_min", 5)),
                            "running": link_sampler.is_running()})

    @router.add("POST", "/api/monitor/enabled")
    def monitor_enabled(req: Request) -> Response:
        enabled = req.body.get("enabled")
        if not isinstance(enabled, bool):
            return Response.err(E_BAD_REQUEST, "enabled boolean required")
        config.set("monitor.enabled", enabled)
        running = apply_monitor_enabled(enabled)
        audit_op(req, "monitor.enabled", "ok",
                 detail={"enabled": enabled, "running": running})
        return Response.ok({"enabled": enabled, "running": running,
                            "interval_min": int(config.get("monitor.interval_min", 5))})

    @router.add("POST", "/api/monitor/sample")
    def monitor_sample(req: Request) -> Response:
        entry = link_sampler.sample()
        fired = alert_engine.evaluate(entry)
        audit_op(req, "monitor.sample", "ok", detail={"alerts": len(fired)})
        return Response.ok({"sample": entry, "alerts_fired": fired})

    @router.add("GET", "/api/alerts")
    def alerts_history(req: Request) -> Response:
        days = int(req.query.get("days", "7") or 7)
        return Response.ok({"items": alert_engine.history(days)})

    @router.add("POST", "/api/alerts/test")
    def alerts_test(req: Request) -> Response:
        test_alert = {"event": "test", "value": 0, "threshold": 0,
                      "message": "NetCheck test notification"}
        alert_engine._notify(test_alert)
        audit_op(req, "alerts.test", "ok")
        return Response.ok({"sent": True})

    # ---------- snapshots (F23) ----------
    @router.add("GET", "/api/snapshots")
    def snap_list(req: Request) -> Response:
        return Response.ok({"items": snapshots.list()})

    @router.add("POST", "/api/snapshots")
    def snap_create(req: Request) -> Response:
        meta = snapshots.create(source=req.body.get("source", "manual"),
                                note=req.body.get("note", ""))
        audit_op(req, "snapshot.create", "ok", target=meta["id"])
        return Response.ok(meta)

    @router.add("GET", "/api/snapshots/{snap_id}/diff")
    def snap_diff(req: Request) -> Response:
        d = snapshots.diff(req.params["snap_id"])
        if "error" in d:
            return Response.err(E_BAD_REQUEST, d["error"], 404)
        return Response.ok(d)

    @router.add("POST", "/api/snapshots/{snap_id}/restore")
    def snap_restore(req: Request) -> Response:
        result = snapshots.restore(req.params["snap_id"])
        audit_op(req, "snapshot.restore", "ok" if result.get("ok") else "error",
                 target=req.params["snap_id"])
        if not result.get("ok"):
            return Response.err(3002, result.get("err", "restore failed"))
        return Response.ok(result)

    # ---------- tools (F28-F34) ----------
    @router.add("GET", "/api/lan/devices")
    def lan_devices(req: Request) -> Response:
        intensity = req.query.get("intensity", "medium")
        return Response.ok(discover(intensity))

    @router.add("POST", "/api/tools/port-check")
    def tool_portcheck(req: Request) -> Response:
        targets = req.body.get("targets", [])
        if not targets or not isinstance(targets, list):
            return Response.err(E_BAD_REQUEST, "targets list required")
        results = check_ports(targets)
        audit_op(req, "tools.portcheck", "ok", detail={"count": len(results)})
        return Response.ok({"results": results})

    @router.add("POST", "/api/tools/traceroute")
    def tool_traceroute(req: Request) -> Response:
        target = req.body.get("target", "")
        if not target:
            return Response.err(E_BAD_REQUEST, "target required")
        result = run_traceroute(target)
        audit_op(req, "tools.traceroute", "ok", target=target)
        return Response.ok(result)

    @router.add("POST", "/api/tools/dns-compare")
    def tool_dns_compare(req: Request) -> Response:
        domain = req.body.get("domain", "")
        if not domain:
            return Response.err(E_BAD_REQUEST, "domain required")
        return Response.ok(dns_compare(domain))

    @router.add("GET", "/api/security/exposure")
    def tool_security(req: Request) -> Response:
        return Response.ok(check_security())

    @router.add("GET", "/api/tunnel/status")
    def tool_tunnel(req: Request) -> Response:
        from .tools.security import _check_tunnel
        return Response.ok(_check_tunnel())

    # ---------- repair (F10-F13) ----------
    @router.add("POST", "/api/fix/{check_id}")
    def fix(req: Request) -> Response:
        confirm = bool(req.body.get("confirm"))
        reg = diag_registry()
        cls = reg.get(req.params["check_id"])
        fixable = cls.spec.fixable if cls else None
        params = dict(req.body.get("params", {}))
        params.pop("action", None)  # action choice is server-controlled only
        # enrich with primary iface when the caller did not provide one
        pri = next((i for i in collector.get()["interfaces"]
                    if i.get("is_primary")), None)
        if "iface" not in params and pri and fixable in (
                "fix-link", "fix-dhcp", "fix-dns", "fix-gateway", "fix-ipv6",
                "fix-mtu", "fix-routes"):
            params["iface"] = pri["name"]
        if pri and fixable == "fix-gateway":
            addr = pri.get("ipv4", [{}])[0]
            params.setdefault("ipv4", addr.get("addr", ""))
            params.setdefault("prefix", addr.get("prefix", 24))
        # IPv6: primary missing the v6 stack -> re-enable via sysctl; otherwise
        # re-solicit RA/DHCPv6 (networkctl reload+reconfigure, M1-measured)
        action_override = ("sysctl-ipv6"
                           if pri and not pri.get("ipv6")
                           and fixable in ("fix-ipv6", "fix-routes") else "")
        if fixable == "fix-dns":
            params.setdefault("dns", config.get("repair.dns_servers",
                                                ["223.5.5.5", "119.29.29.29"]))
        if fixable == "fix-gateway" and not params.get("gateway"):
            return Response.err(E_BAD_REQUEST, "gateway required", 400)
        if fixable == "fix-dhcp":
            # Re-apply DHCP only on DHCP-configured interfaces; silently switching
            # a static NAS address to DHCP would cut off remote management -> guide
            if pri and pri.get("mode") == "dhcp":
                params.setdefault("mode", "dhcp")
            else:
                return Response.ok({"code": 0, "mode": "guide",
                                    "guide": GUIDE["fix-dhcp-static"]})
        if fixable == "fix-time":
            params.setdefault("unit", "ntp.service")
        context = {"req_id": req.req_id, "actor": req.actor}
        if action_override:
            context["action"] = action_override
        out = fix_engine.fix(req.params["check_id"], fixable or "", params, confirm,
                             context=context)
        code = out.get("code", 0)
        if code == 0:
            return Response.ok(out)
        return Response.err(code, out.get("message", "fix failed"),
                            400 if code in (1002, 2002) else 500)

    @router.add("GET", "/api/fix/history")
    def fix_history(req: Request) -> Response:
        return Response.ok({"items": fix_engine.history()})

    @router.add("POST", "/api/fix/history/delete")
    def fix_history_delete(req: Request) -> Response:
        record_id = req.body.get("record_id", "")
        if not isinstance(record_id, str) or not record_id:
            return Response.err(E_BAD_REQUEST, "record_id required")
        deleted = fix_engine.delete(record_id)
        audit_op(req, "history.delete", "ok" if deleted else "error",
                 target=record_id, detail={"type": "repair"})
        if not deleted:
            return Response.err(E_BAD_REQUEST, "history record not found", 404)
        return Response.ok({"deleted": True})

    @router.add("GET", "/api/fix/history/export")
    def fix_history_export(req: Request) -> Response:
        record_id = req.query.get("record_id", "")
        if not record_id:
            return Response.err(E_BAD_REQUEST, "record_id required")
        record = next((item for item in fix_engine.history()
                       if item.get("record_id") == record_id), None)
        audit_op(req, "history.export", "ok" if record else "error",
                 target=record_id, detail={"type": "repair"})
        if not record:
            return Response.err(E_BAD_REQUEST, "history record not found", 404)
        return Response.ok(repair_export(record, version))

    @router.add("POST", "/api/history/clear")
    def history_clear(req: Request) -> Response:
        diag_deleted = diag_history.clear()
        fix_deleted = fix_engine.clear()
        audit_op(req, "history.clear", "ok",
                 detail={"diagnosis": diag_deleted, "repair": fix_deleted})
        return Response.ok({"diag_deleted": diag_deleted,
                            "fix_deleted": fix_deleted})

    # ---------- jobs plumbing ----------
    @router.add("GET", "/api/jobs/{job_id}")
    def get_job(req: Request) -> Response:
        job = jobs.get(req.params["job_id"])
        if not job:
            return Response.err(E_BAD_REQUEST, "job not found", 404)
        return Response.ok(job.to_dict())

    log_event(logger, "router_built", detail={"endpoints": len(router.routes)})
    return router


def run(app_root: str, sock_path: str, data_dir: str, log_dir: str) -> None:
    logger = setup_logging(log_dir)
    router = build_router(app_root, data_dir, log_dir)
    Handler.router = router
    Handler.logger = logger
    os.makedirs(os.path.dirname(sock_path) or ".", exist_ok=True)
    server = UnixHTTPServer(sock_path, Handler)
    log_event(logger, "server_started", detail={"socket": sock_path, "pid": os.getpid()})

    def shutdown(signum, frame):  # noqa: ANN001
        log_event(logger, "server_stopping", detail={"signal": signum})
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
        log_event(logger, "server_stopped")
