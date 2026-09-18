"""Privileged helper server: whitelist dispatch with backup/verify/rollback.

Security layers (security review): SO_PEERCRED + startup token (4), parameter
validation (6.3), template whitelist rendering + built-in syntax check (6.5),
atomic writes, pre-execution backup with SHA-256 (7.3), JSONL audit (9),
per-action 30s rate limit + serial lock (4.4). net-apply/snap-restore always
finish with reload + reconfigure (M1 finding 12.2).
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..fix.actions import ParamError, build_argv, validate

DEFAULT_BINS = {"ip": "/usr/sbin/ip", "networkctl": "/usr/bin/networkctl",
                "systemctl": "/usr/bin/systemctl", "resolvectl": "/usr/bin/resolvectl",
                "sysctl": "/usr/sbin/sysctl"}

NETWORK_DIR = "/etc/systemd/network"


def _resolve_bins() -> Dict[str, str]:
    bins = {}
    search = ("/usr/sbin", "/usr/bin", "/sbin", "/bin")
    for name, preferred in DEFAULT_BINS.items():
        if os.path.exists(preferred):
            bins[name] = preferred
            continue
        for d in search:
            p = os.path.join(d, name)
            if os.path.exists(p):
                bins[name] = p
                break
        else:
            bins[name] = name
    return bins


class HelperServer:
    """Testable helper core; probe/write/log functions are injectable."""

    def __init__(self, sock_dir: str = "/run/netcheck", netcheck_uid: int = -1,
                 netcheck_gid: int = -1,
                 network_dir: str = NETWORK_DIR, backups_dir: str = "",
                 audit_path: str = "", token: Optional[str] = None,
                 exec_fn: Optional[Callable] = None):
        self.sock_dir = sock_dir
        self.netcheck_uid = netcheck_uid
        self.netcheck_gid = netcheck_gid if netcheck_gid >= 0 else netcheck_uid
        self.network_dir = network_dir
        self.backups_dir = backups_dir or os.path.join(
            os.path.dirname(network_dir), "..", "backups")
        self.audit_path = audit_path
        self.token = token or secrets.token_hex(32)
        self.bins = _resolve_bins()
        self._exec = exec_fn or self._default_exec
        self._lock = threading.Lock()
        self._last_action_ts: Dict[str, float] = {}
        self.allowed_ifaces: Optional[List[str]] = None  # injected by main service

    # ---------------- exec ----------------
    @staticmethod
    def _default_exec(argv: List[str], timeout: float = 30.0) -> Tuple[int, str]:
        try:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                               env={"PATH": "/usr/sbin:/usr/bin:/bin"},
                               start_new_session=True)
            return p.returncode, (p.stdout or "") + (p.stderr or "")
        except subprocess.TimeoutExpired:
            return -124, "timeout"
        except FileNotFoundError:
            return 127, f"not found: {argv[0]}"

    # ---------------- audit ----------------
    def audit(self, level: str, **fields: Any) -> None:
        if not self.audit_path:
            return
        entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "lvl": level}
        entry.update({k: v for k, v in fields.items() if v is not None})
        os.makedirs(os.path.dirname(self.audit_path), exist_ok=True)
        with open(self.audit_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False)[:4096] + "\n")

    # ---------------- backup / rollback ----------------
    def _backup_file(self, path: str, action: str) -> Optional[str]:
        if not os.path.exists(path):
            return None
        ts = time.strftime("%Y%m%d-%H%M%S")
        bdir = os.path.join(self.backups_dir, f"{action}-{ts}")
        os.makedirs(bdir, exist_ok=True)
        dst = os.path.join(bdir, os.path.basename(path))
        shutil.copy2(path, dst)
        with open(dst, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        meta = {"original_path": path, "sha256": digest,
                "mode": oct(os.stat(path).st_mode & 0o777),
                "owner": os.stat(path).st_uid}
        with open(os.path.join(bdir, "meta.json"), "w") as f:
            json.dump(meta, f, indent=2)
        return bdir

    def _atomic_write(self, path: str, content: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = os.path.join(os.path.dirname(path),
                           f".{os.path.basename(path)}.tmp-{secrets.token_hex(4)}")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        try:
            with os.fdopen(fd, "w") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
            os.chmod(path, 0o644)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    # ---------------- actions ----------------
    def dispatch(self, action: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Validate -> backup -> execute -> verify; rollback on failure."""
        try:
            clean = validate(action, params, self.allowed_ifaces)
        except ParamError as exc:
            self.audit("WARN", action=action, reason="param_reject", detail=str(exc))
            return {"ok": False, "rc": 1002, "stdout": "", "err": str(exc)}

        now = time.time()
        with self._lock:  # serial + 30s per-action rate limit (4.4)
            if now - self._last_action_ts.get(action, 0) < 30:
                self.audit("WARN", action=action, reason="rate_limited")
                return {"ok": False, "rc": 1003, "stdout": "", "err": "rate limited"}
            self._last_action_ts[action] = now

        t0 = time.monotonic()
        backup_dir: Optional[str] = None
        try:
            if action == "net-apply":
                result, backup_dir = self._do_net_apply(clean)
            elif action == "snap-restore":
                result, backup_dir = self._do_snap_restore(clean)
            elif action in ("dns-set", "gateway-set"):
                result, backup_dir = self._do_targeted_network_update(action, clean)
            else:
                result = self._do_argv(action, clean)
        except Exception as exc:  # noqa: BLE001
            self.audit("CRIT", action=action, reason="exception", detail=str(exc)[:200])
            return {"ok": False, "rc": 5000, "stdout": "", "err": str(exc)}

        ok = result["ok"]
        self.audit("INFO" if ok else "WARN", action=action,
                   params={k: v for k, v in clean.items()},
                   rc=result["rc"], ok=ok, backup_dir=backup_dir,
                   dur_ms=int((time.monotonic() - t0) * 1000),
                   stdout_hash=hashlib.sha256(
                       result.get("stdout", "").encode()).hexdigest()[:16])
        return result

    def _do_argv(self, action: str, params: Dict[str, Any]) -> Dict[str, Any]:
        argvs = build_argv(action, params, self.bins)
        last_rc, last_out = 0, ""
        for argv in argvs:
            rc, out = self._exec(argv)
            last_rc, last_out = rc, out
            if rc != 0:
                break
        return {"ok": last_rc == 0, "rc": last_rc, "stdout": last_out[-4096:]}

    def _do_net_apply(self, p: Dict[str, Any]) -> Tuple[Dict[str, Any], Optional[str]]:
        from .network_template import render_net_apply, syntax_check
        path = os.path.join(self.network_dir, f"10-{p['iface']}.network")
        content = render_net_apply(p["iface"], p["mode"], p.get("ipv4", ""),
                                   p.get("prefix", 24), p.get("gateway", ""),
                                   p.get("dns"), p.get("mtu"))
        errors = syntax_check(content)  # built-in primary (no networkd-analyze)
        if errors:
            self.audit("WARN", action="net-apply", reason="networkd_verify_fail",
                       detail="; ".join(errors))
            return {"ok": False, "rc": 1002, "stdout": "", "err": "; ".join(errors)}, None
        backup_dir = self._backup_file(path, "net-apply")
        self._atomic_write(path, content)
        rc, out = self._reload_reconfigure(p["iface"])
        if rc != 0 and backup_dir:
            self._rollback(backup_dir, p["iface"])
            return {"ok": False, "rc": rc, "stdout": out,
                    "err": "reload failed; rolled back"}, backup_dir
        return {"ok": True, "rc": 0, "stdout": out}, backup_dir

    def _do_snap_restore(self, p: Dict[str, Any]) -> Tuple[Dict[str, Any], Optional[str]]:
        snap_dir = os.path.join(self.backups_dir, "..", "snapshots", p["snapshot_id"])
        snap_dir = os.path.normpath(snap_dir)
        if not os.path.isdir(snap_dir):
            return {"ok": False, "rc": 1002, "stdout": "",
                    "err": "snapshot not found"}, None
        files = [f for f in os.listdir(snap_dir) if f.endswith(".network")]
        if not files:
            return {"ok": False, "rc": 1002, "stdout": "",
                    "err": "snapshot has no .network files"}, None
        affected: List[str] = []
        backup_dir = None
        from .network_template import syntax_check
        for fname in files:
            content = open(os.path.join(snap_dir, fname), encoding="utf-8").read()
            if syntax_check(content):
                return {"ok": False, "rc": 1002, "stdout": "",
                        "err": f"snapshot file {fname} fails syntax check"}, backup_dir
        for fname in files:
            path = os.path.join(self.network_dir, fname)
            backup_dir = self._backup_file(path, "snap-restore") or backup_dir
            self._atomic_write(path, content)
            m = re.match(r"10-(.+)\.network", fname)
            if m:
                affected.append(m.group(1))
        rc, out = 0, ""
        for ifc in affected:
            rc, out = self._reload_reconfigure(ifc)
            if rc != 0:
                break
        if rc != 0 and backup_dir:
            self._rollback(backup_dir, affected[0] if affected else "")
        return {"ok": rc == 0, "rc": rc, "stdout": out}, backup_dir

    def _do_targeted_network_update(self, action: str,
                                    p: Dict[str, Any]) -> Tuple[Dict[str, Any], Optional[str]]:
        """Update one networkd value while preserving unrelated TOS settings."""
        from .network_template import syntax_check
        path = os.path.join(self.network_dir, f"10-{p['iface']}.network")
        try:
            with open(path, encoding="utf-8") as f:
                original = f.read()
        except OSError as exc:
            return {"ok": False, "rc": 1002, "stdout": "",
                    "err": f"network file unavailable: {exc}"}, None

        if action == "dns-set":
            updated = self._replace_section_value(
                original, "Network", "DNS", " ".join(p["dns"]))
        else:
            updated = self._replace_default_gateway(original, p["gateway"])
        errors = syntax_check(updated)
        if errors:
            self.audit("WARN", action=action, reason="networkd_verify_fail",
                       detail="; ".join(errors))
            return {"ok": False, "rc": 1002, "stdout": "",
                    "err": "; ".join(errors)}, None

        backup_dir = self._backup_file(path, action)
        self._atomic_write(path, updated)
        rc, out = self._reload_reconfigure(p["iface"])
        if rc == 0 and action == "dns-set":
            # networkctl preserves a manual resolved override on some TOS
            # builds, so apply the validated file value to the live link too.
            rc, out = self._exec([self.bins["resolvectl"], "dns",
                                  p["iface"]] + p["dns"])
        if rc != 0 and backup_dir:
            self._rollback(backup_dir, p["iface"])
        else:
            # Give resolved/networkd a moment to apply the new link settings.
            time.sleep(1.0)
        return {"ok": rc == 0, "rc": rc, "stdout": out}, backup_dir

    @staticmethod
    def _join_preserving_tail(lines: List[str], original: str) -> str:
        """Keep the original number of trailing newlines/blank lines."""
        tail_newlines = len(original) - len(original.rstrip("\n"))
        if tail_newlines < 1:
            tail_newlines = 1
        return "\n".join(lines) + ("\n" * tail_newlines)

    @staticmethod
    def _replace_section_value(text: str, section_name: str, key: str,
                               value: str) -> str:
        """Replace one key in the first matching section, preserving the rest."""
        lines = text.splitlines()
        section = None
        section_start = -1
        replaced = False
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                if section == section_name and not replaced and section_start >= 0:
                    lines.insert(i, f"{key}={value}")
                    replaced = True
                section = stripped[1:-1]
                section_start = i
                continue
            if section == section_name and stripped.split("=", 1)[0].strip() == key:
                lines[i] = f"{key}={value}"
                replaced = True
        if not replaced:
            if section == section_name and section_start >= 0:
                lines.append(f"{key}={value}")
            else:
                lines.extend(["", f"[{section_name}]", f"{key}={value}"])
        return HelperServer._join_preserving_tail(lines, text)

    @staticmethod
    def _replace_default_gateway(text: str, gateway: str) -> str:
        """Replace the gateway in the default-route [Route] section only."""
        lines = text.splitlines()
        section = None
        route_ranges = []
        start = None
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                if section == "Route" and start is not None:
                    route_ranges.append((start, i))
                section = stripped[1:-1]
                start = i if section == "Route" else None
        if section == "Route" and start is not None:
            route_ranges.append((start, len(lines)))

        target = None
        for start, end in route_ranges:
            block = lines[start:end]
            destinations = [line for line in block
                            if line.strip().startswith("Destination=")]
            if (not destinations or
                    any(line.strip() == "Destination=0.0.0.0/0" for line in destinations)):
                target = (start, end)
                break
        if target is None:
            lines.extend(["", "[Route]", "Destination=0.0.0.0/0",
                          f"Gateway={gateway}"])
            return HelperServer._join_preserving_tail(lines, text)

        start, end = target
        replaced = False
        for i in range(start, end):
            if lines[i].strip().startswith("Gateway="):
                lines[i] = f"Gateway={gateway}"
                replaced = True
                break
        if not replaced:
            lines.insert(end, f"Gateway={gateway}")
        return HelperServer._join_preserving_tail(lines, text)

    def _reload_reconfigure(self, iface: str) -> Tuple[int, str]:
        """M1-measured mandatory sequence: reload alone does not reconfigure."""
        rc, out = self._exec([self.bins["networkctl"], "reload"])
        if rc != 0:
            return rc, out
        return self._exec([self.bins["networkctl"], "reconfigure", iface])

    def _rollback(self, backup_dir: str, iface: str) -> None:
        try:
            for fname in os.listdir(backup_dir):
                if fname.endswith(".network"):
                    shutil.copy2(os.path.join(backup_dir, fname),
                                 os.path.join(self.network_dir, fname))
            self._reload_reconfigure(iface)
            self.audit("WARN", action="rollback", reason="rolled_back",
                       backup_dir=backup_dir)
        except OSError as exc:
            self.audit("CRIT", action="rollback", reason="rollback_failed",
                       detail=str(exc))

    # ---------------- socket server ----------------
    def serve(self) -> None:
        os.makedirs(self.sock_dir, mode=0o700, exist_ok=True)
        token_path = os.path.join(self.sock_dir, "token")
        sock_path = os.path.join(self.sock_dir, "helper.sock")
        fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(self.token)
        if self.netcheck_uid >= 0:
            os.chown(token_path, self.netcheck_uid, self.netcheck_gid)
            # Runtime dir layout is root:netcheck 0770 (no setgid - the units
            # run with RestrictSUIDSGID=true, which rejects chmod that sets
            # the sgid bit): the bpf collector needs a root-owned dir to
            # create its socket in, and the netcheck group keeps the dir
            # reachable for the main service. Refresh only the group here and
            # keep root ownership - chowning to netcheck would break bpf on its
            # next restart (see init.d/netcheck-helper.service ExecStartPre).
            os.chown(self.sock_dir, 0, self.netcheck_gid)
        if os.path.exists(sock_path):
            os.unlink(sock_path)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(sock_path)
        os.chmod(sock_path, 0o600)
        if self.netcheck_uid >= 0:
            os.chown(sock_path, self.netcheck_uid, self.netcheck_gid)
        srv.listen(8)
        print(f"helper listening on {sock_path}", file=sys.stderr)
        while True:
            conn, _ = srv.accept()
            try:
                cred = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                       struct.calcsize("3i"))
                _, peer_uid, _ = struct.unpack("3i", cred)
                if peer_uid != self.netcheck_uid:
                    self.audit("WARN", reason="peer_uid_reject", peer_uid=peer_uid)
                    continue
                req = json.loads(conn.recv(64 * 1024).decode("utf-8"))
                if not secrets.compare_digest(str(req.get("token", "")), self.token):
                    self.audit("WARN", reason="token_reject")
                    conn.sendall(json.dumps(
                        {"ok": False, "rc": 3001, "err": "auth_failed"}).encode())
                    continue
                result = self.dispatch(req.get("action", ""),
                                       req.get("params", {}))
                conn.sendall(json.dumps(result).encode())
            except (OSError, ValueError) as exc:
                try:
                    conn.sendall(json.dumps(
                        {"ok": False, "rc": 5000, "err": str(exc)}).encode())
                except OSError:
                    pass
            finally:
                conn.close()


def main() -> int:
    import pwd
    try:
        pw = pwd.getpwnam("netcheck")
        uid, gid = pw.pw_uid, pw.pw_gid  # uid != gid when the group existed
    except KeyError:                     # before useradd (real-device case)
        print("netcheck user missing", file=sys.stderr)
        return 1
    app_root = os.environ.get("NETCHECK_ROOT",
                              "/usr/local/netcheck")
    server = HelperServer(
        sock_dir=os.environ.get("NETCHECK_RUN_DIR", "/run/netcheck"),
        netcheck_uid=uid,
        netcheck_gid=gid,
        backups_dir=os.path.join(app_root, "data", "backups"),
        audit_path=os.path.join(app_root, "logs", "helper-audit.log"))
    server.serve()
    return 0


if __name__ == "__main__":
    sys.exit(main())
