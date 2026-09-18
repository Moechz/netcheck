"""FixEngine: precheck -> backup -> execute -> verify -> rollback -> audit (F11/F12).

repair.mode=helper: executes via the privileged helper (R1 contract approved).
repair.mode=guide:  returns paste-ready guidance text (degradation path).
"""
from __future__ import annotations
import hashlib
import json
import os
import secrets
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from .actions import ParamError, validate
from .helper_client import HelperClient

# check_id -> (action, params builder) for the helper mode
CHECK_TO_ACTION = {
    "link-speed": "link-toggle", "link-errors": "link-toggle",
    "ipv4-addr": "net-apply", "ipv4-mask": "net-apply",
    "dhcp-lease": "net-apply", "ip-conflict": "net-apply",
    "gateway-subnet": "gateway-set", "gateway-reach": "gateway-set",
    "default-route": "gateway-set", "connected-routes": "net-apply",
    "dns-config": "dns-set", "dns-reachable": "dns-set", "dns-resolve": "dns-set",
    "ipv6-dns": "dns-set",
    "ipv6-global-addr": "net-reload", "ipv6-default-route": "net-reload",
    "ipv6-reach": "net-reload",
    "mtu-probe": "mtu-set", "wan-ping": "gateway-set",
    "system-time": "svc-restart", "ntp-server": "svc-restart",
}

# post-repair verification: related checks to re-run (design 6.1)
VERIFY_MAP = {
    "link-speed": ["link-speed"],
    "link-errors": ["link-errors"],
    "ipv4-addr": ["ipv4-addr", "gateway-subnet"],
    "ipv4-mask": ["ipv4-addr"], "dhcp-lease": ["dhcp-lease"],
    "ip-conflict": ["ip-conflict"],
    "gateway-subnet": ["gateway-reach"], "gateway-reach": ["gateway-reach"],
    "default-route": ["default-route", "gateway-reach"],
    "connected-routes": ["connected-routes"],
    "dns-config": ["dns-config", "dns-reachable", "dns-resolve"],
    "dns-reachable": ["dns-reachable", "dns-resolve"],
    "dns-resolve": ["dns-resolve"], "ipv6-dns": ["ipv6-dns"],
    "ipv6-global-addr": ["ipv6-global-addr", "ipv6-default-route"],
    "ipv6-default-route": ["ipv6-default-route", "ipv6-global-addr"],
    "ipv6-reach": ["ipv6-reach"],
    "mtu-probe": ["mtu-probe"],
    "system-time": ["system-time", "ntp-server"],
    "ntp-server": ["ntp-server"],
}

GUIDE = {
    "fix-link": [
        "sudo ip link set <if> down && sleep 1 && sudo ip link set <if> up",
        "# if speed stays degraded, replace the cable or switch port",
    ],
    "fix-dhcp": [
        "sudo cp -a /etc/systemd/network /etc/systemd/network.bak-$(date +%s)",
        "sudo sed -i 's/^DHCP=.*/DHCP=ipv4/' /etc/systemd/network/10-<if>.network",
        "sudo networkctl reload && sudo networkctl reconfigure <if>",  # M1-measured
    ],
    "fix-dhcp-static": [
        # prose lines are mapped to guidemsg.* keys in the Web UI (translated);
        # command lines fall through to mono rendering
        "This interface uses a static address; NetCheck will not switch it to DHCP automatically.",
        "Changing a NAS address can cut off remote management.",
        "Identify the duplicate device from the MAC shown in the scan detail, shut it down or change its address, or assign this NAS a new static address in TOS Control Panel > Network.",
    ],
    "fix-gateway": [
        "sudo cp /etc/systemd/network/10-<if>.network /etc/systemd/network/10-<if>.network.bak",
        "sudo sed -i 's/^Gateway=.*/Gateway=<correct-gw>/' /etc/systemd/network/10-<if>.network",
        "sudo networkctl reload && sudo networkctl reconfigure <if>",
    ],
    "fix-dns": [
        "sudo resolvectl dns <if> 223.5.5.5 119.29.29.29",
        "# persistent: add DNS=223.5.5.5 to [Network] in 10-<if>.network, then:",
        "sudo networkctl reload && sudo networkctl reconfigure <if>",
    ],
    "fix-ipv6": [
        "sudo sysctl -w net.ipv6.conf.<if>.disable_ipv6=0",
    ],
    "fix-mtu": [
        "sudo ip link set <if> mtu <probed-mtu>",
    ],
    "fix-time": [
        "sudo systemctl restart ntp.service",  # device-verified service
    ],
    "fix-tunnel": [
        "Open TOS Control Panel > Network Services > Remote Access.",
        "Sign in to TNAS.online again, then rerun this check.",
        "If it remains disconnected, verify internet access and TerraMaster service status.",
    ],
}


class FixEngine:
    def __init__(self, config, helper: Optional[HelperClient] = None,
                 history_path: str = "", collector=None,
                 run_check_fn: Optional[Callable] = None,
                 audit_fn: Optional[Callable] = None):
        self.config = config
        self.helper = helper or HelperClient()
        self.collector = collector
        self.run_check = run_check_fn
        self.audit = audit_fn or (lambda **kw: None)
        self.history_path = history_path
        self._history_lock = threading.Lock()

    # ---------------- public API ----------------
    @staticmethod
    def _log_event(event: str, **fields: Any) -> Dict[str, Any]:
        return {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "event": event, **fields}

    def fix(self, check_id: str, fixable: str, params: Dict[str, Any],
            confirm: bool, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        context = context or {}
        req_id = str(context.get("req_id") or "")
        operator = str(context.get("actor") or "")
        if not confirm:
            return {"code": 1002, "message": "confirm required"}
        mode = self.config.get("repair.mode")
        if mode == "guide":
            if GUIDE.get(fixable):
                return {"code": 0, "mode": "guide", "guide": GUIDE[fixable]}
            return {"code": 1002, "message": "no automatic fix available"}
        if not fixable:
            return {"code": 1002, "message": "no automatic fix available"}
        # server-controlled action override (app.py: sysctl vs re-solicit for IPv6)
        action = context.get("action") or CHECK_TO_ACTION.get(
            check_id, fixable if fixable in
            ("link-toggle", "net-apply", "dns-set",
             "gateway-set", "sysctl-ipv6", "mtu-set",
             "svc-restart") else "")
        if not action:
            if GUIDE.get(fixable):
                return {"code": 0, "mode": "guide", "guide": GUIDE[fixable]}
            return {"code": 1002, "message": f"no auto-fix for {check_id}"}

        # 1) precheck: target still failing (F11)
        precheck_status = None
        request_event = {"check_id": check_id, "fixable": fixable, "params": params}
        if req_id:
            request_event["req_id"] = req_id
        if operator:
            request_event["operator"] = operator
        event_log = [self._log_event("repair.request", **request_event)]
        if self.run_check:
            status = self.run_check(check_id)
            precheck_status = status
            event_log.append(self._log_event("repair.precheck", check_id=check_id,
                                             status=status))
            if status == "pass":
                return {"code": 2002, "message": "check currently passes"}
            if status == "na":
                return {"code": 2002, "message": "check not applicable"}

        # 2) validate locally (defense in depth)
        try:
            clean = validate(action, params)
        except ParamError as exc:
            return {"code": 1002, "message": str(exc)}

        # 3) execute via helper (backup happens inside the helper, 7.3)
        t0 = time.monotonic()
        result = self.helper.call(action, clean)
        dur = int((time.monotonic() - t0) * 1000)
        event_log.append(self._log_event(
            "repair.execute", action=action, params=clean,
            ok=result.get("ok", False), rc=result.get("rc"),
            stdout=result.get("stdout", ""), stderr=result.get("stderr", ""),
            duration_ms=dur))

        entry = {"record_id": "fix-" + secrets.token_hex(8),
                 "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "check_id": check_id,
                 "action": action, "params": clean, "result": result,
                 "dur_ms": dur, "ok": result.get("ok", False), "log": event_log}
        if req_id:
            entry["req_id"] = req_id
        if operator:
            entry["operator"] = operator
        entry["precheck_status"] = precheck_status
        self.audit(action="fix.execute", target=check_id,
                   result="ok" if result.get("ok") else "error", detail=clean,
                   req_id=req_id)

        # 4) verify: re-run related checks (F12); helper already rolled back on failure
        verified = None
        pending = False
        if result.get("ok") and self.run_check:
            observed, pending = self._verify(check_id)
            entry["verification_observed"] = observed
            if pending:
                verified = {check: "pending" for check, status in observed.items()
                            if status != "pass"}
                entry["verified"] = verified
                entry["verified_pending"] = True
            else:
                verified = observed
                entry["verified"] = verified
        verified_ok = (verified is None or
                       all(status in self._VERIFY_OK for status in verified.values()))
        if not verified_ok:
            entry["verified_ok"] = False
        event_log.append(self._log_event(
            "repair.verify", checks=verified if verified is not None
            else entry.get("verification_observed", {}), pending=pending,
            ok=verified_ok))
        self._append_history(entry)
        return {"code": 0 if result.get("ok") and (verified_ok or pending) else 3002,
                "mode": "helper", "result": result,
                "verified": verified,
                "message": ("ntp service restarted; synchronization is pending"
                            if pending else
                            "" if verified_ok else "verification failed after repair"),
                "history": entry}

    _VERIFY_OK = ("pass", "warn", "na")

    def _verify(self, check_id: str) -> Tuple[Dict[str, str], bool]:
        """Run related checks; warn/na count as non-failure (improved-not-failing).

        NTP receives a bounded synchronization grace window (returns pending);
        IPv6 checks get a short bounded retry for RA/DHCPv6 re-negotiation,
        after which a still-failing check is a real 3002 (never "pending").
        """
        checks = VERIFY_MAP.get(check_id, [check_id])
        grace_key = {"system-time": "diag.ntp_verify_timeout_sec",
                     "ntp-server": "diag.ntp_verify_timeout_sec",
                     "ipv6-global-addr": "diag.ipv6_verify_timeout_sec",
                     "ipv6-default-route": "diag.ipv6_verify_timeout_sec",
                     "ipv6-reach": "diag.ipv6_verify_timeout_sec"}.get(check_id)
        timeout = float(self.config.get(grace_key, 0) or 0) if grace_key else 0.0
        ntp_pending = check_id in ("system-time", "ntp-server")
        deadline = time.monotonic() + timeout
        while True:
            statuses = {check: self.run_check(check) for check in checks}
            if all(status in self._VERIFY_OK for status in statuses.values()):
                return statuses, False
            if not grace_key or time.monotonic() >= deadline:
                return statuses, ntp_pending
            time.sleep(min(3.0, max(0.0, deadline - time.monotonic())))

    # ---------------- history ----------------
    def history(self) -> List[Dict[str, Any]]:
        return [dict(item, record_id=self._record_id(item, index))
                for index, item in enumerate(self._read_history())]

    def delete(self, record_id: str) -> bool:
        """Delete one repair-history record by its stable ID."""
        if not isinstance(record_id, str) or not record_id:
            return False
        with self._history_lock:
            items = self._read_history()
            for index, item in enumerate(items):
                if self._record_id(item, index) == record_id:
                    del items[index]
                    self._write_history(items)
                    return True
            return False

    def clear(self) -> int:
        """Clear repair history and return the removed record count."""
        with self._history_lock:
            items = self._read_history()
            count = len(items)
            self._write_history([])
            return count

    def _read_history(self) -> List[Dict[str, Any]]:
        try:
            with open(self.history_path, encoding="utf-8") as f:
                items = json.load(f).get("items", [])
            return items if isinstance(items, list) else []
        except (OSError, ValueError):
            return []

    @staticmethod
    def _record_id(item: Dict[str, Any], index: int) -> str:
        existing = item.get("record_id")
        if isinstance(existing, str) and existing:
            return existing
        # Old packages did not persist IDs. Keep the fallback deterministic so
        # a displayed legacy record remains addressable until the file changes.
        canonical = json.dumps(item, ensure_ascii=False, sort_keys=True,
                               separators=(",", ":"))
        digest = hashlib.sha256(f"{index}:{canonical}".encode("utf-8")).hexdigest()
        return "legacy-fix-" + digest[:20]

    def _write_history(self, items: List[Dict[str, Any]]) -> None:
        os.makedirs(os.path.dirname(self.history_path) or ".", exist_ok=True)
        tmp = self.history_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as stream:
            json.dump({"items": items[-200:]}, stream, ensure_ascii=False, indent=2)
        os.replace(tmp, self.history_path)

    def _append_history(self, entry: Dict[str, Any]) -> None:
        with self._history_lock:
            items = self._read_history()
            items.append(entry)
            self._write_history(items)
