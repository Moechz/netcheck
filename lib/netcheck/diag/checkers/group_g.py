"""Group G - other: MTU probe, system time, connection/fd exhaustion."""
from __future__ import annotations
import re

from ..engine import BaseChecker, register_checker


def _ping_do(probe, gw: str, size: int) -> bool:
    r = probe(["ping", "-M", "do", "-s", str(size), "-c", "1", "-W", "1", gw],
              timeout=3)
    return r.rc == 0


@register_checker("mtu-probe", "G", "check.mtu_probe", fixable="fix-mtu", weight=0.02,
                  na_fn=lambda ctx: not (ctx.get("nics", {}).get("interfaces") or [{}])[0].get("gateway"))
class MtuProbe(BaseChecker):
    def collect(self):
        pri = self.primary() or {}
        return pri.get("gateway"), pri.get("mtu"), pri.get("name", "")

    def evaluate(self, data):
        gw, actual_mtu, iface = data
        if not gw:
            return self.na("no gateway")
        raw_expected = self.cfg.get("expected_mtu")
        expected_mtu = None
        if raw_expected not in (None, "", 0):
            try:
                expected_mtu = int(raw_expected)
            except (TypeError, ValueError):
                expected_mtu = None
        mtu_label = f"{iface or 'primary'} MTU={actual_mtu or 'unknown'}"
        expected_label = (f"MTU={expected_mtu}" if expected_mtu
                          else "DF payload passes")
        if _ping_do(self.probe, gw, 1472):
            if (expected_mtu and isinstance(actual_mtu, int)
                    and actual_mtu != expected_mtu):
                return self.warn(
                    f"1472B payload passes; {mtu_label}",
                    expected_label,
                    f"mtu_policy_mismatch: primary MTU {actual_mtu}, expected {expected_mtu}")
            reason = ("" if not isinstance(actual_mtu, int) or actual_mtu == 1500
                      else f"runtime MTU {actual_mtu}; no expected MTU policy")
            return self.pass_(f"1472B payload passes; {mtu_label}",
                             expected_label, reason)
        lo, hi = 68, 1471
        for _ in range(6):
            mid = (lo + hi + 1) // 2
            if _ping_do(self.probe, gw, mid):
                lo = mid
            else:
                hi = mid - 1
        best = lo + 28
        if best < 1492:
            return self.fail(f"best path MTU={best}; {mtu_label}", ">=1492",
                             f"mtu_too_small: path MTU {best}")
        return self.warn(f"best path MTU={best}; {mtu_label}",
                        expected_label, f"mtu_pppoe: path MTU {best}")


@register_checker("system-time", "G", "check.system_time", fixable="fix-time", weight=0.03)
class SystemTime(BaseChecker):
    def collect(self):
        r = self.probe(["systemctl", "is-active", "ntp.service"], timeout=2).stdout.strip()
        rv = self.probe(["ntpq", "-c", "rv"], timeout=3).stdout
        date = self.probe(["curl", "-sI", "-m", "4",
                           (self.cfg.get("tos_endpoints") or ["https://www.baidu.com"])[0]],
                          timeout=6).stdout
        return r, rv, date

    def evaluate(self, data):
        active, rv, date_hdr = data
        offset_ms = None
        m = re.search(r"offset=([+-]?[\d.]+)", rv)
        if m:
            offset_ms = abs(float(m.group(1)))
        limit = self.cfg.get("time_offset_sec", 300) * 1000
        if "sync" in rv and "unsync" not in rv and (offset_ms is None or offset_ms < limit):
            return self.pass_(f"ntp active, offset={offset_ms}ms", f"<{limit}ms", "")
        if offset_ms is not None and offset_ms > limit:
            return self.warn(f"offset={offset_ms}ms", f"<{limit}ms",
                             "time_offset: clock skew (certificate risk)")
        return self.na("no time reference available")


@register_checker("conn-exhaust", "G", "check.conn_exhaust", weight=0.02)
class ConnExhaust(BaseChecker):
    def collect(self):
        s = self.probe(["ss", "-s"], timeout=2).stdout
        tw = self.probe(["ss", "-ant", "state", "time-wait"], timeout=2).stdout
        try:
            with open("/proc/sys/fs/file-nr") as f:
                file_nr = f.read().split()
        except OSError:
            file_nr = None
        return s, len(tw.strip().splitlines()) - 1, file_nr

    def evaluate(self, data):
        summary, tw, file_nr = data
        warn = self.cfg.get("conn_timewait_warn", 30000)
        fail = self.cfg.get("conn_timewait_fail", 50000)
        if tw >= fail:
            return self.fail(f"TIME_WAIT={tw}", f"<{fail}", "timewait_high")
        if tw >= warn:
            return self.warn(f"TIME_WAIT={tw}", f"<{warn}", "timewait_high")
        if file_nr:
            used, _, avail = int(file_nr[0]), int(file_nr[1]), int(file_nr[2])
            pct = used * 100.0 / max(used + avail, 1)
            if pct > 90:
                return self.fail(f"fd {pct:.0f}%", "<90%", "fd_exhausted")
            if pct > 80:
                return self.warn(f"fd {pct:.0f}%", "<80%", "fd_exhausted risk")
        return self.pass_(f"TIME_WAIT={tw}", f"<{warn}", "")
