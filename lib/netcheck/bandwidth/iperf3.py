"""iperf3 server/client management and parsers (bandwidth design 3-4).

Parser corrections implemented: per-interval SUM (multi-client streams may share
IDs like [5] - max-dedup would drop a client), latest interval = max t0 (not
max rate), summary section handled separately; client two-segment parsing
(forward -> sum_sent, -R -> sum_received).
"""
from __future__ import annotations
import json
import os
import re
import signal
import subprocess
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

IPERF3 = "/usr/bin/iperf3"
LINE_RE = re.compile(
    r"\[\s*(\d+)\]\s+([\d.]+)-([\d.]+)\s+sec\s+([\d.]+\s+\w?Bytes)\s+"
    r"([\d.]+\s+[KMG]?bits/sec)")
UNIT = {"bits/sec": 1.0, "Kbits/sec": 1e3, "Mbits/sec": 1e6, "Gbits/sec": 1e9}


def port_busy(port: int) -> bool:
    import socket as s
    with s.socket(s.AF_INET, s.SOCK_STREAM) as sock:
        sock.setsockopt(s.SOL_SOCKET, s.SO_REUSEADDR, 1)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def parse_server_log(text: str, offset: int = 0) -> Tuple[int, float, int]:
    """Incremental parse: (new_offset, latest full-interval Mbps, active clients)."""
    lines = text[offset:].splitlines(keepends=True)
    new_offset = offset + sum(len(l.encode()) for l in lines)
    per: Dict[float, float] = {}
    for line in lines:
        if "- - - -" in line:
            break  # summary section: handled by summarize() - check BEFORE regex
        m = LINE_RE.search(line)
        if not m:
            continue
        t0 = round(float(m.group(2)), 2)
        bps = float(m.group(5).split()[0]) * UNIT[m.group(5).split()[1]]
        per[t0] = per.get(t0, 0.0) + bps  # sum all streams/clients per interval
    latest = per[max(per)] / 1e6 if per else 0.0
    data = "".join(lines)
    clients = max(data.count("Accepted connection")
                  - data.count("the client has disconnected"), 0)
    return new_offset, round(latest, 2), clients


def summarize_server_log(text: str) -> Dict[str, Any]:
    """Parse the '- - - -' summary: totals, peak/avg, client count, duration."""
    total_bytes = 0
    peak = 0.0
    intervals: List[float] = []
    duration = 0.0
    in_summary = False
    for line in text.splitlines():
        if "- - - -" in line:
            in_summary = True
            continue
        if not in_summary:
            m = LINE_RE.search(line)
            if m:
                intervals.append(float(m.group(5).split()[0])
                                 * UNIT[m.group(5).split()[1]] / 1e6)
            continue
        # summary rows: [ ID] Interval Transfer Bitrate
        m = re.search(r"([\d.]+)-([\d.]+)\s+sec\s+([\d.]+\s+\w?Bytes)\s+"
                      r"([\d.]+)\s+([KMG]?bits/sec).*?(receiver|sender|total)?", line)
        if not m:
            continue
        t_end = float(m.group(2))
        duration = max(duration, t_end)
        if m.group(6) in ("receiver", "total", None):
            num, unit_s = float(m.group(4)), m.group(5)
            mbps = num * UNIT.get(unit_s, 1.0) / 1e6
            peak = max(peak, mbps)
    has_test = bool(intervals) or peak > 0
    return {"has_test": has_test, "peak_mbps": round(peak, 2),
            "avg_mbps": round(sum(intervals) / len(intervals), 2) if intervals else 0.0,
            "duration_s": round(duration, 1),
            "clients": max(text.count("Accepted connection"), 1) if has_test else 0}


# ---------------- client (two-segment, per-segment parsing per design 4.2) ----------------
def build_client_cmds(target: str, port: int, duration: int, streams: int,
                      udp: bool = False, udp_bw: str = "100M") -> Dict[str, List[str]]:
    base = [IPERF3, "-c", target, "-p", str(port), "-t", str(duration),
            "-P", str(streams), "-J", "--get-server-output"]
    if udp:
        base += ["-u", "-b", udp_bw]
    return {"upload": base, "download": base + ["-R"]}


def parse_iperf3_segment(raw: str, direction: str) -> float:
    """Forward segment -> sum_sent (up); -R segment -> sum_received (down)."""
    j = json.loads(raw)
    key = "sum_sent" if direction == "upload" else "sum_received"
    return j["end"][key]["bits_per_second"] / 1e6


def merge_iperf3_results(up_json: str, dn_json: str) -> Dict[str, Any]:
    up = parse_iperf3_segment(up_json, "upload")
    dn = parse_iperf3_segment(dn_json, "download")
    j = json.loads(up_json)
    end = j["end"]
    retr = end["sum_sent"].get("retransmits", 0)
    recv = end.get("sum_received", {})
    lost = recv.get("lost_packets", 0)
    pkts = recv.get("packets", 0)
    return {"upload_mbps": round(up, 2), "download_mbps": round(dn, 2),
            "retransmits": retr,
            "loss_pct": round(lost / pkts * 100, 2) if pkts else 0.0,
            "jitter_ms": recv.get("jitter_ms", 0.0),
            "version": j.get("start", {}).get("version", "")}


def run_client(target: str, port: int = 5201, duration: int = 10, streams: int = 4,
               udp: bool = False, udp_bw: str = "100M",
               run=subprocess.run) -> Dict[str, Any]:
    """Two serial segments (upload then download); classify errors (design 4.4)."""
    cmds = build_client_cmds(target, port, duration, streams, udp, udp_bw)
    outputs: Dict[str, str] = {}
    for seg in ("upload", "download"):
        try:
            p = run(cmds[seg], capture_output=True, text=True,
                    timeout=duration + 30)
        except subprocess.TimeoutExpired:
            return {"ok": False, "code": 4001, "err": "timeout"}
        if p.returncode != 0:
            err = (p.stderr or "") + p.stdout
            if "unable to connect" in err or "Connection refused" in err:
                return {"ok": False, "code": 4001, "err": "connect_failure"}
            if "resolve" in err or "Name or service" in err:
                return {"ok": False, "code": 4001, "err": "dns_failure"}
            if "version" in err.lower() or "protocol" in err.lower():
                return {"ok": False, "code": 5000, "err": "version_incompatible"}
            return {"ok": False, "code": 5000, "err": err[:200]}
        outputs[seg] = p.stdout
    try:
        result = merge_iperf3_results(outputs["upload"], outputs["download"])
    except (ValueError, KeyError) as exc:
        return {"ok": False, "code": 5000, "err": f"parse_error: {exc}"}
    return {"ok": True, **result}


# ---------------- server session ----------------
class ServerSession:
    def __init__(self, port: int, log_path: str,
                 idle_timeout: int = 300, max_lifetime: int = 3600):
        self.id = f"srv-{uuid.uuid4().hex[:8]}"
        self.port = port
        self.log_path = log_path
        self.idle_timeout = idle_timeout
        self.max_lifetime = max_lifetime
        self.started_at = time.time()
        self.state = "inactive"
        self.proc: Optional[subprocess.Popen] = None
        self._offset = 0
        self.last_activity = self.started_at
        self.realtime: Dict[str, Any] = {"rx_mbps": 0.0, "tx_mbps": 0.0,
                                         "active_clients": 0}
        self.summary: Dict[str, Any] = {}

    def start(self, popen=subprocess.Popen) -> None:
        # archive old log (design 3.1)
        if os.path.exists(self.log_path):
            os.replace(self.log_path, self.log_path + ".prev")
        self.proc = popen(
            [IPERF3, "-s", "-p", str(self.port), "-i", "1",
             "--logfile", self.log_path],
            start_new_session=True, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE)
        time.sleep(0.5)
        if self.proc.poll() is not None:
            err = b""
            try:
                err = self.proc.stderr.read() or b""
            except OSError:
                pass
            raise RuntimeError(f"iperf3 server exited: {err.decode()[:200]}")
        self.state = "listening"

    def poll_realtime(self) -> Dict[str, Any]:
        try:
            with open(self.log_path, encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            return self.realtime
        self._offset, mbps, clients = parse_server_log(text, self._offset)
        if mbps > 0 or clients > 0:
            self.last_activity = time.time()
        self.realtime = {"rx_mbps": mbps, "tx_mbps": 0.0,
                         "active_clients": clients}
        return self.realtime

    def stop(self, reason: str = "user") -> Dict[str, Any]:
        if self.proc and self.proc.poll() is None:
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
                time.sleep(1)
                if self.proc.poll() is None:
                    os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass
        try:
            with open(self.log_path, encoding="utf-8", errors="replace") as f:
                self.summary = summarize_server_log(f.read())
        except OSError:
            self.summary = {"has_test": False}
        self.state = "done" if self.summary.get("has_test") else "stopped"
        self.summary["reason"] = reason
        return self.summary

    def expired(self) -> Optional[str]:
        if self.state not in ("listening", "serving"):
            return None
        if time.time() - self.last_activity > self.idle_timeout:
            return "idle-timeout"
        if time.time() - self.started_at > self.max_lifetime:
            return "max-lifetime"
        return None
