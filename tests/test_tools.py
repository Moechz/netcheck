"""Tool tests: port check, traceroute parser, DNS compare, security."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from netcheck.tools.portcheck import check_port
from netcheck.tools.traceroute import _parse_traceroute, _find_breakpoint
from netcheck.tools.security import _check_exposure, HIGH_RISK

PASS = FAIL = 0


def check(name, expected, actual):
    global PASS, FAIL
    if expected == actual:
        PASS += 1; print(f"PASS {name}")
    else:
        FAIL += 1; print(f"FAIL {name}: expected={expected!r} got={actual!r}")


# ---------- port check ----------
r = check_port("127.0.0.1", 1, "tcp", timeout=1)
check("port.closed", False, r["reachable"])
check("port.rtt_recorded", True, r["rtt_ms"] is not None)

# ---------- traceroute parser ----------
TR = """ 1  192.168.124.1  0.517 ms  0.755 ms
 2  100.68.0.1  5.2 ms  5.1 ms
 3  * * *
 4  * * *
 5  * * *
 6  8.8.8.8  12.3 ms"""
hops = _parse_traceroute(TR)
check("trace.hops", 6, len(hops))
check("trace.first_ip", "192.168.124.1", hops[0]["ip"])
check("trace.timeout", True, hops[2]["timeout"])
bp = _find_breakpoint(hops)
check("trace.breakpoint", 5, bp["hop"] if bp else None)
check("trace.attribution", "ISP backbone", bp["attribution"] if bp else None)

# no breakpoint in clean trace
TR2 = """ 1  192.168.1.1  0.5 ms
 2  8.8.8.8  10.0 ms"""
hops2 = _parse_traceroute(TR2)
check("trace.no_breakpoint", None, _find_breakpoint(hops2))

# ---------- security exposure ----------
SS_OUT = """State Recv-Q Send-Q Local Address:Port Peer Address:Port
LISTEN 0 128 0.0.0.0:22 0.0.0.0:*
LISTEN 0 50 0.0.0.0:445 0.0.0.0:*
LISTEN 0 511 127.0.0.1:8080 0.0.0.0:*
LISTEN 0 128 0.0.0.0:5588 0.0.0.0:*"""
import netcheck.tools.security as sec
from unittest.mock import patch
with patch.object(sec.sysprobe, "run") as mock_run:
    class FakeR:
        def __init__(self, stdout=""):
            self.stdout, self.rc, self.stderr = stdout, 0, ""
    mock_run.side_effect = lambda argv, timeout=5: FakeR(SS_OUT)
    exp = _check_exposure()
check("sec.exposed_count", 3, exp["exposed_count"])
check("sec.high_risk_count", 2, exp["high_risk_count"])
check("sec.score_range", True, 0 <= exp["score"] <= 100)
check("sec.process_unknown", "unknown", exp["ports"][0]["process"])

# TOS CLI is the authoritative firewall status source.
with patch.object(sec.sysprobe, "run") as mock_run:
    mock_run.side_effect = lambda argv, timeout=5: FakeR(
        "PROPERTY         VALUE\nFirewall Status  enabled\n"
    )
    fw = sec._check_firewall()
check("sec.firewall_tos_enabled", (True, "tos-firewall", "tos-cli"),
      (fw["active"], fw["service"], fw["source"]))

# Tunnel uses business connectivity states, not an untranslated kernel-style "down".
TUNNEL_UP_IP = "10: tnas0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 state UNKNOWN\n    inet 100.64.1.2/22 scope global tnas0\n"
TUNNEL_UP_NO_IP = "10: tnas0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 state UNKNOWN\n"
TUNNEL_DOWN = "10: tnas0: <POINTOPOINT,MULTICAST,NOARP> mtu 1500 state DOWN\n"
with patch.object(sec.sysprobe, "run") as mock_run:
    mock_run.side_effect = lambda argv, timeout=5: FakeR(TUNNEL_UP_IP)
    tun = sec._check_tunnel()
check("sec.tunnel_connected", "connected", tun["status"])
with patch.object(sec.sysprobe, "run") as mock_run:
    mock_run.side_effect = lambda argv, timeout=5: FakeR(TUNNEL_UP_NO_IP)
    tun_no_ip = sec._check_tunnel()
check("sec.tunnel_no_ip", "no_ip", tun_no_ip["status"])
with patch.object(sec.sysprobe, "run") as mock_run:
    mock_run.side_effect = lambda argv, timeout=5: FakeR(TUNNEL_DOWN)
    tun_down = sec._check_tunnel()
check("sec.tunnel_disconnected", "disconnected", tun_down["status"])

print()
print(f"RESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
