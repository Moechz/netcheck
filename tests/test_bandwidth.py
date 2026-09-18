"""M6 bandwidth tests: parsers, mutex, lifecycle, ookla fallbacks, traffic sampler."""
import json
import os
import socket
import sys
import threading
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from netcheck.bandwidth.iperf3 import (parse_server_log, summarize_server_log,
                                       merge_iperf3_results, build_client_cmds)
from netcheck.bandwidth.ookla import Speedtest, run_ookla
from netcheck.bandwidth.service import BandwidthSvc, Busy
from netcheck.bandwidth.bpf_client import BpfTrafficClient
from netcheck.bandwidth.traffic import TrafficSampler, parse_proc_net_dev

PASS = FAIL = 0


def check(name, expected, actual):
    global PASS, FAIL
    if expected == actual:
        PASS += 1; print(f"PASS {name}")
    else:
        FAIL += 1; print(f"FAIL {name}: expected={expected!r} got={actual!r}")


# ---------- server log parsing (correction: multi-client same stream id) ----------
# two concurrent clients sharing stream id [5] in the same interval:
# correct = sum (1760); the old max-dedup bug would return 960
LOG = """[  5] 0.00-1.00 sec  100 MBytes  800 Mbits/sec
[  5] 0.00-1.00 sec  120 MBytes  960 Mbits/sec
- - - - - - - - - - - - - - -
[ ID] Interval Transfer Bitrate
[  5] 0.00-10.00 sec 1.20 GBytes 1000 Mbits/sec receiver
"""
off, latest, clients = parse_server_log(LOG, 0)
check("log.multi_client_sum", 1760.0, latest)      # sum of same-id clients, not max
summary = summarize_server_log(LOG)
check("log.summary_peak", 1000.0, summary["peak_mbps"])
check("log.summary_has_test", True, summary["has_test"])

# latest = max t0 interval (2.0s -> 1600), not max across all
LOG2 = "[ 5] 0.00-1.00 sec 100 MBytes 2000 Mbits/sec\n[ 5] 1.00-2.00 sec 100 MBytes 100 Mbits/sec\n"
_, latest2, _ = parse_server_log(LOG2, 0)
check("log.latest_not_max", 100.0, latest2)

# ---------- client segment merge (correction: per-segment parsing) ----------
up_json = json.dumps({"start": {"version": "3.9"},
                      "end": {"sum_sent": {"bits_per_second": 900e6, "retransmits": 15},
                              "sum_received": {"bits_per_second": 1e6}}})
dn_json = json.dumps({"start": {"version": "3.9"},
                      "end": {"sum_sent": {"bits_per_second": 0.5e6},
                              "sum_received": {"bits_per_second": 940e6,
                                               "lost_packets": 2, "packets": 10000,
                                               "jitter_ms": 0.1}}})
merged = merge_iperf3_results(up_json, dn_json)
check("client.upload_from_forward", 900.0, merged["upload_mbps"])
check("client.download_from_reverse", 940.0, merged["download_mbps"])
check("client.retransmits", 15, merged["retransmits"])
cmds = build_client_cmds("192.168.124.56", 5201, 10, 4)
check("client.reverse_flag", True, "-R" in cmds["download"] and "-R" not in cmds["upload"])

# ---------- service: mutex + lifecycle ----------
class FakeConfig:
    def __init__(self):
        self.data = {"bandwidth": {"iperf3_port": 5999, "duration_sec": 1},
                     "retention": {"bandwidth_history": 100}}
    def get(self, key, default=None):
        node = self.data
        for part in key.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

def fake_client_ok(target, port, duration, streams, udp, udp_bw):
    return {"ok": True, "upload_mbps": 900.0, "download_mbps": 940.0,
            "retransmits": 5, "loss_pct": 0.0, "jitter_ms": 0.1}

tmp = tempfile.mkdtemp(prefix="nc-bw-")
svc = BandwidthSvc(FakeConfig(), tmp, run_client_fn=fake_client_ok,
                   ookla_fn=lambda **kw: {"ok": True, "download_mbps": 300.0,
                                          "upload_mbps": 50.0, "latency_ms": 20.0})
out = svc.start("lan", "client", {"target": "192.168.124.56"})
check("svc.start_jobid", True, out["job_id"].startswith("bw-"))
# second start immediately -> Busy (F18)
try:
    svc.start("wan", "ookla", {})
    check("svc.mutex", "no-busy", "should-have-raised")
except Busy as e:
    check("svc.mutex", ("lan", "client"), (e.active["type"], e.active["mode"]))
# wait for the job to finish AND the lock to be released (state is set
# before the finally-block releases the guard - avoid the race)
for _ in range(80):
    st = svc.status()
    if svc._active is None and st["state"] in ("done", "failed", "idle"):
        break
    time.sleep(0.05)
check("svc.job_done", "done", st["state"])
check("svc.job_result", 940.0, st["result"]["download_mbps"])
hist = svc.history()
check("svc.history_len", 1, len(hist["items"]))
check("svc.history_latest", True, str(hist["latest"].get("lan", "")).startswith("bw-"))
# after completion a new task can start
out2 = svc.start("wan", "ookla", {})
check("svc.start_after_done", True, out2["job_id"].startswith("bw-"))
for _ in range(80):
    st2 = svc.status()
    if svc._active is None and st2["state"] in ("done", "failed", "idle"):
        break
    time.sleep(0.05)
check("svc.ookla_done", "done", st2["state"])
check("svc.ookla_result", 300.0, st2["result"]["download_mbps"])
check("svc.stop_when_idle", "no_active_task", svc.stop().get("error"))

# ---------- ookla fallback chain (fake session) ----------
class FakeResponse:
    def __init__(self, text="", content=b""):
        self.text = text; self.content = content
class FakeSession:
    def __init__(self, servers_xml="<servers></servers>", fail=False):
        self.servers_xml = servers_xml; self.fail = fail; self.calls = 0
    def get(self, url, timeout=10):
        self.calls += 1
        if self.fail:
            raise OSError("offline")
        if "speedtest-servers" in url:
            return FakeResponse(self.servers_xml)
        if "latency.txt" in url:
            return FakeResponse("p=0", b"0")
        return FakeResponse("", b"x" * 1000000)
    def post(self, url, data=None, timeout=10):
        return FakeResponse()

xml = '<servers><server url="https://s1.example.com/latency.txt" name="S1"/>' \
      '<server url="https://s2.example.com/latency.txt" name="S2"/></servers>'
sess = FakeSession(xml)
st_ = Speedtest(session=sess)
servers, source = st_.get_servers()
check("ookla.live_list", ("live", 2), (source, len(servers)))
# offline -> builtin fallback
cache = os.path.join(tmp, "speedtest-servers.json")
st2 = Speedtest(session=FakeSession(fail=True), cache_path=cache)
servers2, source2 = st2.get_servers()
check("ookla.builtin_fallback", "builtin", source2)
# cache hit after a live fetch
st3 = Speedtest(session=sess, cache_path=cache)
st3.get_servers()
st4 = Speedtest(session=FakeSession(fail=True), cache_path=cache)
servers4, source4 = st4.get_servers()
check("ookla.cache_fallback", "cache", source4)
check("ookla.cache_servers", 2, len(servers4))
# best server probes latency
best, ms = st_.best_server(servers)
check("ookla.best_server", True, best["name"] in ("S1", "S2") and ms >= 0)

# ---------- traffic sampler ----------
PROC_T1 = "Inter-|   Receive |  Transmit\n face|bytes packets errs drop ...|bytes ...\n  eth0: 1000 10 0 0 0 0 0 0 2000 10 0 0 0 0 0 0\n"
PROC_T2 = PROC_T1.replace("eth0: 1000", "eth0: 2000").replace(" 2000 10 0 0 0 0 0 0\n", " 2600 10 0 0 0 0 0 0\n")
state = {"n": 0}
def fake_read():
    state["n"] += 1
    return PROC_T1 if state["n"] == 1 else PROC_T2
sampler = TrafficSampler(interval=0.05, read_fn=fake_read)
sampler.tick(); time.sleep(0.06); sampler.tick()
snap = sampler.snapshot("eth0")
check("traffic.counters", 2000, snap["eth0"]["rx_bytes"])
check("traffic.bps_computed", True, snap["eth0"]["rx_bps"] > 0)
check("traffic.parse", {"eth0"}, set(parse_proc_net_dev(PROC_T1)))

# ---------- Go/eBPF collector protocol ----------
unix_path = os.path.join(tmp, "bpf-traffic.sock")
body = json.dumps({
    "source": "bpf", "available": True, "ts": "2026-09-06T16:56:09+08:00",
    "interfaces": {
        "eth0": {"rx_bytes": 100, "rx_packets": 1, "tx_bytes": 200,
                 "tx_packets": 2, "rx_bps": 800, "tx_bps": 1600},
        "lo": {"rx_bytes": 1, "rx_packets": 1, "tx_bytes": 1,
               "tx_packets": 1, "rx_bps": 0, "tx_bps": 0}
    }
}).encode("utf-8")
def fake_bpf_server():
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(unix_path)
        server.listen(1)
        server.settimeout(2)
        bpf_ready.set()
        conn, _ = server.accept()
        with conn:
            conn.recv(4096)
            conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: "
                         + str(len(body)).encode("ascii") + b"\r\n\r\n" + body)
bpf_ready = threading.Event()
def run_fake_bpf_server():
    fake_bpf_server()
bpf_thread = threading.Thread(target=run_fake_bpf_server, daemon=True)
bpf_thread.start()
bpf_ready.wait(1)
bpf_snap = BpfTrafficClient(unix_path, timeout=1).snapshot("eth0")
check("bpf.source", "bpf", bpf_snap["source"])
check("bpf.iface_filter", {"eth0"}, set(bpf_snap["interfaces"]))
check("bpf.rates", (800, 1600), (bpf_snap["interfaces"]["eth0"]["rx_bps"],
                                  bpf_snap["interfaces"]["eth0"]["tx_bps"]))
bpf_thread.join(timeout=1)

print()
print(f"RESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
