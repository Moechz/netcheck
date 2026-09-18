"""Monitor tests: sampler storage/query, alert thresholds, throttle, webhook."""
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from netcheck.monitor.alerts import AlertEngine
from netcheck.monitor.sampler import LinkSampler

PASS = FAIL = 0


def check(name, expected, actual):
    global PASS, FAIL
    if expected == actual:
        PASS += 1; print(f"PASS {name}")
    else:
        FAIL += 1; print(f"FAIL {name}: expected={expected!r} got={actual!r}")


class FakeConfig:
    def __init__(self, data=None):
        self.data = data or {
            "monitor": {"thresholds": {"loss_pct": 10, "latency_ms": 500},
                        "retain_days": 30},
            "alerts": {"cooldown_min": 30, "channels": {"webhook": {"url": ""}}},
            "diag": {"ping_public_ips": ["223.5.5.5"]},
        }
    def get(self, key, default=None):
        node = self.data
        for part in key.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node


class FakeProbe:
    def __init__(self, loss=0, rtt=5):
        self.loss, self.rtt = loss, rtt
    def __call__(self, argv, timeout=5):
        class R:
            def __init__(self, rc, stdout):
                self.rc, self.stdout, self.stderr = rc, stdout, ""
        if argv[0] == "ip" and "route" in argv:
            return R(0, "default via 192.168.124.1 dev eth0\n192.168.124.0/24 dev eth0")
        if argv[0] == "ping":
            s = f"3 packets transmitted, {3 - int(3 * self.loss / 100)} received"
            s += f"\nrtt min/avg/max/mdev = {self.rtt}/{self.rtt}/{self.rtt}/0.5 ms"
            return R(0, s)
        return R(0, "")


# ---------- sampler ----------
tmp = tempfile.mkdtemp(prefix="nc-mon-")
cfg = FakeConfig()
s = LinkSampler(tmp, cfg, probe=FakeProbe(loss=0, rtt=5))
sample = s.sample()
check("sampler.gw_loss", 0.0, sample.get("gw_loss_pct"))
check("sampler.gw_rtt", 5.0, sample.get("gw_rtt_ms"))
check("sampler.loss_0", 0.0, sample.get("pub_loss_pct"))
check("sampler.rtt", 5.0, sample.get("pub_rtt_ms"))
check("sampler.persisted", 1, len(s.query(days=1)))

# Query must restore newest-first order after merging append-only daily shards.
multi_tmp = tempfile.mkdtemp(prefix="nc-mon-order-")
os.makedirs(os.path.join(multi_tmp, "trends"))
now = time.time()
with open(os.path.join(multi_tmp, "trends", "2026-08-01.json"), "w") as f:
    json.dump([{"ts": now - 5000}, {"ts": now - 3000}], f)
with open(os.path.join(multi_tmp, "trends", "2026-08-02.json"), "w") as f:
    json.dump([{"ts": now - 4000}, {"ts": now}], f)
s3 = LinkSampler(multi_tmp, cfg, probe=FakeProbe())
check("sampler.query_newest_first_desc", True,
      all(a["ts"] >= b["ts"] for a, b in zip(s3.query(days=1), s3.query(days=1)[1:])))
check("sampler.query_first_is_newest", now, s3.query(days=1)[0]["ts"])
s3.start()
check("sampler.start_running", True, s3.is_running())
s3.stop()
check("sampler.stop_not_running", False, s3.is_running())

# high-loss sample
s2 = LinkSampler(tmp, cfg, probe=FakeProbe(loss=100, rtt=600))
sample2 = s2.sample()
check("sampler.high_loss", 100.0, sample2.get("gw_loss_pct"))
check("sampler.high_rtt", 600.0, sample2.get("gw_rtt_ms"))

# ---------- alerts ----------
notifications = []
engine = AlertEngine(tmp, FakeConfig(), notify_fn=lambda a: notifications.append(a))
fired = engine.evaluate(sample2)
check("alert.count", 4, len(fired))
check("alert.gw_loss", "gateway_loss", fired[0]["event"])
check("alert.gw_latency", True, "gateway_latency" in [f["event"] for f in fired])
check("alert.notified", 4, len(notifications))

# throttle: same event within cooldown is suppressed
fired2 = engine.evaluate(sample2)
check("alert.throttled", 0, len(fired2))
check("alert.history", 4, len(engine.history(days=1)))

# no alerts on healthy sample
fired3 = engine.evaluate(sample)
check("alert.healthy_none", 0, len(fired3))

print()
print(f"RESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
