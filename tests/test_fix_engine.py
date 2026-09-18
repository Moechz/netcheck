"""M4 tests: helper dispatch (backup/rollback/rate-limit/M1 sequence) + FixEngine."""
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from netcheck.fix.engine import FixEngine
from netcheck.fix.actions import ParamError, validate
import netcheck.fix.engine as fix_engine_module
from netcheck.helper.network_template import render_net_apply, syntax_check
from netcheck.helper.server import HelperServer

PASS = FAIL = 0


def check(name, expected, actual):
    global PASS, FAIL
    if expected == actual:
        PASS += 1; print(f"PASS {name}")
    else:
        FAIL += 1; print(f"FAIL {name}: expected={expected!r} got={actual!r}")


# ---------- template & syntax ----------
content = render_net_apply("eth0", "static", ipv4="192.168.1.10", prefix=24,
                           gateway="192.168.1.1", dns=["223.5.5.5"], mtu=1500)
check("tpl.has_match", True, "[Match]" in content and "Name=eth0" in content)
check("tpl.has_route", True, "Gateway=192.168.1.1" in content)
check("tpl.syntax_ok", [], syntax_check(content))
bad = content + "\n[Evil]\nExec=/bin/sh -c id\n"
check("tpl.syntax_rejects_section", True, any("unknown section" in e for e in syntax_check(bad)))
injected = render_net_apply("eth0", "static", ipv4="1.2.3.4\n[Match]", prefix=24)
check("tpl.syntax_rejects_newline", True, bool(syntax_check(injected)))

# ---------- helper dispatch with fake exec ----------
tmp = tempfile.mkdtemp(prefix="nc-helper-test-")
netdir = os.path.join(tmp, "network"); os.makedirs(netdir)
backups = os.path.join(tmp, "backups"); os.makedirs(backups)
audit_log = os.path.join(tmp, "helper-audit.log")
# pre-existing config to back up
orig = "[Match]\nName=eth0\n\n[Network]\nDHCP=no\nAddress=10.0.0.9/24\n"
open(os.path.join(netdir, "10-eth0.network"), "w").write(orig)

exec_calls = []
def fake_exec(argv, timeout=30.0):
    exec_calls.append(argv)
    return 0, ""
def failing_reload_exec(argv, timeout=30.0):
    exec_calls.append(argv)
    if "reload" in argv or "reconfigure" in argv:
        return 1, "simulated failure"
    return 0, ""

srv = HelperServer(netcheck_uid=-1, network_dir=netdir, backups_dir=backups,
                   audit_path=audit_log, exec_fn=fake_exec)

# 1) argv action success (mtu-set)
r = srv.dispatch("mtu-set", {"iface": "eth0", "mtu": 1500})
check("helper.mtu.ok", (True, 0), (r["ok"], r["rc"]))

# 2) injection rejected + audited
r = srv.dispatch("mtu-set", {"iface": "eth0; reboot", "mtu": 1500})
check("helper.inject.rejected", (False, 1002), (r["ok"], r["rc"]))

# 3) rate limit: same action within 30s
r = srv.dispatch("mtu-set", {"iface": "eth0", "mtu": 1500})
check("helper.rate_limited", (False, 1003), (r["ok"], r["rc"]))

# 4) net-apply success: backup + M1 sequence (reload THEN reconfigure)
srv2 = HelperServer(netcheck_uid=-1, network_dir=netdir, backups_dir=backups,
                    audit_path=audit_log, exec_fn=fake_exec)
r = srv2.dispatch("net-apply", {"iface": "eth0", "mode": "static",
                                "ipv4": "192.168.1.10", "prefix": 24,
                                "gateway": "192.168.1.1", "dns": ["223.5.5.5"]})
check("helper.netapply.ok", True, r["ok"])
new_content = open(os.path.join(netdir, "10-eth0.network")).read()
check("helper.netapply.content", True, "Address=192.168.1.10/24" in new_content)
reload_idx = next(i for i, a in enumerate(exec_calls) if a[1:2] == ["reload"])
reconf_idx = next(i for i, a in enumerate(exec_calls) if a[1:2] == ["reconfigure"])
check("helper.netapply.m1_sequence", True, reload_idx < reconf_idx)
backups_made = [d for d in os.listdir(backups) if d.startswith("net-apply-")]
check("helper.netapply.backup", True, bool(backups_made))

# 5) rollback on reload failure (original file restored)
srv3 = HelperServer(netcheck_uid=-1, network_dir=netdir, backups_dir=backups,
                    audit_path=audit_log, exec_fn=failing_reload_exec)
r = srv3.dispatch("net-apply", {"iface": "eth0", "mode": "dhcp"})
check("helper.netapply.reload_fail", False, r["ok"])
after = open(os.path.join(netdir, "10-eth0.network")).read()
check("helper.netapply.rolled_back", True, "Address=192.168.1.10/24" in after or "10.0.0.9" in after)

# targeted DNS/Gateway edits preserve unrelated TOS networkd keys
target_file = os.path.join(netdir, "10-target.network")
open(target_file, "w").write(
    "[Match]\nMACAddress=02:00:00:00:00:01\n\n[Network]\nDHCP=ipv6\n"
    "Address=192.168.1.10/24\nDNS=192.0.2.53\n\n[Route]\n"
    "Destination=0.0.0.0/0\nGateway=192.168.1.254\nMetric=100\n\n"
)
target_cases = (
    ("dns-set", {"iface": "target", "dns": ["223.5.5.5", "119.29.29.29"]},
     "DNS", "223.5.5.5 119.29.29.29"),
    ("gateway-set", {"iface": "target", "gateway": "192.168.1.1",
                     "ipv4": "192.168.1.10", "prefix": 24},
     "Gateway", "192.168.1.1"),
)
for action, params, key, value in target_cases:
    srv_target = HelperServer(netcheck_uid=-1, network_dir=netdir,
                               backups_dir=backups, audit_path=audit_log,
                               exec_fn=fake_exec)
    result = srv_target.dispatch(action, params)
    content = open(target_file).read()
    check(f"helper.{action}.ok", True, result["ok"])
    check(f"helper.{action}.value", True, f"{key}={value}" in content)
    check(f"helper.{action}.preserves", True,
          "MACAddress=02:00:00:00:00:01" in content and "Metric=100" in content)
    check(f"helper.{action}.preserves_tail", True, content.endswith("\n\n"))
    check(f"helper.{action}.backup", True,
          any(name.startswith(action) for name in os.listdir(backups)))

# 6) audit entries written
audit_lines = [json.loads(l) for l in open(audit_log)]
check("helper.audit.count", True, len(audit_lines) >= 6)
check("helper.audit.param_reject", True,
      any(e.get("reason") == "param_reject" for e in audit_lines))
check("helper.audit.no_token", True,
      not any("token_hex" in json.dumps(e) for e in audit_lines))

# ---------- FixEngine ----------
try:
    validate("gateway-set", {"iface": "eth0", "gateway": "192.168.1.1",
                             "ipv4": "192.168.1.10", "prefix": 24})
    valid_gateway = True
except ParamError:
    valid_gateway = False
check("fix.gateway.params_valid", True, valid_gateway)
try:
    validate("gateway-set", {"iface": "eth0", "gateway": "10.0.0.1",
                             "ipv4": "192.168.1.10", "prefix": 24})
    cross_subnet = ""
except ParamError as exc:
    cross_subnet = str(exc)
check("fix.gateway.cross_subnet_rejected", True, "same subnet" in cross_subnet)
try:
    validate("dns-set", {"iface": "eth0", "dns": []})
    empty_dns = ""
except ParamError as exc:
    empty_dns = str(exc)
check("fix.dns.empty_rejected", True, "1-3" in empty_dns)

class FakeConfig:
    def __init__(self, mode): self.mode = mode
    def get(self, key, default=None):
        return self.mode if key == "repair.mode" else default

class FakeHelper:
    def __init__(self, ok=True): self.ok = ok; self.calls = []
    def call(self, action, params):
        self.calls.append((action, params))
        return {"ok": self.ok, "rc": 0 if self.ok else 1, "stdout": "done"}

hist = os.path.join(tmp, "fix-history.json")
engine = FixEngine(FakeConfig("guide"), history_path=hist)
out = engine.fix("link-state", "fix-link", {}, confirm=True)
check("fix.guide.text", True, out["mode"] == "guide" and bool(out["guide"]))
out = engine.fix("tnas-online", "fix-tunnel", {}, confirm=True)
check("fix.tunnel.guidance", True,
      out["mode"] == "guide" and "TNAS.online" in "".join(out["guide"]))
check("fix.no_physical_autofix", 1002,
      engine.fix("link-state", "", {}, confirm=True)["code"])
check("fix.gateway.action_mapping", "gateway-set",
      fix_engine_module.CHECK_TO_ACTION["gateway-reach"])
check("fix.dns.action_mapping", "dns-set",
      fix_engine_module.CHECK_TO_ACTION["dns-reachable"])

mapping_engine = FixEngine(FakeConfig("helper"), helper=FakeHelper(ok=True),
                           history_path=hist)
out = mapping_engine.fix("gateway-reach", "fix-gateway",
                         {"iface": "eth0", "gateway": "192.168.1.1",
                          "ipv4": "192.168.1.10", "prefix": 24}, True)
check("fix.gateway.helper_ok", 0, out["code"])

failed_engine = FixEngine(FakeConfig("helper"), helper=FakeHelper(ok=True),
                          history_path=hist, run_check_fn=lambda cid: "fail")
out = failed_engine.fix("dns-reachable", "fix-dns",
                        {"iface": "eth0", "dns": ["223.5.5.5"]}, True)
check("fix.verification_failure_is_error",
      (3002, "verification failed after repair"), (out["code"], out.get("message")))

ntp_pending_engine = FixEngine(FakeConfig("helper"), helper=FakeHelper(ok=True),
                               history_path=hist,
                               run_check_fn=lambda cid: "fail")
out = ntp_pending_engine.fix("ntp-server", "fix-time",
                             {"unit": "ntp.service"}, True)
check("fix.ntp_pending_not_failed",
      (0, {"ntp-server": "pending"},
       "ntp service restarted; synchronization is pending"),
      (out["code"], out.get("verified"), out.get("message")))
check("fix.ntp_pending_history", True,
      ntp_pending_engine.history()[-1].get("verified_pending") is True)

# M3 device findings: ipv6 action mapping / net-reload iface / precheck na /
# verify accepting warn|na / ipv6 verify failure is a real 3002 (never pending)
check("fix.ipv6_default_route.action_mapping", "net-reload",
      fix_engine_module.CHECK_TO_ACTION["ipv6-default-route"])
check("fix.ipv6_global_addr.action_mapping", "net-reload",
      fix_engine_module.CHECK_TO_ACTION["ipv6-global-addr"])
check("fix.net_reload_iface_ok", {"iface": "eth0"},
      validate("net-reload", {"iface": "eth0"}))
check("fix.net_reload_no_params_ok", {}, validate("net-reload", {}))
try:
    validate("net-reload", {"mode": "dhcp"})
    check("fix.net_reload_rejects_extra", False, True)
except ParamError:
    check("fix.net_reload_rejects_extra", True, True)
na_engine = FixEngine(FakeConfig("helper"), helper=FakeHelper(ok=True),
                      history_path=hist, run_check_fn=lambda cid: "na")
check("fix.precheck_na_skips", 2002,
      na_engine.fix("ntp-server", "fix-time",
                    {"unit": "ntp.service"}, True)["code"])
warn_engine = FixEngine(FakeConfig("helper"), helper=FakeHelper(ok=True),
                        history_path=hist, run_check_fn=lambda cid: "warn")
check("fix.verify_warn_ok", 0,
      warn_engine.fix("dns-reachable", "fix-dns",
                      {"iface": "eth0", "dns": ["223.5.5.5"]}, True)["code"])
v6fail_engine = FixEngine(FakeConfig("helper"), helper=FakeHelper(ok=True),
                          history_path=hist, run_check_fn=lambda cid: "fail")
v6out = v6fail_engine.fix("ipv6-global-addr", "fix-ipv6", {"iface": "eth0"}, True)
check("fix.ipv6_verify_fail_is_3002", (3002, False),
      (v6out["code"], v6out.get("verified_pending") or False))

helper = FakeHelper(ok=True)
calls = {"n": 0}
def fake_check(cid):
    # first link-speed call = precheck (fail); after the fix it passes
    if cid == "link-speed":
        calls["n"] += 1
        return "fail" if calls["n"] == 1 else "pass"
    return "pass"
engine2 = FixEngine(FakeConfig("helper"), helper=helper, history_path=hist,
                    run_check_fn=fake_check)
out = engine2.fix("link-speed", "fix-link", {"iface": "eth0", "direction": "up"},
                  True, {"req_id": "req-unit-test", "actor": "admin"})
check("fix.helper.ok", 0, out["code"])
check("fix.helper.action", ("link-toggle", "eth0"), (helper.calls[0][0], helper.calls[0][1]["iface"]))
check("fix.helper.verified", "pass", out["verified"]["link-speed"])
# 4 original + dns(warn) + ipv6(3002) appended by the M3 block above;
# the precheck-na path returns early and records no history entry
check("fix.history.recorded", 6, len(engine2.history()))
check("fix.process_log_events",
      ["repair.request", "repair.precheck", "repair.execute", "repair.verify"],
      [item["event"] for item in engine2.history()[-1].get("log", [])])
check("fix.process_log_result", (True, 0, "done"),
      (engine2.history()[-1]["log"][2]["ok"],
       engine2.history()[-1]["log"][2]["rc"],
       engine2.history()[-1]["log"][2]["stdout"]))
check("fix.process_context", ("req-unit-test", "admin", "req-unit-test", "admin"),
      (engine2.history()[-1].get("req_id"), engine2.history()[-1].get("operator"),
       engine2.history()[-1]["log"][0].get("req_id"),
       engine2.history()[-1]["log"][0].get("operator")))

# precheck: check passes -> 2002
engine3 = FixEngine(FakeConfig("helper"), helper=FakeHelper(), history_path=hist,
                    run_check_fn=lambda cid: "pass")
out = engine3.fix("link-speed", "fix-link", {"iface": "eth0", "direction": "up"}, True)
check("fix.precheck.2002", 2002, out["code"])

# confirm missing -> 1002
check("fix.no_confirm", 1002, engine2.fix("link-speed", "fix-link", {}, False)["code"])

print()
print(f"RESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
