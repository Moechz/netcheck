"""Diagnosis engine tests: checker three-branch cases, score, full run."""
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from netcheck.diag.engine import BaseChecker, registry, run_diag
from netcheck.diag.report import build_report, compute_score, level

PASS = FAIL = 0


def check(name, expected, actual):
    global PASS, FAIL
    if expected == actual:
        PASS += 1; print(f"PASS {name}")
    else:
        FAIL += 1; print(f"FAIL {name}: expected={expected!r} got={actual!r}")


class FakeResult:
    def __init__(self, rc=0, stdout=""):
        self.rc, self.stdout, self.stderr, self.elapsed_ms = rc, stdout, "", 0


def make_probe(mapping, default=None):
    """probe(argv, timeout) -> FakeResult; matches on first element / substrings."""
    def probe(argv, timeout=5.0):
        key = " ".join(argv)
        for pat, res in mapping.items():
            if pat in key:
                return FakeResult(*res) if isinstance(res, tuple) else FakeResult(res)
        return FakeResult(*(default or (0, "")))
    return probe


NICS_OK = {  # healthy OVS device snapshot (schema per collector)
    "arch": "ovs", "interfaces": [
        {"name": "ovs_eth0", "index": 3, "type": "ovs_internal", "operstate": "up",
         "carrier": True, "mac": "6c:bf:b5:04:b3:82", "mtu": 1500,
         "speed_mbps": None, "duplex": None, "driver": "openvswitch",
         "ipv4": [{"addr": "192.168.124.55", "prefix": 24, "scope": "global"}],
         "ipv6": [{"addr": "240e:3bb::4de", "prefix": 128, "scope": "global",
                   "origin": "slaac", "dynamic": True}],
         "gateway": "192.168.124.1", "mode": "static", "phys": "eth0",
         "rx_errors": 0, "tx_dropped": 0, "is_primary": True},
        {"name": "eth0", "index": 2, "type": "physical", "operstate": "up",
         "carrier": True, "mac": "6c:bf:b5:04:b3:82", "mtu": 1500,
         "speed_mbps": 2500, "duplex": "full", "driver": "r8125",
         "ipv4": [], "ipv6": [], "gateway": None, "mode": "none",
         "rx_errors": 0, "tx_dropped": 0, "is_primary": False},
    ],
    "_routes4": {"ovs_eth0": [{"gateway": "192.168.124.1", "proto": "static", "metric": 1024}]},
    "_routes6": {"ovs_eth0": [{"gateway": "fe80::1", "proto": "ra", "metric": 1024}]},
}

CFG = {"timeout_sec": 2, "dns_probe_domain": "www.baidu.com",
       "ping_public_ips": ["223.5.5.5"],
       "public_probe_urls": ["https://www.baidu.com"]}

# ---------- individual checker three-branch cases ----------
reg = registry()

def eval_checker(cid, nics, probe=None):
    cls = reg[cid]
    checker = cls({"cfg": CFG, "nics": nics, "probe": probe or make_probe({})})
    return checker.evaluate(checker.collect())

def eval_checker_cfg(cid, nics, cfg, probe=None):
    cls = reg[cid]
    checker = cls({"cfg": cfg, "nics": nics, "probe": probe or make_probe({})})
    return checker.evaluate(checker.collect())

# A: link-state normal / fail / na
check("A.link_state.pass", "pass", eval_checker("link-state", NICS_OK).status)
nics_down = dict(NICS_OK, interfaces=[dict(i) for i in NICS_OK["interfaces"]])
nics_down["interfaces"][1]["operstate"] = "down"
link_state_down = eval_checker("link-state", nics_down)
check("A.link_state.unplugged_informational", ("pass", None),
      (link_state_down.status, link_state_down.fixable))
check("A.link_state.unplugged_visible", True,
      "0 up, 1 down (eth0=down)" == link_state_down.detail["actual"])
check("A.link_state.na", "na", eval_checker("link-state", {"arch": "direct", "interfaces": []}).status)

# A: a down physical port has no duplex; it must not create a second fault
nics_spare_down = dict(NICS_OK, interfaces=[dict(i) for i in NICS_OK["interfaces"]] + [{
    "name": "eth1", "index": 4, "type": "physical", "operstate": "down",
    "carrier": False, "duplex": None, "speed_mbps": None,
}])
duplex_with_down = eval_checker("link-duplex", nics_spare_down)
check("A.link_duplex.ignores_down_port", ("pass", None), (duplex_with_down.status, duplex_with_down.fixable))
check("A.link_duplex.down_reason_deferred", True,
      "link-state" in duplex_with_down.detail["reason"])
check("A.link_duplex.all_down_na", "na", eval_checker("link-duplex", nics_down).status)
nics_duplex_unknown = dict(NICS_OK, interfaces=[dict(i) for i in NICS_OK["interfaces"]])
nics_duplex_unknown["interfaces"][1]["duplex"] = None
duplex_unknown = eval_checker("link-duplex", nics_duplex_unknown)
check("A.link_duplex.active_unknown_warn", ("warn", None),
      (duplex_unknown.status, duplex_unknown.fixable))

# A: link-speed degraded warn
nics_slow = dict(NICS_OK, interfaces=[dict(i) for i in NICS_OK["interfaces"]])
nics_slow["interfaces"][1]["speed_mbps"] = 100
check("A.link_speed.warn", "warn", eval_checker("link-speed", nics_slow).status)
check("A.link_speed.pass", "pass", eval_checker("link-speed", NICS_OK).status)
check("A.link_duplex.pass", "pass", eval_checker("link-duplex", NICS_OK).status)

# I: smb-multichannel disabled is a neutral configuration state -> na, not pass
nics_mc = dict(NICS_OK, interfaces=[dict(i) for i in NICS_OK["interfaces"]] + [{
    "name": "eth1", "index": 4, "type": "physical", "operstate": "up",
    "carrier": True, "duplex": "full", "speed_mbps": 2500,
}])
probe_mc = make_probe({"testparm": (0, "Loaded services file.\nserver multi channel support = No\n")})
mc_disabled = eval_checker("smb-multichannel", nics_mc, probe=probe_mc)
check("I.smb_multichannel.disabled_informational", ("na", None),
      (mc_disabled.status, mc_disabled.fixable))
check("I.smb_multichannel.disabled_not_green", True,
      "disabled" in mc_disabled.detail["reason"])
probe_mc_on = make_probe({"testparm": (0, "server multi channel support = Yes\n")})
mc_on = eval_checker("smb-multichannel", nics_mc, probe=probe_mc_on)
check("I.smb_multichannel.enabled_pass", "pass", mc_on.status)
probe_mc_default = make_probe({"testparm": (0, "Loaded services file.\n")})
mc_default = eval_checker("smb-multichannel", nics_mc, probe=probe_mc_default)
check("I.smb_multichannel.samba_default_pass", "pass", mc_default.status)

# B: ipv4-addr normal / apipa fail / na
check("B.ipv4_addr.pass", "pass", eval_checker("ipv4-addr", NICS_OK).status)
nics_apipa = dict(NICS_OK, interfaces=[dict(i) for i in NICS_OK["interfaces"]])
nics_apipa["interfaces"][0]["ipv4"] = [{"addr": "169.254.1.5", "prefix": 16, "scope": "global"}]
res = eval_checker("ipv4-addr", nics_apipa)
check("B.ipv4_addr.apipa", ("fail", True), (res.status, "apipa" in res.detail["reason"]))

# B: gateway-subnet pass/cross-subnet
check("B.gateway_subnet.pass", "pass", eval_checker("gateway-subnet", NICS_OK).status)
nics_gw = dict(NICS_OK, interfaces=[dict(i) for i in NICS_OK["interfaces"]])
nics_gw["interfaces"][0]["gateway"] = "10.0.0.1"
check("B.gateway_subnet.fail", "fail", eval_checker("gateway-subnet", nics_gw).status)

# B: gateway-reach pass (loss 0) / fail (100 + no ARP)
probe_gw_ok = make_probe({"ping -c": (0, "2 packets transmitted, 2 received")})
probe_gw_bad = make_probe({"ping -c": (1, "2 packets transmitted, 0 received"),
                           "ip neigh": (0, "")})
check("B.gateway_reach.pass", "pass", eval_checker("gateway-reach", NICS_OK, probe_gw_ok).status)
check("B.gateway_reach.fail", "fail", eval_checker("gateway-reach", NICS_OK, probe_gw_bad).status)

# B: ip-conflict non-root degradation -> pass heuristic (device-verified path)
probe_conflict = make_probe({"arping": (1, "arping: socket: Operation not permitted"),
                             "ip neigh": (0, "192.168.124.1 dev ovs_eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE")})
res = eval_checker("ip-conflict", NICS_OK, probe_conflict)
check("B.ip_conflict.degraded_pass", ("pass", True),
      (res.status, "non-authoritative" in res.detail["actual"]))

# B: ip-conflict arping ran but unusable (e.g. transient send error) -> na, no fix button
probe_unusable = make_probe({"arping": (1, "arping: sendto: Network is unreachable"),
                             "ip neigh": (0, "")})
res = eval_checker("ip-conflict", NICS_OK, probe_unusable)
check("B.ip_conflict.probe_unusable_na", ("na", "probe_unavailable"),
      (res.status, res.detail["reason"].split(":", 1)[0]))

# C: default-route pass / missing fail / conflict fail
check("C.default_route.pass", "pass", eval_checker("default-route", NICS_OK).status)
check("C.default_route.missing", "fail",
      eval_checker("default-route", {"arch": "ovs", "interfaces": NICS_OK["interfaces"], "_routes4": {}}).status)
routes_conflict = {"ovs_eth0": [{"gateway": "192.168.124.1", "metric": 1024}],
                   "eth1": [{"gateway": "10.0.0.1", "metric": 100}]}
check("C.default_route.conflict", "fail",
      eval_checker("default-route", dict(NICS_OK, _routes4=routes_conflict)).status)

# F: wan-tcp classification (dns_failure exit 6 -> fix-dns)
probe_dns_fail = make_probe({"curl": (6, "")})
res = eval_checker("wan-tcp", NICS_OK, probe_dns_fail)
check("F.wan_tcp.dns_failure", ("fail", "fix-dns"), (res.status, res.fixable))
probe_http_ok = make_probe({"curl": (0, "200")})
check("F.wan_tcp.pass", "pass", eval_checker("wan-tcp", NICS_OK, probe_http_ok).status)

# F: TOS firewall state is authoritative, while proxy state is reported separately
probe_fw_on = make_probe({"tos firewall": (0, "PROPERTY         VALUE\nFirewall Status  enabled\n")})
cfg_proxy_disabled = dict(CFG, _tos_services={
    "available": True, "tnas_online": {}, "ddns": {"records": []},
    "proxy": {"enabled": False},
})
with patch.dict(os.environ, {}, clear=True):
    fw_on = eval_checker_cfg("proxy-firewall", NICS_OK,
                             cfg_proxy_disabled, probe_fw_on)
check("F.proxy_firewall.enabled_pass",
      ("pass", "firewall enabled; no proxy in environment or TOS settings"),
      (fw_on.status, fw_on.detail["actual"]))
cfg_tos_proxy = dict(CFG, _tos_services={
    "available": True, "tnas_online": {}, "ddns": {"records": []},
    "proxy": {"enabled": True, "server": "203.0.113.10", "port": 7890},
})
with patch.dict(os.environ, {}, clear=True):
    tos_proxy = eval_checker_cfg("proxy-firewall", NICS_OK,
                                 cfg_tos_proxy, probe_fw_on)
check("F.proxy_firewall.tos_proxy_warn", ("warn", "TOS proxy configured"),
      (tos_proxy.status, tos_proxy.detail["actual"].split("; ")[1]))
probe_proxy_dead = make_probe({"tos firewall": (0, "PROPERTY         VALUE\nFirewall Status  enabled\n"),
                               "curl": (28, "")})
with patch.dict(os.environ, {}, clear=True):
    dead_tos_proxy = eval_checker_cfg("proxy-firewall", NICS_OK,
                                      cfg_tos_proxy, probe_proxy_dead)
check("F.proxy_firewall.dead_tos_proxy", ("fail", "TOS:default"),
      (dead_tos_proxy.status, dead_tos_proxy.detail["actual"]))
with patch.dict(os.environ, {}, clear=True):
    proxy_state_unknown = eval_checker("proxy-firewall", NICS_OK, probe_fw_on)
check("F.proxy_firewall.state_unavailable", "na", proxy_state_unknown.status)
probe_fw_off = make_probe({"tos firewall": (0, "PROPERTY         VALUE\nFirewall Status  disabled\n")})
with patch.dict(os.environ, {}, clear=True):
    fw_off = eval_checker_cfg("proxy-firewall", NICS_OK,
                               cfg_proxy_disabled, probe_fw_off)
check("F.proxy_firewall.disabled_warn", ("warn", "firewall_disabled"),
      (fw_off.status, fw_off.detail["reason"].split(":")[0]))
with patch.dict(os.environ, {"https_proxy": "http://127.0.0.1:9"}, clear=False):
    bad_proxy = eval_checker("proxy-firewall", NICS_OK, probe_fw_on)
check("F.proxy_firewall.reachable_env_proxy", ("warn", "1 environment variable(s)"),
      (bad_proxy.status, bad_proxy.detail["actual"].split("; ")[1]))
with patch.dict(os.environ, {"https_proxy": "http://127.0.0.1:9"}, clear=False):
    dead_env_proxy = eval_checker("proxy-firewall", NICS_OK, probe_proxy_dead)
check("F.proxy_firewall.dead_env_proxy", ("fail", "environment:https_proxy"),
      (dead_env_proxy.status, dead_env_proxy.detail["actual"]))

# G: a manually raised non-standard primary MTU is visible even when the path passes
probe_mtu_ok = make_probe({"ping -M do": (0, "1 received")})
check("G.mtu.standard_pass", "pass",
      eval_checker("mtu-probe", NICS_OK, probe_mtu_ok).status)
nics_mtu_2500 = dict(NICS_OK, interfaces=[dict(i) for i in NICS_OK["interfaces"]])
nics_mtu_2500["interfaces"][0]["mtu"] = 2500
mtu_2500 = eval_checker("mtu-probe", nics_mtu_2500, probe_mtu_ok)
check("G.mtu.jumbo_default_pass", ("pass", "runtime MTU 2500; no expected MTU policy"),
      (mtu_2500.status, mtu_2500.detail["reason"]))
cfg_mtu_expected_1500 = dict(CFG, expected_mtu=1500)
mtu_policy_mismatch = eval_checker_cfg("mtu-probe", nics_mtu_2500,
                                       cfg_mtu_expected_1500, probe_mtu_ok)
check("G.mtu.explicit_policy_mismatch_warn", ("warn", "mtu_policy_mismatch"),
      (mtu_policy_mismatch.status,
       mtu_policy_mismatch.detail["reason"].split(":")[0]))
cfg_mtu_2500 = dict(CFG, expected_mtu=2500)
mtu_expected = eval_checker_cfg("mtu-probe", nics_mtu_2500,
                                cfg_mtu_2500, probe_mtu_ok)
check("G.mtu.expected_override_pass", "pass", mtu_expected.status)

# H: ntp-server pass / na
probe_ntp = make_probe({"systemctl is-active ntp": (0, "active"),
                        "ntpq": (0, "     remote ... \n*139.199.1.1  2u  ...")})
check("H.ntp.pass", "pass", eval_checker("ntp-server", NICS_OK, probe_ntp).status)
probe_ntp_off = make_probe({"systemctl is-active ntp": (3, "inactive")})
check("H.ntp.na", "na", eval_checker("ntp-server", NICS_OK, probe_ntp_off).status)
# H: ntp active with reachable candidates but no selection -> warn, not fail
# (M3 device finding: far/jittery upstream peers make ntpd flap sync)
probe_ntp_pending = make_probe({"systemctl is-active ntp": (0, "active"),
    "ntpq": (0, "     remote           refid      st t when poll reach\n"
               "================================================\n"
               " 139.199.1.1     10.0.0.2        3 u   64   64  376   20ms    1ms   2ms")})
check("H.ntp.sync_pending_warn", "warn",
      eval_checker("ntp-server", NICS_OK, probe_ntp_pending).status)
probe_ntp_isolated = make_probe({"systemctl is-active ntp": (0, "active"),
    "ntpq": (0, "     remote           refid      st t when poll reach\n"
               "================================================\n"
               " LOCAL(0)        .LOCL.          5 l   87   64    0")})
check("H.ntp.isolated_fail", "fail",
      eval_checker("ntp-server", NICS_OK, probe_ntp_isolated).status)

# H: TNAS.online disabled / enabled-but-down / enabled-and-connected
NICS_TNAS = dict(NICS_OK, interfaces=NICS_OK["interfaces"] + [{
    "name": "tnas0", "index": 8, "type": "tunnel", "operstate": "up",
    "ipv4": [{"addr": "100.82.124.2", "prefix": 22, "scope": "global"}],
    "ipv6": [], "is_primary": False,
}])
check("H.tnas_online.disabled", "na", eval_checker("tnas-online", NICS_OK).status)
nics_tnas_down = dict(NICS_TNAS, interfaces=[dict(i) for i in NICS_TNAS["interfaces"]])
nics_tnas_down["interfaces"][-1]["operstate"] = "down"
check("H.tnas_online.down", ("fail", "enabled · disconnected"),
      (eval_checker("tnas-online", nics_tnas_down).status,
       eval_checker("tnas-online", nics_tnas_down).detail["actual"]))
cfg_tnas_enabled = dict(CFG, _tos_services={
    "available": True,
    "tnas_online": {"code": 2, "connect_status": 2},
    "ddns": {"records": []},
})
tnas_api_ok = eval_checker_cfg("tnas-online", NICS_OK, cfg_tnas_enabled)
check("H.tnas_online.official_connected", ("pass", "enabled · connected"),
      (tnas_api_ok.status, tnas_api_ok.detail["actual"]))

cfg_tnas_connecting = dict(CFG, _tos_services={
    "available": True,
    "tnas_online": {"code": 1, "connect_status": 0},
    "ddns": {"records": []},
})
check("H.tnas_connecting.tunnel_down", "fail",
      eval_checker_cfg("tnas-online", nics_tnas_down,
                       cfg_tnas_connecting).status)

cfg_tnas_disabled = dict(CFG, _tos_services={
    "available": True,
    "tnas_online": {"code": 0, "connect_status": 0},
    "ddns": {"records": []},
})
check("H.tnas_online.official_disabled_stale_iface", "na",
      eval_checker_cfg("tnas-online", nics_tnas_down,
                       cfg_tnas_disabled).status)

probe_tnas_unreachable = make_probe({
    "ping -c": (0, "2 packets transmitted, 0 received"),
    "curl": (6, ""),
})
tnas_no_api = eval_checker("tnas-online", NICS_TNAS, probe_tnas_unreachable)
check("H.tnas_online.no_api_state_unknown", ("warn", "enabled · state unknown"),
      (tnas_no_api.status, tnas_no_api.detail["actual"]))

# H: DDNS official state records disabled / connected / update failed
cfg_ddns = lambda records: dict(CFG, _tos_services={
    "available": True,
    "tnas_online": {"code": 0, "status": 0},
    "ddns": {"records": records},
})
check("H.ddns.no_records", "na", eval_checker_cfg("ddns", NICS_OK, cfg_ddns([])).status)
check("H.ddns.all_disabled", "na", eval_checker_cfg(
    "ddns", NICS_OK, cfg_ddns([{"enabled": False}])).status)
check("H.ddns.connected", ("pass", "enabled · connected (1/1)"), (
    eval_checker_cfg("ddns", NICS_OK, cfg_ddns(
        [{"enabled": True, "last_update_result": "2032"}])).status,
    eval_checker_cfg("ddns", NICS_OK, cfg_ddns(
        [{"enabled": True, "last_update_result": "2032"}])).detail["actual"]))
check("H.ddns.update_failed", ("fail", "enabled · disconnected (0/1)"), (
    eval_checker_cfg("ddns", NICS_OK, cfg_ddns(
        [{"enabled": True, "last_update_result": ""}])).status,
    eval_checker_cfg("ddns", NICS_OK, cfg_ddns(
        [{"enabled": True, "last_update_result": ""}])).detail["actual"]))
check("H.ddns.status_unavailable", "na", eval_checker("ddns", NICS_OK).status)

# E: ipv6 gate -> whole group na without IPv6
nics_no_v6 = dict(NICS_OK, interfaces=[dict(NICS_OK["interfaces"][0]), dict(NICS_OK["interfaces"][1])])
nics_no_v6["interfaces"][0]["ipv6"] = []
check("E.gate.na_fn", True, bool(reg["ipv6-global-addr"].spec.na_fn({"nics": nics_no_v6})))

# E: ipv6 no-service -> na (M3 device finding: router provides no RA/DHCPv6,
# link-local-only host cannot obtain global config via any local repair)
nics_v6_llonly = dict(NICS_OK, _routes6={},
                      interfaces=[dict(i) for i in NICS_OK["interfaces"]])
nics_v6_llonly["interfaces"][0]["ipv6"] = [
    {"addr": "fe80::6ebf:b5ff:fe02:83ff", "prefix": 64, "scope": "link",
     "origin": "link", "dynamic": False}]
check("E.v6_global.no_service_na", "na",
      eval_checker("ipv6-global-addr", nics_v6_llonly).status)
check("E.v6_defroute.no_service_na", "na",
      eval_checker("ipv6-default-route", nics_v6_llonly).status)
check("E.v6_dns.no_service_na", "na",
      eval_checker("ipv6-dns", nics_v6_llonly).status)
# primary without any v6 stack (kernel disabled) while service exists -> fail
nics_v6_primary_disabled = dict(
    NICS_OK, interfaces=[dict(i) for i in NICS_OK["interfaces"]])
nics_v6_primary_disabled["interfaces"][0]["ipv6"] = []
check("E.v6_global.if_disabled_fail", "fail",
      eval_checker("ipv6-global-addr", nics_v6_primary_disabled).status)
# link-local only while the LAN does provide v6 (route present) -> fail
nics_v6_ll_with_service = dict(nics_v6_llonly, _routes6=NICS_OK["_routes6"])
check("E.v6_global.service_but_ll_fail", "fail",
      eval_checker("ipv6-global-addr", nics_v6_ll_with_service).status)

# I: bond gate -> na without bond
check("I.bond.na", "na", eval_checker("bond-lacp", NICS_OK).status)

# I: kernel bond (TOS control-panel form under the OVS bridge) - the collector
# classifies it as type=bond, but ovs-vsctl show has no "type: bond" for it
NICS_BOND = {"arch": "ovs", "interfaces": NICS_OK["interfaces"] + [
    {"name": "bond0", "index": 9, "type": "bond", "operstate": "up",
     "carrier": True, "mac": "6c:bf:b5:04:b3:82", "mtu": 1500,
     "speed_mbps": None, "duplex": None, "driver": "bonding",
     "ipv4": [], "ipv6": [], "gateway": None, "mode": "none",
     "rx_errors": 0, "tx_dropped": 0, "is_primary": False}],
    "_routes4": NICS_OK["_routes4"], "_routes6": NICS_OK["_routes6"]}

probe_bond_lacp = make_probe({
    "cat /proc/net/bonding/bond0": (0,
        "Ethernet Channel Bonding Driver: v6.2.0\n"
        "Bonding Mode: IEEE 802.3AD Dynamic link aggregation\n"
        "Slave Interface: eth1\nMII Status: up\n"),
})
res = eval_checker("bond-lacp", NICS_BOND, probe_bond_lacp)
check("I.bond.kernel_lacp_pass", ("pass", "bond0: 802.3AD (LACP)"),
      (res.status, res.detail["actual"]))

probe_bond_ab = make_probe({
    "cat /proc/net/bonding/bond0": (0,
        "Bonding Mode: adaptive load balancing\nSlave Interface: eth1\n"),
})
res = eval_checker("bond-lacp", NICS_BOND, probe_bond_ab)
check("I.bond.kernel_non_lacp_warn", ("warn", "bond_mode_not_lacp"),
      (res.status, res.detail["reason"]))

# I: OVS-native bond - lacp column set -> pass
probe_ovs_bond = make_probe({
    "ovs-vsctl show": (0, "Bridge ovsbr\n    Port bond0\n        Interface eth1\n            type: system\n"),
    "ovs-vsctl list port": (0, "name                : bond0\nbond_mode           : balance-tcp\nlacp                : active\n"),
    "cat /proc/net/bonding": (1, ""),
})
res = eval_checker("bond-lacp", NICS_BOND, probe_ovs_bond)
check("I.bond.ovs_lacp_pass", "pass", res.status)

# I: OVS bond_mode set but lacp empty -> warn
probe_ovs_slb = make_probe({
    "ovs-vsctl show": (0, "Bridge ovsbr\n    Port bond0\n        type: bond\n"),
    "ovs-vsctl list port": (0, "bond_mode           : balance-slb\nlacp                : []\n"),
    "cat /proc/net/bonding": (1, ""),
})
res = eval_checker("bond-lacp", NICS_BOND, probe_ovs_slb)
check("I.bond.ovs_no_lacp_warn", ("warn", "bond_mode_not_lacp"),
      (res.status, res.detail["reason"]))

# ---------- score computation ----------
def mk(id_, status):
    return {"id": id_, "group": id_[0].upper(), "status": status,
            "detail": {}, "fixable": None}
check("score.all_pass", 100, compute_score([mk(i, "pass") for i in reg]))
check("score.na_ignored", 100,
      compute_score([mk(i, "na") for i in reg]))
one_fail = [mk(i, "pass") for i in reg]
one_fail[0]["status"] = "fail"
s = compute_score(one_fail)
check("score.single_fail_ge_90", True, s >= 90)
all_fail = [mk(i, "fail") for i in reg]
check("score.all_fail", 0, compute_score(all_fail))
check("level.fault", "fault", level(50))
check("level.warning", "warning", level(80))
check("level.healthy", "healthy", level(95))

# ---------- full engine run with mocked probe ----------
probe_full = make_probe({
    "ping -c": (0, "2 packets transmitted, 2 received"),
    "curl": (0, "200"),
    "dig": (0, "1.2.3.4"),
    "getent hosts": (0, "1.2.3.4 www.baidu.com"),
    "resolvectl status": (0, "DNS Servers: 192.168.124.1"),
    "ip route show": (0, "192.168.124.0/24 dev ovs_eth0 proto kernel scope link"),
    "systemctl is-active ntp": (0, "active"),
    "ntpq": (0, "*139.199.1.1  2u  ..."),
    "arping": (1, "arping: socket: Operation not permitted"),
    "ip neigh": (0, "192.168.124.1 dev ovs_eth0 lladdr aa:bb REACHABLE"),
    "ss -s": (0, "TCP: 10"),
    "ss -ant": (0, ""),
    "ss -ltn": (0, "LISTEN 0 50 0.0.0.0:445"),
    "pgrep": (0, "1234"),
    "testparm": (1, ""),
    "ovs-vsctl show": (0, "no bridges"),
    "networkctl status": (0, "State: routable"),
    "ping -M do": (0, "1 received"),
    "curl -sI": (0, "date: x"),
    "ping -6": (0, "2 received"),
    "curl -6": (0, "200"),
})
results = run_diag(CFG, nics=NICS_OK, probe=probe_full)
report = build_report([r.to_dict() for r in results], "test-job", 0, 1234)
check("fullrun.total", 35, report["summary"]["total"])
check("fullrun.score_ge_90", True, report["score"] >= 90)
check("fullrun.groups", ["A", "B", "C", "D", "E", "F", "G", "H", "I"], sorted(report["groups"].keys()))
check("fullrun.group_a_first", "link-state", report["groups"]["A"][0]["id"])
check("fullrun.log_events", 35, len(report["log"]))

print()
print(f"RESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
