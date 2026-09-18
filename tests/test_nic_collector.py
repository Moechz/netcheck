"""Dual-architecture fixture tests for NicCollector (design section 12 cases 1-9,15-19)."""
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from netcheck.collectors.nic import (NicCollector, parse_ip_d_link, parse_ovs_vsctl_show,
                                     pair_internal_phys, parse_ethtool, parse_proc_net_dev,
                                     parse_network_text, derive_mode, sys_interface_names)

FIX = os.path.join(os.path.dirname(__file__), "fixtures")
PASS = FAIL = 0


def check(name, expected, actual):
    global PASS, FAIL
    if expected == actual:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name}: expected={expected!r} got={actual!r}")


def make_collector(device):
    """Collector wired to fixture outputs (no live commands)."""
    d = os.path.join(FIX, device)
    files = {f: open(os.path.join(d, f), encoding="utf-8").read() for f in os.listdir(d)}

    def fake_probe(argv, timeout=5.0):
        class R:
            def __init__(self, rc, stdout):
                self.rc, self.stdout, self.stderr, self.elapsed_ms = rc, stdout, "", 0
        key = argv[0] + ("_d" if argv[1:2] == ["-d"] else "")
        ethtool_key = "ethtool_" + argv[-1] + ".txt"
        if argv[0] == "ip" and "-d" in argv:
            return R(0, files["ip_d_link.txt"])
        if argv[0] == "ip" and "-4" in argv:
            return R(0, files["ip4_addr.txt"])
        if argv[0] == "ip" and "-6" in argv:
            return R(0, files["ip6_addr.txt"])
        if argv[0] == "ip":
            return R(0, files["ip_route.txt"])
        if argv[0] == "ovs-vsctl":
            return R(0, files["ovs_show.txt"])
        if argv[0] == "ethtool":
            return R(0, files.get(ethtool_key, "Link detected: no"))
        return R(127, "")

    def fake_read(path):
        if path == "/proc/net/dev":
            return files.get("proc_net_dev.txt", "")
        if path.endswith(".network"):
            base = os.path.basename(path)
            if base in files:
                return files[base]
            return ""
        # /sys/class/net/<if>/{operstate,carrier,mtu,address}
        parts = path.rstrip("/").split("/")
        if len(parts) >= 6 and parts[4] == "net":
            if parts[-1] == "operstate":
                link_states = dict(re.findall(r"^(\S+):.*?state (\S+)", files["ip_d_link.txt"], re.M))
                return ("down" if "NO-CARRIER" in files["ip_d_link.txt"].split(parts[4 - 2] + ":", 1)[1][:80]
                        else link_states.get(parts[5], "up"))
            if parts[-1] == "carrier":
                return "0" if "NO-CARRIER" in files["ip_d_link.txt"] else "1"
        return ""

    return NicCollector(probe=fake_probe, read=fake_read,
                        network_dir=os.path.join(d, "unused"))


def patch_glob(monkey_dir):
    """Point .network glob at the fixture dir."""
    import glob as g
    real_glob = g.glob
    d = monkey_dir
    def fake_glob(pat):
        if pat.endswith("*.network"):
            return [os.path.join(d, f) for f in os.listdir(d) if f.endswith(".network")]
        return real_glob(pat)
    import netcheck.collectors.nic as nic
    orig = nic.glob.glob
    nic.glob.glob = fake_glob
    return lambda: setattr(nic.glob, "glob", orig)


# ---------- parser unit tests ----------
with tempfile.TemporaryDirectory(prefix="nc-sys-class-test-") as sys_root:
    os.mkdir(os.path.join(sys_root, "eth0"))
    os.symlink("eth0", os.path.join(sys_root, "eth1"))
    open(os.path.join(sys_root, "bonding_masters"), "w").close()
    open(os.path.join(sys_root, "tm_ovs_bonds"), "w").close()
    check("parser.sys_names_real_netdevs_only", {"eth0", "eth1"},
          sys_interface_names(sys_root))

links = parse_ip_d_link(open(os.path.join(FIX, "device1/ip_d_link.txt")).read())
check("parser.link.count", 7, len(links))
check("parser.link.ovs_internal_flag", "internal", links["ovs_eth0"]["ovs_subtype"])
check("parser.link.master", "ovs-system", links["eth0"]["master"])

bridges = parse_ovs_vsctl_show(open(os.path.join(FIX, "device1/ovs_show.txt")).read())
check("parser.ovs.bridges", 2, len(bridges))
check("parser.ovs.pairing", {"ovs_eth0": "eth0", "ovs_eth1": "eth1"}, pair_internal_phys(bridges))

et = parse_ethtool(open(os.path.join(FIX, "device1/ethtool_eth0.txt")).read())
check("parser.ethtool", (2500, "full", True), (et["speed_mbps"], et["duplex"], et["link_detected"]))

dev = parse_proc_net_dev(open(os.path.join(FIX, "device1/proc_net_dev.txt")).read())
check("parser.procdev.ifaces", {"lo", "eth0", "ovs_eth0"}, set(dev))
check("parser.procdev.rx_bytes", 1234567890, dev["ovs_eth0"]["rx_bytes"])

sec = parse_network_text(open(os.path.join(FIX, "device1/10-eth0.network")).read())
check("parser.network.dhcp", ["ipv6"], sec["Network"]["DHCP"])
check("parser.network.addr", ["192.168.124.55/24"], sec["Network"]["Address"])
mi = derive_mode(sec["Network"])
check("parser.network.mode", ("static", "dhcp6"), (mi["mode"], mi["detail"]["v6"]))

# ---------- device 1 (OVS architecture) end-to-end ----------
restore = patch_glob(os.path.join(FIX, "device1"))
try:
    c1 = make_collector("device1")
    snap = c1.get(force=True)
    names = [i["name"] for i in snap["interfaces"]]
    check("dev1.arch", "ovs", snap["arch"])
    check("dev1.interfaces", ["ovs_eth0", "lo", "eth0", "eth1", "ovs_eth1", "docker0", "tnas0"], names)
    check("dev1.no_ovs_system", False, "ovs-system" in names)
    by = {i["name"]: i for i in snap["interfaces"]}
    check("dev1.primary", True, by["ovs_eth0"]["is_primary"])
    check("dev1.ovs_pair", "eth0", by["ovs_eth0"]["phys"])
    check("dev1.ovs_type", "ovs_internal", by["ovs_eth0"]["type"])
    check("dev1.ovs_speed_inherit", None, by["ovs_eth0"]["speed_mbps"])
    check("dev1.phys_speed", 2500, by["eth0"]["speed_mbps"])
    check("dev1.ip", "192.168.124.55", by["ovs_eth0"]["ipv4"][0]["addr"])
    check("dev1.gateway", "192.168.124.1", by["ovs_eth0"]["gateway"])
    check("dev1.mode", "static", by["ovs_eth0"]["mode"])
    check("dev1.v6_origin", "slaac", by["ovs_eth0"]["ipv6"][0]["origin"])
    check("dev1.eth1_down", "down", by["eth1"]["operstate"])
    check("dev1.tnas_type", "tunnel", by["tnas0"]["type"])
    check("dev1.docker_type", "docker", by["docker0"]["type"])
finally:
    restore()

# ---------- device 2 (direct architecture) ----------
restore = patch_glob(os.path.join(FIX, "device2"))
try:
    c2 = make_collector("device2")
    snap = c2.get(force=True)
    by = {i["name"]: i for i in snap["interfaces"]}
    check("dev2.arch", "direct", snap["arch"])
    check("dev2.no_ovs", False, any(n.startswith("ovs_") for n in by))
    check("dev2.primary", True, by["eth0"]["is_primary"])
    check("dev2.ip", "192.168.124.56", by["eth0"]["ipv4"][0]["addr"])
    check("dev2.mode", "static", by["eth0"]["mode"])
    check("dev2.speed", 2500, by["eth0"]["speed_mbps"])
finally:
    restore()

# ---------- cache behavior ----------
c = make_collector("device2")
c.get(force=True)
snap2 = c.get()  # within TTL -> same object
check("cache.hit", True, snap2 is c._cache)
c.invalidate()
check("cache.invalidated", None, c._cache)

print()
print(f"RESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
