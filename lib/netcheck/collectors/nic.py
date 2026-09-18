"""NIC collector: one pass -> structured info for every interface (F2).

Implements the NIC Collector detailed design: dual-architecture (OVS/direct)
detection, parsers for ip/ovs-vsctl/ethtool//proc/net/dev/.network, type
classification with priority rules, is_primary and mode detection.
"""
from __future__ import annotations
import fnmatch
import glob
import ipaddress
import os
import re
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set

from . import sysprobe

# ---------------------------------------------------------------- regexes (design 4.2/4.3/4.4)
RE_LINK_HEADER = re.compile(
    r"^(?P<index>\d+):\s+(?P<name>\S+):\s+<(?P<flags>[^>]*)>"
    r"\s+mtu\s+(?P<mtu>\d+)(?:\s+qdisc\s+\S+)?"
    r"(?:\s+master\s+(?P<master>\S+))?(?:\s+state\s+(?P<state>\S+))?.*$")
RE_LINK_TYPE = re.compile(r"^\s+link/(?P<type>\S+)\s+(?P<mac>\S+)")
RE_OVS_SUB = re.compile(r"^\s+openvswitch\s+(?P<sub>internal|datapath|system)")
RE_VETH = re.compile(r"^\s+veth\s+")
RE_BOND = re.compile(r"^\s+bond\s+mode\s+\S+")
RE_BRIDGE = re.compile(r"^\s+bridge\s+")

RE_IFACE = re.compile(r"^\d+:\s+(?P<name>\S+):\s")
RE_INET = re.compile(r"^\s+inet\s+(?P<addr>[\d.]+)/(?P<prefix>\d+).*?scope\s+(?P<scope>\w+)")
RE_INET6 = re.compile(
    r"^\s+inet6\s+(?P<addr>[0-9a-fA-F:]+)/(?P<prefix>\d+).*?scope\s+(?P<scope>\w+)"
    r"(?P<flags>(?:\s+(?:global|dynamic|deprecated|tentative|mngtmpaddr|noprefixroute))+)?")
RE_ROUTE = re.compile(
    r"^(?P<dst>\S+)\s+(?:via\s+(?P<via>\S+))?\s*(?:dev\s+(?P<dev>\S+))?"
    r".*?(?:proto\s+(?P<proto>\S+))?.*?(?:metric\s+(?P<metric>\d+))?")

RE_BRIDGE_LINE = re.compile(r"^\s{4}Bridge\s+(\S+)")
RE_PORT_LINE = re.compile(r"^\s{8}Port\s+(\S+)")
RE_IFACE_LINE = re.compile(r"^\s{12}Interface\s+(\S+)")
RE_TYPE_LINE = re.compile(r"^\s{16}type:\s+(\S+)")

RE_SPEED = re.compile(r"^\s*Speed:\s+(\d+)Mb/s\s*$")
RE_SPEED_UNKNOWN = re.compile(r"^\s*Speed:\s*Unknown")
RE_DUPLEX = re.compile(r"^\s*Duplex:\s+(\w+)")
RE_LINK_DETECTED = re.compile(r"^\s*Link detected:\s+(yes|no)")

RE_PROCDEV = re.compile(
    r"^\s*(?P<iface>[^:\s]+):\s*(?P<rx_bytes>\d+)\s+(?P<rx_packets>\d+)\s+"
    r"(?P<rx_errs>\d+)\s+(?P<rx_drop>\d+)\s+(?P<rx_fifo>\d+)\s+(?P<rx_frame>\d+)\s+"
    r"(?P<rx_compressed>\d+)\s+(?P<rx_multicast>\d+)\s+"
    r"(?P<tx_bytes>\d+)\s+(?P<tx_packets>\d+)\s+(?P<tx_errs>\d+)\s+(?P<tx_drop>\d+)\s+"
    r"(?P<tx_fifo>\d+)\s+(?P<tx_colls>\d+)\s+(?P<tx_carrier>\d+)\s+(?P<tx_compressed>\d+)\s*$")

# design 9.1 priority 5 name pattern
RE_PHYS_NAME = re.compile(r"^(eth|en[osip]?|eno|enp|ens|enx)\d*")


# ---------------------------------------------------------------- parsers
def parse_ip_d_link(text: str) -> Dict[str, dict]:
    links: Dict[str, dict] = {}
    cur: Optional[dict] = None
    for raw in text.splitlines():
        m = RE_LINK_HEADER.match(raw)
        if m:
            cur = {"index": int(m["index"]), "name": m["name"],
                   "flags": set(m["flags"].split(",")), "mtu": int(m["mtu"]),
                   "master": m["master"] or None, "state": m["state"] or None,
                   "link_type": None, "mac": None, "ovs_subtype": None,
                   "altnames": []}
            links[cur["name"]] = cur
            continue
        if cur is None:
            continue
        m = RE_LINK_TYPE.match(raw)
        if m:
            cur["link_type"], cur["mac"] = m["type"], m["mac"]
        elif (m := RE_OVS_SUB.match(raw)):
            cur["ovs_subtype"] = m["sub"]
        elif RE_VETH.match(raw):
            cur["link_type"] = "veth"
        elif RE_BOND.match(raw):
            cur["link_type"] = "bond"
        elif RE_BRIDGE.match(raw) and cur["link_type"] is None:
            cur["link_type"] = "bridge"
        elif raw.startswith("    altname "):
            cur["altnames"].append(raw.split()[1])
    return links


def parse_ip_addr(text: str, family: int) -> Dict[str, List[dict]]:
    out: Dict[str, List[dict]] = {}
    cur: Optional[str] = None
    for raw in text.splitlines():
        m = RE_IFACE.match(raw)
        if m:
            cur = m["name"]
            out.setdefault(cur, [])
            continue
        if cur is None:
            continue
        m = (RE_INET if family == 4 else RE_INET6).match(raw)
        if m:
            out[cur].append({"addr": m["addr"], "prefix": int(m["prefix"]),
                             "scope": m["scope"], "origin": None,
                             "dynamic": "dynamic" in (m.groupdict().get("flags") or "")})
    return out


def parse_ip_route_default(text: str) -> Dict[str, List[dict]]:
    routes: Dict[str, List[dict]] = {}
    for raw in text.splitlines():
        m = RE_ROUTE.match(raw)
        if not m or m["dst"] != "default":
            continue
        dev = m["dev"] or "?"
        routes.setdefault(dev, []).append(
            {"gateway": m["via"], "proto": m["proto"],
             "metric": int(m["metric"]) if m["metric"] else 1024})
    return routes


def parse_ovs_vsctl_show(text: str) -> List[dict]:
    bridges: List[dict] = []
    cur_br: Optional[dict] = None
    for raw in text.splitlines():
        if (m := RE_BRIDGE_LINE.match(raw)):
            cur_br = {"name": m.group(1), "ports": []}
            bridges.append(cur_br)
            continue
        if cur_br is None:
            continue
        if (m := RE_PORT_LINE.match(raw)):
            cur_br["ports"].append({"name": m.group(1), "interfaces": []})
            continue
        if (m := RE_IFACE_LINE.match(raw)) and cur_br["ports"]:
            cur_br["ports"][-1]["interfaces"].append({"name": m.group(1), "type": None})
            continue
        # NOTE: parentheses are essential - the walrus must bind the match only
        if (m := RE_TYPE_LINE.match(raw)) and cur_br["ports"]:
            cur_br["ports"][-1]["interfaces"][-1]["type"] = m.group(1)
    return bridges


def pair_internal_phys(bridges: List[dict]) -> Dict[str, str]:
    pairs: Dict[str, str] = {}
    for br in bridges:
        internals = [p["interfaces"][0]["name"] for p in br["ports"]
                     if p["interfaces"] and p["interfaces"][0]["type"] == "internal"]
        others = [p["interfaces"][0]["name"] for p in br["ports"]
                  if p["interfaces"] and p["interfaces"][0]["type"] != "internal"]
        for i in internals:  # rule 1: name pairing ovs_ethN <-> ethN
            if i.startswith("ovs_") and i[len("ovs_"):] in others:
                pairs[i] = i[len("ovs_"):]
        if len(internals) == 1 and len(others) == 1 and internals[0] not in pairs:
            pairs[internals[0]] = others[0]  # rule 2: unique pair
        for p in br["ports"]:  # rule 3: bond port
            if p["interfaces"] and p["interfaces"][0]["type"] == "bond":
                for i in internals:
                    pairs.setdefault(i, p["interfaces"][0]["name"])
    return pairs


def parse_ethtool(text: str) -> dict:
    out = {"speed_mbps": None, "duplex": None, "link_detected": None, "notes": []}
    for raw in text.splitlines():
        if (m := RE_SPEED.match(raw)):
            v = int(m.group(1))
            out["speed_mbps"] = None if v == 4294967295 else v
        elif RE_SPEED_UNKNOWN.match(raw):
            out["speed_mbps"] = None
        elif (m := RE_DUPLEX.match(raw)):
            out["duplex"] = m.group(1).lower()
        elif (m := RE_LINK_DETECTED.match(raw)):
            out["link_detected"] = m.group(1) == "yes"
    return out


def parse_proc_net_dev(text: str) -> Dict[str, dict]:
    out: Dict[str, dict] = {}
    for raw in text.splitlines()[2:]:
        if (m := RE_PROCDEV.match(raw)):
            d = m.groupdict()
            out[d["iface"]] = {k: int(v) for k, v in d.items() if k != "iface"}
    return out


# ---------------------------------------------------------------- .network parsing (design 8)
def parse_network_text(text: str) -> Dict[str, Dict[str, List[str]]]:
    sections: Dict[str, Dict[str, List[str]]] = {}
    cur: Optional[str] = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            cur = line[1:-1]
            sections.setdefault(cur, {})
            continue
        if cur is None:
            continue
        for token in (t.strip() for t in line.split(",") if t.strip()):
            k, _, v = token.partition("=")
            if k.strip():
                sections[cur].setdefault(k.strip(), []).append(v.strip())
    return sections


def _file_matches(match: Dict[str, List[str]], ifname: str, mac: str, link_type: str) -> bool:
    def has(k: str) -> bool:
        return bool(match.get(k))
    name_ok = (not has("Name")) or any(fnmatch.fnmatch(ifname, p) for p in match["Name"])
    mac_ok = (not has("MACAddress")) or any(
        mac and mac.lower() == p.lower() for p in match["MACAddress"])
    type_ok = (not has("Type")) or any(link_type == t for t in match["Type"])
    return name_ok and mac_ok and type_ok


def _is_v4(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).version == 4
    except ValueError:
        return False


def derive_mode(net: Dict[str, List[str]]) -> dict:
    dhcp = net.get("DHCP", ["no"])[0].lower()
    addrs = net.get("Address", [])
    has_v4 = any("/" in a and _is_v4(a.split("/")[0]) for a in addrs)
    has_v6 = any("/" in a and not _is_v4(a.split("/")[0]) for a in addrs)
    v4_dhcp, v4_static = dhcp in ("yes", "true", "ipv4"), has_v4
    v6_dhcp, v6_static = dhcp in ("yes", "true", "ipv6"), has_v6
    ra = net.get("IPv6AcceptRA", ["yes"])[0].lower() in ("yes", "true")
    mode = ("dhcp" if v4_dhcp else "static" if v4_static
            else "dhcp" if v6_dhcp else "static" if v6_static else "none")
    detail = {"v4": "dhcp" if v4_dhcp else ("static" if v4_static else "none"),
              "v6": "dhcp6" if v6_dhcp else ("static6" if v6_static
                                             else "slaac" if ra else "none")}
    return {"mode": mode, "detail": detail, "dhcp": dhcp,
            "addresses": addrs, "ra": ra}


def collect_mode(ifname: str, mac: str, link_type: str,
                 files: List[str], read) -> dict:
    merged: Dict[str, List[str]] = {}
    for path in sorted(files):
        sec = parse_network_text(read(path))
        if _file_matches(sec.get("Match", {}), ifname, mac, link_type or "ether"):
            for k, v in sec.get("Network", {}).items():
                merged[k] = v  # later files override (systemd semantics)
    return derive_mode(merged)


def sys_interface_names(sys_root: str = "/sys/class/net") -> Set[str]:
    """Return actual netdev entries, excluding sysfs control files.

    Linux exposes real interfaces as directories (usually symlinks to a netdev
    directory). TOS also places regular files such as ``bonding_masters`` and
    ``tm_ovs_bonds`` in the same class directory; those are controls, not links.
    """
    try:
        return {name for name in os.listdir(sys_root)
                if os.path.isdir(os.path.join(sys_root, name))}
    except OSError:
        return set()


# ---------------------------------------------------------------- classification (design 9)
def classify(name: str, link: dict, ovs_internal: set, ethtool_speed) -> Optional[str]:
    lt = link.get("link_type")
    if lt == "loopback" or name == "lo":
        return "loopback"
    if link.get("ovs_subtype") == "internal" or name in ovs_internal:
        return "ovs_internal"
    if lt == "bond" or os.path.exists(f"/proc/net/bonding/{name}"):
        return "bond"
    if name == "ovs-system" or link.get("ovs_subtype") == "datapath":
        return None  # filtered from display
    if RE_PHYS_NAME.match(name) or ethtool_speed is not None:
        return "physical"
    if name == "docker0" or (lt == "bridge" and
                             re.match(r"^(docker|br-|virbr)", name)):
        return "docker"
    if lt == "veth":
        return "veth"
    if name == "tnas0" or lt in {"tun", "tap", "gretap", "sit", "ipip", "gre"}:
        return "tunnel"
    return "virtual"


def determine_primary(interfaces: Dict[str, dict],
                      routes_v4: Dict[str, List[dict]],
                      routes_v6: Dict[str, List[dict]]) -> set:
    cand = sorted(((r["metric"], dev) for dev, rs in routes_v4.items() for r in rs),
                  key=lambda t: t[0])
    for _, dev in cand:
        if dev in interfaces and any(a["scope"] == "global" for a in interfaces[dev]["ipv4"]):
            return {dev}
    for dev in routes_v6:
        if dev in interfaces:
            return {dev}
    for dev in sorted(interfaces, key=lambda d: interfaces[d]["index"]):
        if any(a["scope"] == "global" for a in interfaces[dev]["ipv4"]):
            return {dev}
    return set()


# ---------------------------------------------------------------- collector
class NicCollector:
    """Cached (TTL 2s) one-pass collector; probe/read injectable for tests."""

    def __init__(self, probe=None, read=None, ttl: float = 2.0,
                 network_dir: str = "/etc/systemd/network"):
        self._probe = probe or sysprobe.run
        self._read = read or sysprobe.read_file
        self.ttl = ttl
        self.network_dir = network_dir
        self._lock = threading.RLock()
        self._cache: Optional[dict] = None
        self._ts = 0.0
        self.traffic: Dict[str, dict] = {}

    def get(self, force: bool = False) -> dict:
        with self._lock:
            now = time.monotonic()
            if force or self._cache is None or now - self._ts >= self.ttl:
                self._cache = self._collect_all()
                self._ts = now
            return self._cache

    def invalidate(self) -> None:
        with self._lock:
            self._cache, self._ts = None, 0.0

    # ---------------- single pass ----------------
    def _collect_all(self) -> dict:
        p = self._probe
        r_link = p(["ip", "-d", "link", "show"])
        links = parse_ip_d_link(r_link.stdout)
        # /sys cross-check: include interfaces that appeared between commands
        sys_names = sys_interface_names()
        for name in sys_names - set(links):
            links[name] = {"index": 9999, "name": name, "flags": set(),
                           "mtu": int(self._to_int(self._read(f"/sys/class/net/{name}/mtu")) or 0),
                           "master": None, "state": None, "link_type": None,
                           "mac": self._read(f"/sys/class/net/{name}/address").strip() or None,
                           "ovs_subtype": None, "altnames": []}

        r_v4 = p(["ip", "-4", "addr"])
        r_v6 = p(["ip", "-6", "addr"])
        addrs4 = parse_ip_addr(r_v4.stdout, 4)
        addrs6 = parse_ip_addr(r_v6.stdout, 6)
        r_rt4 = p(["ip", "route"])
        routes4 = parse_ip_route_default(r_rt4.stdout)
        r_rt6 = p(["ip", "-6", "route", "show", "default"])
        routes6 = parse_ip_route_default(r_rt6.stdout)

        r_ovs = p(["ovs-vsctl", "show"], timeout=3)
        bridges = parse_ovs_vsctl_show(r_ovs.stdout)
        arch = "direct" if r_ovs.rc != 0 or not bridges else "ovs"
        pairs = pair_internal_phys(bridges) if arch == "ovs" else {}
        ovs_internal_names = set(pairs) | {
            p["interfaces"][0]["name"] for br in bridges for p in br["ports"]
            if p["interfaces"] and p["interfaces"][0]["type"] == "internal"}

        traffic = parse_proc_net_dev(self._read("/proc/net/dev"))
        self.traffic.update(traffic)

        network_files = sorted(glob.glob(os.path.join(self.network_dir, "*.network")))

        interfaces: Dict[str, dict] = {}
        for name, link in links.items():
            etht: dict = {"speed_mbps": None, "duplex": None, "link_detected": None}
            probe_candidate = classify(name, link, ovs_internal_names, None)
            if probe_candidate in ("physical", "bond") or probe_candidate is None:
                etht = parse_ethtool(p(["ethtool", name], timeout=3).stdout)
            itype = classify(name, link, ovs_internal_names, etht["speed_mbps"])
            if itype is None:
                continue  # ovs-system filtered
            operstate = (self._read(f"/sys/class/net/{name}/operstate").strip()
                        or link.get("state") or "").lower() or None
            carrier_raw = self._read(f"/sys/class/net/{name}/carrier").strip()
            modeinfo = collect_mode(name, link.get("mac") or "", link.get("link_type") or "",
                                    network_files, self._read)
            stats = traffic.get(name, {})
            v6_list = [dict(a) for a in addrs6.get(name, [])]
            for a6 in v6_list:  # origin backfill (design 8.4)
                if a6["scope"] == "link":
                    a6["origin"] = "link"
                elif a6["scope"] == "host":
                    a6["origin"] = "host"
                elif a6["dynamic"]:
                    a6["origin"] = "slaac"
                elif any(a6["addr"] in cfg for cfg in modeinfo["addresses"]):
                    a6["origin"] = "static"
                elif modeinfo["dhcp"] in ("ipv6", "yes", "true"):
                    a6["origin"] = "dhcp6"
            interfaces[name] = {
                "name": name, "index": link["index"], "type": itype,
                "operstate": operstate, "carrier": carrier_raw == "1",
                "mac": link.get("mac") or "", "mtu": link["mtu"],
                "speed_mbps": etht["speed_mbps"], "duplex": etht["duplex"],
                "speed_note": self._speed_note(name, itype, pairs, etht, interfaces),
                "driver": self._driver(name, itype),
                "ipv4": addrs4.get(name, []), "ipv6": v6_list,
                "gateway": self._gateway(name, routes4),
                "ipv6_gateway": self._gateway(name, routes6),
                "mode": modeinfo["mode"], "mode_detail": modeinfo["detail"],
                "rx_bytes": stats.get("rx_bytes", 0), "tx_bytes": stats.get("tx_bytes", 0),
                "rx_errors": stats.get("rx_errs", 0), "tx_dropped": stats.get("tx_drop", 0),
                "rx_bps": 0, "tx_bps": 0,
                "phys": pairs.get(name),
                "is_primary": False,
            }
        primary = determine_primary(interfaces, routes4, routes6)
        for name in primary:
            interfaces[name]["is_primary"] = True
        ordered = sorted(interfaces.values(),
                         key=lambda i: (not i["is_primary"], i["index"]))
        return {"arch": arch, "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "interfaces": ordered, "_routes4": routes4, "_routes6": routes6}

    @staticmethod
    def _to_int(s: str) -> Optional[int]:
        try:
            return int(s.strip())
        except (ValueError, AttributeError):
            return None

    @staticmethod
    def _gateway(name: str, routes: Dict[str, List[dict]]) -> Optional[str]:
        best = routes.get(name)
        if not best:
            return None
        return min(best, key=lambda r: r["metric"])["gateway"]

    @staticmethod
    def _driver(name: str, itype: str) -> str:
        defaults = {"loopback": "loopback", "ovs_internal": "openvswitch",
                    "docker": "bridge", "tunnel": "tun"}
        if itype in defaults:
            return defaults[itype]
        return ""

    def _speed_note(self, name: str, itype: str, pairs: Dict[str, str],
                    etht: dict, interfaces: Dict[str, dict]) -> str:
        if itype == "ovs_internal" and name in pairs:
            phys = pairs[name]
            speed = etht.get("speed_mbps")
            if speed:
                return f"virtual port, inherits physical {phys} ({speed} Mb/s)"
            return f"virtual port, inherits physical {phys} (currently no link)"
        if itype == "loopback":
            return "loopback interface, no physical link"
        if itype == "tunnel":
            return "TOS remote-access tunnel"
        if itype == "docker":
            return "Docker bridge"
        if etht.get("link_detected") is False:
            return "link not connected"
        return ""
