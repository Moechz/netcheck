"""Group B - IPv4: address, mask, lease, gateway subnet/reach, conflict."""
from __future__ import annotations
import ipaddress
import re

from ..engine import BaseChecker, register_checker
from ._util import ping_loss, same_subnet


@register_checker("ipv4-addr", "B", "check.ipv4_addr", fixable="fix-dhcp", weight=0.04)
class Ipv4Addr(BaseChecker):
    def collect(self):
        return self.primary()

    def evaluate(self, pri):
        if pri is None:
            return self.na("no active port")
        addrs = [a for a in pri.get("ipv4", [])
                 if a.get("scope") == "global"
                 and not a["addr"].startswith("169.254.")]
        if addrs:
            a = addrs[0]
            return self.pass_(f"{a['addr']}/{a['prefix']}", "valid global IPv4", "")
        if any(a["addr"].startswith("169.254.") for a in pri.get("ipv4", [])):
            return self.fail("169.254.x.x only", "global IPv4",
                             "apipa: DHCP failed (link-local only)")
        return self.fail("no IPv4", "global IPv4", "no_address: no IPv4 address")


@register_checker("ipv4-mask", "B", "check.ipv4_mask", fixable="fix-dhcp", weight=0.01)
class Ipv4Mask(BaseChecker):
    def collect(self):
        return self.primary()

    def evaluate(self, pri):
        if pri is None or not pri.get("ipv4"):
            return self.na("no IPv4")
        a = pri["ipv4"][0]
        try:
            iface = ipaddress.ip_interface(f"{a['addr']}/{a['prefix']}")
        except ValueError:
            return self.fail(f"prefix={a['prefix']}", "0-32", "invalid_mask")
        if iface.ip == iface.network.network_address or iface.ip == iface.network.broadcast_address:
            return self.warn(str(iface), "host address",
                             "network_broadcast_host: address is network/broadcast id")
        return self.pass_(str(iface), "valid unicast in subnet", "")


@register_checker("dhcp-lease", "B", "check.dhcp_lease", fixable="fix-dhcp", weight=0.02)
class DhcpLease(BaseChecker):
    def collect(self):
        pri = self.primary() or {}
        if pri.get("mode") != "dhcp":
            return {"skip": "static"}
        r = self.probe(["networkctl", "status", pri["name"]], timeout=3)
        return {"skip": "", "output": r.stdout}

    def evaluate(self, data):
        if data.get("skip"):
            return self.na(f"mode={data['skip']} (not DHCP)")
        out = data.get("output", "")
        if "LeaseLifetime" in out or "Address" in out:
            return self.pass_("lease present", "valid lease", "")
        return self.fail("no lease info", "valid lease",
                         "lease_expired: DHCP mode without a usable lease")


@register_checker("gateway-subnet", "B", "check.gateway_subnet", fixable="fix-gateway", weight=0.02)
class GatewaySubnet(BaseChecker):
    def collect(self):
        return self.primary()

    def evaluate(self, pri):
        if pri is None or not pri.get("gateway"):
            return self.na("no default route")
        a = pri["ipv4"][0]
        if same_subnet(a["addr"], a["prefix"], pri["gateway"]):
            return self.pass_(f"gw {pri['gateway']} in subnet", "same subnet", "")
        return self.fail(f"gw {pri['gateway']} outside {a['addr']}/{a['prefix']}",
                         "same subnet", "gateway_cross_subnet")


@register_checker("gateway-reach", "B", "check.gateway_reach", fixable="fix-gateway", weight=0.05,
                  timeout=6)
class GatewayReach(BaseChecker):
    def collect(self):
        pri = self.primary() or {}
        return pri.get("gateway")

    def evaluate(self, gw):
        if not gw:
            return self.na("no gateway")
        loss = ping_loss(self.probe, gw, count=2, wait=2)
        threshold = self.cfg.get("loss_threshold_pct", 20)
        if loss is None:
            return self.fail("ping unavailable", f"loss<{threshold}%",
                             "undeterminable: ping failed to run")
        if loss < threshold:
            return self.pass_(f"loss={loss}%", f"<{threshold}%", "")
        # ARP cross-check (ICMP may be blocked; design 4.2.5)
        neigh = self.probe(["ip", "neigh", "show"], timeout=2).stdout
        arp_ok = gw in neigh and "REACHABLE" in neigh.split(gw, 1)[1][:60]
        if loss == 100 and not arp_ok:
            return self.fail("ping/ARP all failed", "reachable", "no_reply")
        return self.warn(f"loss={loss}%", f"<{threshold}%",
                         "icmp_blocked" if arp_ok else "packet_loss")


@register_checker("ip-conflict", "B", "check.ip_conflict", fixable="fix-dhcp", weight=0.02)
class IpConflict(BaseChecker):
    """arping -D needs CAP_NET_RAW (device-verified 2026-08-25); non-root
    degrades to an ip-neigh heuristic per the design 4.2.6."""

    def collect(self):
        pri = self.primary() or {}
        if not pri.get("ipv4"):
            return {"skip": "no IPv4"}
        ip = pri["ipv4"][0]["addr"]
        r = self.probe(["arping", "-D", "-c", "3", "-I", pri["name"], ip], timeout=6)
        neigh = self.probe(["ip", "neigh", "show"], timeout=2).stdout
        return {"skip": "", "ip": ip, "arping_rc": r.rc,
                "arping_out": r.stdout + r.stderr, "neigh": neigh}

    def evaluate(self, data):
        if data.get("skip"):
            return self.na(data["skip"])
        if "Operation not permitted" in data["arping_out"]:
            # heuristic: same IP with multiple MACs in the ARP table
            macs = re.findall(rf"{re.escape(data['ip'])}\s+dev\s+\S+\s+lladdr\s+(\S+)",
                              data["neigh"])
            if len(set(macs)) > 1:
                return self.warn(f"{len(set(macs))} MACs for {data['ip']}",
                                 "unique owner",
                                 "suspected_conflict: heuristic hit (non-authoritative)")
            return self.pass_("heuristic: no duplicates (non-authoritative)",
                              "no conflict", "")
        if data["arping_rc"] == 0 and "Reply" not in data["arping_out"]:
            return self.pass_("no conflict reply (DAD)", "no reply", "")
        if "Reply" in data["arping_out"]:
            return self.fail("reply received", "no reply",
                             "ip_conflict: another host answered DAD")
        # arping ran but produced no usable answer (e.g. transient send error):
        # the conflict state is unknown, not "conflict detected" -> na, no fix
        return self.na("probe_unavailable: arping failed")
