"""Group C - routes: default route, connected routes."""
from __future__ import annotations
import ipaddress

from ..engine import BaseChecker, register_checker


@register_checker("default-route", "C", "check.default_route", fixable="fix-gateway", weight=0.05)
class DefaultRoute(BaseChecker):
    def collect(self):
        return self.nics.get("_routes4", {})

    def evaluate(self, routes):
        defaults = [(dev, r) for dev, rs in routes.items() for r in rs]
        if not defaults:
            if not any(i.get("ipv4") for i in self.nics["interfaces"]):
                return self.na("no active interface")
            return self.fail("no default route", "exactly one",
                             "route_missing: no IPv4 default route")
        if len(defaults) == 1:
            dev, r = defaults[0]
            return self.pass_(f"via {r['gateway']} dev {dev} metric {r['metric']}",
                              "exactly one", "")
        gateways = {r["gateway"] for _, r in defaults}
        if len(gateways) == 1:
            return self.warn(f"{len(defaults)} routes same gw", "exactly one",
                             "route_conflict: redundant default routes")
        return self.fail(f"{len(defaults)} routes, {len(gateways)} gateways", "exactly one",
                         "route_conflict: multiple default gateways")


@register_checker("connected-routes", "C", "check.connected_routes", fixable="fix-routes", weight=0.02)
class ConnectedRoutes(BaseChecker):
    def collect(self):
        return self.probe(["ip", "route", "show"], timeout=3).stdout

    def evaluate(self, out):
        active = [i for i in self.nics["interfaces"]
                  if i.get("ipv4") and i.get("operstate") == "up"]
        if not active:
            return self.na("no active port")
        missing = []
        for i in active:
            a = i["ipv4"][0]
            subnet = str(ipaddress.ip_interface(
                f"{a['addr']}/{a['prefix']}").network)
            if not any(f"{subnet} dev {i['name']}" in line for line in out.splitlines()):
                missing.append(f"{i['name']}:{subnet}")
        if missing:
            return self.fail(",".join(missing), "each active subnet routed",
                             "connected_route_missing: address present but route missing")
        return self.pass_("all active subnets routed", "complete", "")
