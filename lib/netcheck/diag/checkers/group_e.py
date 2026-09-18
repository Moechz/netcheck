"""Group E - IPv6: global address, default route, DNS, reachability."""
from __future__ import annotations

from ..engine import BaseChecker, register_checker
from ._util import gate_ipv6, https_probe, ping_loss, v6_service_present


@register_checker("ipv6-global-addr", "E", "check.ipv6_global_addr", fixable="fix-ipv6",
                  weight=0.01, na_fn=lambda ctx: not gate_ipv6(ctx))
class Ipv6GlobalAddr(BaseChecker):
    def collect(self):
        return self.primary()

    def evaluate(self, pri):
        if pri is None:
            return self.na("no active port")
        if not pri.get("ipv6"):
            return self.fail("IPv6 disabled on this interface", "global address",
                             "ipv6_disabled_if: kernel IPv6 disabled on primary")
        globals_ = [a for a in pri.get("ipv6", []) if a.get("scope") == "global"]
        if globals_:
            return self.pass_(globals_[0]["addr"], "global address", "")
        if not v6_service_present(self.nics):
            return self.na("no IPv6 service on this network (router provides no RA/DHCPv6)")
        return self.fail("link-local only", "global address",
                         "link_local_only: IPv6 not properly configured")


@register_checker("ipv6-default-route", "E", "check.ipv6_default_route", fixable="fix-routes",
                  weight=0.01, na_fn=lambda ctx: not gate_ipv6(ctx))
class Ipv6DefaultRoute(BaseChecker):
    def collect(self):
        return self.nics.get("_routes6", {})

    def evaluate(self, routes):
        if routes:
            dev, rs = next(iter(routes.items()))
            r = rs[0]
            return self.pass_(f"via {r['gateway']} dev {dev}", "exists", "")
        if not v6_service_present(self.nics):
            return self.na("no IPv6 service on this network (router provides no RA/DHCPv6)")
        return self.fail("missing", "exists", "route_missing_v6")


@register_checker("ipv6-dns", "E", "check.ipv6_dns", fixable="fix-dns", weight=0.01,
                  na_fn=lambda ctx: not gate_ipv6(ctx))
class Ipv6Dns(BaseChecker):
    def collect(self):
        out = self.probe(["resolvectl", "status"], timeout=3).stdout
        has_v6_dns = any(":" in ip and not ip.startswith("fe80")
                         for line in out.split("DNS Servers:")[1:]
                         for ip in line.splitlines()[0].split())
        domain = self.cfg.get("dns_probe_domain", "www.baidu.com")
        r = self.probe(["dig", "AAAA", domain, "+time=2", "+tries=1", "+short"],
                       timeout=4)
        return has_v6_dns, r

    def evaluate(self, data):
        if not v6_service_present(self.nics):
            return self.na("no IPv6 service on this network")
        has_v6_dns, r = data
        if has_v6_dns or (r.rc == 0 and r.stdout.strip()):
            return self.pass_("v6 DNS or AAAA available", "available", "")
        if r.rc == 0 and not r.stdout.strip():
            return self.warn("AAAA NODATA", "AAAA", "aaaa_nodata: domain has no AAAA")
        return self.fail("no v6 DNS + AAAA failed", "available", "no_ipv6_dns")


@register_checker("ipv6-reach", "E", "check.ipv6_reach", fixable="fix-ipv6", weight=0.02,
                  na_fn=lambda ctx: not gate_ipv6(ctx))
class Ipv6Reach(BaseChecker):
    def collect(self):
        pri = self.primary() or {}
        has_global = any(a.get("scope") == "global" for a in pri.get("ipv6", []))
        has_route = bool(self.nics.get("_routes6"))
        if not (has_global and has_route):
            return {"na": "no v6 address/route"}
        target = (self.cfg.get("ipv6_targets") or ["2400:3200::1"])[0]
        return {"na": "", "loss": ping_loss(self.probe, target, count=2, wait=2, ipv6=True)}

    def evaluate(self, data):
        if data.get("na"):
            return self.na(data["na"])
        loss = data["loss"]
        if loss is None or loss >= 100:
            cls, code = https_probe(self.probe, "https://[2400:3200::1]", timeout=4) \
                if False else ("unknown", None)
            # v6 TCP fallback via curl -6 on a dual-stack URL
            r = self.probe(["curl", "-6", "-sS", "-o", "/dev/null", "-m", "4",
                            self.cfg.get("public_probe_urls", ["https://www.baidu.com"])[0]],
                           timeout=6)
            if r.rc == 0:
                return self.pass_("v6 TCP ok (ICMP blocked)", "any probe", "")
            return self.fail("v6 unreachable", "reachable", "ipv6_unreachable")
        if loss < (self.cfg.get("loss_threshold_pct", 20)):
            return self.pass_(f"loss={loss}%", "<20%", "")
        return self.warn(f"loss={loss}%", "<20%", "packet_loss v6")
