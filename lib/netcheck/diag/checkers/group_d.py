"""Group D - DNS: config, reachability, resolution (systemd-resolved)."""
from __future__ import annotations
import re
import time

from ..engine import BaseChecker, register_checker


def _dns_servers(probe):
    out = probe(["resolvectl", "status"], timeout=3).stdout
    servers = re.findall(r"DNS Servers:\s+(.+)", out)
    flat = []
    for line in servers:
        flat.extend(ip.strip(".,") for ip in line.split() if ":" in ip or "." in ip)
    return flat, out


@register_checker("dns-config", "D", "check.dns_config", fixable="fix-dns", weight=0.03)
class DnsConfig(BaseChecker):
    def collect(self):
        return _dns_servers(self.probe)

    def evaluate(self, data):
        servers, _ = data
        if not any(i.get("ipv4") for i in self.nics["interfaces"]):
            return self.na("no active port")
        valid = [s for s in servers if s not in ("0.0.0.0", "")]
        if not valid:
            return self.fail("empty", ">=1 valid DNS", "empty_dns")
        if "0.0.0.0" in servers:
            return self.fail(f"{servers}", "valid IPs", "invalid_dns: contains 0.0.0.0")
        return self.pass_(f"{len(valid)} server(s): {', '.join(valid[:3])}",
                          ">=1 valid DNS", "")


@register_checker("dns-reachable", "D", "check.dns_reachable", fixable="fix-dns", weight=0.04,
                  timeout=8)
class DnsReachable(BaseChecker):
    def collect(self):
        servers, _ = _dns_servers(self.probe)
        domain = self.cfg.get("dns_probe_domain", "www.baidu.com")
        results = []
        for s in servers[:3]:
            r = self.probe(["dig", "@" + s, domain, "+time=2", "+tries=1", "+short", "A"],
                           timeout=4)
            results.append((s, r.rc, r.stdout.strip()))
        return servers, results

    def evaluate(self, data):
        servers, results = data
        if not servers:
            return self.na("no DNS configured")
        ok = [s for s, rc, out in results if rc == 0 and out]
        if len(ok) == len(results):
            return self.pass_(f"all {len(ok)} reachable", ">=1 reachable", "")
        if ok:
            return self.warn(f"{len(ok)}/{len(results)} reachable", "all",
                             "partial_unreachable")
        return self.fail("all DNS probes failed", ">=1 reachable", "dns_unreachable")


@register_checker("dns-resolve", "D", "check.dns_resolve", fixable="fix-dns", weight=0.04,
                  timeout=6)
class DnsResolve(BaseChecker):
    def collect(self):
        if not _dns_servers(self.probe)[0]:
            return None
        domain = self.cfg.get("dns_probe_domain", "www.baidu.com")
        t0 = time.monotonic()
        r = self.probe(["getent", "hosts", domain], timeout=5)
        return time.monotonic() - t0, r

    def evaluate(self, data):
        if data is None:
            return self.na("no DNS")
        elapsed, r = data
        ms = int(elapsed * 1000)
        slow = self.cfg.get("resolve_slow_ms", 2000)
        if r.rc == 0 and r.stdout.strip():
            if ms > slow:
                return self.warn(f"{ms}ms", f"<={slow}ms", "slow resolution")
            return self.pass_(f"{ms}ms", f"<={slow}ms", "")
        return self.fail(f"rc={r.rc}", "resolve", "resolve_failed")
