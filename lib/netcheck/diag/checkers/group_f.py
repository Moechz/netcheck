"""Group F - internet: public ping, TCP/HTTPS, proxy/firewall."""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from ..engine import BaseChecker, register_checker
from ._util import ping_loss, https_probe


@register_checker("wan-ping", "F", "check.wan_ping", fixable="fix-gateway", weight=0.04,
                  na_fn=lambda ctx: not ctx.get("nics", {}).get("_routes4"))
class WanPing(BaseChecker):
    def collect(self):
        ips = self.cfg.get("ping_public_ips", ["223.5.5.5", "8.8.8.8"])
        return [ping_loss(self.probe, ip, count=2, wait=2) for ip in ips[:2]]

    def evaluate(self, losses):
        if all(l is None for l in losses):
            return self.fail("ping unavailable", "any reply",
                             "undeterminable: ping failed to run")
        if any(l == 0 for l in losses if l is not None):
            return self.pass_("public ping ok", "any reply", "")
        # ICMP may be blocked; wan-tcp makes the final call (anti false-positive)
        return self.warn("all public ping lost", "any reply",
                         "icmp_blocked: TCP verdict pending (see wan-tcp)")


@register_checker("wan-tcp", "F", "check.wan_tcp", weight=0.07,
                  na_fn=lambda ctx: not ctx.get("nics", {}).get("_routes4"))
class WanTcp(BaseChecker):
    FIX = {"dns_failure": "fix-dns", "cert_failure": "fix-time",
           "connect_failure": "fix-gateway", "timeout": "fix-gateway"}

    def collect(self):
        url = (self.cfg.get("public_probe_urls") or ["https://www.baidu.com"])[0]
        return https_probe(self.probe, url, timeout=5)

    def evaluate(self, data):
        cls, code = data
        if cls == "ok":
            return self.pass_(f"HTTP {code}", "200/3xx", "")
        self._fixable_override = self.FIX.get(cls)
        return self.fail(cls, "HTTP 200/3xx", f"{cls}: curl exit classification")


@register_checker("proxy-firewall", "F", "check.proxy_firewall", weight=0.03,
                  na_fn=lambda ctx: not ctx.get("nics", {}).get("interfaces"))
class ProxyFirewall(BaseChecker):
    def collect(self):
        import os
        proxies = {k: v for k, v in os.environ.items()
                   if k.lower().endswith("_proxy")}
        service_status = self.cfg.get("_tos_services", {})
        tos_proxy = (service_status.get("proxy")
                     if service_status.get("available") else None)
        tos_fw = self.probe(["tos", "firewall", "status"], timeout=3).stdout
        legacy_fw = ""
        if _firewall_state(tos_fw) == "unknown":
            legacy_fw = "\n".join(
                self.probe(["systemctl", "is-active", service], timeout=2).stdout.strip()
                for service in ("ufw", "firewalld")
            )
        targets = _proxy_targets(proxies, tos_proxy)
        probe_results = [
            (source, _proxy_probe(self.probe, url))
            for source, url in targets
        ]
        return proxies, tos_proxy, probe_results, tos_fw, legacy_fw

    def evaluate(self, data):
        proxies, tos_proxy, proxy_probe_results, tos_fw, legacy_fw = data
        state = _firewall_state(tos_fw)
        if state == "unknown" and "active" in legacy_fw:
            state = "enabled"
        tos_proxy_enabled = bool(tos_proxy and tos_proxy.get("enabled"))
        advanced = [
            protocol for protocol in ("http", "https", "socks")
            if isinstance(tos_proxy, dict)
            and isinstance(tos_proxy.get(protocol), dict)
            and tos_proxy[protocol].get("enabled")
        ]
        proxy_sources = []
        if proxies:
            proxy_sources.append(f"{len(proxies)} environment variable(s)")
        if tos_proxy_enabled:
            proxy_sources.append("TOS proxy configured")
        if advanced:
            proxy_sources.append("TOS advanced " + "/".join(advanced).upper())
        tos_proxy_known = isinstance(tos_proxy, dict)
        if proxy_sources:
            proxy_label = "; ".join(proxy_sources)
        elif not tos_proxy_known:
            proxy_label = "TOS proxy state unavailable"
        else:
            proxy_label = "no proxy in environment or TOS settings"

        unreachable = [source for source, reachable in proxy_probe_results
                       if not reachable]
        if unreachable:
            return self.fail(", ".join(unreachable), "reachable proxy server",
                             "bad_proxy: configured proxy server is unreachable")
        if state == "unknown":
            # na(reason) takes a single argument; the proxy label is the reason
            return self.na(proxy_label)
        if not tos_proxy_known and not proxies:
            return self.na("TOS proxy state unavailable; "
                           "proxy settings could not be read")
        if state == "disabled":
            return self.warn(f"firewall disabled; {proxy_label}",
                             "firewall enabled",
                             "firewall_disabled: enable the TOS firewall for inbound filtering")
        if proxy_sources:
            return self.warn(f"firewall enabled; {proxy_label}",
                             "no unexpected proxy",
                             "proxy_in_use: configured proxy server is reachable")
        return self.pass_("firewall enabled; no proxy in environment or TOS settings",
                          "firewall enabled and no unexpected proxy",
                          "TOS firewall is enabled")


def _firewall_state(output: str) -> str:
    match = re.search(r"Firewall\s+Status\s+(\w+)", output, re.IGNORECASE)
    if not match:
        return "unknown"
    value = match.group(1).lower()
    if value in ("enabled", "active", "on", "true"):
        return "enabled"
    if value in ("disabled", "inactive", "off", "false"):
        return "disabled"
    return "unknown"


def _valid_proxy_url(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return False
    return (parsed.scheme in ("http", "https", "socks5", "socks5h")
            and bool(parsed.hostname) and port is not None
            and 1 <= port <= 65535)


def _proxy_url(server: str, port: int, protocol: str = "http") -> Optional[str]:
    if not isinstance(server, str) or not server.strip():
        return None
    try:
        port_int = int(port)
    except (TypeError, ValueError):
        return None
    scheme = "socks5h" if protocol == "socks" else "http"
    host = server.strip()
    bracketed = f"[{host}]" if ":" in host and not host.startswith("[") else host
    url = f"{scheme}://{bracketed}:{port_int}"
    return url if _valid_proxy_url(url) else None


def _proxy_targets(proxies: Dict[str, str],
                   tos_proxy: Optional[dict]) -> List[Tuple[str, str]]:
    """Build credential-free proxy URLs for reachability checks."""
    targets = []
    for key, value in sorted(proxies.items()):
        if not value:
            continue
        parsed = urlsplit(value)
        try:
            port = parsed.port
        except ValueError:
            port = None
        scheme = parsed.scheme or "http"
        host = parsed.hostname or ""
        bracketed = f"[{host}]" if ":" in host and not host.startswith("[") else host
        url = f"{scheme}://{bracketed}:{port}" if port else value
        targets.append((f"environment:{key}", url) if _valid_proxy_url(url)
                        else (f"environment:{key}:invalid", ""))

    if not isinstance(tos_proxy, dict):
        return targets
    if tos_proxy.get("enabled"):
        url = _proxy_url(tos_proxy.get("server", ""),
                         tos_proxy.get("port", 0))
        targets.append(("TOS:default", url) if url else ("TOS:default:invalid", ""))
    for protocol in ("http", "https", "socks"):
        item = tos_proxy.get(protocol)
        if not isinstance(item, dict) or not item.get("enabled"):
            continue
        url = _proxy_url(item.get("server", ""), item.get("port", 0), protocol)
        name = f"TOS:{protocol}"
        targets.append((name, url) if url else (f"{name}:invalid", ""))
    return targets


def _proxy_probe(probe, url: str, timeout: int = 3) -> bool:
    """Test the configured proxy endpoint without sending credentials."""
    if not _valid_proxy_url(url):
        return False
    result = probe([
        "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
        "--connect-timeout", str(timeout), "--max-time", str(timeout),
        "--proxy", url, "http://example.com",
    ], timeout=timeout + 2)
    return result.rc == 0
