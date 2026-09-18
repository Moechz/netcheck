"""Group H - TOS platform services: update, market, TNAS.online, NTP."""
from __future__ import annotations

from ..engine import BaseChecker, register_checker
from ._util import https_probe


def _endpoint_check(self, urls, label):
    results = []
    for url in urls:
        cls, code = https_probe(self.probe, url, timeout=5)
        results.append((cls, code))
    return results


class _EndpointChecker(BaseChecker):
    FIX = {"dns_failure": "fix-dns", "cert_failure": "fix-time"}

    def _finish(self, results, urls):
        if any(c == "ok" for c, _ in results):
            return self.pass_(f"reachable ({len(results)} endpoint(s))", "reachable", "")
        cls = next(c for c, _ in results)
        if cls == "http_error":
            return self.fail(f"HTTP {next(code for c, code in results if c == 'http_error')}",
                             "2xx/3xx", "http_error: server-side issue")
        self._fixable_override = self.FIX.get(cls)
        return self.fail(cls, "reachable", f"{cls}: endpoint probe failed")


@register_checker("tos-update-server", "H", "check.tos_update_server", weight=0.05,
                  na_fn=lambda ctx: not ctx.get("nics", {}).get("_routes4"))
class TosUpdate(_EndpointChecker):
    def collect(self):
        return _endpoint_check(self, self.cfg.get(
            "tos_endpoints", ["https://download3.terra-master.com",
                              "https://dl.terra-master.com"]), "update")

    def evaluate(self, results):
        return self._finish(results, None)


@register_checker("tos-market", "H", "check.tos_market", weight=0.05,
                  na_fn=lambda ctx: not ctx.get("nics", {}).get("_routes4"))
class TosMarket(_EndpointChecker):
    def collect(self):
        return _endpoint_check(self, ["https://app.terra-master.com"], "market")

    def evaluate(self, results):
        return self._finish(results, None)


@register_checker("tnas-online", "H", "check.tnas_online",
                  fixable="fix-tunnel", weight=0.03)
class TnasOnline(BaseChecker):
    def collect(self):
        service_status = self.cfg.get("_tos_services", {})
        tnas = next((i for i in self.nics["interfaces"] if i.get("type") == "tunnel"), None)
        return {"api": service_status.get("tnas_online") if service_status.get("available") else None,
                "tnas": tnas}

    def evaluate(self, data):
        api = data.get("api") if isinstance(data.get("api"), dict) else {}
        tnas = data.get("tnas")
        api_code = api.get("code") if isinstance(api.get("code"), int) else None
        connect_status = (api.get("connect_status")
                          if isinstance(api.get("connect_status"), int) else None)

        # TOS 7's Remote Access page treats code=2 and connect_status=2 as a
        # live connection. That official state is authoritative even when the
        # virtual network blocks ICMP or the public fallback DNS fails.
        if api_code == 2 and connect_status == 2:
            return self.pass_("enabled · connected", "enabled and connected",
                              "TOS service reports TNAS.online connected")

        if api_code == 0:
            return self.na("TNAS.online is disabled")

        api_enabled = api_code is not None and api_code >= 1

        if tnas is None:
            if api_enabled:
                return self.fail("enabled · no tunnel interface", "tnas0 present",
                                 "tnas_online_enabled_but_tnas0_missing")
            return self.na("TNAS.online is disabled (no tnas0 interface)")

        if tnas.get("operstate") not in ("up", "unknown"):
            return self.fail("enabled · disconnected", "up and connected",
                             "tunnel_down")
        if api_enabled:
            return self.fail("enabled · connecting", "enabled and connected",
                             f"TOS service reports code={api_code}, "
                             f"connect_status={connect_status}")

        # Without the official state API, an up tnas0 only proves that the
        # interface exists; TOS may deliberately not answer gateway ICMP.
        return self.warn("enabled · state unknown", "enabled and connected",
                         "tnas0 is up but the TOS status API is unavailable")


@register_checker("ddns", "H", "check.ddns", weight=0.02)
class Ddns(BaseChecker):
    """Evaluate the official TOS DDNS record/update state.

    TOS marks a record connected when either IPv4 or IPv6 had a successful
    update (``last_update_result`` / ``v6_last_update_result``).
    """
    def collect(self):
        service_status = self.cfg.get("_tos_services", {})
        return {"api": service_status.get("ddns") if service_status.get("available") else None}

    @staticmethod
    def _successful(value: Any) -> bool:
        return value not in (None, False, "", 0)

    def evaluate(self, data):
        api = data.get("api") if isinstance(data.get("api"), dict) else None
        records = api.get("records") if isinstance(api, dict) else None
        if not isinstance(records, list):
            return self.na("DDNS status is unavailable (a TOS session is required)")
        if not records:
            return self.na("DDNS is disabled (no records configured)")

        enabled = []
        for record in records:
            if not isinstance(record, dict):
                continue
            value = record.get("enabled", False)
            if value is True or str(value).lower() == "true":
                enabled.append(record)
        if not enabled:
            return self.na("DDNS is disabled (all records are disabled)")

        connected = [r for r in enabled
                     if self._successful(r.get("last_update_result"))
                     or self._successful(r.get("v6_last_update_result"))]
        if connected:
            return self.pass_(f"enabled · connected ({len(connected)}/{len(enabled)})",
                              "enabled and connected",
                              f"{len(connected)} of {len(enabled)} DDNS records updated successfully")
        return self.fail(f"enabled · disconnected (0/{len(enabled)})",
                         "enabled and connected",
                         f"DDNS update failed for {len(enabled)} enabled record(s)")


@register_checker("ntp-server", "H", "check.ntp_server", fixable="fix-time", weight=0.02)
class NtpServer(BaseChecker):
    def collect(self):
        active = self.probe(["systemctl", "is-active", "ntp.service"], timeout=2).stdout.strip()
        peers = self.probe(["ntpq", "-c", "peers"], timeout=3).stdout
        return active, peers

    def evaluate(self, data):
        active, peers = data
        if active != "active":
            return self.na("ntp.service not enabled")
        sync_line = [l for l in peers.splitlines() if l.startswith(("*", "+"))]
        if sync_line:
            return self.pass_("synced with upstream", "synchronized", "")
        # upstream candidates reachable but not yet selected: marginal upstream
        # quality (far/jittery peers) makes ntpd flap sync; warn instead of fail
        # so the user is not pushed into a fix->rescan-failed loop (M3 finding)
        for line in peers.splitlines():
            fields = line.split()
            if (len(fields) >= 7 and "LOCAL" not in line
                    and fields[6].isdigit() and int(fields[6], 8) > 0):
                return self.warn("upstream reachable, sync pending (unstable upstream)",
                                 "synchronized", "ntp_sync_pending")
        return self.fail("no synced peer", "synchronized",
                         "ntp_unreachable: ntp active but unsynchronized")
