"""Group A - link layer: state, speed, duplex, errors (physical ports)."""
from __future__ import annotations
import time

from ..engine import BaseChecker, register_checker


@register_checker("link-state", "A", "check.link_state", timeout=3,
                  fixable=None, weight=0.05)
class LinkState(BaseChecker):
    def collect(self):
        return self.physical_ports()

    def evaluate(self, ports):
        if not ports:
            return self.na("no physical ports")
        up = [p for p in ports if p.get("operstate") == "up"]
        down = [p for p in ports if p.get("operstate") != "up"]
        if not down:
            return self.pass_(f"all {len(ports)} up", "up", "")
        # An unplugged physical port is a runtime fact, not a health failure.
        # Report it for visibility while other checks determine whether the
        # NAS still has a usable management/network path.
        down_text = ", ".join(f"{p['name']}={p.get('operstate') or 'unknown'}" for p in down)
        return self.pass_(f"{len(up)} up, {len(down)} down ({down_text})",
                          "up or unconnected", "unconnected physical ports are informational only")


@register_checker("link-speed", "A", "check.link_speed", timeout=3,
                  fixable="fix-link", weight=0.03)
class LinkSpeed(BaseChecker):
    def collect(self):
        return self.physical_ports()

    def evaluate(self, ports):
        if not ports:
            return self.na("no physical ports")
        degraded = [p for p in ports if p.get("speed_mbps") and p["speed_mbps"] < 1000]
        unknown = [p for p in ports if not p.get("speed_mbps") and p.get("operstate") == "up"]
        if degraded:
            p = degraded[0]
            return self.warn(f"{p['name']}={p['speed_mbps']}Mb/s", ">=1000Mb/s",
                             "degraded: negotiated below port capability")
        if unknown:
            return self.fail(",".join(p["name"] for p in unknown) + " speed unknown",
                             "numeric speed", "unknown: speed unreadable")
        return self.pass_(f"all >=1000Mb/s ({ports[0]['name']}={ports[0].get('speed_mbps')}Mb/s)",
                          ">=1000Mb/s", "")


@register_checker("link-duplex", "A", "check.link_duplex", timeout=3,
                  fixable=None, weight=0.02)
class LinkDuplex(BaseChecker):
    def collect(self):
        return self.physical_ports()

    def evaluate(self, ports):
        if not ports:
            return self.na("no physical ports")
        # Duplex is reported by the PHY after carrier negotiation. A down port
        # has no meaningful duplex; link-state already reports that condition.
        connected = [p for p in ports if p.get("operstate") == "up"]
        if not connected:
            return self.na("duplex unavailable while all physical links are down")
        half = [p["name"] for p in connected if p.get("duplex") == "half"]
        if half:
            return self.warn(",".join(half) + " half", "full",
                             "half_duplex: collisions cause loss/slowness")
        if all(p.get("duplex") == "full" for p in connected):
            down = len(ports) - len(connected)
            reason = f"{down} down port(s) are handled by link-state" if down else ""
            return self.pass_("full", "full", reason)
        unknown = [p["name"] for p in connected if p.get("duplex") != "full"]
        return self.warn(",".join(unknown) + " duplex unreadable", "full",
                         "duplex_unreadable: check driver, cable, and switch port")


@register_checker("link-errors", "A", "check.link_errors", timeout=4,
                  fixable="fix-link", weight=0.02)
class LinkErrors(BaseChecker):
    def collect(self):
        # double-read stats ~1s apart for a delta (design 4.1.4)
        s1 = {p["name"]: p.get("rx_errors", 0) for p in self.physical_ports()}
        time.sleep(1.0)
        s2 = {p["name"]: p.get("rx_errors", 0)
              for p in self.nics["interfaces"] if p.get("type") == "physical"}
        return {k: s2.get(k, 0) - s1.get(k, 0) for k in s1}, s1

    def evaluate(self, data):
        deltas, _ = data
        threshold = self.cfg.get("error_delta_threshold", 10)
        if not deltas:
            return self.na("no physical ports")
        worst = max(deltas.items(), key=lambda kv: kv[1])
        if worst[1] > threshold:
            return self.fail(f"{worst[0]} delta={worst[1]}", f"delta<={threshold}",
                             "error_burst: rx error burst (bad cable?)")
        if worst[1] > 0:
            return self.warn(f"{worst[0]} delta={worst[1]}", "0",
                             "error_burst: minor error growth")
        return self.pass_("delta=0", f"<= {threshold}", "")
