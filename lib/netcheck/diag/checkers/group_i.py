"""Group I - transport: SMB/NFS services, bond LACP/throughput, multichannel."""
from __future__ import annotations

import re

from ..engine import BaseChecker, register_checker
from ._util import gate_bond


@register_checker("smb-service", "I", "check.smb_service", weight=0.02)
class SmbService(BaseChecker):
    def collect(self):
        pgrep = self.probe(["pgrep", "-x", "smbd"], timeout=2)
        listen = self.probe(["ss", "-ltn"], timeout=2).stdout
        return pgrep.rc, ":445" in listen

    def evaluate(self, data):
        pgrep_rc, listening = data
        if pgrep_rc == 0 and listening:
            return self.pass_("smbd running, 445 listening", "running", "")
        if pgrep_rc == 0 and not listening:
            return self.fail("smbd running but 445 not listening", "445 listening",
                             "smbd_down: service not accepting")
        return self.fail("smbd not running", "running",
                         "smbd_down: enable SMB in TOS control panel")


@register_checker("nfs-service", "I", "check.nfs_service", weight=0.01)
class NfsService(BaseChecker):
    def collect(self):
        listen = self.probe(["ss", "-ltn"], timeout=2).stdout
        exports = ""
        try:
            with open("/etc/exports", encoding="utf-8", errors="replace") as f:
                exports = f.read().strip()
        except OSError:
            exports = ""
        return ":2049" in listen, bool(exports)

    def evaluate(self, data):
        listening, has_exports = data
        if listening:
            return self.pass_("2049 listening", "running", "")
        if has_exports:
            return self.fail("exports present but service down", "2049 listening",
                             "nfsd_down")
        return self.na("NFS not enabled")


@register_checker("bond-lacp", "I", "check.bond_lacp", fixable="fix-aggregation", weight=0.02,
                  na_fn=lambda ctx: not gate_bond(ctx))
class BondLacp(BaseChecker):
    def collect(self):
        show = self.probe(["ovs-vsctl", "show"], timeout=3).stdout
        # TOS link aggregation often builds a kernel bond and attaches it to
        # the OVS bridge as a plain system port; ovs-vsctl never prints
        # "type: bond" for it, so read the kernel bonding state for every
        # bond the collector classified (device finding 2026-09-15).
        kernel = {}
        for i in self.nics.get("interfaces", []):
            if i.get("type") != "bond":
                continue
            r = self.probe(["cat", f"/proc/net/bonding/{i['name']}"], timeout=2)
            m = re.search(r"Bonding Mode:\s*(.+)", r.stdout)
            if m:
                kernel[i["name"]] = m.group(1).strip()
        return {"show": show, "kernel": kernel}

    def evaluate(self, data):
        show, kernel = data["show"], data["kernel"]
        if kernel:
            # kernel bond(s) present - the TOS control-panel form
            for name, mode in sorted(kernel.items()):
                if "802.3AD" in mode.upper():
                    return self.pass_(f"{name}: 802.3AD (LACP)",
                                      "lacp negotiated", "")
            name, mode = sorted(kernel.items())[0]
            return self.warn(f"{name}: {mode}", "802.3AD (LACP)",
                             "bond_mode_not_lacp")
        # OVS-native bonds: "ovs-vsctl show" does not label bond ports, so the
        # authoritative columns of "list port" decide (lacp / bond_mode).
        ports = self.probe(["ovs-vsctl", "list", "port"], timeout=3).stdout
        lacp = re.search(r"^lacp\s*:\s*(active|passive)\s*$", ports, re.M)
        mode = re.search(r"^bond_mode\s*:\s*(\S.*)$", ports, re.M)
        bond_mode_set = bool(mode) and mode.group(1).strip() not in ("[]", "")
        if lacp:
            return self.pass_("bond with LACP config present", "negotiated", "")
        if bond_mode_set:
            return self.warn(f"bond_mode {mode.group(1).strip()}", "lacp negotiated",
                             "bond_mode_not_lacp")
        if "type: bond" in show:  # legacy OVS output fallback
            return self.fail("bond port without LACP config", "lacp negotiated",
                             "lacp_not_negotiated")
        return self.na("no bond configured")


@register_checker("bond-throughput", "I", "check.bond_throughput", fixable="fix-aggregation",
                  weight=0.02, na_fn=lambda ctx: not gate_bond(ctx))
class BondThroughput(BaseChecker):
    def collect(self):
        return None  # requires a configured iperf3 peer (diagnosis-side skip)

    def evaluate(self, _):
        return self.na("no iperf3 peer configured; verify via LAN speed test mode A")


@register_checker("smb-multichannel", "I", "check.smb_multichannel", weight=0.01)
class SmbMultichannel(BaseChecker):
    def collect(self):
        testparm = self.probe(["testparm", "-s"], timeout=3).stdout
        ports = len(self.physical_ports())
        return testparm, ports

    def evaluate(self, data):
        testparm, ports = data
        if ports < 2:
            return self.na("single physical port")
        low = testparm.lower()
        setting = re.search(r"server\s+multi\s+channel\s+support\s*=\s*([^\r\n]+)",
                            low)
        if setting and setting.group(1).strip().startswith("no"):
            # Optional and disabled is a neutral configuration state. It must
            # not look like a healthy enabled feature (PASS) or a fault (WARN).
            return self.na("disabled (optional feature); enable in Samba if needed")
        return self.pass_(f"{ports} ports, multichannel available", "enabled", "")
