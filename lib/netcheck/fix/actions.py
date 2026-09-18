"""Whitelist action specs + parameter validation (security review sections 5/6).

The same validation runs on both sides: the FixEngine validates before sending,
the helper re-validates after receiving (defense in depth).
"""
from __future__ import annotations
import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple

ACTIONS = ("link-toggle", "net-reload", "net-apply", "dns-set", "gateway-set",
           "sysctl-ipv6", "mtu-set", "svc-restart", "snap-restore")

IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
IPV4_RE = re.compile(
    r"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$")
UNIT_ENUM = {"systemd-networkd.service", "ntp.service", "netplug.service"}
SNAP_ID_RE = re.compile(r"^[A-Fa-f0-9-]{1,64}$")


class ParamError(ValueError):
    pass


def _req(params: Dict[str, Any], key: str, types) -> Any:
    if key not in params:
        raise ParamError(f"missing parameter: {key}")
    v = params[key]
    if not isinstance(v, types):
        raise ParamError(f"parameter {key} has wrong type")
    return v


def _iface(v: str) -> str:
    if not isinstance(v, str) or not IFACE_RE.match(v) or v in ("lo", "docker0", "tnas0", "all", "default"):
        raise ParamError(f"interface not allowed: {v!r}")
    return v


def _ipv4(v: str) -> str:
    if not isinstance(v, str) or not IPV4_RE.match(v) or v == "0.0.0.0":
        raise ParamError(f"invalid IPv4: {v!r}")
    return v


def _dns_list(v: Any) -> List[str]:
    if not isinstance(v, list) or not 1 <= len(v) <= 3:
        raise ParamError("dns must be a list of 1-3 entries")
    out = []
    for item in v:
        try:
            addr = ipaddress.ip_address(item)
        except ValueError:
            raise ParamError(f"invalid DNS server: {item!r}")
        if addr.is_unspecified:
            raise ParamError("0.0.0.0 is not a valid DNS server")
        out.append(str(addr))
    return out


def validate(action: str, params: Dict[str, Any],
             allowed_ifaces: Optional[List[str]] = None) -> Dict[str, Any]:
    """Validate and normalize params for a whitelist action."""
    if action not in ACTIONS:
        raise ParamError(f"unknown action: {action!r}")
    p = params if isinstance(params, dict) else {}
    out: Dict[str, Any] = {}

    if action == "link-toggle":
        ifc = _iface(_req(p, "iface", str))
        direction = _req(p, "direction", str)
        if direction not in ("up", "down"):
            raise ParamError("direction must be up|down")
        out = {"iface": ifc, "direction": direction}

    elif action == "net-reload":
        # iface optional: without it only `networkctl reload` runs; with it the
        # M1-measured reload+reconfigure sequence re-solicits RA/DHCPv6
        if set(p) - {"iface"}:
            raise ParamError("net-reload takes only an optional iface parameter")
        out = {"iface": _iface(_req(p, "iface", str))} if "iface" in p else {}

    elif action == "net-apply":
        ifc = _iface(_req(p, "iface", str))
        mode = _req(p, "mode", str)
        if mode not in ("dhcp", "static", "reset"):
            raise ParamError("mode must be dhcp|static|reset")
        if mode == "reset" and set(p) - {"iface", "mode"}:
            raise ParamError("reset mode accepts only iface+mode")
        out = {"iface": ifc, "mode": mode}
        if mode == "static":
            out["ipv4"] = _ipv4(_req(p, "ipv4", str))
            prefix = _req(p, "prefix", int)
            if not 1 <= prefix <= 30:
                raise ParamError("prefix out of range [1,30]")
            out["prefix"] = prefix
            if "gateway" in p:
                gw = _ipv4(p["gateway"])
                # gateway must be in the same subnet (security review A3)
                net = ipaddress.ip_interface(f"{out['ipv4']}/{prefix}").network
                if ipaddress.ip_address(gw) not in net:
                    raise ParamError("gateway not in the same subnet")
                out["gateway"] = gw
            if "dns" in p:
                out["dns"] = _dns_list(p["dns"])
        if "mtu" in p:
            mtu = p["mtu"]
            if not isinstance(mtu, int) or not 1280 <= mtu <= 9000:
                raise ParamError("mtu out of range [1280,9000]")
            out["mtu"] = mtu

    elif action == "dns-set":
        ifc = _iface(_req(p, "iface", str))
        out = {"iface": ifc, "dns": _dns_list(p.get("dns", []))}

    elif action == "gateway-set":
        ifc = _iface(_req(p, "iface", str))
        gateway = _ipv4(_req(p, "gateway", str))
        ipv4 = _ipv4(_req(p, "ipv4", str))
        prefix = _req(p, "prefix", int)
        if not 1 <= prefix <= 32:
            raise ParamError("prefix out of range [1,32]")
        network = ipaddress.ip_interface(f"{ipv4}/{prefix}").network
        if ipaddress.ip_address(gateway) not in network:
            raise ParamError("gateway not in the same subnet")
        out = {"iface": ifc, "gateway": gateway, "ipv4": ipv4, "prefix": prefix}

    elif action == "sysctl-ipv6":
        ifc = _iface(_req(p, "iface", str))
        out = {"iface": ifc}

    elif action == "mtu-set":
        ifc = _iface(_req(p, "iface", str))
        mtu = _req(p, "mtu", int)
        if not 1280 <= mtu <= 9000:
            raise ParamError("mtu out of range [1280,9000]")
        out = {"iface": ifc, "mtu": mtu}

    elif action == "svc-restart":
        unit = _req(p, "unit", str)
        if unit not in UNIT_ENUM:
            raise ParamError(f"unit not in enum: {unit!r}")
        out = {"unit": unit}

    elif action == "snap-restore":
        snap_id = _req(p, "snapshot_id", str)
        if not SNAP_ID_RE.match(snap_id):
            raise ParamError("invalid snapshot id")
        out = {"snapshot_id": snap_id}

    # optional collector whitelist cross-check (A1: iface in collector result)
    if allowed_ifaces is not None and "iface" in out and out["iface"] not in allowed_ifaces:
        raise ParamError(f"iface not in collector whitelist: {out['iface']!r}")
    return out


def build_argv(action: str, params: Dict[str, Any],
               bins: Dict[str, str]) -> List[List[str]]:
    """Build execve argv lists for an action (parameters MUST be pre-validated)."""
    if action == "link-toggle":
        return [[bins["ip"], "link", "set", params["iface"], params["direction"]]]
    if action == "net-reload":
        argvs = [[bins["networkctl"], "reload"]]
        if params.get("iface"):
            argvs.append([bins["networkctl"], "reconfigure", params["iface"]])
        return argvs
    if action == "dns-set":
        if params["dns"]:
            return [[bins["resolvectl"], "dns", params["iface"]] + params["dns"]]
        return [[bins["resolvectl"], "revert", params["iface"]]]  # T6 measured
    if action == "gateway-set":
        # File-backed, backup/rollback action; no direct argv is safe.
        raise ParamError("gateway-set has no direct argv")
    if action == "sysctl-ipv6":
        return [[bins["sysctl"], "-w",
                 f"net.ipv6.conf.{params['iface']}.disable_ipv6=0"]]
    if action == "mtu-set":
        return [[bins["ip"], "link", "set", params["iface"], "mtu", str(params["mtu"])]]
    if action == "svc-restart":
        return [[bins["systemctl"], "restart", params["unit"]]]
    raise ParamError(f"action {action} has no direct argv (file-based)")
