"""Report assembly + weighted health score (design sections 3.3/3.4/5.2)."""
from __future__ import annotations
from datetime import datetime
from typing import Dict, List

WEIGHTS: Dict[str, float] = {
    # A
    "link-state": 0.05, "link-speed": 0.03, "link-duplex": 0.02, "link-errors": 0.02,
    # B
    "ipv4-addr": 0.04, "ipv4-mask": 0.01, "dhcp-lease": 0.02, "gateway-subnet": 0.02,
    "gateway-reach": 0.05, "ip-conflict": 0.02,
    # C
    "default-route": 0.05, "connected-routes": 0.02,
    # D
    "dns-config": 0.03, "dns-reachable": 0.04, "dns-resolve": 0.04,
    # E
    "ipv6-global-addr": 0.01, "ipv6-default-route": 0.01, "ipv6-dns": 0.01,
    "ipv6-reach": 0.02,
    # F
    "wan-ping": 0.04, "wan-tcp": 0.07, "proxy-firewall": 0.03,
    # G
    "mtu-probe": 0.02, "system-time": 0.03, "conn-exhaust": 0.02,
    # H
    "tos-update-server": 0.05, "tos-market": 0.05,
    "tnas-online": 0.03, "ddns": 0.02, "ntp-server": 0.02,
    # I
    "smb-service": 0.02, "nfs-service": 0.01, "bond-lacp": 0.02,
    "bond-throughput": 0.02, "smb-multichannel": 0.01,
}

GROUP_NAMES = {
    "A": "link", "B": "ipv4", "C": "routes", "D": "dns", "E": "ipv6",
    "F": "internet", "G": "other", "H": "tos_services", "I": "transport",
}

# Canonical intra-group ordering (design appendix listing order, not alphabetical)
CANONICAL_ORDER = [
    "link-state", "link-speed", "link-duplex", "link-errors",
    "ipv4-addr", "ipv4-mask", "dhcp-lease", "gateway-subnet", "gateway-reach", "ip-conflict",
    "default-route", "connected-routes",
    "dns-config", "dns-reachable", "dns-resolve",
    "ipv6-global-addr", "ipv6-default-route", "ipv6-dns", "ipv6-reach",
    "wan-ping", "wan-tcp", "proxy-firewall",
    "mtu-probe", "system-time", "conn-exhaust",
    "tos-update-server", "tos-market", "tnas-online", "ddns", "ntp-server",
    "smb-service", "nfs-service", "bond-lacp", "bond-throughput", "smb-multichannel",
]
_ORDER_IDX = {cid: i for i, cid in enumerate(CANONICAL_ORDER)}


def compute_score(results: List[dict]) -> int:
    applicable = [r for r in results if r["status"] in ("pass", "warn", "fail")]
    total = sum(WEIGHTS.get(r["id"], 0.01) for r in applicable)
    if total == 0:
        return 100
    penalty = sum((10.0 if r["status"] == "fail" else 3.0 if r["status"] == "warn" else 0.0)
                  * WEIGHTS.get(r["id"], 0.01) for r in applicable)
    return max(0, round(100 - 100.0 * penalty / (10.0 * total)))


def level(score: int) -> str:
    return "fault" if score < 70 else ("warning" if score < 90 else "healthy")


def build_report(results: list, job_id: str, started_at: float,
                 duration_ms: float) -> dict:
    ordered = sorted(results, key=lambda r: (r["group"], _ORDER_IDX.get(r["id"], 999)))
    started_iso = datetime.fromtimestamp(started_at).astimezone().isoformat(
        timespec="milliseconds")
    event_log: List[dict] = [
        {
            "ts": started_iso,
            "event": "check.result",
            "group": result["group"],
            "check_id": result["id"],
            "status": result["status"],
            "detail": result.get("detail") or {},
        }
        for result in ordered
    ]
    score = compute_score(ordered)
    groups: Dict[str, list] = {}
    for r in ordered:
        groups.setdefault(r["group"], []).append(r)
    issues = [{"id": r["id"], "group": r["group"], "status": r["status"],
               "severity": "critical" if r["status"] == "fail" else "warning",
               "reason": (r.get("detail") or {}).get("reason", ""),
               "fixable": r["fixable"]}
              for r in ordered if r["status"] in ("fail", "warn")]
    summary = {s: sum(1 for r in ordered if r["status"] == s)
               for s in ("pass", "warn", "fail", "na")}
    summary["total"] = len(ordered)
    return {
        "job_id": job_id,
        "started_at": started_at,
        "duration_ms": round(duration_ms, 1),
        "score": score, "level": level(score),
        "groups": groups, "issues": issues,
        "log": event_log,
        "fixable": [r["id"] for r in ordered if r["fixable"] and r["status"] in ("fail", "warn")],
        "summary": summary,
    }
