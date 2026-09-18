"""DNS comparison: local vs public resolvers (F31)."""
from __future__ import annotations
import time
from typing import Any, Dict, List

from ..collectors import sysprobe

PUBLIC_DNS = ["223.5.5.5", "119.29.29.29", "8.8.8.8"]


def compare(domain: str, public_dns: List[str] = None) -> Dict[str, Any]:
    """Compare local DNS resolution against public resolvers."""
    dns_list = public_dns or PUBLIC_DNS
    results = {}

    # local resolution
    t0 = time.monotonic()
    r = sysprobe.run(["dig", "+short", domain, "A"], timeout=5)
    local_ms = round((time.monotonic() - t0) * 1000)
    local_ips = [ip for ip in r.stdout.strip().split("\n") if ip]

    results["local"] = {"ips": local_ips, "time_ms": local_ms, "rc": r.rc}

    # public resolvers
    for dns in dns_list[:3]:
        t0 = time.monotonic()
        r = sysprobe.run(["dig", f"@{dns}", "+short", domain, "A",
                          "+time=2", "+tries=1"], timeout=5)
        ms = round((time.monotonic() - t0) * 1000)
        ips = [ip for ip in r.stdout.strip().split("\n") if ip]
        results[dns] = {"ips": ips, "time_ms": ms, "rc": r.rc}

    # check for mismatch (possible hijack/poisoning)
    public_ips = set()
    for dns in dns_list[:3]:
        if dns in results:
            public_ips.update(results[dns]["ips"])
    mismatch = bool(local_ips and public_ips and
                    not set(local_ips) & public_ips)

    return {"domain": domain, "results": results, "mismatch": mismatch,
            "verdict": "possible_hijack" if mismatch else "consistent"}
