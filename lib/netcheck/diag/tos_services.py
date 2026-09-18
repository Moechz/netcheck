"""Read-only TOS service status bridge.

TOS 7 exposes the state consumed by its Remote Access page at:
  * ``/v2/srv/online2/status`` for TNAS.online
  * ``/v2/ddns/`` for DDNS records
  * ``/v2/networkSet/GetProxyConf`` for TOS proxy settings

Those endpoints are session-protected.  When the NetCheck WebUI starts a scan,
the TOS iframe proxy forwards the browser's TOS cookie and CSRF headers to this
backend.  This module reuses that request context for two local, read-only GET
requests.  Credentials are never logged or persisted, and only loopback TOS
hosts are allowed.
"""
from __future__ import annotations

import json
import ssl
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

TOS_ONLINE_PATH = "/v2/srv/online2/status"
DDNS_PATH = "/v2/ddns/"
TOS_PROXY_PATH = "/v2/networkSet/GetProxyConf"

FetchFn = Callable[[str, Dict[str, str], float], Tuple[int, Any]]


def _cookie_value(cookie_header: str, name: str) -> str:
    prefix = f"{name}="
    for raw in cookie_header.split(";"):
        item = raw.strip()
        if item.startswith(prefix):
            return item[len(prefix):]
    return ""


def _local_base_urls(headers: Dict[str, str]) -> List[str]:
    """Build safe local TOS URLs from proxy headers, newest TOS layout first."""
    forwarded_host = headers.get("x-forwarded-host", "").split(",", 1)[0].strip()
    host_header = headers.get("host", "").split(",", 1)[0].strip()
    raw_host = forwarded_host or host_header
    candidates: List[str] = []

    if raw_host:
        # The TOS host may be a remote NAS address, but the request is made by
        # the backend on that NAS.  Preserve the local port and scheme only.
        hostname = raw_host.rstrip("]").split(":", 1)[0].strip("[]")
        port = ""
        if ":" in raw_host:
            port = raw_host.rsplit(":", 1)[1]
        scheme = headers.get("x-forwarded-proto", "").split(",", 1)[0].strip()
        if scheme not in ("http", "https"):
            scheme = "https" if port == "443" else "http"
        if hostname and port.isdigit() and 1 <= int(port) <= 65535:
            default = "443" if scheme == "https" else "80"
            suffix = "" if port == default else f":{port}"
            candidates.append(f"{scheme}://127.0.0.1{suffix}")

    # TOS 7 installations commonly expose the desktop on a dedicated HTTP port.
    # Keep the normal HTTP ports as no-harm fallbacks; closed ports fail fast.
    candidates.extend(("http://127.0.0.1:8181", "http://127.0.0.1"))

    seen = set()
    unique = []
    for url in candidates:
        if url not in seen:
            seen.add(url)
            unique.append(url)
    return unique


def _is_local_https_or_http(url: str) -> bool:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https") or parsed.hostname is None:
        return False
    return parsed.hostname in ("127.0.0.1", "localhost", "::1")


def _default_fetch(url: str, headers: Dict[str, str], timeout: float) -> Tuple[int, Any]:
    request = Request(url, headers=headers, method="GET")
    context = ssl._create_unverified_context()  # local TOS certificate is self-signed
    try:
        with urlopen(request, timeout=timeout, context=context) as response:
            raw = response.read(512 * 1024)
            return int(response.status), json.loads(raw.decode("utf-8"))
    except HTTPError as exc:
        exc.read(4096)
        return int(exc.code), None
    except (URLError, TimeoutError, OSError, UnicodeError, json.JSONDecodeError):
        return 0, None


def _payload(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Unwrap the TOS platform envelope without accepting nested wrappers."""
    data = raw.get("data")
    if isinstance(data, dict) and isinstance(data.get("data"), dict):
        return {}
    return data if isinstance(data, dict) else raw


def _sanitize_online(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Keep only state fields; TOS may return account identifiers."""
    payload = _payload(raw)
    return {key: payload.get(key) for key in ("code", "status", "connect_status")
            if key in payload}


def _sanitize_ddns(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Keep only per-record enable/update state; never retain credentials."""
    payload = _payload(raw)
    records = []
    source = payload.get("records")
    if isinstance(source, list):
        for record in source:
            if not isinstance(record, dict):
                continue
            records.append({key: record.get(key) for key in
                            ("enabled", "last_update_result",
                             "v6_last_update_result") if key in record})
    return {"records": records}


def _sanitize_proxy(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Keep proxy endpoint/state fields; never retain credentials."""
    payload = _payload(raw)
    allowed = ("enabled", "server", "port", "auth_enabled", "bypass_local",
               "advanced_enabled", "no_proxy")
    result = {key: payload.get(key) for key in allowed if key in payload}
    for protocol in ("http", "https", "socks"):
        source = payload.get(protocol)
        if isinstance(source, dict):
            result[protocol] = {
                key: source.get(key) for key in
                ("enabled", "server", "port", "auth_enabled") if key in source
            }
    return result


def collect_current_status(headers: Dict[str, str], timeout: float = 2.0,
                           fetch: Optional[FetchFn] = None) -> Dict[str, Any]:
    """Return sanitized TNAS.online/DDNS state; never return raw credentials."""
    cookie = headers.get("cookie", "")
    if not cookie:
        return {"available": False, "reason": "tos_session_unavailable"}

    request_headers = {"Accept": "application/json", "Cookie": cookie}
    csrf = _cookie_value(cookie, "X-Csrf-Token")
    if csrf:
        request_headers["X-Csrf-Token"] = csrf

    fetch_fn = fetch or _default_fetch
    for base in _local_base_urls(headers):
        if not _is_local_https_or_http(base):
            continue
        online_status, online = fetch_fn(base + TOS_ONLINE_PATH,
                                         request_headers, timeout)
        if online_status <= 0 or not isinstance(online, dict):
            continue

        ddns_status, ddns = fetch_fn(base + DDNS_PATH, request_headers, timeout)
        proxy_status, proxy = fetch_fn(base + TOS_PROXY_PATH,
                                       request_headers, timeout)
        if ddns_status <= 0:
            return {"available": False, "reason": "tos_api_unreachable",
                    "http_status": ddns_status}
        if ddns_status != 200 or not isinstance(ddns, dict):
            return {"available": False, "reason": "tos_api_forbidden",
                    "http_status": ddns_status}

        return {
            "available": True,
            "tnas_online": _sanitize_online(online),
            "ddns": _sanitize_ddns(ddns),
            "proxy": _sanitize_proxy(proxy) if proxy_status == 200 and isinstance(proxy, dict) else None,
        }

    return {"available": False, "reason": "tos_api_unreachable"}
