"""Route table + middleware chain: request_id -> auth -> rate_limit -> route -> error_map."""
from __future__ import annotations
import re
import secrets
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

# Error codes (Technical Design 4.1)
E_OK = 0
E_UNAUTHORIZED = 1001
E_BAD_REQUEST = 1002
E_RATE_LIMITED = 1003
E_TASK_RUNNING = 2001
E_NO_FAULT = 2002
E_HELPER_UNAVAILABLE = 3001
E_FIX_FAILED = 3002
E_TARGET_UNREACHABLE = 4001
E_INTERNAL = 5000

_PUBLIC_PATHS = {"/health", "/api/auth/status"}
_PUBLIC_PREFIXES = ("/api/auth/setup", "/api/auth/login",
                     "/api/auth/recover")


class Request:
    def __init__(self, method: str, path: str, query: Dict[str, str],
                 headers: Dict[str, str], body: Any, req_id: str):
        self.method = method
        self.path = path
        self.query = query
        self.headers = headers
        self.body = body if isinstance(body, dict) else {}
        self.req_id = req_id
        self.params: Dict[str, str] = {}
        self.actor = "anonymous"


class Response:
    def __init__(self, code: int = E_OK, message: str = "ok", data: Any = None,
                 http_status: int = 200):
        self.code = code
        self.message = message
        self.data = data
        self.http_status = http_status

    @staticmethod
    def ok(data: Any = None) -> "Response":
        return Response(E_OK, "ok", data)

    @staticmethod
    def err(code: int, message: str, http_status: int = 400) -> "Response":
        return Response(code, message, None, http_status)


Handler = Callable[[Request], Response]
RouteEntry = Tuple[re.Pattern, str, Handler]  # (pattern, method, handler)


class _RateLimiter:
    """Simple sliding-window limiter: {key: [timestamps]}."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._hits: Dict[str, List[float]] = {}

    def allow(self, key: str, limit: int, window_sec: float) -> bool:
        now = time.time()
        with self._lock:
            hits = [t for t in self._hits.get(key, []) if now - t < window_sec]
            if len(hits) >= limit:
                self._hits[key] = hits
                return False
            hits.append(now)
            self._hits[key] = hits
            return True


class Router:
    """Routes + middleware. Services are injected via ctx dict."""

    def __init__(self, services: Dict[str, Any]):
        self.services = services
        self.routes: List[RouteEntry] = []
        self.limiter = _RateLimiter()

    def add(self, method: str, pattern: str) -> Callable[[Handler], Handler]:
        regex = re.compile("^" + re.sub(r"\{(\w+)\}", r"(?P<\1>[^/]+)", pattern) + "$")

        def deco(fn: Handler) -> Handler:
            self.routes.append((regex, method.upper(), fn))
            return fn
        return deco

    # ---------------- middleware ----------------
    @staticmethod
    def _is_public(path: str) -> bool:
        return path in _PUBLIC_PATHS or path.startswith(_PUBLIC_PREFIXES)

    def _check_auth(self, req: Request) -> Optional[Response]:
        auth_srv = self.services["auth"]
        header = req.headers.get("authorization", "")
        token = header[7:].strip() if header.lower().startswith("bearer ") else ""
        if not auth_srv.check_session(token):
            return Response.err(E_UNAUTHORIZED, "unauthorized", 401)
        req.actor = auth_srv.username()
        return None

    def dispatch(self, method: str, path: str, query: Dict[str, str],
                 headers: Dict[str, str], body: Any) -> Response:
        req_id = headers.get("x-request-id") or secrets.token_hex(8)
        req = Request(method, path, query, headers, body, req_id)
        try:
            # route match
            matched_path = False
            for regex, route_method, handler in self.routes:
                m = regex.match(path)
                if not m:
                    continue
                matched_path = True
                if route_method != method.upper():
                    continue
                req.params = m.groupdict()
                # auth (public paths bypass)
                if not self._is_public(path):
                    resp = self._check_auth(req)
                    if resp is not None:
                        return resp
                # global write rate-limit guard: settings writes 10/min per actor
                if method.upper() == "POST" and path.startswith("/api/settings"):
                    if not self.limiter.allow(f"settings:{req.actor}", 10, 60):
                        return Response.err(E_RATE_LIMITED, "rate limited", 429)
                return handler(req)
            if matched_path:
                return Response.err(E_BAD_REQUEST, "method not allowed", 405)
            return Response.err(E_BAD_REQUEST, "not found", 404)
        except Exception as exc:  # noqa: BLE001 - top-level boundary
            logger = self.services.get("logger")
            if logger:
                logger.exception("route_error", extra={"req_id": req_id})
            return Response.err(E_INTERNAL, f"internal error: {type(exc).__name__}", 500)
