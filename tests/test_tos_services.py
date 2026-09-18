"""TOS Remote Access status bridge tests."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from netcheck.diag.tos_services import collect_current_status

PASS = FAIL = 0


def check(name, expected, actual):
    global PASS, FAIL
    if expected == actual:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name}: expected={expected!r} got={actual!r}")


check("no_cookie.skipped", False,
      collect_current_status({})["available"])

def fetch_ok(url, headers, timeout):
    check("request.csrf_forwarded", "csrf-token", headers.get("X-Csrf-Token"))
    if url.endswith("/v2/srv/online2/status"):
        return 200, {"data": {"code": 2, "connect_status": 2,
                              "user": "secret@example.com"},
                     "code_num": 0, "code": True}
    if url.endswith("/v2/ddns/"):
        return 200, {"data": {"records": [
            {"enabled": True, "last_update_result": "x", "user": "secret"}
        ]}, "code_num": 0, "code": True}
    if url.endswith("/v2/networkSet/GetProxyConf"):
        return 200, {"data": {"enabled": True, "server": "203.0.113.10",
                              "port": 7890, "auth_enabled": False,
                              "username": "secret", "password": "secret"},
                     "code_num": 0, "code": True}
    raise AssertionError(url)

headers = {
    "cookie": "X-Csrf-Token=csrf-token; TOS_SESSION=opaque",
    "host": "192.168.124.56:8181",
}
status = collect_current_status(headers, fetch=fetch_ok)
check("success.available", True, status["available"])
check("success.online_state", 2, status["tnas_online"]["code"])
check("success.online_connect_state", 2,
      status["tnas_online"]["connect_status"])
check("success.ddns_records", 1, len(status["ddns"]["records"]))
check("success.proxy_enabled", (True, "203.0.113.10", 7890),
      (status["proxy"]["enabled"], status["proxy"]["server"],
       status["proxy"]["port"]))
check("success.online_no_account", True,
      "user" not in status["tnas_online"])
check("success.ddns_no_credentials", True,
      all("user" not in record for record in status["ddns"]["records"]))
check("success.proxy_no_credentials", True,
      "username" not in status["proxy"] and "password" not in status["proxy"])

def fetch_forbidden(url, headers, timeout):
    if url.endswith("/v2/srv/online2/status"):
        return 200, {"code": 0}
    return 403, None

status = collect_current_status(headers, fetch=fetch_forbidden)
check("forbidden.available", False, status["available"])
check("forbidden.reason", "tos_api_forbidden", status["reason"])

def fetch_unreachable(url, headers, timeout):
    return 0, None

status = collect_current_status(headers, fetch=fetch_unreachable)
check("unreachable.available", False, status["available"])
check("unreachable.reason", "tos_api_unreachable", status["reason"])

print()
print(f"RESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
