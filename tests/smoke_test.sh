#!/bin/bash
# NetCheck M2 skeleton smoke test: starts the server on a temp Unix socket
# and exercises health/auth/settings/jobs endpoints. Requires curl + python3.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN="$(mktemp -d /tmp/netcheck-smoke.XXXXXX)"
SOCK="$RUN/netcheck.sock"
PASS=0; FAIL=0

cleanup() { [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null; rm -rf "$RUN"; }
trap cleanup EXIT

api() { # api METHOD PATH [JSON_BODY] [TOKEN]
    local method="$1" path="$2" body="${3:-}" token="${4:-}" args=()
    args+=(-s --unix-socket "$SOCK" -X "$method" "http://localhost$path")
    [ -n "$body" ] && args+=(-H 'Content-Type: application/json' -d "$body")
    [ -n "$token" ] && args+=(-H "Authorization: Bearer $token")
    curl "${args[@]}"
}

check() { # check NAME EXPECT ACTUAL
    if [ "$2" = "$3" ]; then PASS=$((PASS+1)); echo "PASS $1";
    else FAIL=$((FAIL+1)); echo "FAIL $1  expected=[$2] got=[$3]"; fi
}

NETCHECK_ROOT="$ROOT" NETCHECK_DATA="$RUN/data" NETCHECK_LOGS="$RUN/logs" \
NETCHECK_SOCK="$SOCK" python3 "$ROOT/bin/netcheck" &
SRV_PID=$!
for i in $(seq 1 20); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "FATAL: server did not start"; cat "$RUN/logs/app.log" 2>/dev/null; exit 1; }

# 1. health (public)
check "health.code" "0" "$(api GET /health | python3 -c 'import json,sys;print(json.load(sys.stdin)["code"])')"
check "health.proxy_path" "0" "$(api GET /v2/proxy/netcheck/health | python3 -c 'import json,sys;print(json.load(sys.stdin)["code"])')"
check "health.proxy2_path" "0" "$(api GET /v2/proxy2/netcheck/health | python3 -c 'import json,sys;print(json.load(sys.stdin)["code"])')"
check "health.app_path" "0" "$(api GET /netcheck/health | python3 -c 'import json,sys;print(json.load(sys.stdin)["code"])')"
check "health.config_app_path" "0" "$(api GET /netcheck/netcheck/health | python3 -c 'import json,sys;print(json.load(sys.stdin)["code"])')"
# 2. version without auth -> 1001
check "version.unauth" "1001" "$(api GET /api/version | python3 -c 'import json,sys;print(json.load(sys.stdin)["code"])')"
# 3. first-run status is public but does not disclose the account
check "status.firstrun" "False False" "$(api GET /api/auth/status | python3 -c 'import json,sys;d=json.load(sys.stdin)["data"];print(d["initialized"], "username" in d)')"
# 4. setup + login
SETUP_OUT=$(api POST /api/auth/setup '{"username":"admin","password":"netcheck123"}')
check "setup.ok" "0" "$(echo "$SETUP_OUT" | python3 -c 'import json,sys;print(json.load(sys.stdin)["code"])')"
RECCODE=$(echo "$SETUP_OUT" | python3 -c 'import json,sys;print(json.load(sys.stdin)["data"]["recovery_code"])')
check "setup.recovery_code" "12" "${#RECCODE}"
check "setup.duplicate" "1002" "$(api POST /api/auth/setup '{"username":"x","password":"netcheck123"}' | python3 -c 'import json,sys;print(json.load(sys.stdin)["code"])')"
TOKEN=$(api POST /api/auth/login '{"username":"admin","password":"netcheck123"}' | python3 -c 'import json,sys;print(json.load(sys.stdin)["data"]["token"])')
check "login.token" "43" "${#TOKEN}"
check "status.auth" "True True admin" "$(api GET /api/auth/status "" "$TOKEN" | python3 -c 'import json,sys;d=json.load(sys.stdin)["data"];print(d["initialized"],d["authenticated"],d["username"])')"
# 5. authed endpoints
check "version.auth" "0" "$(api GET /api/version "" "$TOKEN" | python3 -c 'import json,sys;d=json.load(sys.stdin);v=d["data"];print(d["code"] if v.get("app_name")=="NetCheck" and v.get("developer")=="Moechz" and v.get("publisher")=="Moechz" and v.get("arch") and v.get("build_time") else 999)')"
check "settings.mode" "helper" "$(api GET /api/settings "" "$TOKEN" | python3 -c 'import json,sys;print(json.load(sys.stdin)["data"]["repair"]["mode"])')"
check "settings.write" "en-US" "$(api POST /api/settings '{"language":"en-US"}' "$TOKEN" | python3 -c 'import json,sys;print(json.load(sys.stdin)["data"]["language"])')"
# 6. bad login / bad token / 404 / bad JSON
check "login.bad" "1001" "$(api POST /api/auth/login '{"username":"admin","password":"wrongpass1"}' | python3 -c 'import json,sys;print(json.load(sys.stdin)["code"])')"
check "token.bad" "1001" "$(api GET /api/settings "" "badtoken" | python3 -c 'import json,sys;print(json.load(sys.stdin)["code"])')"
check "route.404" "1002" "$(api GET /api/nope "" "$TOKEN" | python3 -c 'import json,sys;print(json.load(sys.stdin)["code"])')"
check "body.badjson" "1002" "$(curl -s --unix-socket "$SOCK" -X POST -H 'Content-Type: application/json' -d '{bad' http://localhost/api/auth/login | python3 -c 'import json,sys;print(json.load(sys.stdin)["code"])')"
# 7. audit trail exists with expected actions
AUDIT="$RUN/logs/operation-audit.jsonl"
check "audit.exists" "yes" "$([ -s "$AUDIT" ] && echo yes || echo no)"
check "audit.actions" "auth.setup auth.setup auth.login settings.write auth.login" \
  "$(python3 -c 'import json;print(" ".join(json.loads(l)["action"] for l in open("'"$AUDIT"'")))')"
# 8. no password leak in any log
check "audit.noleak" "0" "$(grep -c netcheck123 "$RUN/logs"/*.log* "$RUN/logs"/*.jsonl* 2>/dev/null | awk -F: '{s+=$2}END{print s+0}')"
# 9. app.log is valid JSON lines
check "applog.jsonl" "ok" "$(python3 -c 'import json;[json.loads(l) for l in open("'"$RUN/logs/app.log"'")];print("ok")' 2>/dev/null || echo bad)"


# 10. new M3 endpoints
check "interfaces.schema" "0" "$(api GET /api/interfaces "" "$TOKEN" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["code"] if "arch" in d["data"] and "hostname" in d["data"] else 999)')"
check "status.schema" "0" "$(api GET /api/status "" "$TOKEN" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["code"] if "primary" in d["data"] and "online" in d["data"] and "hostname" in d["data"] else 999)')"
JOB=$(api POST /api/diag/run '{}' "$TOKEN" | python3 -c 'import json,sys;print(json.load(sys.stdin)["data"]["job_id"])')
check "diag.jobid" "yes" "$([ -n "$JOB" ] && echo yes || echo no)"
for i in $(seq 1 40); do
  ST=$(api GET "/api/diag/report?job_id=$JOB" "" "$TOKEN" | python3 -c 'import json,sys;print(json.load(sys.stdin)["data"]["state"])')
  [ "$ST" != "running" ] && break
  sleep 0.5
done
check "diag.done" "yes" "$([ "$ST" = "done" ] || [ "$ST" = "failed" ] && echo yes || echo no)"
check "diag.report.schema" "yes" "$(api GET "/api/diag/report?job_id=$JOB" "" "$TOKEN" | python3 -c 'import json,sys;d=json.load(sys.stdin)["data"]["report"];print("yes" if "score" in d and "groups" in d and "summary" in d else "no")')"
check "diag.history_saved" "1" "$(api GET /api/diag/history "" "$TOKEN" | python3 -c 'import json,sys;print(json.load(sys.stdin)["data"]["total"])')"
check "diag.history_export" "diagnosis True True True" "$(api GET "/api/diag/history/export?job_id=$JOB" "" "$TOKEN" | python3 -c 'import json,sys;d=json.load(sys.stdin)["data"];r=d["record"];print(d["type"], bool(d["log"]), bool(r.get("req_id")), bool(r.get("operator")))')"
check "diag.history_delete" "True" "$(api POST /api/diag/history/delete "{\"job_id\":\"$JOB\"}" "$TOKEN" | python3 -c 'import json,sys;print(json.load(sys.stdin)["data"]["deleted"])')"
check "diag.history_delete_missing" "1002" "$(api POST /api/diag/history/delete "{\"job_id\":\"$JOB\"}" "$TOKEN" | python3 -c 'import json,sys;print(json.load(sys.stdin)["code"])')"
mkdir -p "$RUN/data"
cat > "$RUN/data/fix-history.json" <<'FIX_HISTORY'
{"items": [{"ts": "2026-08-30T10:00:00+0800", "check_id": "dns-reachable", "action": "dns-set", "params": {}, "result": {"ok": true}, "dur_ms": 10, "ok": true}]}
FIX_HISTORY
FIX_ID=$(api GET /api/fix/history "" "$TOKEN" | python3 -c 'import json,sys;print(json.load(sys.stdin)["data"]["items"][0]["record_id"])')
check "fix.history_export" "repair True" "$(api GET "/api/fix/history/export?record_id=$FIX_ID" "" "$TOKEN" | python3 -c 'import json,sys;d=json.load(sys.stdin)["data"];print(d["type"], bool(d["log"]))')"
check "fix.history_delete" "True" "$(api POST /api/fix/history/delete "{\"record_id\":\"$FIX_ID\"}" "$TOKEN" | python3 -c 'import json,sys;print(json.load(sys.stdin)["data"]["deleted"])')"
check "history.clear" "0 0" "$(api POST /api/history/clear '{}' "$TOKEN" | python3 -c 'import json,sys;d=json.load(sys.stdin)["data"];print(d["diag_deleted"], d["fix_deleted"])')"
check "monitor.pause" "False False" "$(api POST /api/monitor/enabled '{"enabled":false}' "$TOKEN" | python3 -c 'import json,sys;d=json.load(sys.stdin)["data"];print(d["enabled"], d["running"])')"
check "monitor.paused_status" "False False" "$(api GET /api/monitor/link-quality "" "$TOKEN" | python3 -c 'import json,sys;d=json.load(sys.stdin)["data"];print(d["enabled"], d["running"])')"
check "monitor.enabled_invalid" "1002" "$(api POST /api/monitor/enabled '{}' "$TOKEN" | python3 -c 'import json,sys;print(json.load(sys.stdin)["code"])')"
check "monitor.resume" "True True" "$(api POST /api/monitor/enabled '{"enabled":true}' "$TOKEN" | python3 -c 'import json,sys;d=json.load(sys.stdin)["data"];print(d["enabled"], d["running"])')"

# 10. bandwidth endpoints (client to a dead port -> controlled failure path)
check "bw.badmode" "1002" "$(api POST /api/bandwidth/start '{"type":"lan","mode":"bogus"}' "$TOKEN" | python3 -c 'import json,sys;print(json.load(sys.stdin)["code"])')"
BW_JOB=$(api POST /api/bandwidth/start '{"type":"lan","mode":"client","target":"127.0.0.1","port":1,"duration":1}' "$TOKEN" | python3 -c 'import json,sys;print(json.load(sys.stdin)["data"]["job_id"])')
check "bw.jobid" "yes" "$([ -n "$BW_JOB" ] && echo yes || echo no)"
for i in $(seq 1 40); do
  BST=$(api GET /api/bandwidth/status "" "$TOKEN" | python3 -c 'import json,sys;print(json.load(sys.stdin)["data"]["state"])')
  [ "$BST" != "running" ] && break
  sleep 0.5
done
check "bw.finished" "yes" "$([ "$BST" = "done" ] || [ "$BST" = "failed" ] && echo yes || echo no)"
check "bw.realtime" "0" "$(api GET /api/realtime "" "$TOKEN" | python3 -c 'import json,sys;print(json.load(sys.stdin)["code"])')"


# 8b. security: duplicate setup rejected; recover (public) rotates the code
check "sec.setup_rejected" "1002" "$(api POST /api/auth/setup '{"username":"x","password":"netcheck123"}' | python3 -c 'import json,sys;print(json.load(sys.stdin)["code"])')"
REC_OUT=$(api POST /api/auth/recover '{"username":"admin","recovery_code":"'"$RECCODE"'","new_password":"rotated123"}')
REC_CODE=$(echo "$REC_OUT" | python3 -c 'import json,sys;print(json.load(sys.stdin)["code"])')
NEWCODE=$([ "$REC_CODE" = "0" ] && echo "$REC_OUT" | python3 -c 'import json,sys;print(json.load(sys.stdin)["data"]["recovery_code"])' || echo "")
check "sec.recover_public_ok" "0" "$REC_CODE"
check "sec.recover_rotates" "12" "${#NEWCODE}"
check "sec.recover_old_pw_dead" "1001" "$(api POST /api/auth/login '{"username":"admin","password":"netcheck123"}' | python3 -c 'import json,sys;print(json.load(sys.stdin)["code"])')"
check "sec.recover_new_pw_works" "0" "$(api POST /api/auth/login '{"username":"admin","password":"rotated123"}' | python3 -c 'import json,sys;print(json.load(sys.stdin)["code"])')"
check "sec.recover_old_code_dead" "1001" "$(api POST /api/auth/recover '{"username":"admin","recovery_code":"'"$RECCODE"'","new_password":"another123"}' | python3 -c 'import json,sys;print(json.load(sys.stdin)["code"])')"

echo; echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
