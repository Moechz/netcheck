"""Auth security unit tests: recovery code flow, lockout hints, rate limiting."""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from netcheck.auth import AuthService

PASS = FAIL = 0


def check(name, expected, actual):
    global PASS, FAIL
    if expected == actual:
        PASS += 1; print(f"PASS {name}")
    else:
        FAIL += 1; print(f"FAIL {name}: expected={expected!r} got={actual!r}")


tmp = tempfile.mkdtemp(prefix="nc-auth-")
auth = AuthService(tmp)

# ---------- setup returns one-time recovery code ----------
ok, reason, code = auth.setup("admin", "netcheck123")
check("setup.ok", (True, "ok"), (ok, reason))
check("setup.recovery_len", True, len(code) >= 12)

# ---------- login info carries attempts_remaining ----------
t1, i1 = auth.login("admin", "wrongpass1")
check("login.bad.attempts", ("bad_credentials", 4), (i1["reason"], i1["attempts_remaining"]))
t2, i2 = auth.login("admin", "netcheck123")
check("login.ok_after_fail", "ok", i2["reason"])
check("login.token", True, bool(t2))

# ---------- lockout: 5 consecutive failures -> locked with seconds ----------
auth2 = AuthService(tempfile.mkdtemp(prefix="nc-auth2-"))
auth2.setup("admin", "netcheck123")
last = None
for i in range(5):
    last = auth2.login("admin", "wrongpass1X")[1]
check("lockout.triggered", "locked", last["reason"])
check("lockout.seconds_range", True, 0 < last.get("locked_remaining_sec", 0) <= 300)
# correct password rejected during lockout
tok, info = auth2.login("admin", "netcheck123")
check("lockout.rejects_correct", (None, "locked"), (tok, info["reason"]))
check("lockout.remaining_api", True, auth2.lockout_remaining("admin") > 0)

# ---------- recovery: happy path rotates code + revokes sessions ----------
tok_before, _ = auth.login("admin", "netcheck123")
check("session.before_recover", True, auth.check_session(tok_before))
ok, out = auth.recover("admin", code, "newpass456")
check("recover.ok", True, ok)
check("recover.rotated_code", True, out != code and len(out) >= 12)
check("recover.revokes_sessions", False, auth.check_session(tok_before))
# old password dead, new works
t3, i3 = auth.login("admin", "netcheck123")
check("recover.old_pw_dead", "bad_credentials", i3["reason"])
t4, i4 = auth.login("admin", "newpass456")
check("recover.new_pw_works", "ok", i4["reason"])

# ---------- recovery: wrong code rejected, shares brute-force counters ----------
auth3 = AuthService(tempfile.mkdtemp(prefix="nc-auth3-"))
_, _, code3 = auth3.setup("admin", "netcheck123")
for i in range(4):
    ok, msg = auth3.recover("admin", "WRONG", "whatever123")
check("recover.wrong_before_lock", "bad_credentials", msg)
ok, msg = auth3.recover("admin", "WRONG", "whatever123")
check("recover.locks_after_5", "locked", msg)
ok, msg = auth3.recover("admin", code3, "newpass456")
check("recover.locked_rejects_valid", "locked", msg)

# ---------- recovery: weak new password rejected ----------
auth4 = AuthService(tempfile.mkdtemp(prefix="nc-auth4-"))
_, _, code4 = auth4.setup("admin", "netcheck123")
ok, msg = auth4.recover("admin", code4, "short")
check("recover.weak_pw", "weak_password", msg)

# ---------- rate limit: 10 attempts/min per username ----------
# alternating correct/wrong so the consecutive-failure lockout never fires;
# the 11th attempt within 60s hits the per-username rate limit
auth5 = AuthService(tempfile.mkdtemp(prefix="nc-auth5-"))
auth5.setup("admin", "netcheck123")
reasons = []
for i in range(12):
    pw = "netcheck123" if i % 2 == 0 else "wrongpass1X"
    reasons.append(auth5.login("admin", pw)[1]["reason"])
check("rate.no_lockout_when_alternating", True, "locked" not in reasons[:10])
check("rate.after_11", "rate_limited", reasons[10])
# even the correct password is rate-limited within the window
t6, i6 = auth5.login("admin", "netcheck123")
check("rate.correct_still_limited", "rate_limited", i6["reason"])

print()
print(f"RESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
