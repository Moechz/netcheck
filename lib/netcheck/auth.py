"""App-local accounts (F37-F40): PBKDF2-HMAC-SHA256 + session tokens, lockout, rate limit."""
from __future__ import annotations
import hashlib
import hmac
import json
import os
import secrets
import tempfile
import threading
import time
from typing import Any, Dict, Optional, Tuple

PBKDF2_ITERATIONS = 200_000
SESSION_TTL_SEC = 24 * 3600
LOCKOUT_SEC = 5 * 60
MAX_FAILURES = 5
LOGIN_RATE_PER_MIN = 10

ERR_LOCKED = "locked"
ERR_CREDENTIALS = "bad_credentials"
ERR_WEAK_PASSWORD = "weak_password"


def _hash_password(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations).hex()


def _password_ok(password: str) -> bool:
    return (len(password) >= 8
            and any(c.isalpha() for c in password)
            and any(c.isdigit() for c in password))


class AuthService:
    """File-backed account store (data/auth/) with sessions, lockout and rate limit."""

    def __init__(self, auth_dir: str):
        self.dir = auth_dir
        self.users_path = os.path.join(auth_dir, "users.json")
        self.sessions_path = os.path.join(auth_dir, "sessions.json")
        os.makedirs(auth_dir, exist_ok=True)
        self._lock = threading.RLock()
        self._failures: Dict[str, int] = {}
        self._locked_until: Dict[str, float] = {}
        self._login_times: Dict[str, list] = {}

    # ---------- accounts ----------
    def is_initialized(self) -> bool:
        return os.path.exists(self.users_path)

    def setup(self, username: str, password: str) -> Tuple[bool, str]:
        with self._lock:
            if self.is_initialized():
                return False, "already_initialized"
            if not self._valid_username(username):
                return False, "bad_username"
            if not _password_ok(password):
                return False, ERR_WEAK_PASSWORD
            salt = secrets.token_bytes(16)
            recovery_code = secrets.token_urlsafe(9)   # 12 chars, shown ONCE
            rec_salt = secrets.token_bytes(16)
            self._write_json(self.users_path, {
                "username": username,
                "salt": salt.hex(),
                "pbkdf2_hash": _hash_password(password, salt),
                "iterations": PBKDF2_ITERATIONS,
                "recovery_salt": rec_salt.hex(),
                "recovery_hash": _hash_password(recovery_code, rec_salt),
                "created_at": int(time.time()),
            }, mode=0o600)
            return True, "ok", recovery_code

    @staticmethod
    def _valid_username(username: str) -> bool:
        return 3 <= len(username) <= 32 and username.isalnum()

    def verify_password(self, password: str) -> bool:
        users = self._read_json(self.users_path, {})
        if not users:
            return False
        expected = users.get("pbkdf2_hash", "")
        salt = bytes.fromhex(users.get("salt", ""))
        iterations = int(users.get("iterations", PBKDF2_ITERATIONS))
        actual = _hash_password(password, salt, iterations)
        return hmac.compare_digest(actual, expected)

    def username(self) -> str:
        return self._read_json(self.users_path, {}).get("username", "")

    def change_password(self, old: str, new: str) -> Tuple[bool, str]:
        with self._lock:
            if not self.verify_password(old):
                return False, ERR_CREDENTIALS
            if not _password_ok(new):
                return False, ERR_WEAK_PASSWORD
            users = self._read_json(self.users_path, {})
            salt = secrets.token_bytes(16)
            users["salt"] = salt.hex()
            users["pbkdf2_hash"] = _hash_password(new, salt)
            users["iterations"] = PBKDF2_ITERATIONS
            self._write_json(self.users_path, users, mode=0o600)
            self.revoke_all_sessions()
            return True, "ok"

    def change_username(self, password: str, new_username: str) -> Tuple[bool, str]:
        with self._lock:
            if not self.verify_password(password):
                return False, ERR_CREDENTIALS
            if not self._valid_username(new_username):
                return False, "bad_username"
            users = self._read_json(self.users_path, {})
            users["username"] = new_username
            self._write_json(self.users_path, users, mode=0o600)
            return True, "ok"

    # ---------- recovery ----------
    def recover(self, username: str, recovery_code: str,
                new_password: str) -> Tuple[bool, str]:
        """Reset the password with the one-time recovery code (setup output).

        Shares the brute-force counters with login so repeated bad codes lock
        the account the same way (login.py security requirement F38).
        """
        with self._lock:
            now = time.time()
            key = (username or "?").lower()
            if self._locked_until.get(key, 0) > now:
                return False, ERR_LOCKED
            if not self.is_initialized():
                return False, ERR_CREDENTIALS
            users = self._read_json(self.users_path, {})
            if username != users.get("username"):
                self._bump_failure(key, now)
                if self._locked_until.get(key, 0) > now:
                    return False, ERR_LOCKED
                return False, ERR_CREDENTIALS
            rec_hash = users.get("recovery_hash", "")
            rec_salt = users.get("recovery_salt", "")
            if not rec_hash or not rec_salt:
                return False, "recovery_not_configured"
            iterations = int(users.get("iterations", PBKDF2_ITERATIONS))
            actual = hashlib.pbkdf2_hmac("sha256", (recovery_code or "").encode(),
                                         bytes.fromhex(rec_salt), iterations).hex()
            if not hmac.compare_digest(actual, rec_hash):
                self._bump_failure(key, now)
                if self._locked_until.get(key, 0) > now:
                    return False, ERR_LOCKED
                return False, ERR_CREDENTIALS
            if not _password_ok(new_password or ""):
                return False, ERR_WEAK_PASSWORD
            # rotate recovery code after successful use (one-time semantics)
            new_recovery = secrets.token_urlsafe(9)
            new_rec_salt = secrets.token_bytes(16)
            users["salt"] = secrets.token_bytes(16).hex()
            users["pbkdf2_hash"] = _hash_password(new_password, bytes.fromhex(users["salt"]))
            users["recovery_salt"] = new_rec_salt.hex()
            users["recovery_hash"] = _hash_password(new_recovery, new_rec_salt)
            self._write_json(self.users_path, users, mode=0o600)
            self.revoke_all_sessions()
            self._failures.pop(key, None)
            return True, new_recovery

    def _bump_failure(self, key: str, now: float) -> None:
        fails = self._failures.get(key, 0) + 1
        self._failures[key] = fails
        if fails >= MAX_FAILURES:
            self._locked_until[key] = now + LOCKOUT_SEC
            self._failures[key] = 0

    def lockout_remaining(self, username: str) -> int:
        key = (username or "?").lower()
        return max(0, int(self._locked_until.get(key, 0) - time.time()))

    # ---------- sessions ----------
    def login(self, username: str, password: str) -> Tuple[Optional[str], dict]:
        """Returns (token|None, info) where info carries reason + security hints."""
        with self._lock:
            now = time.time()
            key = (username or "?").lower()
            info: Dict[str, Any] = {"reason": ERR_CREDENTIALS}
            if self._locked_until.get(key, 0) > now:
                info["reason"] = ERR_LOCKED
                info["locked_remaining_sec"] = int(self._locked_until[key] - now)
                return None, info
            # rate limit: 10 login attempts / minute per username
            times = [t for t in self._login_times.get(key, []) if now - t < 60]
            if len(times) >= LOGIN_RATE_PER_MIN:
                info["reason"] = "rate_limited"
                return None, info
            times.append(now)
            self._login_times[key] = times

            if (not self.is_initialized() or username != self.username()
                    or not self.verify_password(password)):
                fails = self._failures.get(key, 0) + 1
                self._failures[key] = fails
                if fails >= MAX_FAILURES:
                    self._locked_until[key] = now + LOCKOUT_SEC
                    self._failures[key] = 0
                    info["reason"] = ERR_LOCKED
                    info["locked_remaining_sec"] = LOCKOUT_SEC
                    return None, info
                info["attempts_remaining"] = MAX_FAILURES - fails
                return None, info

            self._failures[key] = 0
            token = secrets.token_urlsafe(32)
            self._store_session(token)
            return token, {"reason": "ok"}

    def _store_session(self, token: str) -> None:
        sessions = self._read_json(self.sessions_path, {})
        now = int(time.time())
        # prune expired
        sessions = {k: v for k, v in sessions.items() if v.get("expires_at", 0) > now}
        sessions[hashlib.sha256(token.encode()).hexdigest()] = {
            "created_at": now, "expires_at": now + SESSION_TTL_SEC,
        }
        self._write_json(self.sessions_path, sessions, mode=0o600)

    def check_session(self, token: str) -> bool:
        if not token:
            return False
        sessions = self._read_json(self.sessions_path, {})
        entry = sessions.get(hashlib.sha256(token.encode()).hexdigest())
        if not entry:
            return False
        return entry.get("expires_at", 0) > time.time()

    def logout(self, token: str) -> None:
        sessions = self._read_json(self.sessions_path, {})
        sessions.pop(hashlib.sha256(token.encode()).hexdigest(), None)
        self._write_json(self.sessions_path, sessions, mode=0o600)

    def revoke_all_sessions(self) -> None:
        self._write_json(self.sessions_path, {}, mode=0o600)

    # ---------- json helpers ----------
    @staticmethod
    def _read_json(path: str, default: Any) -> Any:
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return default

    @staticmethod
    def _write_json(path: str, data: Any, mode: int = 0o600) -> None:
        fd, tmp = tempfile.mkstemp(prefix=".auth-", dir=os.path.dirname(path))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            os.chmod(tmp, mode)
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
