"""Controlled external-command runner: no shell, argv whitelist, timeout, kill pgid."""
from __future__ import annotations
import os
import shlex
import signal
import subprocess
import time
from dataclasses import dataclass
from typing import List, Optional, Sequence

# Defensive charset for arguments (NIC collector design section 3)
_FORBIDDEN = set(';&|`$()<>\'\\"\n')

# Binary whitelist: only these may be executed (paths resolved lazily so the
# module also works on dev machines where /usr/sbin et al. differ)
ALLOWED_BASENAMES = {
    "ip", "ethtool", "ovs-vsctl", "ping", "ping6", "curl", "dig", "getent",
    "resolvectl", "networkctl", "ss", "traceroute", "arping", "smbclient",
    "testparm", "pgrep", "ntpq", "systemctl", "cat",
    "tos",
}


@dataclass
class ProbeResult:
    rc: int
    stdout: str
    stderr: str
    elapsed_ms: int


class ProbeError(Exception):
    pass


def _validate(argv: Sequence[str]) -> None:
    if not argv:
        raise ProbeError("empty argv")
    base = os.path.basename(argv[0])
    if base not in ALLOWED_BASENAMES:
        raise ProbeError(f"binary not whitelisted: {base}")
    for arg in argv[1:]:
        if any(ch in _FORBIDDEN for ch in arg):
            raise ProbeError(f"forbidden characters in argument: {arg!r}")


def resolve(binary: str) -> str:
    """Resolve a whitelisted binary to an absolute path using a safe PATH."""
    base = os.path.basename(binary)
    if base not in ALLOWED_BASENAMES:
        raise ProbeError(f"binary not whitelisted: {base}")
    if os.path.isabs(binary) and os.path.exists(binary):
        return binary
    search = ("/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/bin")
    for d in search:
        p = os.path.join(d, base)
        if os.path.exists(p):
            return p
    return base  # fall back to name; exec will fail -> rc 127 recorded


def run(argv: Sequence[str], timeout: float = 5.0,
        env: Optional[dict] = None) -> ProbeResult:
    """Run a whitelisted command without a shell; kill the process group on timeout."""
    argv = [str(a) for a in argv]
    _validate(argv)
    exe = resolve(argv[0])
    run_env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"}
    if env:
        run_env.update(env)
    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            [exe] + argv[1:], capture_output=True, text=True, timeout=timeout,
            env=run_env, start_new_session=True)
        elapsed = int((time.monotonic() - t0) * 1000)
        return ProbeResult(proc.returncode, proc.stdout, proc.stderr, elapsed)
    except subprocess.TimeoutExpired:
        elapsed = int((time.monotonic() - t0) * 1000)
        return ProbeResult(-9, "", "timeout", elapsed)
    except FileNotFoundError:
        return ProbeResult(127, "", f"not found: {argv[0]}", 0)
    except PermissionError:
        return ProbeResult(126, "", f"permission denied: {argv[0]}", 0)


def read_file(path: str) -> str:
    """Read a text file safely (empty string on error)."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def run_lines(argv: Sequence[str], timeout: float = 5.0) -> List[str]:
    return run(argv, timeout).stdout.splitlines()
