"""Diagnosis engine: registry, two-stage scheduling with deadline, gates.

Implements the Diagnostic Checks design section 2 (including the Python 3.10
concurrent.futures.TimeoutError correction: use wait() with a stage deadline,
never future.result(timeout=...) + except TimeoutError).
"""
from __future__ import annotations
import importlib
import pkgutil
import time
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from ..collectors import sysprobe
from ..collectors.nic import NicCollector

_CHECKERS: Dict[str, type] = {}


@dataclass
class CheckerSpec:
    id: str
    group: str
    name_key: str
    timeout: float = 5.0
    fixable: Optional[str] = None
    weight: float = 1.0
    na_fn: Optional[Callable[[dict], bool]] = None


@dataclass
class CheckResult:
    id: str
    group: str
    name_key: str
    status: str                    # pass | warn | fail | na
    detail: Dict[str, Any] = field(default_factory=dict)
    fixable: Optional[str] = None
    duration_ms: float = 0.0
    duration: float = 0.0          # alias kept for report sugar

    def to_dict(self) -> dict:
        return {"id": self.id, "group": self.group, "name_key": self.name_key,
                "status": self.status, "detail": self.detail,
                "fixable": self.fixable, "duration_ms": round(self.duration_ms, 1)}


def register_checker(id: str, group: str, name_key: str, timeout: float = 5.0,
                     fixable: Optional[str] = None, weight: float = 1.0,
                     na_fn: Optional[Callable[[dict], bool]] = None):
    def deco(cls):
        cls.spec = CheckerSpec(id, group, name_key, timeout, fixable, weight, na_fn)
        _CHECKERS[id] = cls
        return cls
    return deco


def registry() -> Dict[str, type]:
    if not _CHECKERS:
        _import_all_checkers()
    return _CHECKERS


def _import_all_checkers() -> None:
    from . import checkers as pkg
    for mod in pkgutil.iter_modules(pkg.__path__):
        importlib.import_module(f"{pkg.__name__}.{mod.name}")


class BaseChecker:
    """Read-only checker; probe injectable for tests via ctx['probe']."""

    spec: CheckerSpec

    def __init__(self, ctx: dict):
        self.ctx = ctx
        self.probe = ctx.get("probe") or sysprobe.run

    @property
    def cfg(self) -> dict:
        return self.ctx.get("cfg", {})

    @property
    def nics(self) -> dict:
        return self.ctx.get("nics") or {"arch": "direct", "interfaces": []}

    def primary(self) -> Optional[dict]:
        for i in self.nics["interfaces"]:
            if i.get("is_primary"):
                return i
        return None

    def physical_ports(self) -> List[dict]:
        return [i for i in self.nics["interfaces"] if i.get("type") == "physical"]

    def collect(self) -> Any:  # noqa: D102 - overridden per checker
        return None

    def evaluate(self, data: Any) -> CheckResult:  # noqa: D102
        raise NotImplementedError

    # ---- result helpers ----
    def pass_(self, actual="", expected="", reason="") -> CheckResult:
        return self._res("pass", actual, expected, reason)

    def warn(self, actual="", expected="", reason="") -> CheckResult:
        return self._res("warn", actual, expected, reason)

    def fail(self, actual="", expected="", reason="") -> CheckResult:
        return self._res("fail", actual, expected, reason)

    def na(self, reason="not applicable") -> CheckResult:
        return CheckResult(self.spec.id, self.spec.group, self.spec.name_key,
                           "na", {"reason": reason}, self.spec.fixable)

    def _res(self, status, actual, expected, reason) -> CheckResult:
        fixable = getattr(self, "_fixable_override", None) or self.spec.fixable
        return CheckResult(self.spec.id, self.spec.group, self.spec.name_key, status,
                           {"actual": actual, "expected": expected, "reason": reason},
                           fixable)


def _fail_undeterminable(cls, reason: str) -> CheckResult:
    return CheckResult(cls.spec.id, cls.spec.group, cls.spec.name_key, "fail",
                       {"actual": None, "expected": None,
                        "reason": f"undeterminable: {reason}"}, cls.spec.fixable)


def _run_one(cls: type, ctx: dict) -> CheckResult:
    t0 = time.monotonic()
    try:
        checker = cls(ctx)
        result = checker.evaluate(checker.collect())
    except Exception as exc:  # noqa: BLE001 - checker boundary (design 2.3)
        result = _fail_undeterminable(cls, f"{type(exc).__name__}")
    result.duration_ms = (time.monotonic() - t0) * 1000
    return result


def run_diag(cfg: dict, nics: Optional[dict] = None,
             probe=None, collector: Optional[NicCollector] = None) -> List[CheckResult]:
    """Two-stage scheduling: ABC (local) then DEFGHI (external probing)."""
    ctx: Dict[str, Any] = {"cfg": cfg, "probe": probe}
    if nics is None and collector is not None:
        nics = collector.get()
    ctx["nics"] = nics or {"arch": "direct", "interfaces": []}

    reg = registry()
    results: List[CheckResult] = []
    default_timeout = float(cfg.get("timeout_sec", 5))
    for stage in ("ABC", "DEFGHI"):
        with ThreadPoolExecutor(max_workers=4) as ex:
            futs = {}
            for g in stage:
                for cid, cls in reg.items():
                    if cls.spec.group != g:
                        continue
                    if cls.spec.na_fn and cls.spec.na_fn(ctx):
                        results.append(cls(ctx).na())
                        continue
                    futs[ex.submit(_run_one, cls, ctx)] = cls
            if not futs:
                continue
            deadline = max(time.monotonic() + max(c.spec.timeout, default_timeout)
                           for c in futs.values())
            pending = set(futs)
            while pending:
                done, pending = wait(pending,
                                     timeout=max(0, deadline - time.monotonic()))
                for fut in done:
                    results.append(fut.result())
                if pending:  # stage deadline hit
                    for fut in pending:
                        fut.cancel()
                        results.append(_fail_undeterminable(futs[fut], "timeout"))
                    pending = set()
    return results
