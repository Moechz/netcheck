"""Config snapshots (F23) and network reset (F24).

Snapshot: tar.gz of /etc/systemd/network/*.network + route/DNS state + meta.
Restore: via helper snap-restore action (M4 pipeline).
Reset: backup all -> rewrite to DHCP=true -> reload+reconfigure (M1-measured).
"""
from __future__ import annotations
import glob
import hashlib
import io
import json
import os
import tarfile
import time
import uuid
from typing import Any, Dict, List, Optional

from .collectors import sysprobe

NETWORK_DIR = "/etc/systemd/network"


class SnapshotService:
    """Snapshot create/list/diff; restore/reset delegate to the helper."""

    def __init__(self, data_dir: str, helper_client=None, keep: int = 20):
        self.snap_dir = os.path.join(data_dir, "snapshots")
        os.makedirs(self.snap_dir, exist_ok=True)
        self.helper = helper_client
        self.keep = keep

    def create(self, source: str = "manual", note: str = "") -> Dict[str, Any]:
        snap_id = f"snap-{uuid.uuid4().hex[:12]}"
        sdir = os.path.join(self.snap_dir, snap_id)
        os.makedirs(sdir)
        # copy .network files
        for f in glob.glob(os.path.join(NETWORK_DIR, "*.network")):
            with open(f, "rb") as src:
                dst_path = os.path.join(sdir, os.path.basename(f))
                with open(dst_path, "wb") as dst:
                    dst.write(src.read())
        # capture state summary
        state = {
            "routes": sysprobe.run(["ip", "route"], timeout=3).stdout,
            "dns": sysprobe.run(["resolvectl", "status"], timeout=3).stdout[:2000],
            "links": sysprobe.run(["ip", "-br", "link"], timeout=3).stdout,
        }
        with open(os.path.join(sdir, "state.json"), "w") as f:
            json.dump(state, f, indent=2)
        # meta with checksums
        files = {}
        for fname in os.listdir(sdir):
            if fname.endswith(".network"):
                with open(os.path.join(sdir, fname), "rb") as f:
                    files[fname] = hashlib.sha256(f.read()).hexdigest()
        meta = {"id": snap_id, "ts": time.time(), "source": source, "note": note,
                "files": files, "version": 1}
        with open(os.path.join(sdir, "meta.json"), "w") as f:
            json.dump(meta, f, indent=2)
        self._prune()
        return meta

    def list(self) -> List[Dict[str, Any]]:
        out = []
        for d in sorted(os.listdir(self.snap_dir), reverse=True):
            mpath = os.path.join(self.snap_dir, d, "meta.json")
            if os.path.exists(mpath):
                try:
                    with open(mpath) as f:
                        out.append(json.load(f))
                except (OSError, ValueError):
                    pass
        return out

    def get(self, snap_id: str) -> Optional[Dict[str, Any]]:
        for s in self.list():
            if s["id"] == snap_id:
                return s
        return None

    def diff(self, snap_id: str) -> Dict[str, Any]:
        """Compare snapshot .network files against current live files."""
        sdir = os.path.join(self.snap_dir, snap_id)
        if not os.path.isdir(sdir):
            return {"error": "snapshot not found"}
        changes: List[Dict[str, str]] = []
        snap_files = {f: os.path.join(sdir, f) for f in os.listdir(sdir)
                      if f.endswith(".network")}
        live_files = {os.path.basename(f): f
                      for f in glob.glob(os.path.join(NETWORK_DIR, "*.network"))}
        for fname in sorted(set(snap_files) | set(live_files)):
            snap_content = live_content = None
            if fname in snap_files:
                with open(snap_files[fname]) as f:
                    snap_content = f.read()
            if fname in live_files:
                with open(live_files[fname]) as f:
                    live_content = f.read()
            if snap_content != live_content:
                changes.append({"file": fname,
                                "snapshot": snap_content or "(absent)",
                                "current": live_content or "(absent)"})
        return {"snapshot": snap_id, "changes": changes,
                "total": len(changes)}

    def restore(self, snap_id: str) -> Dict[str, Any]:
        """Restore via the helper snap-restore action (M4 pipeline)."""
        if not self.helper:
            return {"ok": False, "err": "helper not available"}
        return self.helper.call("snap-restore", {"snapshot_id": snap_id})

    def reset_network(self) -> Dict[str, Any]:
        """F24: backup all -> rewrite to DHCP -> reload+reconfigure."""
        if not self.helper:
            return {"ok": False, "err": "helper not available"}
        backup_snap = self.create(source="pre-reset", note="auto backup before network reset")
        # for each .network file, apply DHCP reset via helper
        results = []
        for f in glob.glob(os.path.join(NETWORK_DIR, "*.network")):
            ifname = os.path.basename(f).replace("10-", "").replace(".network", "")
            r = self.helper.call("net-apply", {"iface": ifname, "mode": "reset"})
            results.append({"iface": ifname, "ok": r.get("ok", False)})
        all_ok = all(r["ok"] for r in results)
        if not all_ok:
            # rollback to the backup snapshot
            self.restore(backup_snap["id"])
        return {"ok": all_ok, "backup_snapshot": backup_snap["id"],
                "results": results}

    def _prune(self):
        snaps = self.list()
        for s in snaps[self.keep:]:
            import shutil
            shutil.rmtree(os.path.join(self.snap_dir, s["id"]), ignore_errors=True)


# fix typo constant
NETWORK_DIR = "/etc/systemd/network"
NETWORK_DIR = NETWORK_DIR  # alias used above (kept for compat)
