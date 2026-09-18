"""Snapshot tests: create/list/diff/prune (mocked filesystem)."""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from netcheck.snapshot import SnapshotService

PASS = FAIL = 0


def check(name, expected, actual):
    global PASS, FAIL
    if expected == actual:
        PASS += 1; print(f"PASS {name}")
    else:
        FAIL += 1; print(f"FAIL {name}: expected={expected!r} got={actual!r}")


# mock the network dir
import netcheck.snapshot as snap_mod
tmp_net = tempfile.mkdtemp(prefix="nc-net-")
tmp_data = tempfile.mkdtemp(prefix="nc-data-")
snap_mod.NETWORK_DIR = tmp_net

# seed a .network file
with open(os.path.join(tmp_net, "10-eth0.network"), "w") as f:
    f.write("[Match]\nName=eth0\n\n[Network]\nDHCP=no\nAddress=192.168.1.10/24\n")

svc = SnapshotService(tmp_data, keep=3)

# create
meta = svc.create(source="manual", note="test")
check("snap.id_prefix", True, meta["id"].startswith("snap-"))
check("snap.files", 1, len(meta["files"]))
check("snap.note", "test", meta["note"])

# list
check("snap.list_1", 1, len(svc.list()))

# diff (no changes)
d = svc.diff(meta["id"])
check("snap.diff_no_change", 0, d["total"])

# modify the live file, diff again
with open(os.path.join(tmp_net, "10-eth0.network"), "w") as f:
    f.write("[Match]\nName=eth0\n\n[Network]\nDHCP=ipv4\n")
d2 = svc.diff(meta["id"])
check("snap.diff_1_change", 1, d2["total"])
check("snap.diff_file", "10-eth0.network", d2["changes"][0]["file"])

# prune (keep=3)
for i in range(5):
    svc.create(source="auto")
check("snap.pruned", 3, len(svc.list()))

# get by id
latest = svc.list()[0]
got = svc.get(latest["id"])
check("snap.get", True, got is not None)

print()
print(f"RESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
