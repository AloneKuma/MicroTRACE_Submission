"""Runs whose transport failed are left out of Exp. 3 scoring, and the split records them."""
import json
import os
import types

from mtcore.exp3 import run


def test_failed_transport_runs_leave_the_split(tmp_path, monkeypatch):
    w = tmp_path
    os.makedirs(w / "splits")
    json.dump({"runs": ["r1", "r2", "r3"]}, open(w / "splits" / "c.json", "w"))
    for r, ok in (("r1", True), ("r2", False)):            # r3 has no transport.json: kept
        d = w / "received" / "c" / r
        os.makedirs(d)
        json.dump({"ok": ok, "run": r}, open(d / "transport.json", "w"))
    logged = []
    monkeypatch.setattr(run, "log", lambda work, msg: logged.append(msg))
    a = types.SimpleNamespace(work=str(w))
    assert run.prune_failed_transports(a, "c") == ["r2"]
    d = json.load(open(w / "splits" / "c.json"))
    assert d["runs"] == ["r1", "r3"] and d["transport_failed"] == ["r2"]
    assert logged and "TRANSPORT_FAILED c: 1" in logged[0]
    assert run.prune_failed_transports(a, "c") == []        # idempotent
    assert json.load(open(w / "splits" / "c.json"))["transport_failed"] == ["r2"]


def test_no_split_no_change(tmp_path):
    a = types.SimpleNamespace(work=str(tmp_path))
    assert run.prune_failed_transports(a, "missing") == []
