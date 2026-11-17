"""2026-11-17 Exp. 3 harness fixes: what stopped the held-out sessions, each pinned by a test.

1. A run whose transport failed is left out before detection (it failed every pass of exp3-b).
2. A condition that needs an earlier output skips a run whose earlier transport failed, instead of
   stopping the runner (exp3-b stopped there, so suppression and compromise never ran).
3. Idle exit counts from the first input, not from start-up (43 of 59 live runs ended before
   their data arrived).
4. The received dump leaves out the live pipeline's own records.
"""
import json
import os
import time
import types

import pytest

from mtcore.agents.run import AgentRunner
from mtcore.exp3 import run, slot
from mtcore.orchestrator.run import OrchRunner


def _transport(w, cond, r, ok):
    d = w / "received" / cond / r
    os.makedirs(d, exist_ok=True)
    json.dump({"ok": ok, "run": r}, open(d / "transport.json", "w"))


def test_transport_failed_reads_the_record(tmp_path):
    a = types.SimpleNamespace(work=str(tmp_path))
    _transport(tmp_path, "nofault", "r1", True)
    _transport(tmp_path, "nofault", "r2", False)
    assert not run.transport_failed(a, "nofault", "r1")
    assert run.transport_failed(a, "nofault", "r2")
    assert not run.transport_failed(a, "nofault", "r3")      # no record: not a failure


def test_detect_leaves_failed_transports_out(tmp_path, monkeypatch):
    w = tmp_path
    os.makedirs(w / "splits")
    json.dump({"runs": ["r1", "r2"]}, open(w / "splits" / "c.json", "w"))
    _transport(w, "c", "r1", True)
    _transport(w, "c", "r2", False)
    seen = {}
    monkeypatch.setattr(run, "log", lambda *_: None)
    monkeypatch.setattr(run, "received_files", lambda a, c, runs, kind: seen.setdefault(kind, list(runs)))
    monkeypatch.setattr(run, "pass_applies", lambda p, c: False)
    a = types.SimpleNamespace(work=str(w), keep_jsonl=True)
    assert run.stage_detect(a, {"condition": "c"}, [], ["r1", "r2"]) == 0
    assert seen["jsonl"] == ["r1"]
    assert json.load(open(w / "splits" / "c.json"))["runs"] == ["r1"]


def test_needed_output_lost_at_transport_is_not_applied(tmp_path, monkeypatch):
    w = tmp_path
    for r in ("r1", "r2"):
        os.makedirs(w / "base" / r)
        json.dump({"nodes": []}, open(w / "base" / r / "base.json", "w"))
    _transport(w, "nofault", "r2", False)                 # r2's no-fault transport failed
    out = w / "detect" / "nofault" / "full" / "runs" / "r1"
    os.makedirs(out)
    (out / "output.jsonl.gz").write_bytes(b"")
    calls = []
    monkeypatch.setattr(run, "log", lambda *_: None)
    monkeypatch.setattr(run, "base_root", lambda a, v: str(w / "base"))
    monkeypatch.setattr(run.PL, "template_path", lambda *_: "t.json")
    monkeypatch.setattr(run.PL, "write_run_plans",
                        lambda tf, base, out_dir, need: calls.append(need) or {"applied": True})
    a = types.SimpleNamespace(work=str(w), conditions="x")
    cond = {"condition": "suppress", "template": "t", "needs": "nofault:full"}
    assert run.stage_plans(a, cond, ["r1", "r2"]) == ["r1"]
    assert len(calls) == 1
    sp = json.load(open(w / "splits" / "suppress.json"))
    assert sp["needed_transport_failed"] == ["r2"] and sp["not_applied"] == ["r2"]


def test_needed_output_missing_without_a_failed_transport_still_stops(tmp_path, monkeypatch):
    w = tmp_path
    os.makedirs(w / "base" / "r1")
    json.dump({"nodes": []}, open(w / "base" / "r1" / "base.json", "w"))

    def plans(tf, base, out_dir, need):
        raise SystemExit("needs the earlier output")
    monkeypatch.setattr(run, "base_root", lambda a, v: str(w / "base"))
    monkeypatch.setattr(run.PL, "template_path", lambda *_: "t.json")
    monkeypatch.setattr(run.PL, "write_run_plans", plans)
    a = types.SimpleNamespace(work=str(w), conditions="x")
    with pytest.raises(SystemExit):
        run.stage_plans(a, {"condition": "s", "template": "t", "needs": "nofault:full"}, ["r1"])


class _Fake:
    """Stands in for a runner: step() returns input only from t_first on."""
    def __init__(self, t_first):
        self.t0, self.t_first, self.steps_with_input = time.time(), t_first, 0
        self.consumer = types.SimpleNamespace(close=lambda: None)
        self.producer = types.SimpleNamespace(flush=lambda *_: None)

    def step(self):
        if time.time() - self.t0 >= self.t_first and self.steps_with_input < 3:
            self.steps_with_input += 1
            return 1
        time.sleep(0.01)
        return 0

    publish = heartbeats = commit = checkpoint_now = lambda self: None


@pytest.mark.parametrize("cls", [AgentRunner, OrchRunner])
def test_idle_exit_waits_for_the_first_input(cls):
    f = _Fake(t_first=0.5)                 # input arrives after more than the idle limit
    cls.run(f, lambda: False, idle_exit_s=0.2)
    assert f.steps_with_input == 3         # it stayed up and read the input


@pytest.mark.parametrize("cls", [AgentRunner, OrchRunner])
def test_idle_exit_without_any_input_still_ends(cls, monkeypatch):
    import sys
    monkeypatch.setattr(sys.modules[cls.__module__], "STARTUP_IDLE_S", 0.3)
    f = _Fake(t_first=1e9)
    t = time.time()
    cls.run(f, lambda: False, idle_exit_s=0.1)
    assert time.time() - t < 5


def test_dump_leaves_pipeline_records_out():
    assert {"restreamer", "agents", "orchestrator"} <= slot.PIPELINE_PRODUCERS
    assert "ingest-receiver" not in slot.PIPELINE_PRODUCERS
