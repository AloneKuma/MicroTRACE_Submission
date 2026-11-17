"""Exp. 3 runner units (mtcore.exp3): base export without truth, plan instantiation,
ablation parameter derivation, fault-log consistency, score_pilot.py --fault-log-root.
No Kafka, Go binaries or truth needed; the end-to-end dry run is
experiments/exp3/tests/dryrun_exp3.sh."""
import builtins
import gzip
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from mtcore import REPO
from mtcore.exp3 import base as B
from mtcore.exp3 import check as C
from mtcore.exp3 import plans as PL
from mtcore.exp3.ctl import LocalCtl

sys.path.insert(0, str(Path(REPO) / "src" / "scripts" / "pilot"))
import score_pilot as SP  # noqa: E402

T0 = 1704067200_000_000_000        # 2024-01-01T00:00:00Z


def ev(lid, t_s, source="EBPF", node="n-1", family="file.read", lane="NORMAL"):
    ne = {"event_id": lid, "source": source, "time": {"event_time": B.ns_rfc3339(T0 + int(t_s * 1e9))}}
    if source == "EBPF":
        ne["ebpf"] = {"node_id": node, "event_family": family}
    return {"lane": lane, "topic": "norm.events.v0", "key_type": "KEY_PRIMARY_ENTITY", "key_components": ["POD", "p"],
            "envelope": {"kind": "NORMALIZED_EVENT", "logical_id": lid, "normalized_event": ne}}


def make_run(root, run_id="run-1"):
    d = Path(root) / run_id
    (d / "shipper").mkdir(parents=True)
    (d / "restricted").mkdir()
    (d / "restricted" / "truth_findings.pb").write_bytes(b"secret")
    (d / "base.pb").write_bytes(b"secret")
    (d / "manifest.json").write_text(json.dumps({"run_id": run_id, "observability_profile": "clean",
                                                 "scenario_ids": ["x"], "seeds": {"a": 1}}))
    w1 = [ev("e1", 0, node="uid-w1"), ev("e2", 10, node="uid-w1"),
          ev("e3", 20, node="uid-w1", family="ns.change", lane="PRIORITY"), ev("e4", 30, node="uid-w1")]
    cp = [ev("g1", 1, source="GATEWAY"), ev("c1", 2, node="uid-cp"), ev("g2", 600, source="GATEWAY"),
          {"topic": "ground.truth.v0", "envelope": {"ground_truth_action": {"x": 1}, "logical_id": "gt1"}},
          {"lane": "NORMAL", "watermark": B.ns_rfc3339(T0)}]
    for name, lines in (("node-w1", w1), ("node-cp", cp)):
        with open(d / "shipper" / f"{name}.jsonl", "w", encoding="utf-8", newline="\n") as fh:
            for x in lines:
                fh.write(json.dumps(x) + "\n")
    return d


@pytest.fixture
def exported(tmp_path, monkeypatch):
    run = make_run(tmp_path / "runs")
    real_open = builtins.open

    def guarded(p, *a, **k):
        s = str(p)
        assert "restricted" not in s and not s.endswith("base.pb"), f"opened truth {s}"
        return real_open(p, *a, **k)
    monkeypatch.setattr(builtins, "open", guarded)
    meta = B.export_run(run, tmp_path / "base")
    monkeypatch.setattr(builtins, "open", real_open)
    return tmp_path / "base" / "run-1", meta


def test_base_export_drops_truth_keeps_every_other_line(exported, tmp_path):
    out, meta = exported
    assert meta["truth_removed"] == 1 and B.verify_export(out) == []
    cp_in = [ln for ln in open(tmp_path / "runs" / "run-1" / "shipper" / "node-cp.jsonl", "rb") if b"ground" not in ln]
    assert open(out / "nodes" / "node-cp.jsonl", "rb").readlines() == cp_in
    m = json.load(open(out / "manifest.json"))
    assert "scenario_ids" not in m and "seeds" not in m and m["observability_profile"] == "clean"
    roles = {n["node"]: (n["role"], n["node_id"]) for n in meta["nodes"]}
    assert roles == {"node-cp": ("control-plane", "uid-cp"), "node-w1": ("worker", "uid-w1")}
    assert meta["stream_start_ns"] == T0 and meta["stream_end_ns"] == T0 + 600 * 10**9


def test_base_export_is_skipped_when_unchanged(exported, tmp_path):
    out, meta = exported
    again = B.export_run(tmp_path / "runs" / "run-1", tmp_path / "base")
    assert again == json.load(open(out / "base.json"))


def test_target_rules_and_times(exported):
    _, meta = exported
    assert PL.pick_target("first-priority-ebpf", meta)[:2] == ("node-w1", T0 + 20 * 10**9)
    assert PL.pick_target("largest-worker", meta)[0] == "node-w1"
    assert PL.pick_target("control-plane", meta)[0] == "node-cp"
    assert PL.resolve_time("start+240s", meta, None) == B.ns_rfc3339(T0 + 240 * 10**9)
    assert PL.resolve_time("start+50%", meta, None) == B.ns_rfc3339(T0 + 300 * 10**9)
    assert PL.resolve_time("target+1s", meta, T0) == B.ns_rfc3339(T0 + 10**9)
    assert PL.resolve_time("target+1s", meta, None) is None
    assert PL.resolve_time("2026-10-08T12:00:00Z", meta, None) == "2026-10-08T12:00:00Z"


def test_targeted_fault_goes_to_the_target_node_only(exported):
    _, meta = exported
    tpl = {"version": "faultplan.v0", "seed": 1, "target": "first-priority-ebpf",
           "faults": [{"id": "stop", "kind": "stop", "stage": "source", "nodes": "target", "after": "target+1s"},
                      {"id": "loss", "kind": "loss", "stage": "transit", "rate": 0.1}]}
    plans, m = PL.instantiate(tpl, meta)
    assert [f["id"] for f in plans["node-w1"]["faults"]] == ["stop", "loss"]
    assert [f["id"] for f in plans["node-cp"]["faults"]] == ["loss"]
    assert plans["node-w1"]["faults"][0]["after"] == B.ns_rfc3339(T0 + 21 * 10**9)
    assert "nodes" not in plans["node-w1"]["faults"][0] and m["applied"]


def test_no_target_means_not_applied(exported):
    _, meta = exported
    for n in meta["nodes"]:
        n["first_priority_ebpf"] = None
    tpl = {"version": "faultplan.v0", "seed": 1, "target": "first-priority-ebpf",
           "faults": [{"id": "stop", "kind": "stop", "stage": "source", "nodes": "target", "after": "target+1s"}]}
    plans, m = PL.instantiate(tpl, meta)
    assert not m["applied"] and all(not p["faults"] for p in plans.values()) and m["skipped"]


def test_decisive_contradictions_from_output(tmp_path, exported):
    _, meta = exported
    out = tmp_path / "o.jsonl.gz"
    recs = [{"witnessId": "w1", "status": "UNPROVEN"},
            {"witnessId": "w1", "status": "REJECTED", "contradictions": [
                {"decisive": True, "evidenceEventIds": ["e2"]}, {"decisive": False, "evidenceEventIds": ["e9"]}]},
            {"witnessId": "w2", "status": "CONFIRMED", "contradictions": [{"decisive": True, "evidenceEventIds": ["e7"]}]}]
    with gzip.open(out, "wt") as fh:
        for r in recs:
            fh.write(json.dumps({"topic": "witness.decisions.v0", "record": r}) + "\n")
    assert PL.decisive_contradictions(str(out)) == ["e2"]
    tpl = {"version": "faultplan.v0", "seed": 1, "faults": [
        {"id": "sup", "kind": "suppress", "stage": "transit", "select": {"logical_ids": "@decisive_contradictions"}}]}
    plans, m = PL.instantiate(tpl, meta, str(out))
    assert plans["node-cp"]["faults"][0]["select"]["logical_ids"] == ["e2"] and m["applied"]


def test_written_plans_are_deterministic_and_valid(tmp_path, exported):
    _, meta = exported
    for name in sorted(os.listdir(Path(REPO) / "experiments" / "exp3" / "plans")):
        tf = Path(REPO) / "experiments" / "exp3" / "plans" / name
        if "@decisive" in tf.read_text():
            continue
        a = PL.write_run_plans(str(tf), meta, str(tmp_path / "p1" / name))
        b = PL.write_run_plans(str(tf), meta, str(tmp_path / "p2" / name))
        assert a == b
        for f in os.listdir(tmp_path / "p1" / name):
            if f.endswith(".yaml"):
                x = (tmp_path / "p1" / name / f).read_bytes()
                assert x == (tmp_path / "p2" / name / f).read_bytes()
                plan = yaml.safe_load(x)
                assert plan["version"] == "faultplan.v0"
                assert all(k not in fl for fl in plan["faults"] for k in ("nodes",))


def test_conditions_and_passes_configs_load():
    c = PL.load_conditions(os.path.join(REPO, "experiments", "exp3", "configs", "conditions.tsv"))
    names = [x["condition"] for x in c]
    assert names[0] == "nofault" and len(names) == len(set(names))
    for x in c:
        assert os.path.exists(PL.template_path(os.path.join(REPO, "experiments", "exp3", "configs", "x"), x["template"]))
        if x["needs"]:
            assert x["needs"].split(":")[0] in names[:names.index(x["condition"])]
    from mtcore.exp3.run import load_passes
    p = load_passes(os.path.join(REPO, "experiments", "exp3", "configs", "passes.tsv"), "/m.yaml")
    assert [r["name"] for r in p][:3] == ["full", "no_contra_coverage", "no_epoch"]


def test_derived_params_change_only_the_ablation(tmp_path):
    from mtcore.exp3.run import derive_params
    main = os.path.join(REPO, "src", "params", "frozen", "pilot-multistep-fit.K10.mlv2.yaml")
    out = derive_params(main, "no_epoch", str(tmp_path))
    a, b = open(main).read().splitlines(), open(out).read().splitlines()
    diff = [x for x in b if x not in a]
    assert diff == ["  ablations:", "  - no_epoch"] and [x for x in a if x not in b] == ["  ablations: []"]
    assert os.path.exists(os.path.join(tmp_path, "params", "no_epoch", "models", "pilot-multistep-fit", "IF_B.json"))
    with pytest.raises(ValueError):
        derive_params(main, "no_such_switch", str(tmp_path))


def _write(p, lines):
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh:
        for x in lines:
            fh.write(json.dumps(x) + "\n")


def test_fault_log_consistency(exported, tmp_path):
    out, meta = exported
    fl = tmp_path / "fl"
    log = [{"header": {"node": "uid-w1", "stage": "source"}},
           {"fault_id": "l", "kind": "loss", "stage": "source", "logical_id": "e1", "lane": "NORMAL",
            "action": "dropped_unreported"},
           {"header": {"node": "uid-w1", "stage": "transit"}},
           {"fault_id": "t", "kind": "loss", "stage": "transit", "logical_id": "e2", "lane": "NORMAL", "seq": 2,
            "action": "dropped_reported"}]
    _write(fl / "faults.jsonl", log)
    gap = {"producer_id": "ingest-receiver", "source_completeness": {
        "scope": "node=uid-w1/boot=b/lane=NORMAL", "gaps": [{"reason": "DROPPED_BEFORE", "detail": "transport seq 2-2 not delivered"}]}}
    got = [{"topic": "norm.events.v0", "envelope": {"logical_id": x}} for x in ("e3", "e4", "g1", "c1", "g2")]
    _write(tmp_path / "rx.jsonl", got + [{"topic": "source.completeness.v0", "envelope": gap}])
    r = C.check_run(str(out), str(tmp_path / "rx.jsonl"), str(fl))
    assert r["ok"], r
    _write(tmp_path / "rx2.jsonl", got + [{"topic": "norm.events.v0", "envelope": {"logical_id": "e1"}}])
    r = C.check_run(str(out), str(tmp_path / "rx2.jsonl"), str(fl))
    assert not r["ok"] and r["failures"]["dropped_absent"] == ["e1"] and r["failures"]["transit_reported"]


def test_local_ctl_roundtrip(tmp_path):
    c = LocalCtl(tmp_path / "ctl")
    (tmp_path / "t").mkdir()
    (tmp_path / "t" / "a.txt").write_text("x")
    c.put_tree("jobs/j1/certs", tmp_path / "t")
    assert c.list_jobs() == []                              # not ready until job.json
    c.put_json("jobs/j1/job.json", {"sender": 0})
    assert c.list_jobs() == ["j1"] and c.get_json("jobs/j1/job.json") == {"sender": 0}
    c.get_tree("jobs/j1/certs", tmp_path / "u")
    assert (tmp_path / "u" / "a.txt").read_text() == "x" and c.get_json("done/j1.json") is None


# --- score_pilot.py --fault-log-root ---------------------------------------------------------------
def test_score_pilot_refuses_fault_logs_at_detect(tmp_path):
    with pytest.raises(SystemExit):
        SP.main(["--pilot", str(tmp_path), "--split", str(tmp_path / "s.json"), "--params", str(tmp_path / "p"),
                 "--out-dir", str(tmp_path / "o"), "--stage", "detect", "--fault-log-root", str(tmp_path)])


def test_score_pilot_passes_the_run_fault_log(tmp_path, monkeypatch):
    calls = []

    def run(cmd, cwd=None, stdout=None, stderr=None, **kw):
        calls.append(cmd)
        if "mtcore.harness.score" in cmd:
            Path(cmd[cmd.index("--out") + 1]).write_text('{"ok": 1}')
        return SimpleNamespace(returncode=0, stdout="")
    monkeypatch.setattr(SP.subprocess, "run", run)
    params = tmp_path / "p.yaml"
    params.write_text("x: 1\n")
    a = SimpleNamespace(out_dir=str(tmp_path / "out"), pilot=str(tmp_path / "runs"), params=str(params), no_ml=False,
                        stage="score", truth_root=str(tmp_path / "truth"), drop_source=None,
                        fault_log_root=str(tmp_path / "fl"))
    out = tmp_path / "out" / "runs" / "r1"
    out.mkdir(parents=True)
    with gzip.open(out / "output.jsonl.gz", "wt") as fh:
        fh.write("{}\n")
    (out / "time.json").write_text(json.dumps({"exit": 0, **SP.stamp(a)}))
    assert SP.run_one("r1", a)[1].startswith("FAILED (no fault log")    # never scored as fault-free
    (tmp_path / "fl" / "r1").mkdir(parents=True)
    (tmp_path / "fl" / "r1" / "faults.jsonl").write_text('{"header": {}}\n')
    assert SP.run_one("r1", a)[1] == "ok"
    scored = [c for c in calls if "mtcore.harness.score" in c]
    assert [("--fault-log" in c) for c in scored] == [False, True]          # nofault, then with the log
    assert scored[1][scored[1].index("--fault-log") + 1] == str(tmp_path / "fl" / "r1" / "faults.jsonl")
    assert (out / "score.json").exists() and (out / "score_nofault.json").exists()


def test_detection_commands_never_carry_truth_or_fault_logs(tmp_path):
    from mtcore.exp3 import run as R
    a = SimpleNamespace(work=str(tmp_path), workers=2, truth_root="/truth", faultlogs="/faultlogs")
    cond = {"condition": "loss-transit-20"}
    for p in ({"name": "full", "correlator": "go", "params": "/m.yaml", "ablation": "", "findings_from": "",
               "sage_variant": ""},
              {"name": "sage_ag", "correlator": "sage", "params": "/m.yaml", "ablation": "", "findings_from": "full",
               "sage_variant": "ag"}):
        det = R.score_pilot_cmd(a, cond, p, "detect")
        assert "--stage" in det and det[det.index("--stage") + 1] == "detect"
        assert not any("/truth" in x or "/faultlogs" in x for x in det)
        sc = R.score_pilot_cmd(a, cond, p, "score")
        assert sc[sc.index("--fault-log-root") + 1] == os.path.join("/faultlogs", "loss-transit-20")
