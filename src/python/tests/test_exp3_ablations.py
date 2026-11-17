"""Exp. 3 ablations decided 2026-11-16 (docs/plans/exp3-runner-worklog.md Q-1, Q-2, Q-4, Q-7):
the GO switches no_coverage and no_uncertainty, the No-OffNode drop of PATH_FLOW, the pass
config, the merged fault log, and the UR/PCC summary columns."""
import gzip
import io
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import agent_fixtures as F
import orch_fixtures as O
import test_orch_admission as A
import test_orch_witness as TW
from test_agent_gaps import idle
from test_drop_source import STREAM, norm

from mtcore import REPO
from mtcore.harness import offline
from mtcore.harness.score import read_fault_log
from mtcore.orchestrator import ablations

sys.path.insert(0, str(Path(REPO) / "src" / "scripts" / "pilot"))
import score_pilot as SP  # noqa: E402

PA, NF = A.PA, A.NF
CONFIRMED, REJECTED, UNPROVEN = A.CONFIRMED, A.REJECTED, A.UNPROVEN
NOCOV, NOUNC = O.oparams(ablations=["no_coverage"]), O.oparams(ablations=["no_uncertainty"])


def test_new_switches_are_registered_and_off_by_default():
    assert {"no_coverage", "no_uncertainty"} <= set(ablations.ABLATIONS)
    assert not O.oparams().ablated("no_coverage") and not O.oparams().ablated("no_uncertainty")
    for name in ("src/params/frozen/pilot-multistep-fit.K10.mlv2.yaml", "src/params/frozen/fit-ri-on.K10.yaml"):
        p = O.OrchParams.load(os.path.join(REPO, name))
        assert not p.ablations


# --- Q-1 No-Coverage -----------------------------------------------------------------------
def test_no_coverage_confirms_a_pair_whose_contradiction_source_reported_a_loss():
    recs = A._flow(reuse=False, loss_node="node-1")          # the reusing CONNECT lost, loss recorded
    full = A.published(A.run(*recs))[("f1", "f2", NF)]
    assert full.status == UNPROVEN and full.contradiction_coverage[0].loss_overlap
    nc = A.published(A.run(*recs, oparams=NOCOV))[("f1", "f2", NF)]
    assert nc.status == CONFIRMED and not nc.contradiction_coverage[0].loss_overlap


def test_no_coverage_ignores_an_idle_gap_over_the_interval():
    e1, e2 = A.proc(1, 10), A.proc(5, 11)
    recs = [e1, e2, A.fnd("f1", e1), A.fnd("f2", e2), idle(2, 4)]
    full = A.published(A.run(*recs))[("f1", "f2", PA)]
    assert full.status == UNPROVEN and full.contradiction_coverage[0].idle_overlap
    assert A.status_of(A.run(*recs, oparams=NOCOV), "f1", "f2", PA) == CONFIRMED


def test_no_coverage_takes_a_missing_action_id_as_no_id():
    # loss near f2 only: DistinctAction unresolved in Full, resolved (distinct) under no_coverage
    e1, e2 = A.proc(1, 10), A.proc(5, 11)
    recs = [e1, e2, A.fnd("f1", e1), A.fnd("f2", e2), F.loss(12, 14, source="EBPF")]
    assert A.status_of(A.run(*recs), "f1", "f2", PA) == UNPROVEN
    assert A.status_of(A.run(*recs, oparams=NOCOV), "f1", "f2", PA) == CONFIRMED


def test_no_coverage_keeps_epochs_and_contradictions():
    e1, e2 = A.proc(1, 10, ingest=1.2), A.proc(5, 11, ingest=5.5)
    w = A.published(A.run(e1, e2, A.fnd("f1", e1), A.fnd("f2", e2), *A.c1b(10), oparams=NOCOV))[("f1", "f2", PA)]
    assert w.status == UNPROVEN and w.contradiction_coverage[0].epoch_overlap
    assert A.status_of(A.run(*A._flow(reuse=True), oparams=NOCOV), "f1", "f2", NF) == REJECTED


# --- Q-2 No-Uncertainty --------------------------------------------------------------------
def test_no_uncertainty_accepts_a_pair_whose_declared_uncertainty_exceeds_the_cap():
    e1, e2 = TW.proc(1, 10, unc_ms=3000), TW.proc(5, 11, unc_ms=3000)      # eps 6 s > eps_bar 5 s
    recs = [e1, e2, TW.fnd("f1", e1), TW.fnd("f2", e2)]
    assert ("f1", "f2", PA) not in TW.run(*recs).passing()
    eng = TW.run(*recs, oparams=NOUNC)
    assert ("f1", "f2", PA) in eng.passing()
    [d] = TW.why(eng, "f1", "f2", PA)
    assert d.eps_ns == 6 * 10**9 and d.slack_ns == 4 * 10**9               # declared eps kept, not used


def test_no_uncertainty_rejects_a_small_negative_gap_the_uncertainty_allowed():
    e1, e2 = TW.proc(1.0, 10, unc_ms=1), TW.proc(0.999, 11, unc_ms=1)       # node_seq says e1 first
    recs = [e1, e2, TW.fnd("f1", e1), TW.fnd("f2", e2)]
    assert ("f1", "f2", PA) in TW.run(*recs).passing()
    eng = TW.run(*recs, oparams=NOUNC)
    assert ("f1", "f2", PA) not in eng.passing()
    assert A.status_of(A.run(*recs, oparams=NOUNC), "f1", "f2", PA) == REJECTED


def test_switches_off_leave_the_example_trace_unchanged():
    def dump(op):
        eng = A.run(*[env for _l, _t, env, _k in O.trace_records()], oparams=op)
        return [env.SerializeToString(deterministic=True) for _t, _k, env in eng.drain()]
    base = dump(O.oparams())
    assert base and dump(O.oparams(ablations=[])) == base


# --- Q-4 No-OffNode ------------------------------------------------------------------------
def test_path_flow_is_droppable_and_declared_not_shipped(tmp_path):
    log = io.StringIO()
    kept = list(offline.drop_filter(iter(STREAM + [norm("p1", "PATH_FLOW")]), "PATH_FLOW", log))
    decl = kept[0][1].source_completeness
    assert decl.source == F.common_pb2.Source.Value("PATH_FLOW") and "No-OffNode" in decl.gaps[0].detail
    ids = [e.normalized_event.event_id for _, e in kept[1:] if e.HasField("normalized_event")]
    assert ids == ["e1", "a1", "g1", "d1", "x1", "a2"]                       # DB_AUDIT stays
    (tmp_path / "d.jsonl").write_text(log.getvalue())
    assert read_fault_log(str(tmp_path / "d.jsonl"))[0] == {"p1", "L-p1"}


def test_exp1_sources_keep_their_declared_text():
    kept = list(offline.drop_filter(iter(STREAM), "AUDIT", io.StringIO()))
    assert kept[0][1].source_completeness.gaps[0].detail == "Exp. 1 telemetry ablation: source not shipped"
    assert offline.SECURITY == ("EBPF", "GATEWAY", "KYVERNO", "AUDIT")


def test_score_pilot_merges_the_flow_drop_log_with_the_injector_log(tmp_path, monkeypatch):
    seen = []

    def run(cmd, cwd=None, stdout=None, stderr=None, **kw):
        if "mtcore.harness.score" in cmd:
            if "--fault-log" in cmd:
                seen.append(read_fault_log(cmd[cmd.index("--fault-log") + 1]))
            Path(cmd[cmd.index("--out") + 1]).write_text('{"ok": 1}')
        return SimpleNamespace(returncode=0, stdout="")
    monkeypatch.setattr(SP.subprocess, "run", run)
    params = tmp_path / "p.yaml"
    params.write_text("x: 1\n")
    a = SimpleNamespace(out_dir=str(tmp_path / "out"), pilot=str(tmp_path / "runs"), params=str(params), no_ml=False,
                        stage="score", truth_root=str(tmp_path / "truth"), drop_source="PATH_FLOW",
                        fault_log_root=str(tmp_path / "fl"))
    out = tmp_path / "out" / "runs" / "r1"
    out.mkdir(parents=True)
    with gzip.open(out / "output.jsonl.gz", "wt") as fh:
        fh.write("{}\n")
    with gzip.open(out / "dropped.jsonl.gz", "wt") as fh:
        fh.write('{"header": {"ablation": "drop-source"}}\n{"logical_id": "p1", "action": "dropped_reported"}\n')
    (out / "time.json").write_text(json.dumps({"exit": 0, **SP.stamp(a)}))
    (tmp_path / "fl" / "r1").mkdir(parents=True)
    (tmp_path / "fl" / "r1" / "faults.jsonl").write_text(
        '{"header": {"node": "n"}}\n{"logical_id": "e9", "action": "dropped_unreported"}')    # no final newline
    assert SP.run_one("r1", a)[1] == "ok"
    assert seen == [({"e9", "p1"}, set())]
    assert not (out / "faults_merged.jsonl").exists() and not (out / "dropped.jsonl").exists()


def test_score_pilot_cli_allows_only_path_flow_with_a_fault_log_root(tmp_path):
    common = ["--pilot", str(tmp_path), "--split", str(tmp_path / "s.json"), "--params", str(tmp_path / "p"),
              "--out-dir", str(tmp_path / "o"), "--stage", "score", "--fault-log-root", str(tmp_path)]
    with pytest.raises(SystemExit):
        SP.main(common + ["--drop-source", "AUDIT"])
    with pytest.raises(FileNotFoundError):                  # past argument checks: reads the split file
        SP.main(common + ["--drop-source", "PATH_FLOW"])


# --- passes config (Q-1, Q-2, Q-4, Q-5) ------------------------------------------------------
def test_passes_config_enables_the_new_passes_where_their_mechanism_is_exercised():
    from mtcore.exp3.run import load_passes, pass_applies
    p = {r["name"]: r for r in load_passes(os.path.join(REPO, "experiments", "exp3", "configs", "passes.tsv"),
                                            "/m.yaml")}
    assert p["no_coverage"]["ablation"] == "no_coverage" and p["no_uncertainty"]["ablation"] == "no_uncertainty"
    assert p["no_offnode"]["ablation"] == "drop:PATH_FLOW" and "no_history" not in p
    for name, conds in (("no_coverage", ("nofault", "loss-transit-20", "outage-ebpf-source")),
                        ("no_uncertainty", ("nofault", "skew-10s-undeclared")),
                        ("no_offnode", ("nofault", "loss-source-40", "outage-gateway-transit"))):
        assert all(pass_applies(p[name], c) for c in conds)
    assert not pass_applies(p["no_uncertainty"], "loss-transit-20")
    # exp3-b (Targeted): ONLY=nofault,suppress-*,compromise-* still runs every ablation on nofault
    assert {n for n, r in p.items() if pass_applies(r, "nofault")} >= {
        "full", "no_contra_coverage", "no_epoch", "no_coverage", "no_uncertainty", "no_offnode"}


def test_bad_drop_or_switch_in_passes_is_refused(tmp_path):
    from mtcore.exp3.run import load_passes
    for abl in ("drop:AUDIT", "no_such_switch"):
        f = tmp_path / "p.tsv"
        f.write_text(f"x\tgo\t@main\t{abl}\t-\t-\tnofault\n")
        with pytest.raises(SystemExit):
            load_passes(str(f), "/m.yaml")


def test_no_offnode_commands_drop_at_detect_and_merge_at_score(tmp_path):
    from mtcore.exp3 import run as R
    a = SimpleNamespace(work=str(tmp_path), workers=2, truth_root="/truth", faultlogs="/faultlogs")
    p = {"name": "no_offnode", "correlator": "go", "params": "/m.yaml", "ablation": "drop:PATH_FLOW",
         "findings_from": "", "sage_variant": ""}
    det = R.score_pilot_cmd(a, {"condition": "loss-transit-20"}, p, "detect")
    assert det[det.index("--drop-source") + 1] == "PATH_FLOW" and det[det.index("--params") + 1] == "/m.yaml"
    assert not any("/truth" in x or "/faultlogs" in x for x in det)
    sc = R.score_pilot_cmd(a, {"condition": "loss-transit-20"}, p, "score")
    assert "--drop-source" in sc and "--fault-log-root" in sc


def test_derived_params_for_the_new_switches(tmp_path):
    from mtcore.exp3.run import derive_params
    main = os.path.join(REPO, "src", "params", "frozen", "fit-ri-on.K10.yaml")
    for sw in ("no_coverage", "no_uncertainty"):
        out = derive_params(main, sw, str(tmp_path))
        a, b = open(main).read().splitlines(), open(out).read().splitlines()
        assert [x for x in b if x not in a] == ["  ablations:", f"  - {sw}"]


# --- Q-7 UR and PCC ------------------------------------------------------------------------
def _gzlines(p, lines):
    p.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(p, "wt", encoding="utf-8") as fh:
        for x in lines:
            fh.write(json.dumps(x) + "\n")


def test_summary_reports_ur_and_pcc_with_definitions(tmp_path):
    from mtcore.exp3 import summary as S
    w, cond, run = tmp_path / "w", "compromise-blind", "r1"
    d = w / "detect" / cond / "full"
    d.mkdir(parents=True)
    (d / "summary.json").write_text(json.dumps({
        "runs_scored": 1, "correlator": "go", "findings": {}, "links": {}, "paths": {},
        "end_to_end": {"findings": {"present": 40, "unresolved": 10, "recall": 0.5}}}))
    wit = lambda wid, st, a, b: {"topic": "witness.decisions.v0",  # noqa: E731
                                 "record": {"witnessId": wid, "status": st, "sourceFindingId": a, "targetFindingId": b}}
    fnd = lambda fid, evs: {"topic": "findings.v0", "record": {"findingId": fid, "inputEventIds": evs}}  # noqa: E731
    _gzlines(d / "runs" / run / "output.jsonl.gz", [
        fnd("fa", ["ea"]), fnd("fb", ["eb"]), fnd("fc", ["ec"]),
        wit("w1", "CONFIRMED", "fa", "fb"),                        # source on the compromised node: counted
        wit("w2", "CONFIRMED", "fb", "fc"),                        # source elsewhere
        wit("w3", "CONFIRMED", "fa", "fc"), wit("w3", "UNPROVEN", "fa", "fc")])   # revised: not counted
    rx = lambda eid, node: {"topic": "norm.events.v0", "envelope": {"normalized_event": {  # noqa: E731
        "event_id": eid, "ebpf": {"node_id": node}}}}
    _gzlines(w / "received" / cond / run / "shipper" / "received.jsonl.gz",
             [rx("ea", "uid-w1"), rx("eb", "uid-cp"), rx("ec", "uid-w1")])
    fl = tmp_path / "fl"
    (fl / cond / run).mkdir(parents=True)
    (fl / cond / run / "faults.jsonl").write_text(
        '{"header": {"node": "uid-cp", "stage": "source"}}\n{"header": {"node": "uid-w1", "stage": "source"}}\n'
        '{"fault_id": "compromise-blind", "kind": "blind", "logical_id": "x", "action": "dropped_unreported"}\n')
    rows = S.write_summary(str(w), [cond], str(fl))
    [r] = rows
    assert r["ur"] == 0.25 and r["pcc"] == 1 and r["pcc_runs_compromised"] == 1
    out = json.load(open(w / "exp3-summary.json"))
    assert set(out["definitions"]) == {"UR", "PCC"} and out["rows"][0]["pcc"] == 1
    md = (w / "exp3-summary.md").read_text()
    assert "- UR:" in md and "- PCC:" in md


def test_compromised_node_from_the_plan_when_the_fault_left_no_entry(tmp_path):
    from mtcore.exp3 import summary as S
    (tmp_path / "plan").mkdir()
    (tmp_path / "plan" / "meta.json").write_text(json.dumps(
        {"target": "node-w1", "faults_per_node": {"node-w1": ["compromise-stop"], "node-cp": []}}))
    (tmp_path / "base").mkdir()
    (tmp_path / "base" / "base.json").write_text(json.dumps(
        {"nodes": [{"node": "node-w1", "node_id": "uid-w1"}, {"node": "node-cp", "node_id": "uid-cp"}]}))
    assert S.compromised_nodes(None, str(tmp_path / "plan"), str(tmp_path / "base")) == {"uid-w1"}
