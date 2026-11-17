"""Exp. 4 runner core (mtcore.harness.exp4): the timing schedule (warm-up, rotated repeats, training
timed once), finding-rate units, configurations, the input cache, time caps, the replay and the
truth-free scoring step."""
import gzip
import json
import sys
import time
from types import SimpleNamespace

import pytest

import agent_fixtures as F
import orch_fixtures as O
from microtrace.v0 import witness_pb2

from mtcore.harness import exp4 as E
from mtcore.orchestrator.engine import Engine
from mtcore.orchestrator.keys import PROCESS_ANCESTRY

from test_orch_witness import fnd, proc

REPO_EXP4 = E.REPO / "experiments" / "exp4"


def _row(unit, system="go", timed="yes", train="no", prep="no", config=None, workload="m1"):
    return {"unit": unit, "system": system, "config": config or unit, "workload": workload, "workers": "2",
            "timed": timed, "train": train, "prep": prep}


# --- schedule -----------------------------------------------------------------------------
def test_three_units_rotate_abc_bca_cab_after_one_untimed_warmup():
    steps = E.schedule([_row("A"), _row("B"), _row("C")], repeats=3)
    acc = [s for s in steps if s["phase"] == "accuracy"]
    assert [s["unit"] for s in acc] == ["A", "B", "C"] and not any(s["timed"] for s in acc)
    assert E.rotation(steps) == {"rep1": ["A", "B", "C"], "rep2": ["B", "C", "A"], "rep3": ["C", "A", "B"]}
    assert all(s["timed"] for s in steps if s["phase"].startswith("rep"))


def test_untimed_units_run_once_and_training_is_timed_once_before_its_warmup():
    rows = [_row("ref", timed="no"), _row("full"), _row("orthrus", system="orthrus", train="yes", prep="yes")]
    steps = E.schedule(rows, repeats=3)
    assert steps[0]["step"] == "prep.orthrus" and not steps[0]["timed"]
    names = [s["step"] for s in steps]
    assert names.count("accuracy.ref") == 1 and not any(n.endswith(".ref") and n.startswith("rep") for n in names)
    train = [s for s in steps if s["action"] == "train"]
    assert [s["step"] for s in train] == ["accuracy.orthrus.train"] and train[0]["timed"]
    assert names.index("accuracy.orthrus.train") < names.index("accuracy.orthrus")
    assert [s["action"] for s in steps if s["unit"] == "orthrus" and s["phase"].startswith("rep")] == ["detect"] * 3
    assert E.rotation(steps) == {"rep1": ["full", "orthrus"], "rep2": ["orthrus", "full"], "rep3": ["full", "orthrus"]}


def test_many_units_rotate_by_a_third_of_the_list():
    rows = [_row(f"u{i}") for i in range(7)]
    rot = E.rotation(E.schedule(rows, repeats=3))
    assert [r[0] for r in rot.values()] == ["u0", "u2", "u4"]
    assert all(sorted(r) == sorted(x["unit"] for x in rows) for r in rot.values())


def test_duplicate_units_are_refused():
    with pytest.raises(ValueError):
        E.schedule([_row("A"), _row("A")])


def test_committed_plans_name_only_known_settings():
    for passes in ("passes.aws.tsv", "passes.local.tsv"):
        steps = E.complete_plan(E.schedule(E.read_tsv(REPO_EXP4 / passes)), REPO_EXP4 / "configs.tsv",
                                REPO_EXP4 / "workloads.tsv", REPO_EXP4 / "caps.tsv", REPO_EXP4 / "commands.tsv")
        assert all(s["cap_s"] > 0 for s in steps)
        assert all(s.get("cmd") for s in steps if s["system"] != "go")


def test_a_missing_cap_stops_the_plan(tmp_path):
    caps = tmp_path / "caps.tsv"
    caps.write_text("config\tworkload\tunit_cap_s\nfull\t*\t60\n")
    with pytest.raises(KeyError):
        E.complete_plan(E.schedule([_row("full"), _row("no_index")]), caps_path=caps)


# --- configurations and units -----------------------------------------------------------------
def test_configurations_override_k_l_t_and_index_without_touching_the_frozen_file():
    params = E.REPO / "src" / "params" / "frozen" / "pilot-multistep-fit.K10.mlv2.yaml"
    before = params.read_bytes()
    cfg = E.configs(REPO_EXP4 / "configs.tsv")
    full = E.oparams_for(params, cfg["full"])
    assert (full.K, full.L, full.T_ns) == (10, 6, 10000 * 10**9) and not full.ablations
    assert E.oparams_for(params, cfg["no_index"]).ablated("no_index")
    ex = E.oparams_for(params, cfg["exhaustive"])
    assert ex.ablated("no_index") and ex.K >= 10**6 and ex.L >= 10**6 and ex.T_ns >= 10**18
    assert E.oparams_for(params, cfg["reduced_k"]).K < full.K
    assert E.oparams_for(params, cfg["reduced_l"]).L < full.L
    assert E.oparams_for(params, cfg["reduced_t"]).T_ns < full.T_ns
    assert params.read_bytes() == before


def test_unknown_ablation_in_a_configuration_is_an_error(tmp_path):
    p = tmp_path / "c.tsv"
    p.write_text('config\toverrides\nbad\t{"ablations": ["no_indx"]}\n')
    with pytest.raises(ValueError):
        E.configs(p)


def test_units_are_consecutive_groups_in_run_id_order():
    units, left = E.make_units(["r3", "r1", "r4", "r2", "r5"], 2)
    assert [u["members"] for u in units] == [["r1", "r2"], ["r3", "r4"]] and left == ["r5"]
    units, left = E.make_units([f"r{i:03d}" for i in range(328)], 8)
    assert len(units) == 41 and not left


# --- caps -------------------------------------------------------------------------------------
def test_a_unit_past_its_cap_is_stopped(tmp_path):
    with open(tmp_path / "log", "w") as log:
        t0 = time.monotonic()
        rc, wall, capped, _f = E.timed_run([sys.executable, "-c", "import time; time.sleep(30)"], str(tmp_path), log,
                                           1.0, tmp_path / "t.txt")
    assert capped and wall < 10 and time.monotonic() - t0 < 10
    with open(tmp_path / "log", "w") as log:
        rc, _w, capped, _f = E.timed_run([sys.executable, "-c", "print(1)"], str(tmp_path), log, 30, tmp_path / "t.txt")
    assert rc == 0 and not capped


def test_parse_time():
    assert E.parse_time("Command exited\n2048 1.5 0.25\n") == {"peak_rss_mb": 2.0, "cpu_user_s": 1.5, "cpu_sys_s": 0.25}
    assert E.parse_time("") == {"peak_rss_mb": None, "cpu_user_s": None, "cpu_sys_s": None}


# --- replay and cache -------------------------------------------------------------------------
def _write_run(root, run_id, records, findings):
    """A run folder with one shipper file and an archive (score_pilot layout) from envelopes."""
    from google.protobuf import json_format
    d = root / "runs" / run_id / "shipper"
    d.mkdir(parents=True)
    with open(d / "node-1.jsonl", "w") as fh:
        fh.write(json.dumps({"lane": "NORMAL", "watermark": "x"}) + "\n")
        for env in records:
            fh.write(json.dumps({"topic": "norm.events.v0", "envelope": json_format.MessageToDict(env)}) + "\n")
        fh.write(json.dumps({"topic": "ground.truth.v0", "envelope": {"logical_id": "gt"}}) + "\n")
    a = root / "arch" / "runs" / run_id
    a.mkdir(parents=True)
    with gzip.open(a / "output.jsonl.gz", "wt") as fh:
        for env in findings:
            fh.write(json.dumps({"topic": "findings.v0", "record": json_format.MessageToDict(env.finding)},
                                sort_keys=True) + "\n")


def _chain(prefix, lineage):
    e1, e2, e3 = proc(10, 1, lineage=lineage), proc(20, 2, lineage=lineage), proc(30, 3, lineage=lineage)
    return [e1, e2, e3], [fnd(f"{prefix}1", e1), fnd(f"{prefix}2", e2), fnd(f"{prefix}3", e3)]


def test_replay_from_json_and_from_the_cache_give_the_same_output(tmp_path):
    ev, fs = _chain("fa", "ln-a")
    _write_run(tmp_path, "r1", ev, fs)
    run_dir, arch = tmp_path / "runs" / "r1", E.archived_output(tmp_path / "arch", "r1")
    p = O.oparams()
    plain = E.replay([run_dir], [arch], p)
    assert plain["findings"] == 3 and plain["records"] == 3 and plain["confirmed_witnesses"] >= 2
    cache = tmp_path / "cache.bin"
    E.write_cache(run_dir, arch, cache)
    assert [t for t, _e in E.read_cache(cache)] == ["norm.events.v0"] * 3 + ["findings.v0"] * 3
    cached = E.replay([run_dir], [arch], p, cache_files=[cache])
    assert cached["digest"] == plain["digest"]
    assert E.replay([run_dir], [arch], p)["digest"] == plain["digest"]      # deterministic


def test_overlay_feeds_both_runs_and_refuses_shared_ids(tmp_path):
    ev1, fs1 = _chain("fa", "ln-a")
    ev2, fs2 = _chain("fb", "ln-b")
    for e in ev2:                       # distinct event IDs, as distinct runs have
        e.normalized_event.event_id += "-b"
    for f in fs2:
        f.finding.input_event_ids[:] = [i + "-b" for i in f.finding.input_event_ids]
    _write_run(tmp_path, "r1", ev1, fs1)
    _write_run(tmp_path, "r2", ev2, fs2)
    runs = [tmp_path / "runs" / r for r in ("r1", "r2")]
    arch = [E.archived_output(tmp_path / "arch", r) for r in ("r1", "r2")]
    both = E.replay(runs, arch, O.oparams())
    assert both["findings"] == 6 and both["records"] == 6
    _write_run(tmp_path, "r3", ev1, fs1)             # a copy of r1: same IDs
    with pytest.raises(E.Collision):
        E.replay([runs[0], tmp_path / "runs" / "r3"], [arch[0], E.archived_output(tmp_path / "arch", "r3")],
                 O.oparams())


@pytest.mark.xfail(strict=True, reason="Property 3 premise (iii): A must bound the gap between a finding's "
                   "order time (event_start) and its supporting events; a windowed finding (H1, 300 s) breaks it, "
                   "and the index then misses a link No-Index confirms (worklog: Deviations, open question Q1)")
def test_index_and_no_index_agree_for_a_windowed_finding():
    e0 = proc(0, 1, lineage="ln-0")                    # the window's first event (another lineage)
    e1, e2 = proc(100, 2, lineage="ln-1"), proc(110, 3, lineage="ln-1")
    fa, fb = fnd("fa", e0, e1), fnd("fb", e2)          # fa's order time is 0, 110 s before fb's
    def links(p):
        eng = Engine(p)
        for env in (e0, e1, e2):
            eng.feed(env, "norm.events.v0")
        for env in (fa, fb):
            eng.feed(env, "findings.v0")
        eng.finish()
        return eng.passing()
    assert ("fa", "fb", PROCESS_ANCESTRY) in links(O.oparams(ablations=["no_index"]))
    assert links(O.oparams()) == links(O.oparams(ablations=["no_index"]))


# --- scoring (no truth) -----------------------------------------------------------------------
def _out(path, links, paths):
    """An output with CONFIRMED witnesses for links and one incident holding paths ((ids), score)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt") as fh:
        for i, (a, b) in enumerate(sorted(links)):
            fh.write(json.dumps({"topic": "witness.decisions.v0", "record": {
                "witnessId": f"w{a}{b}", "sourceFindingId": a, "targetFindingId": b, "status": "CONFIRMED"}}) + "\n")
        fh.write(json.dumps({"topic": "incidents.v0", "record": {
            "incidentId": "i1", "version": "1",
            "rankedPaths": [{"findingIds": list(p), "score": s} for p, s in paths]}}) + "\n")


def _pass(root, step, units, outs, capped=()):
    d = root / "passes" / step
    (d / "units").mkdir(parents=True)
    (d / "units.json").write_text(json.dumps({"units": [{"unit": u, "members": [u]} for u in units]}))
    digests = {}
    for u in units:
        ud = d / "units" / u
        ud.mkdir()
        if u in capped:
            (ud / "time.json").write_text(json.dumps({"exit": -9, "capped": True}))
            continue
        (ud / "time.json").write_text(json.dumps({"exit": 0, "capped": False}))
        _out(ud / "output.jsonl.gz", *outs[u])
        digests[u] = "d-" + u
    (d / "pass.json").write_text(json.dumps({"digests": digests, "go_seconds": 1.0, "pass_wall_s": 2.0}))


def test_score_session_recall_links_and_feasibility(tmp_path):
    ref = {"u0": ({("a", "b"), ("b", "c")}, [(("a", "b", "c"), 0.9), (("a", "b"), 0.8), (("b", "c"), 0.7)]),
           "u1": ({("x", "y")}, [(("x", "y"), 0.9)])}
    full = {"u0": ({("a", "b"), ("b", "c")}, [(("a", "b", "c"), 0.9), (("a", "b"), 0.8)]),
            "u1": ({("x", "y")}, [(("x", "y"), 0.9)])}
    _pass(tmp_path, "accuracy.ref_m1", ["u0", "u1"], ref)
    _pass(tmp_path, "accuracy.full_m1", ["u0", "u1"], full)
    _pass(tmp_path, "accuracy.noindex_m1", ["u0", "u1"], ref, capped=("u1",))
    _pass(tmp_path, "rep1.full_m1", ["u0", "u1"], full)
    steps = [{"step": "accuracy.ref_m1", "phase": "accuracy", "system": "go", "config": "exhaustive", "workload": "m1"},
             {"step": "accuracy.full_m1", "phase": "accuracy", "system": "go", "config": "full", "workload": "m1"},
             {"step": "accuracy.noindex_m1", "phase": "accuracy", "system": "go", "config": "no_index", "workload": "m1"},
             {"step": "rep1.full_m1", "phase": "rep1", "system": "go", "config": "full", "workload": "m1"}]
    res = E.score_session(tmp_path, steps, k=10)
    rows = {r["config"]: r for r in res["rows"]}
    f = rows["full"]
    assert (f["reference_paths"], f["retained"], f["path_recall"]) == (4, 3, 0.75)
    assert f["links_equal_reference"] == 2 and f["links_compared_no_index"] == 1 and f["links_equal_no_index"] == 1
    assert f["repeat_units_equal"] == 2 and f["repeat_units_compared"] == 2
    n = rows["no_index"]
    assert n["capped_units"] == 1 and n["feasible_units"] == 1 and n["path_recall"] == 1.0
    assert rows["exhaustive"]["path_recall"] == 1.0
    k2 = {r["config"]: r for r in E.score_session(tmp_path, steps, k=1)["rows"]}["full"]
    assert (k2["reference_paths"], k2["retained"]) == (2, 2)
    E.write_summary(tmp_path, res)
    assert (tmp_path / "exp4_summary.tsv").read_text().splitlines()[0].startswith("config\tworkload")


def test_command_steps_record_time_and_respect_their_cap(tmp_path):
    ok = E.main(["cmdstep", "--cmd", f'"{sys.executable}" -c "print(1)"', "--cap", "60", "--name", "stub",
                 "--out", str(tmp_path / "ok")])
    rec = json.loads((tmp_path / "ok" / "time.json").read_text())
    assert ok == 0 and rec["exit"] == 0 and not rec["capped"] and rec["command"] == "stub"
    capped = E.main(["cmdstep", "--cmd", f'"{sys.executable}" -c "import time; time.sleep(30)"', "--cap", "1",
                     "--name", "slow", "--out", str(tmp_path / "slow")])
    rec = json.loads((tmp_path / "slow" / "time.json").read_text())
    assert capped == 5 and rec["capped"] and rec["wall_s"] < 10


def test_derive_caps_takes_the_largest_development_unit(tmp_path):
    d = tmp_path / "passes" / "accuracy.full_m1"
    for u, wall in (("u000", 3.0), ("u001", 40.0)):
        (d / "units" / u).mkdir(parents=True)
        (d / "units" / u / "time.json").write_text(json.dumps({"wall_s": wall, "exit": 0, "capped": False}))
    (d / "units.json").write_text(json.dumps({"config": "full", "workload": "m1",
                                              "units": [{"unit": "u000"}, {"unit": "u001"}]}))
    c = tmp_path / "passes" / "accuracy.orthrus.train"
    c.mkdir(parents=True)
    (c / "time.json").write_text(json.dumps({"wall_s": 100.0, "exit": 0, "capped": False, "command": "orthrus"}))
    rows = {(r["config"], r["workload"]): r for r in E.derive_caps(tmp_path, factor=20, floor_s=600)}
    assert rows[("full", "m1")]["dev_max_unit_wall_s"] == 40.0 and rows[("full", "m1")]["proposed_unit_cap_s"] == 840
    assert rows[("orthrus:train", "*")]["proposed_unit_cap_s"] == 2040


def test_derive_paths_reads_lengths_and_spans_of_archived_full_outputs(tmp_path):
    from google.protobuf import json_format
    a = tmp_path / "runs" / "r1"
    a.mkdir(parents=True)
    lines = []
    for fid, t in (("f1", 0), ("f2", 30), ("f3", 200)):
        lines.append({"topic": "findings.v0", "record": json_format.MessageToDict(O.finding(fid, t).finding)})
    lines.append({"topic": "incidents.v0", "record": {"incidentId": "i", "version": "1", "rankedPaths": [
        {"findingIds": ["f1", "f2", "f3"], "score": 0.5}, {"findingIds": ["f1", "f2"], "score": 0.9},
        {"findingIds": ["f3"], "score": 1.0}]}})
    (a / "output.jsonl").write_text("".join(json.dumps(x) + "\n" for x in lines))
    r = E.derive_path_settings(tmp_path, ["r1"])
    assert r["paths"] == 2 and r["length"]["histogram"] == {"2": 1, "3": 1}
    assert r["span_s"]["max"] == 200 and r["proposed"]["L"] == 2 and r["proposed"]["T_s"] == 240
