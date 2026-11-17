"""Converter from our eBPF events to the DARPA-style tables of KAIROS (PIDSMaker)
and ORTHRUS (docs/plans/kairos-orthrus-our-data-plan.md, B1)."""
import csv
import json
import os
import subprocess
import sys

import pytest

from mtcore.baselines.provenance import convert as C
from microtrace.v0 import ebpf_pb2  # noqa: I100 (after mtcore: it sets up gen/)

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
PY = os.path.join(REPO, "src", "python")


def rec(family, **detail):
    r = ebpf_pb2.RawEbpfRecord(event_family=family, node_id="n", boot_id="b")
    r.process.CopyFrom(ebpf_pb2.ProcessKey(node_id="n", boot_id="b", tgid=2, start_time_ns=20))
    r.parent.CopyFrom(ebpf_pb2.ProcessKey(node_id="n", boot_id="b", tgid=1, start_time_ns=10))
    for k, v in detail.items():
        getattr(r, k).CopyFrom(v)
    return r


def test_fork_is_parent_to_child_and_orphan_fork_has_no_edge():
    r = rec("proc.fork")
    assert C._pkey(C.actor(r)) == "n:b:1:10"
    assert C.edges_of(r) == [("EVENT_CLONE", "subject", "n:b:2:20", None, "")]
    r.ClearField("parent")
    assert C._pkey(C.actor(r)) == "n:b:2:20" and C.edges_of(r) == []


def test_edge_types_follow_darpa_tc():
    f = ebpf_pb2.FileIdentity(dev=1, ino=7, resolved_path="/tmp/x")
    assert C.edges_of(rec("file.read", file_access=ebpf_pb2.FileAccessDetail(op=ebpf_pb2.FILE_READ, file=f)))[0][0] \
        == "EVENT_READ"
    assert C.edges_of(rec("file.mutation", file_mutation=ebpf_pb2.FileMutationDetail(op=ebpf_pb2.WRITE, file=f))
                      )[0][0] == "EVENT_WRITE"
    assert C.edges_of(rec("file.mutation", file_mutation=ebpf_pb2.FileMutationDetail(op=ebpf_pb2.UNLINK, file=f))
                      ) == []
    sock = ebpf_pb2.SocketDetail(op=ebpf_pb2.ACCEPT, local=ebpf_pb2.Endpoint(ip="10.0.0.2", port=8080),
                                 remote=ebpf_pb2.Endpoint(ip="10.0.0.1", port=40000),
                                 flow=ebpf_pb2.FlowId(node_id="n", boot_id="b", socket_cookie=5))
    assert C.edges_of(rec("net.accept", socket=sock))[0][:3] == ("EVENT_RECVFROM", "netflow", "cookie:n:b:5")
    fc = ebpf_pb2.FlowCounter(flow=ebpf_pb2.FlowId(node_id="n", boot_id="b", socket_cookie=5), bytes_out=10,
                              bytes_in=3)
    assert [e[0] for e in C.edges_of(rec("net.flow_bytes", flow_counter=fc))] == ["EVENT_SENDTO", "EVENT_RECVFROM"]
    for fam in ("priv.creds", "ns.change", "proc.ptrace", "bpf.call", "proc.exit", "token.file_index"):
        assert C.edges_of(rec(fam)) == []


def test_val_runs_are_fixed_by_run_id_hash():
    ids = [f"r{i}" for i in range(20)]
    assert C.val_runs(ids, 0.15) == C.val_runs(list(reversed(ids)), 0.15)
    assert len(C.val_runs(ids, 0.15)) == 3 and C.val_runs(ids, 0) == set()


@pytest.fixture(scope="module")
def converted(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("prov")
    env = dict(os.environ, PYTHONHASHSEED="1")
    runs = {"train": "chain_container_escape", "test": "h1_external_large_egress"}
    for name, sc in runs.items():
        subprocess.run([sys.executable, "-m", "mtgen", "build", "--scenarios", sc, "--duration-s", "180",
                        "--world", "Small", "--seed", "7", "--out", str(tmp / "runs" / name)],
                       check=True, cwd=PY, env=env, capture_output=True)
    split = tmp / "split.json"
    split.write_text(json.dumps({"fit": ["train"], "score": ["test"]}))
    out = tmp / "out"
    C.main(["--out", str(out), "--name", "MTTEST", "--val-fraction", "0",
            "--runs", f"train={tmp / 'runs'}@{split}:fit", "--runs", f"pilot={tmp / 'runs'}@{split}:score"])
    return tmp, out


def _rows(path):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.reader(fh))


def test_tables_are_consistent(converted):
    _, out = converted
    idx = {}
    for t in ("subject_node_table", "file_node_table", "netflow_node_table"):
        for r in _rows(out / f"{t}.csv"):
            idx[r[1]] = int(r[-1])
    assert sorted(idx.values()) == list(range(len(idx)))
    ev = _rows(out / "event_table.csv")
    assert ev and all(idx[r[0]] == int(r[1]) and idx[r[3]] == int(r[4]) for r in ev)
    assert all(r[0] != r[3] for r in ev)
    assert len({r[5] for r in ev}) == len(ev)
    assert {r[2] for r in ev} <= set(C.EDGE_REVERSED) | {"EVENT_CLONE", "EVENT_WRITE", "EVENT_CONNECT", "EVENT_SENDTO"}


def test_train_runs_lose_scenario_events_only(converted):
    tmp, out = converted
    scen = C.scenario_event_ids(str(tmp / "runs" / "train"))
    assert scen
    m = _rows(out / "event_map.csv")[1:]
    train_ids = {r[1] for r in m if r[0] == "train"}
    assert not train_ids & scen
    all_ebpf = {eid for eid, _, _ in C.read_ebpf(str(tmp / "runs" / "train"))}
    assert train_ids == all_ebpf - scen
    test_ids = {r[1] for r in m if r[0] == "test"}
    assert test_ids == {eid for eid, _, _ in C.read_ebpf(str(tmp / "runs" / "test"))}


def test_days_config_and_ground_truth(converted):
    _, out = converted
    cfg = json.load(open(out / "config.json"))["MTTEST_PILOT"]
    assert cfg["train_dates"] == ["2030-01-01"] and cfg["test_dates"] == ["2030-01-02"]
    assert cfg["ground_truth_relative_path"] == ["pilot/test.csv"]
    assert cfg["attack_to_time_window"] == [["pilot/test.csv", "2030-01-02 00:00:00", "2030-01-02 23:59:59"]]
    gt = _rows(out / "ground_truth" / "pilot" / "test.csv")
    assert gt and all(len(r) == 3 for r in gt)
    ts = [int(r[6]) for r in _rows(out / "event_table.csv")]
    day0 = 1893456000 * 10**9                                     # 2030-01-01 UTC
    assert min(ts) >= day0 and max(ts) < day0 + 2 * 86400 * 10**9


def test_sealed_group_never_reads_its_truth(converted, tmp_path, monkeypatch):
    tmp, _ = converted
    test_dir = str(tmp / "runs" / "test")
    real = C._read_ld

    def guard(path, cls):
        assert not path.startswith(test_dir), f"sealed truth read: {path}"
        return real(path, cls)
    monkeypatch.setattr(C, "_read_ld", guard)
    split = tmp / "split.json"
    out = tmp_path / "sealed"
    C.main(["--out", str(out), "--name", "MTTEST", "--val-fraction", "0", "--sealed", "pilot",
            "--runs", f"train={tmp / 'runs'}@{split}:fit", "--runs", f"pilot={tmp / 'runs'}@{split}:score"])
    gt = _rows(out / "ground_truth" / "pilot" / "test.csv")
    subjects = {r[0]: int(r[-1]) for r in _rows(out / "subject_node_table.csv")}
    test_subjects = {r[5] for r in _rows(out / "event_map.csv")[1:] if r[0] == "test"}
    first = min((subjects[u], u) for u in test_subjects)
    ev = _rows(out / "event_table.csv")
    edge_idx = {int(r[1]) for r in ev} | {int(r[4]) for r in ev}
    first = min((subjects[u], u) for u in test_subjects if subjects[u] in edge_idx)
    assert gt == [[first[1], gt[0][1], str(first[0])]] and gt[0][1].startswith("{'subject': ")
    assert json.load(open(out / "manifest.json"))["sealed"] == ["pilot"]
    with pytest.raises(SystemExit):
        C.main(["--out", str(out), "--sealed", "train", "--runs", f"train={tmp / 'runs'}@{split}:fit"])


# --- B2: scoring adapters ---------------------------------------------------------------

def test_kairos_rule_on_a_converted_run(converted):
    from mtcore.baselines.provenance import score as PS
    from microtrace.v0 import dataset_pb2
    tmp, out = converted
    run_dir = str(tmp / "runs" / "test")
    em = PS.load_event_map(str(out / "event_map.csv"))["test"]
    opps, acts = PS._truth(run_dir)
    host = [o for o in opps if o.finding_type in C.HOST_TYPES and o.expected_state == dataset_pb2.PRESENT]
    assert host
    # Nothing flagged: nothing detected, no flagged nodes.
    s = PS.kairos_summary(PS.kairos_run(run_dir, em, set()))
    assert s["steps"]["present"] == len(host) and s["steps"]["detected"] == 0 and s["nodes"]["flagged"] == 0
    # Flag the attack nodes: every step whose evidence touches them is detected, all flagged nodes are TP.
    attack = PS.nodes_of([e for a in acts if a.is_attack for e in a.rendered_event_ids], em)
    s = PS.kairos_summary(PS.kairos_run(run_dir, em, attack))
    assert s["nodes"]["tp"] == len(attack) and s["nodes"]["fp"] == 0
    want = sum(bool(PS.nodes_of(o.evidence_event_ids, em) & attack) for o in host)
    assert s["steps"]["detected"] == want > 0
    # A flagged node no attack event touches is a false positive; one from another run is ignored.
    background = PS.nodes_of(em, em) - attack
    s = PS.kairos_summary(PS.kairos_run(run_dir, em, {next(iter(background)), "not-a-node-of-this-run"}))
    assert s["nodes"] == {"flagged": 1, "tp": 0, "fp": 1, "precision": 0.0}


def test_kairos_nodes_report_matches_the_step_rule(converted):
    from mtcore.baselines.provenance import score as PS
    tmp, out = converted
    run_dir = str(tmp / "runs" / "test")
    em = PS.load_event_map(str(out / "event_map.csv"))["test"]
    _, acts = PS._truth(run_dir)
    attack = PS.nodes_of([e for a in acts if a.is_attack for e in a.rendered_event_ids], em)
    background = sorted(PS.nodes_of(em, em) - attack)[0]
    flagged = attack | {background, "not-a-node-of-this-run"}
    per = PS.kairos_nodes(run_dir, em, flagged)
    assert set(per) == attack | {background}
    assert all(v["attack_node"] == (n in attack) for n, v in per.items())
    s = PS.kairos_nodes_summary({"test": per})
    run = PS.kairos_summary(PS.kairos_run(run_dir, em, flagged))
    assert s["flagged_nodes"] == run["nodes"]["flagged"] == len(attack) + 1
    assert s["steps_covered"] == run["steps"]["detected"]
    assert s["nodes_covering_steps"] == sum(bool(v["steps"]) for v in per.values())
    assert sum(s["steps_per_covering_node"].values()) == s["nodes_covering_steps"]


def test_detected_cli_kairos_and_nodes_and_missing_truth(converted, tmp_path):
    from mtcore.baselines.provenance import detected as DT, score as PS
    tmp, out = converted
    em = PS.load_event_map(str(out / "event_map.csv"))["test"]
    node = sorted(PS.nodes_of(em, em))[0]
    flagged = tmp_path / "flagged.csv"
    flagged.write_text(f"node_uuid,index_id,node_type,score\n{node},0,subject,1.0\n")
    for cmd in ("kairos", "kairos-nodes"):
        o = tmp_path / f"{cmd}.json"
        assert DT.main([cmd, "--conv", str(out), "--group", "pilot", "--data", str(tmp / "runs"),
                        "--flagged", str(flagged), "--out", str(o)]) == 0 and json.load(open(o))["group"] == "pilot"
    # A wrong truth root is an error, not zero steps.
    with pytest.raises(FileNotFoundError):
        DT.main(["kairos", "--conv", str(out), "--group", "pilot", "--data", str(tmp_path / "nowhere"),
                 "--flagged", str(flagged), "--out", str(tmp_path / "x.json")])


def test_training_run_without_truth_is_an_error(tmp_path):
    (tmp_path / "r" / "restricted").mkdir(parents=True)
    with pytest.raises(FileNotFoundError):
        C.scenario_event_ids(str(tmp_path / "r"))


def test_orthrus_links_findings_of_one_graph_in_time_order():
    from mtcore.baselines.provenance import score as PS
    from microtrace.v0 import finding_pb2

    def f(fid, t, events):
        x = finding_pb2.Finding(finding_id=fid, input_event_ids=events)
        x.event_start.FromNanoseconds(t)
        return x
    findings = {"f1": f("f1", 10, ["e1"]), "f2": f("f2", 20, ["e2"]), "f2b": f("f2b", 20, ["e3"]),
                "f3": f("f3", 30, ["e4"]), "fx": f("fx", 15, ["e9"])}
    em = {"e1": ("p1", "x1"), "e2": ("p2", ""), "e3": ("p3", ""), "e4": ("p4", "x4"), "e9": ("p9", "")}
    recs = PS.orthrus_records("run", [{"x1", "p2", "p3", "x4"}], findings, em, k=2)
    w = {(r["sourceFindingId"], r["targetFindingId"]) for t, r in recs if t == "witness.decisions.v0"}
    assert w == {("f1", "f2"), ("f1", "f2b"), ("f2", "f3"), ("f2b", "f3")}       # fx is not in the graph
    inc = [r for t, r in recs if t == "incidents.v0"]
    assert len(inc) == 1 and set(inc[0]["findingIds"]) == {"f1", "f2", "f2b", "f3"}
    assert PS.orthrus_records("run", [{"nothing"}], findings, em, k=2) == []
    # One graph per seed: same members are one incident, and a shared link counts once.
    recs = PS.orthrus_records("run", [{"x1", "p2"}, {"p1", "p2"}, {"p2", "x4"}], findings, em, k=2)
    assert len([r for t, r in recs if t == "incidents.v0"]) == 2
    assert {(r["sourceFindingId"], r["targetFindingId"]) for t, r in recs if t == "witness.decisions.v0"} == \
        {("f1", "f2"), ("f2", "f3")}
    assert len([r for t, r in recs if t == "witness.decisions.v0"]) == 2


def test_seeds_are_findings_with_graph_nodes_and_graphs_are_one_per_seed():
    from mtcore.baselines.provenance import seeded as SD
    from microtrace.v0 import finding_pb2

    def f(fid, events):
        return finding_pb2.Finding(finding_id=fid, input_event_ids=events)
    findings = {"host": f("host", ["e1"]), "gateway": f("gateway", ["http-1"]), "lost": f("lost", ["e2"])}
    em = {"e1": ("u1", "u2"), "e2": ("u9", "")}
    index = {"u1": "1", "u2": "2"}
    assert SD.seeds_of(findings, em, index) == {"host": ["1", "2"]}
    assert SD.graphs_of({"b": ["1"], "a": ["1", "2"]}, index) == [{"u1", "u2"}, {"u1"}]


def test_context_row_traces_all_flagged_nodes_of_a_run_as_one_graph():
    from mtcore.baselines.provenance import detected as DT
    from mtcore.baselines.provenance import seeded as SD
    em = {"r1": {"e1": ("u1", "u2"), "e2": ("u3", "")}, "r2": {"e1": ("v1", "")}, "train": {"e1": ("t1", "")}}
    node_run = DT.run_of_node(em)
    flagged = [("u3", "13"), ("u1", "11"), ("t1", "99"), ("u1", "11")]
    seeds = DT.seeds_by_run(flagged, node_run, {"r1": "2030-01-04", "r2": "2030-01-05"})
    # One entry per run of the group; a node of another group is dropped; r2 has nothing to trace.
    assert seeds == {"r1": {"date": "2030-01-04", "seeds": {DT.SEED: ["11", "13"]}},
                     "r2": {"date": "2030-01-05", "seeds": {}}}
    # seeded records then makes one graph per run: the union of its traces.
    index = {"u1": "11", "u2": "12", "u3": "13"}
    assert SD.graphs_of({DT.SEED: ["11", "12", "13"]}, index) == [{"u1", "u2", "u3"}]
    assert SD.graphs_of({}, index) == []
