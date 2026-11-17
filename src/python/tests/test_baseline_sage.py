"""SAGE baseline (Exp. 2 and 3): the frozen mapping, findings -> alerts,
SAGE's exported paths -> witnesses and incidents, and the scorer round trip.
The last test runs the real, patched SAGE and needs MT_SAGE_HOME (test host)."""
import json
import os

import pytest
from google.protobuf import json_format

from mtcore.baselines.sage import alerts as A
from mtcore.baselines.sage import mapping as M
from mtcore.baselines.sage import project as P
from mtcore.baselines.sage import run as R
from mtcore.harness import score as S
from microtrace.v0 import common_pb2, dataset_pb2, finding_pb2  # noqa: I100 (after mtcore: it sets up gen/)

TE = dataset_pb2.TruthExpectation
RUN = "0b5c3a2e-1111-4222-8333-444455556666"


def finding(fid, ftype, t, events=(), entities=(), **attrs):
    f = finding_pb2.Finding(finding_id=fid, finding_type=ftype, input_event_ids=list(events))
    f.event_start.FromNanoseconds(int(t * 1e9))
    for etype, uid in entities:
        f.entities.add(type=common_pb2.EntityType.Value(etype), uid=uid)
    for k, v in attrs.items():
        f.attributes[k] = v
    return f


def test_mapping_covers_exactly_the_included_rules():
    m = M.load()
    assert sorted(m.rows) == M.included_types()
    assert all(r.stage in M.STAGES for r in m.rows.values())
    assert m.extra_signatures()["H4"] == "DATA_EXFILTRATION"


def test_g1a_and_g1c_of_one_connection_share_an_endpoint_pair():
    # S-10: G1c is G1a's connection seen from the accepting Pod; its entities
    # are [accepting Pod, connecting Pod], the reverse of G1a's.
    m = M.load()
    g1a = finding("fa", "G1a", 100, entities=[("POD", "client"), ("POD", "server")], port="8080")
    g1c = finding("fc", "G1c", 100.001, entities=[("POD", "server"), ("POD", "client")], port="8080")
    teams, _, skipped = A.build({RUN: [g1a, g1c]}, m)
    al = {a["microtrace_finding_id"]: a for a in teams[RUN]}
    assert not skipped
    assert (al["fa"]["src_ip"], al["fa"]["dest_ip"]) == (al["fc"]["src_ip"], al["fc"]["dest_ip"])
    assert al["fa"]["dest_port"] == al["fc"]["dest_port"] == 8080
    assert m.rows["G1c"].stage == m.rows["G1a"].stage == "LATERAL_MOVEMENT"


def test_mapping_rejects_bad_rows(tmp_path):
    p = tmp_path / "m.yaml"
    p.write_text("version: x\nsage_commit: c\ncategory: c\nfindings:\n  A1: {stage: NOPE, source: [entity:POD], "
                 "destination: [self]}\n")
    with pytest.raises(ValueError, match="unknown SAGE stage"):
        M.load(str(p))
    p.write_text("version: x\nsage_commit: c\ncategory: c\nfindings:\n  A1: {stage: INFO_DISC, source: [self], "
                 "destination: [self]}\n")
    with pytest.raises(ValueError, match="destination selector only"):
        M.load(str(p))
    p.write_text("version: x\nsage_commit: c\ncategory: c\nfindings:\n  A1: {stage: INFO_DISC, source: [entity:POD], "
                 "destination: [entity:SERVICE#1]}\n")
    with pytest.raises(ValueError, match="unknown entity type"):
        M.load(str(p))


def test_gateway_finding_without_a_pod_goes_client_to_gateway():
    # S-11: A1 and A2 carry only HTTP_REQUEST entities, nothing names a workload.
    teams, ips, skipped = A.build({RUN: [finding("f", "A1", 1, entities=[("HTTP_REQUEST", "req")])]}, M.load())
    assert not skipped
    al = teams[RUN][0]
    assert (al["src_ip"], al["dest_ip"]) == (ips[(RUN, "const:client")], ips[(RUN, "const:gateway")])


def test_select_follows_selector_order():
    f = finding("f", "D1", 1, entities=[("POD", "owner"), ("POD", "reader")],
                token_owner_pod_uid="owner", reader_pod_uid="")
    assert A.select(f, ["attr:reader_pod_uid", "attr:token_owner_pod_uid"]) == "owner"
    assert A.select(f, ["entity:POD#1"]) == "reader"
    assert A.select(f, ["entity:NETWORK_ENDPOINT", "const:external"]) == "const:external"
    assert A.select(f, ["self"], source="owner") == "owner"
    assert A.select(f, ["entity:USER"]) is None


def test_alerts_newest_first_with_sage_fields():
    m = M.load()
    fs = [finding("f1", "E2", 100.5, entities=[("POD", "p1")]),
          finding("f2", "H2", 110.25, entities=[("POD", "p1"), ("NETWORK_ENDPOINT", "198.51.100.7")], port="443"),
          finding("f3", "G2", 120, entities=[("POD", "p1")]),            # excluded rule: not mapped
          finding("f4", "B1", 130)]                                       # no principal
    teams, ips, skipped = A.build({RUN: fs}, m)
    al = teams[RUN]
    assert [a["microtrace_finding_id"] for a in al] == ["f2", "f1"]
    assert al[0]["timestamp"] == "1970-01-01T00:01:50.250000+0000"
    assert al[0]["dest_port"] == 443 and "dest_port" not in al[1]
    assert al[1]["src_ip"] == al[1]["dest_ip"] == al[0]["src_ip"]          # E2 acts inside its own Pod
    assert al[0]["alert"] == {"signature": "H2", "category": m.category}
    assert skipped == {"unmapped_type:G2": 1, "no_source:B1": 1}


def test_pseudo_ips_are_per_run_deterministic_and_unique():
    ips = A.PseudoIPs()
    keys = [(r, "pod-%d" % i) for r in ("r1", "r2") for i in range(500)]
    ips.assign(keys)
    assert len({ips[k] for k in keys}) == len(keys)
    again = A.PseudoIPs()
    again.assign(reversed(keys))
    assert all(ips[k] == again[k] for k in keys)
    assert ips[("r1", "pod-1")] != ips[("r2", "pod-1")]


PATHS = [{"victim": "10.0.0.2", "objective": "DATA_EXFILTRATION|unknown", "attacker": "t0-10.0.0.1",
          "episodes": [{"vertex": "a", "start": 5, "end": 6, "alert_ids": ["f1"]},
                       {"vertex": "b", "start": 9, "end": 9, "alert_ids": ["f2", "f3"]},
                       {"vertex": "c", "start": 20, "end": 21, "alert_ids": ["f4"]}]}]
SEQS = {"t0-10.0.0.1->10.0.0.2-0": [{"start": 5, "alert_ids": ["f1"]}, {"start": 9, "alert_ids": ["f2", "f3"]}],
        "t0-10.0.0.1->10.0.0.2-1": [{"start": 30, "alert_ids": ["f5"]}, {"start": 40, "alert_ids": ["f6"]}]}


def _records(out, topic):
    return [rec for t, rec in out if t == topic]


def test_project_links_consecutive_episodes_only():
    out = P.project("ag", {0: RUN}, PATHS, SEQS, k=2)[RUN]
    pairs = sorted((w["sourceFindingId"], w["targetFindingId"]) for w in _records(out, P.WITNESSES))
    assert pairs == [("f1", "f2"), ("f1", "f3"), ("f2", "f4"), ("f3", "f4")]    # never f1 -> f4
    assert all(w["status"] == "CONFIRMED" for w in _records(out, P.WITNESSES))
    (inc,) = _records(out, P.INCIDENTS)
    assert inc["findingIds"] == ["f1", "f2", "f3", "f4"]
    assert [p["findingIds"] for p in inc["rankedPaths"]] == [["f1", "f2", "f4"], ["f1", "f3", "f4"]]
    assert all(len(p["witnessIds"]) == 2 for p in inc["rankedPaths"])


def test_project_k_and_seq_variant():
    out = P.project("ag", {0: RUN}, PATHS, SEQS, k=1)[RUN]
    (inc,) = _records(out, P.INCIDENTS)
    assert len(inc["rankedPaths"]) == 1
    seq = P.project("seq", {0: RUN}, PATHS, SEQS, k=2)[RUN]
    pairs = sorted((w["sourceFindingId"], w["targetFindingId"]) for w in _records(seq, P.WITNESSES))
    assert pairs == [("f1", "f2"), ("f1", "f3"), ("f5", "f6")]
    (inc,) = _records(seq, P.INCIDENTS)                     # one attacker-victim pair, two subsequences
    assert inc["findingIds"] == ["f1", "f2", "f3", "f5", "f6"]


def test_projection_is_deterministic():
    a = P.project("ag", {0: RUN}, PATHS, SEQS, k=2)
    b = P.project("ag", {0: RUN}, list(reversed(PATHS)), dict(reversed(list(SEQS.items()))), k=2)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_scorer_counts_sage_links_like_the_gos():
    def action(seq, ev):
        return dataset_pb2.GroundTruthAction(run_id="r", action_seq=seq, scenario_id="s", is_attack=True,
                                             rendered_event_ids=[ev])

    def opp(o, seq, ev):
        return dataset_pb2.FindingOpportunity(run_id="r", opportunity_id=o, action_seq=seq, finding_type="E2",
                                              expected_state=TE.Value("PRESENT"), evidence_event_ids=[ev])

    def link(lid, a, b, state):
        return dataset_pb2.ActionLink(run_id="r", link_id=lid, from_action_seq=a, to_action_seq=b,
                                      expected_state=TE.Value(state))

    truth = S.Truth([action(i, "e%d" % i) for i in (1, 2, 3, 4)], [opp("o%d" % i, i, "e%d" % i) for i in (1, 2, 3, 4)],
                    [link("L1", 1, 2, "PRESENT"), link("L2", 1, 3, "ABSENT"), link("L3", 2, 4, "PRESENT")])
    fs = {f"f{i}": finding(f"f{i}", "E2", i, events=[f"e{i}"]) for i in (1, 2, 3, 4)}
    lines = [json.dumps({"topic": S.FINDINGS, "record": json_format.MessageToDict(f)}) for f in fs.values()]
    lines += [json.dumps({"topic": t, "record": r}) for t, r in P.project("ag", {0: RUN}, PATHS, {}, k=2)[RUN]]
    lk = S.score(truth, S.Output.parse(lines))["links"]
    assert (lk["tp"], lk["fp"], lk["fn"]) == (2, 2, 0)                    # f1->f3 ABSENT; f3->f4 no truth row
    assert lk["violated_nonlinks"] == [[1, 3]]


def test_trace_count_reads_sages_trace_file(tmp_path):
    assert R.trace_count(str(tmp_path)) is None
    (tmp_path / "exp.txt").write_text("0 0\n")
    assert R.trace_count(str(tmp_path)) == 0
    (tmp_path / "exp.txt").write_text("3 5\n1 3 a b c\n")
    assert R.trace_count(str(tmp_path)) == 3


def test_run_id_of_cached_names():
    assert R.run_id_of(f"/x/twin_safety/{RUN}.output.jsonl") == RUN
    assert R.run_id_of(f"/x/score/runs/{RUN}/output.jsonl.gz") == RUN


@pytest.mark.skipif(not os.environ.get("MT_SAGE_HOME"), reason="needs the patched SAGE (MT_SAGE_HOME)")
def test_real_sage_end_to_end(tmp_path):
    """Two runs, each a five-step chain in one Pod ending in exfiltration: SAGE
    must link consecutive episodes, and the output must score."""
    paths = []
    for n, run in enumerate(("11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")):
        chain = [("E2", 0), ("F1", 40), ("D1", 80), ("H2", 120), ("H4", 160), ("H4", 161)]
        fs = []
        for i, (ftype, dt) in enumerate(chain):
            ents = [("POD", "pod-%d" % n)] + ([("NETWORK_ENDPOINT", "198.51.100.9")] if ftype in ("H2", "H4") else [])
            fs.append(finding("%s-f%d" % (run[:4], i), ftype, 1_700_000_000 + 1000 * n + dt, events=["e%d" % i],
                              entities=ents, token_owner_pod_uid="pod-%d" % n))
        p = tmp_path / ("%s.output.jsonl" % run)
        p.write_text("".join(json.dumps({"topic": S.FINDINGS, "record": json_format.MessageToDict(f)}) + "\n"
                             for f in fs))
        paths.append(str(p))
    stats = R.run(paths, str(tmp_path / "out"), os.environ["MT_SAGE_HOME"], M.load(), t=1.0, w=30, k=2)
    assert stats["sage_exit"] == 0 and stats["runs_with_alerts"] == 2
    assert stats["subsequences"] >= 2
    for variant in P.VARIANTS:
        for p in paths:
            out = S.Output.load(str(tmp_path / "out" / variant / (R.run_id_of(p) + ".jsonl")))
            assert len(out.findings) == 6
    assert stats["variants"]["seq"]["witnesses"] > 0
