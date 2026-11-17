"""Scoring harness (build step 8, Exp. 1-4): opportunity matching, false
positives on lookalikes and background, UNOBSERVABLE neither way, directed
action-pair links with unmapped and intra-action witnesses, the fault-log
adjustment, the generator's truth file format, and the CLI."""
import json

from google.protobuf import json_format

from mtcore.harness import score as S
from microtrace.v0 import dataset_pb2, finding_pb2, incident_pb2, witness_pb2  # noqa: I100 (after mtcore: it sets up gen/)
from mtgen.truth import write_ld_protos

TE = dataset_pb2.TruthExpectation
WT = witness_pb2.WitnessType


def action(seq, events, scenario="scn-1", attack=True):
    return dataset_pb2.GroundTruthAction(run_id="r", action_seq=seq, scenario_id=scenario, is_attack=attack,
                                         rendered_event_ids=events)


def opp(oid, seq, ftype, state, events):
    return dataset_pb2.FindingOpportunity(run_id="r", opportunity_id=oid, action_seq=seq, finding_type=ftype,
                                          expected_state=TE.Value(state), evidence_event_ids=events)


def link(lid, a, b, state, wtype="WITNESS_TYPE_UNSPECIFIED"):
    return dataset_pb2.ActionLink(run_id="r", link_id=lid, from_action_seq=a, to_action_seq=b,
                                  expected_state=TE.Value(state), witness_type=WT.Value(wtype))


def finding(fid, ftype, events):
    return finding_pb2.Finding(finding_id=fid, finding_type=ftype, input_event_ids=events)


def wit(wid, src, dst, status="CONFIRMED", wtype="NETWORK_FLOW"):
    return witness_pb2.Witness(witness_id=wid, source_finding_id=src, target_finding_id=dst,
                               status=witness_pb2.WitnessStatus.Value(status), relationship_type=WT.Value(wtype))


def truth():
    return S.Truth(
        [action(1, ["e1", "e2"]), action(2, ["e3", "e4"]), action(3, ["e5"], scenario="benign", attack=False),
         action(4, ["e6"], scenario="scn-2")],
        [opp("o1", 1, "D1", "PRESENT", ["e1"]), opp("o2", 2, "E2", "PRESENT", ["e3"]),
         opp("o3", 3, "D1", "ABSENT", ["e5"]), opp("o4", 4, "H1", "PRESENT", ["e6"]),
         opp("o5", 2, "B1", "UNOBSERVABLE", ["e4"])],
        [link("L1", 1, 2, "PRESENT", "NETWORK_FLOW"), link("L2", 1, 3, "ABSENT"),
         link("L3", 2, 4, "PRESENT", "REQUEST_IDENTITY")])


def output():
    fs = [finding("f1", "D1", ["e1"]), finding("f2", "E2", ["e9"]), finding("f3", "D1", ["e5"]),
          finding("f4", "B1", ["e4"]), finding("f5", "E2", ["e3", "e3x"])]
    ws = [wit("w1", "f1", "f5"), wit("w2", "f1", "f3"), wit("w3", "f1", "f2"), wit("w4", "f5", "f4"),
          wit("w5", "f5", "f1", status="REJECTED")]
    return S.Output({f.finding_id: f for f in fs}, {w.witness_id: w for w in ws})


def test_findings_true_false_missed_and_unobservable():
    r = S.score(truth(), output())["findings"]
    o = r["overall"]
    assert (o["tp"], o["fn"], o["fp"], o["fp_absent"], o["fp_background"], o["on_unobservable"]) == (2, 1, 2, 1, 1, 1)
    assert o["precision"] == 0.5 and abs(o["recall"] - 2 / 3) < 1e-9
    assert r["false_findings"] == ["f2", "f3"]
    assert r["missed_opportunities"] == ["o4"]
    t = r["per_type"]
    assert (t["D1"]["tp"], t["D1"]["fp_absent"]) == (1, 1)
    assert (t["E2"]["tp"], t["E2"]["fp_background"]) == (1, 1)
    assert t["H1"]["fn"] == 1 and t["H1"]["recall"] == 0.0
    assert t["B1"]["unsupported"] and t["B1"]["recall"] is None and t["B1"]["on_unobservable"] == 1
    assert r["by_scenario"]["scn-1"] == {"present": 2, "tp": 2, "recall": 1.0}
    assert r["by_scenario"]["scn-2"]["recall"] == 0.0


def test_one_finding_on_two_opportunities_counts_each_present_once():
    t = truth()
    t.opportunities.append(opp("o6", 1, "D1", "PRESENT", ["e2"]))
    out = output()
    out.findings["f1"] = finding("f1", "D1", ["e1", "e2"])
    o = S.score(t, out)["findings"]["overall"]
    assert (o["tp"], o["present"]) == (3, 4)


def test_links_directed_pairs_unmapped_intra_and_nonlinks():
    r = S.score(truth(), output())["links"]
    assert (r["tp"], r["fp"], r["fn"], r["present"]) == (1, 2, 1, 2)
    assert r["false_pairs"] == [[1, 3]] and r["violated_nonlinks"] == [[1, 3]]
    assert r["unmapped_witnesses"] == ["w3"]             # f2's input event belongs to no action
    assert r["intra_action_witnesses"] == ["w4"]         # f5 and f4 are both action 2
    assert r["missed_links"] == ["L3"]
    assert r["type_agreement"] == 1.0
    assert r["precision"] == 1 / 3


def test_direction_matters():
    out = output()
    out.witnesses = {"w9": wit("w9", "f5", "f1")}        # 2 -> 1: no row, a false link
    r = S.score(truth(), out)["links"]
    assert (r["tp"], r["fp"]) == (0, 1) and r["false_pairs"] == [[2, 1]]


def test_links_without_an_opportunity_at_both_ends_are_counted_apart():
    t = truth()
    t.actions.append(action(5, ["e7"]))                                # no opportunity on action 5
    t.links += [link("L4", 4, 5, "PRESENT", "PROCESS_ANCESTRY"), link("L5", 1, 5, "ABSENT"),
                link("L6", 5, 2, "PRESENT")]
    out = output()
    out.findings["f6"] = finding("f6", "H1", ["e6"])                   # action 4
    out.findings["f7"] = finding("f7", "E2", ["e7"])                   # action 5, fired on background
    out.witnesses.update({"w6": wit("w6", "f6", "f7"), "w7": wit("w7", "f1", "f7")})
    r = S.score(t, out)["links"]
    assert (r["tp"], r["fn"], r["present"], r["scored_links"]) == (1, 1, 2, 2)   # L4, L6 not in recall
    assert r["unscored_links"] == {"ABSENT": 2, "PRESENT": 2}           # L2: action 3 has an ABSENT opportunity only
    assert r["unscored_proposed"] == [[4, 5]]                          # neither true nor false
    assert [1, 5] in r["false_pairs"] and [1, 5] in r["violated_nonlinks"]       # an unscored nonlink is still false
    assert r["fp"] == 3                                                # 1->3, 1->5 and unmapped w3
    p = S.score(t, path_output((["f1", "f5", "f6"], 0.9)))["paths"]
    assert p["reference_paths"] == 1 and p["recovered"] == 1           # 4->5 and 5->2 are not reference edges
    assert S.scored_link_ids(t) == {"L1", "L3"}


def test_fault_log_makes_dropped_evidence_unobservable(tmp_path):
    log = tmp_path / "faults.jsonl"
    log.write_text("\n".join(json.dumps(x) for x in [
        {"header": {"seed": 1}},
        {"fault_id": "loss", "logical_id": "e6", "action": "dropped_reported"},
        {"fault_id": "skew", "logical_id": "e1", "action": "shifted"},
        {"fault_id": "forge", "logical_id": "e9", "action": "forged"}]) + "\n")
    dropped, forged = S.read_fault_log(str(log))
    assert dropped == {"e6"} and forged == {"e9"}
    r = S.score(truth(), output(), dropped, forged)
    f, lk = r["findings"], r["links"]
    assert f["overall"]["fn"] == 0 and f["missed_opportunities"] == []    # o4 is UNOBSERVABLE now
    assert f["unobservable_opportunities"] == 2 and f["on_forged"] == 1
    assert (lk["present"], lk["fn"], lk["unobservable_links"]) == (1, 0, 1)   # L3's to-action has no PRESENT left
    assert truth().opportunities[3].expected_state == TE.Value("PRESENT")     # base truth untouched


def test_generator_files_and_cli(tmp_path, capsys):
    t = truth()
    d = tmp_path / "restricted"
    d.mkdir()
    write_ld_protos(d / "truth_actions.pb", t.actions)
    write_ld_protos(d / "truth_findings.pb", t.opportunities)
    write_ld_protos(d / "truth_links.pb", t.links)
    loaded = S.Truth.load(str(d))
    assert [a.action_seq for a in loaded.actions] == [1, 2, 3, 4] and len(loaded.links) == 3
    out = output()
    lines = []
    for f in out.findings.values():
        lines.append({"topic": S.FINDINGS, "record": json_format.MessageToDict(f)})
        lines.append({"topic": S.FINDINGS, "record": json_format.MessageToDict(f)})     # redelivered
    lines.append({"topic": S.WITNESSES, "record": json_format.MessageToDict(wit("w1", "f1", "f5", "UNPROVEN"))})
    for w in out.witnesses.values():                                                     # last record wins
        lines.append({"topic": S.WITNESSES, "record": json_format.MessageToDict(w)})
    lines.append({"topic": S.WITNESSES, "heartbeat": {}})
    lines.append({"topic": S.EVALUATIONS, "record": {"evaluationId": "ev1", "outcome": "ABSTAINED"}})
    run = tmp_path / "out.jsonl"
    run.write_text("\n".join(json.dumps(x) for x in lines) + "\n")
    assert S.main(["--truth", str(d), "--output", str(run), "--out", str(tmp_path / "score.json")]) == 0
    got = json.loads((tmp_path / "score.json").read_text())
    want = json.loads(json.dumps(S.score(t, out)))
    assert got["links"] == want["links"]
    assert got["findings"]["overall"] == want["findings"]["overall"]
    assert got["findings"]["evaluations"] == 1 and got["findings"]["abstained"] == 1


def test_truncated_truth_file_is_an_error(tmp_path):
    p = tmp_path / "t.pb"
    write_ld_protos(p, [action(1, ["e1"])])
    p.write_bytes(p.read_bytes()[:-2])
    try:
        S.read_ld(str(p), dataset_pb2.GroundTruthAction)
    except ValueError as e:
        assert "truncated" in str(e)
    else:
        raise AssertionError("no error")


# --- paths, false chains, latency (step 8g; definitions of 2026-10-12) -----------------
def incident(iid, version, *paths):
    return incident_pb2.Incident(incident_id=iid, version=version, ranked_paths=[
        incident_pb2.RankedPath(path_id=f"{iid}-p{i}", finding_ids=fs, score=sc)
        for i, (fs, sc) in enumerate(paths)])


def path_output(*paths, version=1):
    out = output()
    out.findings["f6"] = finding("f6", "H1", ["e6"])                 # action 4
    out._incident(incident("inc-1", version, *paths))
    return out


def test_reference_paths_are_source_to_sink_chains_of_present_links():
    t = truth()                                                       # 1->2 PRESENT, 2->4 PRESENT, 1->3 ABSENT
    states = S.effective_link_states(t, S.effective_states(t, set()))
    assert S.reference_paths(t, states) == ([(1, 2, 4)], False)
    t.links += [link("L4", 1, 5, "PRESENT"), link("L5", 6, 7, "PRESENT"), link("L6", 7, 6, "PRESENT")]
    states = S.effective_link_states(t, S.effective_states(t, set()))
    paths, truncated = S.reference_paths(t, states)
    assert not truncated
    assert paths == [(1, 2, 4), (1, 5), (6, 7)]                      # a cycle no source reaches is still walked
    assert S.reference_paths(t, states, limit=2)[1] is True


def test_a_reference_path_is_recovered_only_in_order_with_distinct_findings():
    r = S.score(truth(), path_output((["f1", "f5", "f6"], 0.9)))["paths"]
    assert (r["reference_paths"], r["recovered"], r["top_k_path_recall"]) == (1, 1, 1.0)
    assert r["by_length"] == {"3": {"reference": 1, "recovered": 1, "recovered_loose": 1, "recall": 1.0}}
    r = S.score(truth(), path_output((["f5", "f1", "f6"], 0.9)))["paths"]          # wrong order
    assert r["recovered"] == 0 and r["missed_paths"] == [[1, 2, 4]]
    r = S.score(truth(), path_output((["f1", "f5"], 0.9), (["f5", "f6"], 0.8)))["paths"]
    assert r["recovered"] == 0                                        # split over two paths: not one path
    acts = {"fx": {1, 2}}
    assert not S.covers((1, 2), ["fx"], acts)                         # one finding cannot stand for two steps


def test_a_false_step_outside_the_matched_stretch_does_not_count_against_it():
    r = S.score(truth(), path_output((["f3", "f1", "f5", "f6"], 0.9)))["paths"]   # f3 -> f1: no truth row
    assert (r["recovered"], r["recovered_loose"], r["top_k_path_recall"]) == (1, 1, 1.0)
    assert r["false_chains"] == 1                                     # the path is still a false chain


def test_a_match_that_holds_only_across_a_false_step_is_not_recovered():
    r = S.score(truth(), path_output((["f1", "f2", "f5", "f6"], 0.9)))["paths"]   # f2 maps to no action
    assert (r["recovered"], r["recovered_loose"]) == (0, 1)
    assert r["top_k_path_recall"] == 0.0 and r["top_k_path_recall_loose"] == 1.0
    assert r["by_length"]["3"] == {"reference": 1, "recovered": 0, "recovered_loose": 1, "recall": 0.0}
    assert r["missed_paths"] == [[1, 2, 4]]


def test_clean_segments_cut_at_false_steps():
    acts = S.finding_actions(truth(), path_output())
    state = {(1, 2): S.PRESENT, (2, 4): S.PRESENT}
    assert S.clean_segments(("f1", "f2", "f5", "f6"), acts, state) == [("f1",), ("f2",), ("f5", "f6")]
    assert S.clean_segments(("f1", "f5", "f6"), acts, state) == [("f1", "f5", "f6")]
    assert S.clean_segments((), acts, state) == []


def test_an_unobservable_link_breaks_the_reference_chain(tmp_path):
    log = tmp_path / "faults.jsonl"
    log.write_text(json.dumps({"logical_id": "e3", "action": "dropped_unreported"}) + "\n")
    t = truth()
    dropped, _ = S.read_fault_log(str(log))
    r = S.score(t, path_output((["f1", "f5", "f6"], 0.9)), dropped)["paths"]
    assert r["reference_paths"] == 0                                  # action 2 blind: 1->2 and 2->4 unobservable


def test_false_chain_rate_counts_retained_paths_with_a_false_step():
    out = path_output((["f1", "f5", "f6"], 0.9), (["f1", "f3"], 0.5), (["f1", "f2"], 0.4), (["f5"], 0.1))
    r = S.score(truth(), out)["paths"]
    assert (r["retained_paths"], r["retained_multi"], r["false_chains"]) == (4, 3, 2)
    assert abs(r["false_chain_rate"] - 2 / 3) < 1e-9
    assert {tuple(x["finding_ids"]) for x in r["false_chain_examples"]} == {("f1", "f3"), ("f1", "f2")}


def test_only_each_incidents_latest_record_counts():
    out = path_output((["f1", "f3"], 0.5), version=1)
    out._incident(incident("inc-1", 2, (["f1", "f5", "f6"], 0.9)))
    out._incident(incident("inc-1", 1, (["f1", "f3"], 0.5)))         # an older version arriving late
    r = S.score(truth(), out)["paths"]
    assert (r["incidents"], r["recovered"], r["false_chains"]) == (1, 1, 0)


def test_reference_run_recall_keeps_the_k_best_paths_per_incident():
    ref = S.Output()
    ref._incident(incident("inc-1", 1, (["a", "b"], 0.9), (["a", "c"], 0.7), (["a", "d"], 0.8)))
    run = S.Output()
    run._incident(incident("inc-1", 1, (["a", "b"], 0.9), (["a", "c"], 0.7)))
    r = S.reference_path_recall(ref, run, k=2)                        # reference top 2: a-b, a-d
    assert (r["reference_paths"], r["retained"], r["recall"]) == (2, 1, 0.5)


def test_latency_from_input_arrival_to_finding_and_from_findings_to_link():
    lines = [{"topic": S.EVENTS, "event": "e1", "timestamp_ms": 1000},
             {"topic": S.EVENTS, "event": "e3", "timestamp_ms": 1100},
             {"topic": S.EVENTS, "event": "e3x", "timestamp_ms": 1300},
             {"topic": S.EVENTS, "event": "e3", "timestamp_ms": 5000},       # redelivered: first counts
             {"topic": S.FINDINGS, "record": json_format.MessageToDict(finding("f1", "D1", ["e1"])),
              "timestamp_ms": 1250},
             {"topic": S.FINDINGS, "record": json_format.MessageToDict(finding("f5", "E2", ["e3", "e3x"])),
              "timestamp_ms": 1800},
             {"topic": S.FINDINGS, "record": json_format.MessageToDict(finding("f9", "E2", ["e404"])),
              "timestamp_ms": 1900},                                         # input not in the dump
             {"topic": S.WITNESSES, "record": json_format.MessageToDict(wit("w1", "f1", "f5", "UNPROVEN")),
              "timestamp_ms": 1850},
             {"topic": S.WITNESSES, "record": json_format.MessageToDict(wit("w1", "f1", "f5")),
              "timestamp_ms": 2100},
             {"topic": S.WITNESSES, "record": json_format.MessageToDict(wit("w1", "f1", "f5")),
              "timestamp_ms": 2600}]
    out = S.Output.parse(json.dumps(x) for x in lines)
    lat = S.score_latency(out)
    f = lat["finding"]
    assert f["overall"]["n"] == 2 and f["without_timestamps"] == 1
    assert sorted([f["per_type"]["D1"]["max_ms"], f["per_type"]["E2"]["max_ms"]]) == [250, 500]
    assert f["overall"]["p50_ms"] == 250 and f["overall"]["max_ms"] == 500 and f["overall"]["mean_ms"] == 375
    c = lat["correlation"]["overall"]
    assert (c["n"], c["max_ms"]) == (1, 300)                          # first CONFIRMED (2100) - later finding (1800)


def test_offline_output_has_no_latency():
    lat = S.score(truth(), output())["latency"]
    assert lat["finding"]["overall"] is None and lat["correlation"]["overall"] is None


def test_dump_writes_event_lines_only_when_asked():
    from mtcore.harness.dump import _line
    from microtrace.v0 import envelope_pb2
    env = envelope_pb2.Envelope(logical_id="lid-1")
    env.normalized_event.event_id = "ev-1"
    assert _line(S.EVENTS, 0, 5, 1234, env, False, events=True) == {"topic": S.EVENTS, "event": "ev-1",
                                                                       "timestamp_ms": 1234}
    assert _line(S.EVENTS, 0, 5, 1234, env, False) is None


def test_same_socket_continuity_links_are_scored():
    # Bytes counted on the connect's own flow: that no witness type of our
    # correlator covers it is a miss, not a reason to drop the link.
    t = truth()
    t.links[0].reason = "same-socket continuity: bytes counted on the connect's flow"
    assert S.scored_link_ids(t) == {"L1", "L3"}


def test_benign_continuity_links_are_not_scored():
    # Two findings of one benign process: neither an attack link nor a
    # mistake, so it does not count.
    t = truth()
    t.links[0].reason = "benign continuity: one decoy process"
    assert S.scored_link_ids(t) == {"L3"}
    r = S.score(t, output())["links"]
    assert [1, 2] in r["unscored_proposed"] and [1, 2] not in r["false_pairs"]


def test_a_link_between_findings_that_share_an_event_is_scored():
    # A correlator that refuses such a link by design misses a true link.
    t = truth()
    t.links[0].reason = "same-process continuity: one connect feeds both rules"
    assert S.scored_link_ids(t) == {"L1", "L3"}


def test_links_are_also_reported_without_same_process_rows():
    t = truth()
    t.links[0].reason = "same-process continuity: one process acts twice"
    r = S.score(t, output())["links"]
    x = r["without_same_process"]
    assert (r["present"], r["tp"]) == (2, 1)
    assert (x["present"], x["tp"], x["fn"], x["fp"]) == (1, 0, 1, r["fp"])


def test_other_actions_of_a_true_links_finding_are_companions_not_false_links():
    # An H1 window finding maps to two egress actions; the witness to it is a
    # true link through one of them (A3). An ABSENT pair stays false.
    t = truth()
    t.actions.append(action(5, ["e7"]))
    t.opportunities.append(opp("o7", 5, "E2", "PRESENT", ["e7"]))
    out = output()
    out.findings["f5"] = finding("f5", "E2", ["e3", "e7"])           # actions 2 and 5
    r = S.score(t, out)["links"]
    assert [1, 2] not in r["false_pairs"] and r["companion_pairs"] == [[1, 5]]
    # w2's ABSENT nonlink stays false; w4 (f5 -> f4 on action 2) now proposes
    # 5 -> 2, and has no true pair, so that one is false too
    assert r["false_pairs"] == [[1, 3], [5, 2]]


def test_incident_merges_and_fragmentation():
    # B1: truth incidents {1, 2, 4} (attack) and {3} (benign).
    t = truth()
    t.incidents = [dataset_pb2.GroundTruthIncident(incident_id="A", action_seqs=[1, 2, 4], is_attack=True),
                   dataset_pb2.GroundTruthIncident(incident_id="B", action_seqs=[3])]
    out = path_output()
    out.incidents = {}
    out._incident(incident_pb2.Incident(incident_id="g1", version=1, finding_ids=["f1", "f3"]))   # 1 and 3: merge
    out._incident(incident_pb2.Incident(incident_id="g2", version=1, finding_ids=["f6"]))         # 4: A split
    r = S.score(t, out)["incidents"]
    assert (r["merges"], r["attack_merges"], r["fragmented"], r["attack_fragmented"]) == (1, 1, 1, 1)
    assert r["merged_examples"] == [{"incident_id": "g1", "truth_incidents": ["A", "B"]}]
    assert S.score(truth(), out)["incidents"] is None                 # no incident truth
