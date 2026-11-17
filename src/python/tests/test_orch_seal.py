"""Orchestrator build step 5e: incidents open, seal at the watermark, amend
after seal, merge with aliases; the example trace's I1 and I2 exactly."""
import pytest

import orch_fixtures as O
from microtrace.v0 import common_pb2, incident_pb2

from mtcore.orchestrator import ablations, emit
from mtcore.orchestrator.seal import AMENDED, OPEN, SEALED, GroupView, IncidentBook

S = 1_000_000_000


def path(*fids, witnesses=()):
    return incident_pb2.RankedPath(finding_ids=list(fids), witness_ids=list(witnesses))


def view(anchor, members, links=(), start=10, end=20, last=100, entity=None, ranked=None, spec=()):
    return GroupView(anchor_fid=anchor, anchor_entity=entity, finding_ids=list(members),
                     link_witness_ids=list(links), ranked_paths=list(ranked if ranked is not None else []),
                     speculative_paths=list(spec), event_start=start * S, event_end=end * S, last_extension=last * S)


def book():
    return IncidentBook(O.oparams())


def one(recs):
    [r] = recs
    return r


# --- open, seal, amend -------------------------------------------------------------
def test_new_group_opens_at_version_1_and_republishes_only_on_change():
    b = book()
    r = one(b.update([view("a", ["a", "b"])], 50 * S, set(), 0))
    assert (r.status, r.version, r.incident_id) == (OPEN, 1, emit.incident_id("a"))
    assert not r.HasField("watermark_time") and not r.sealed_prediction_version
    assert b.update([view("a", ["a", "b"])], 60 * S, set(), 0) == []          # unchanged: nothing
    r = one(b.update([view("a", ["a", "b", "c"], end=30)], 70 * S, set(), 0))
    assert (r.status, r.version, list(r.finding_ids)) == (OPEN, 1, ["a", "b", "c"])   # open: version held


def test_seals_when_the_watermark_reaches_the_last_extension_without_adding_lateness_again():
    b = book()
    assert O.oparams().lateness_ns > 0
    b.update([view("a", ["a"], last=100)], 99 * S, set(), 0)
    assert b.update([], 100 * S - 1, set(), 0) == []
    r = one(b.update([], 100 * S, set(), 0))                 # exactly at last_extension: no lateness added
    assert (r.status, r.version, r.sealed_prediction_version) == (SEALED, 1, "snapshot-1")
    assert r.watermark_time.ToNanoseconds() == 100 * S


def test_seal_time_is_the_last_extension_whatever_the_watermark_step():
    a, b = book(), book()
    a.update([view("x", ["x"], last=100)], 50 * S, set(), 0)
    ra = one(a.update([], 100 * S, set(), 0))
    rb = one(b.update([view("x", ["x"], last=100)], 5000 * S, set(), 0))   # first look already past the seal
    assert ra == rb and ra.status == SEALED


def test_change_after_seal_is_an_amendment_and_the_sealed_snapshot_never_changes():
    b = book()
    sealed = one(b.update([view("a", ["a", "b"], links=["w1"], last=100)], 100 * S, set(), 0))
    r = one(b.update([view("a", ["a", "b", "c"], links=["w1", "w2"], end=30, last=100)], 120 * S, set(), 7 * S))
    assert (r.status, r.version) == (AMENDED, 2)
    assert r.sealed_prediction_version == sealed.sealed_prediction_version == "snapshot-1"
    assert r.watermark_time == sealed.watermark_time
    [am] = r.amendments
    assert (am.version, list(am.late_finding_ids), am.amended_at.ToNanoseconds()) == (2, ["c"], 7 * S)
    assert "findings joined after seal" in am.reason and "links or paths revised" in am.reason
    r3 = one(b.update([], 130 * S, {"EBPF"}, 9 * S))
    assert (r3.version, [a.version for a in r3.amendments]) == (3, [2, 3])
    assert r3.sealed_prediction_version == "snapshot-1"
    assert b.update([view("a", ["a", "b", "c"], links=["w1", "w2"], end=30, last=100)], 140 * S, {"EBPF"}, 0) == []


def test_exclusions_while_open_are_frozen_at_seal_and_later_ones_only_reach_current():
    b = book()
    r = one(b.update([view("a", ["a"], last=100)], 50 * S, {"AUDIT"}, 0))
    assert list(r.source_completeness.current_excluded_sources) == ["AUDIT"]
    assert not r.source_completeness.at_seal_excluded_sources
    r = one(b.update([], 100 * S, set(), 0))       # AUDIT recovered before seal: still recorded
    sc = r.source_completeness
    assert (list(sc.at_seal_excluded_sources), list(sc.current_excluded_sources)) == (["AUDIT"], ["AUDIT"])
    r = one(b.update([], 110 * S, {"EBPF", "AUDIT"}, 0))
    sc = r.source_completeness
    assert (list(sc.at_seal_excluded_sources), list(sc.current_excluded_sources)) == (["AUDIT"], ["AUDIT", "EBPF"])
    assert r.amendments[-1].reason == "ebpf source excluded by max-idle after seal; analyst view only"
    assert b.update([], 120 * S, set(), 0) == []    # recovery after seal changes nothing


# --- merge --------------------------------------------------------------------------
def test_open_merge_takes_the_new_anchors_id_and_aliases_the_rest():
    b = book()
    b.update([view("b", ["b"]), view("c", ["c"])], 50 * S, set(), 0)
    r = one(b.update([view("a", ["a", "b", "c"])], 60 * S, set(), 0))
    assert r.incident_id == emit.incident_id("a") and r.status == OPEN and r.version == 1
    assert list(r.aliases) == sorted([emit.incident_id("b"), emit.incident_id("c")])
    r = one(b.update([view("a", ["a", "b", "c", "d"])], 61 * S, set(), 0))
    assert len(r.aliases) == 2                      # aliases persist on later records


def test_open_group_merging_into_a_sealed_incident_amends_it():
    b = book()
    b.update([view("a", ["a"], last=100)], 100 * S, set(), 0)
    b.update([view("z", ["z"], last=900)], 110 * S, set(), 0)
    r = one(b.update([view("a", ["a", "z"], last=900)], 120 * S, set(), 5 * S))
    assert (r.incident_id, r.status, r.version) == (emit.incident_id("a"), AMENDED, 2)
    assert list(r.aliases) == [emit.incident_id("z")] and r.sealed_prediction_version == "snapshot-1"
    assert list(r.amendments[0].late_finding_ids) == ["z"]
    assert f"merged {emit.incident_id('z')} after seal" in r.amendments[0].reason


def test_late_earlier_anchor_after_seal_moves_the_id_and_keeps_the_frozen_snapshot():
    b = book()
    sealed = one(b.update([view("b", ["b", "c"], last=100)], 100 * S, {"AUDIT"}, 0))
    r = one(b.update([view("a", ["a", "b", "c"], start=5, last=100)], 120 * S, set(), 0))
    assert r.incident_id == emit.incident_id("a") and list(r.aliases) == [sealed.incident_id]
    assert (r.status, r.version, r.sealed_prediction_version) == (AMENDED, 2, "snapshot-1")
    assert r.watermark_time == sealed.watermark_time
    assert list(r.source_completeness.at_seal_excluded_sources) == ["AUDIT"]
    assert list(r.amendments[0].late_finding_ids) == ["a"]


def test_merging_two_sealed_incidents_versions_past_both():
    b = book()
    b.update([view("a", ["a"], last=100)], 100 * S, set(), 0)
    b.update([view("c", ["c"], last=100)], 100 * S, set(), 0)
    b.update([], 101 * S, {"EBPF"}, 0)                      # both amended to version 2
    b.update([view("c", ["c", "d"], last=100)], 102 * S, {"EBPF"}, 0)   # c at version 3
    r = one(b.update([view("a", ["a", "c", "d"], last=100)], 103 * S, {"EBPF"}, 0))
    assert (r.status, r.version) == (AMENDED, 4) and list(r.aliases) == [emit.incident_id("c")]


def test_output_is_sorted_by_incident_id_and_independent_of_group_order():
    groups = [view(x, [x]) for x in "qwertyuiop"]
    one_way = book().update(groups, 50 * S, set(), 0)
    other = book().update(list(reversed(groups)), 50 * S, set(), 0)
    assert one_way == other
    assert [r.incident_id for r in one_way] == sorted(r.incident_id for r in one_way)


# --- ablations ----------------------------------------------------------------------
def test_unknown_ablation_is_rejected():
    assert ablations.validate(["no_index", "no_epoch"]) == {"no_index", "no_epoch"}
    with pytest.raises(ValueError, match="no_indx"):
        ablations.validate(["no_indx"])
    with pytest.raises(ValueError):
        O.oparams(ablations=["no_such_switch"])


def test_every_switch_the_code_reads_is_registered():
    import pathlib
    import re
    root = pathlib.Path(emit.__file__).parent
    used = {m for f in root.glob("*.py") for m in re.findall(r'ablated\("(\w+)"\)', f.read_text(encoding="utf-8"))}
    assert used and used <= set(ablations.ABLATIONS)


# --- example trace ------------------------------------------------------------------
def _trace():
    recs = {label[:2]: env for label, _t, env, _k in O.trace_records()}
    return recs


def test_example_trace_i1_then_i2():
    t = _trace()
    f1, f2, f3 = (t[k].logical_id for k in ("F1", "F2", "F3"))
    w1, w2 = t["W1"].logical_id, t["W2"].logical_id
    pod = next(e for e in t["F1"].finding.entities if e.type == common_pb2.EntityType.Value("POD"))
    seal = O.F.ts(0)
    seal.FromJsonString("2026-09-26T11:00:00Z")
    start, end = (t[k].finding.event_start.ToNanoseconds() for k in ("F1", "F3"))
    g = GroupView(anchor_fid=f1, anchor_entity=pod, finding_ids=[f1, f3], link_witness_ids=[w1],
                  ranked_paths=[path(f1, f3, witnesses=[w1])], speculative_paths=[path(f2, f3, witnesses=[w2])],
                  event_start=start, event_end=end, last_extension=seal.ToNanoseconds())
    b = book()
    i1 = one(b.update([g], seal.ToNanoseconds(), set(), seal.ToNanoseconds()))
    want = t["I1"].incident
    assert i1.decision_version == "orch-0.1"
    i1.decision_version = want.decision_version
    assert i1 == want
    later = O.F.ts(0)
    later.FromJsonString("2026-09-26T11:20:00Z")
    i2 = one(b.update([g], seal.ToNanoseconds() + S, {"AUDIT"}, later.ToNanoseconds()))
    i2.decision_version = want.decision_version
    assert i2 == t["I2"].incident
    _topic, key, env = emit.incident_record(i2, "test")
    assert key.hex() == [k for label, _t, _e, k in O.trace_records() if label.startswith("I2")][0]
