"""Orchestrator build step 5d: canonical dedup, groups and anchors, scores,
top-K and speculative paths, retraction, and the example trace's W2 and I1."""
import math
import os
import random
import sys
from types import SimpleNamespace

import agent_fixtures as F
import orch_fixtures as O
import test_orch_admission as A
from microtrace.v0 import witness_pb2

from mtcore import REPO
from mtcore.orchestrator import emit, groups
from mtcore.orchestrator.engine import Engine

sys.path.insert(0, os.path.join(REPO, "proofs"))
import correlator_ref as R  # noqa: E402

FND, NORM = "findings.v0", "norm.events.v0"
proc, fnd, run = A.proc, A.fnd, A.run


def chain(*times, lineage="ln-1"):
    """Events in one lineage at the given times (node_seq in time order) and
    one finding per event, f1, f2, ..."""
    evs = [proc(t, 10 + i, lineage=lineage) for i, t in enumerate(times)]
    return evs, [fnd(f"f{i + 1}", e) for i, e in enumerate(evs)]


def members(eng):
    return [(g.anchor_fid, g.finding_ids) for g in eng.groups()]


# --- groups and anchors --------------------------------------------------------------
def test_confirmed_links_form_one_group_anchored_at_the_earliest_finding():
    evs, fs = chain(1, 5, 9)
    eng = run(*evs, *fs)
    assert members(eng) == [("f1", ["f1", "f2", "f3"])]


def test_anchor_is_the_earliest_event_time_not_the_smallest_id():
    e1, e2 = proc(1, 10), proc(5, 11)
    eng = run(e1, e2, fnd("z_early", e1), fnd("a_late", e2))
    assert members(eng) == [("z_early", ["z_early", "a_late"])]


def test_findings_with_the_same_action_id_count_once_and_the_smallest_id_represents_them():
    e0, e1, e2 = proc(1, 9), proc(2, 10), proc(6, 11)
    eng = run(e0, e1, e2, fnd("fb", e0, action="act-1"), fnd("fa", e1, action="act-1"), fnd("f3", e2))
    [g] = eng.groups()
    assert g.finding_ids == ["fa", "f3"]                # fb is the same action as fa


def test_unlinked_lineages_are_separate_groups_sorted_by_anchor():
    a, fa = chain(1, 5, lineage="ln-a")
    b, fb = chain(3, 7, lineage="ln-b")
    fb = [fnd(f"g{i + 1}", e) for i, e in enumerate(b)]
    eng = run(*a, *b, *fa, *fb)
    assert members(eng) == [("f1", ["f1", "f2"]), ("g1", ["g1", "g2"])]


def test_a_late_loss_record_retracts_links_and_splits_the_group():
    evs, fs = chain(1, 5, 9)
    eng = run(*evs, *fs)
    assert members(eng) == [("f1", ["f1", "f2", "f3"])]
    eng.drain()
    topic, env = F.loss(6, 8, source="EBPF")             # covers I of f2->f3 and f1->f3 only
    eng.feed(env, topic)
    revised = {(w.source_finding_id, w.target_finding_id): w.status for _t, _k, e in eng.drain()
               for w in [e.witness]}
    assert revised == {("f2", "f3"): A.UNPROVEN, ("f1", "f3"): A.UNPROVEN}
    assert members(eng) == [("f1", ["f1", "f2"])]


def test_every_gap_of_a_completeness_record_counts_for_the_recheck():
    # One record: an open-ended gap from 50 s, then a bounded gap at 6-8 s.
    from microtrace.v0 import common_pb2, envelope_pb2, stream_pb2
    evs, fs = chain(1, 5, 9)
    eng = run(*evs, *fs)
    eng.drain()
    sc = stream_pb2.SourceCompleteness(source=common_pb2.Source.Value("EBPF"), scope=f"node={F.NODE}/boot={F.BOOT}",
                                       status=stream_pb2.CompletenessStatus.Value("INCOMPLETE"))
    getattr(sc.gaps.add(reason=common_pb2.GapReason.Value("DROPPED_BEFORE")), "from").CopyFrom(F.ts(50))
    g = sc.gaps.add(reason=common_pb2.GapReason.Value("DROPPED_BEFORE"))
    getattr(g, "from").CopyFrom(F.ts(6))
    g.to.CopyFrom(F.ts(8))
    env = envelope_pb2.Envelope(schema_major=0, kind=envelope_pb2.RecordKind.Value("SOURCE_COMPLETENESS"),
                                logical_id="two-gaps")
    env.source_completeness.CopyFrom(sc)
    eng.feed(env, "source.completeness.v0")
    assert members(eng) == [("f1", ["f1", "f2"])]


# --- scores ----------------------------------------------------------------------------
def test_link_score_uses_the_neutral_band_for_mapped_pairs_and_q_unmapped_otherwise():
    e1, e2 = proc(1, 10), proc(31, 11)                    # slack ~30 s of W_w = 60 s
    unmapped = run(e1, e2, fnd("f1", e1), fnd("f2", e2)).groups()[0].scores[("f1", "f2")]
    m1, m2 = fnd("f1", e1), fnd("f2", e2)
    m1.finding.primary_tactic = m2.finding.primary_tactic = 3
    mapped = run(e1, e2, m1, m2).groups()[0].scores[("f1", "f2")]
    decay = math.exp(-30 / 60)
    assert math.isclose(unmapped, 0.95 * 0.6 * decay, rel_tol=1e-4)
    assert math.isclose(mapped, 0.95 * 0.85 * decay, rel_tol=1e-4)


# --- paths -----------------------------------------------------------------------------
P = SimpleNamespace(K=2, L=6, T_ns=10**18)


def test_k2_example_from_the_paper_depends_on_commit_order():
    s = {("a", "c"): 0.9, ("c", "b"): 0.5, ("b", "d"): 0.6}
    t = {x: 0 for x in "abcd"}
    o1 = groups.topk_paths([("a", "c"), ("c", "b"), ("b", "d")], s, t, P)
    o2 = groups.topk_paths([("c", "b"), ("b", "d"), ("a", "c")], s, t, P)
    assert ("a", "c", "b", "d") in o2 and ("a", "c", "b", "d") not in o1


def test_top_k_matches_the_proofs_reference_model():
    rng = random.Random(7)
    for _ in range(200):
        nodes = list(range(rng.randint(3, 6)))
        edges = rng.sample([(x, y) for x in nodes for y in nodes if x != y], rng.randint(2, 6))
        s = {e: rng.choice((0.3, 0.5, 0.6, 0.8, 0.9)) for e in edges}
        t = {x: rng.randint(0, 5) for x in nodes}
        k, ln, span = rng.randint(1, 3), rng.randint(2, 5), rng.randint(2, 6)
        ours = groups.topk_paths(edges, s, t, SimpleNamespace(K=k, L=ln, T_ns=span))
        ref = R.topk_paths(edges, s, t, R.Params(K=k, L=ln, T=span))
        assert set(ours) == set(ref)


def test_paths_respect_length_and_span():
    evs, fs = chain(1, 5, 9, 13)
    eng = run(*evs, *fs, oparams=O.oparams(L=3))
    assert max(len(p.finding_ids) for g in eng.groups() for p in g.ranked_paths) == 3


# --- the example trace -------------------------------------------------------------------
def _trace_engine():
    eng = Engine(O.oparams())
    for _label, topic, env, _key in O.trace_records():
        eng.feed(env, NORM if env.HasField("normalized_event") else topic)
    eng.finish()
    return eng


def test_example_trace_gives_w2_enabling_only():
    eng = _trace_engine()
    w2 = next(e.witness for label, _t, e, _k in O.trace_records() if label.startswith("W2"))
    [got] = [e.witness for _t, _k, e in eng.drain() if e.witness.relationship_type == witness_pb2.IMAGE_CLASS]
    for f in ("witness_id", "source_finding_id", "target_finding_id", "relationship_type", "strength_class",
              "join_key_type", "join_key", "direction_basis", "source_event_time", "target_event_time",
              "evidence_event_ids", "status", "applied_limits", "contradiction_coverage"):
        assert getattr(got, f) == getattr(w2, f), f
    assert [(k.component, k.origin, list(k.evidence_event_ids)) for k in got.key_origin] == \
        [(k.component, k.origin, list(k.evidence_event_ids)) for k in w2.key_origin]


def test_example_trace_gives_the_group_of_incident_i1():
    i1 = next(e.incident for label, _t, e, _k in O.trace_records() if label.startswith("I1"))
    [g] = _trace_engine().groups()
    assert g.anchor_fid == i1.anchor_finding_id and g.anchor_entity == i1.anchor_entity
    assert g.finding_ids == list(i1.finding_ids) and g.link_witness_ids == list(i1.link_witness_ids)
    assert [(emit.path_id(p.finding_ids), list(p.witness_ids)) for p in g.ranked_paths] == \
        [(p.path_id, list(p.witness_ids)) for p in i1.ranked_paths]
    assert [(emit.path_id(p.finding_ids), list(p.witness_ids)) for p in g.speculative_paths] == \
        [(p.path_id, list(p.witness_ids)) for p in i1.speculative_paths]
    assert (emit.ts(g.event_start), emit.ts(g.event_end)) == (i1.event_start, i1.event_end)


# --- determinism ------------------------------------------------------------------------
def test_groups_do_not_depend_on_arrival_order_or_on_the_index():
    import test_orch_witness as TW
    for seed in range(4):
        recs = TW._random_set(seed)
        ref = members(run(*recs))
        assert ref
        assert members(run(*recs, oparams=O.oparams(ablations=["no_index"]))) == ref
        rnd = random.Random(seed)
        for _ in range(3):
            shuffled = list(recs)
            rnd.shuffle(shuffled)
            assert members(run(*shuffled)) == ref


def test_link_score_follows_the_tactic_order_and_no_tactic_removes_it():
    # A2: forward along the ATT&CK tactic order weighs more than the same
    # tactic, backward less; No-Tactic sets q_ab = 1, unmapped included.
    e1, e2 = proc(1, 10), proc(31, 11)
    decay = math.exp(-30 / 60)

    def score(ta, tb, **kw):
        m1, m2 = fnd("f1", e1), fnd("f2", e2)
        if ta:
            m1.finding.primary_tactic = ta
        if tb:
            m2.finding.primary_tactic = tb
        return run(e1, e2, m1, m2, **kw).groups()[0].scores[("f1", "f2")]
    assert math.isclose(score(2, 8), 0.95 * 0.90 * decay, rel_tol=1e-4)      # execution -> exfiltration
    assert math.isclose(score(8, 2), 0.95 * 0.50 * decay, rel_tol=1e-4)      # backward
    no_tactic = O.oparams(ablations=["no_tactic"])
    assert math.isclose(score(8, 2, oparams=no_tactic), 0.95 * decay, rel_tol=1e-4)
    assert math.isclose(score(0, 0, oparams=no_tactic), 0.95 * decay, rel_tol=1e-4)


def test_tactic_weight_keeps_the_forward_chain_over_an_ancestors_lookalikes():
    # no-tactic-cases-plan T2: shell C (child of app S) steals the token (D1,
    # credential access) and exfiltrates 20 s later (H4, exfiltration); S
    # makes two new external connections (H2, no tactic) 3 s before H4.
    # Ancestry holds S -> C, so S's H2 link to H4; C -> S does not. With the
    # tactic weight the true D1 -> H4 is among the K = 2 paths; without it
    # the tighter, unmapped H2 paths push it out.
    def ev(t, tgid, parent=None):
        ne = F.ebpf(t, "proc.exec", lineage="ln-s", tgid=tgid, parent_tgid=parent, root_tgid=200)
        ne.time.ingest_time.CopyFrom(F.ts(t + 0.2))
        return F.done(ne)
    # The plan's example, then the ends of overlay v1's gap ranges (D1 -> H4
    # 6.1-20 s, H2a -> H4 1.1-5 s, H2b -> H4 0.9-4 s).
    for d1_h4, h2a_h4, h2b_h4 in [(20, 3, 2.5), (6.1, 5, 4), (20, 1.1, 0.9), (20, 5, 4), (6.1, 1.1, 0.9)]:
        t4 = 10 + d1_h4
        d1e, h2a, h2b, h4e = ev(10, 201, 200), ev(t4 - h2a_h4, 200), ev(t4 - h2b_h4, 200), ev(t4, 201, 200)
        d1, h4 = fnd("d1", d1e, ftype="D1"), fnd("h4", h4e, ftype="H4")
        d1.finding.primary_tactic, h4.finding.primary_tactic = 5, 8
        recs = [d1e, h2a, h2b, h4e, d1, fnd("h2a", h2a, ftype="H2"), fnd("h2b", h2b, ftype="H2"), h4]

        def kept(**kw):
            [g] = run(*recs, **kw).groups()
            return {tuple(p.finding_ids) for p in g.ranked_paths}
        full, no_tactic = kept(), kept(oparams=O.oparams(ablations=["no_tactic"]))
        assert ("d1", "h4") in full, (d1_h4, full)
        assert ("d1", "h4") not in no_tactic, (d1_h4, no_tactic)
        assert all("h2a" in p or "h2b" in p for p in no_tactic)


def test_tactic_weight_drops_a_true_unmapped_chain_for_an_ancestors_forward_lookalikes():
    # The mirror (tactic_ancestor_forward, overlay v1-v2): helper H (child of
    # app S) reads the token twice (D1, D1; benign), is then exploited and
    # spawns agent A; A connects out (H2, no tactic) and its child X
    # exfiltrates 0.6-3 s later (H4; tested up to 4 s): the true link is A's H2 -> X's H4.
    # Ancestry holds H -> A -> X, so H's D1s link to H4. With the tactic
    # weight the forward D1 paths fill the K = 2 slots; without it the
    # tight true link is kept. Gaps at the ends of the overlay's ranges.
    # v2: H's worker W (A's sibling) connects out (H2, benign) about when A
    # does; W -> X has no ancestry, so it never links to H4.
    def ev(t, tgid, parent):
        ne = F.ebpf(t, "proc.exec", lineage="ln-s", tgid=tgid, parent_tgid=parent, root_tgid=200)
        ne.time.ingest_time.CopyFrom(F.ts(t + 0.2))
        return F.done(ne)
    for d1_gap, to_h2, h2_h4, w_h2 in [(7, 6.2, 0.8, -0.8), (12, 13, 4, 0.8), (7, 13, 4, 0), (12, 6.2, 0.8, 0.5)]:
        t_b = 10 + d1_gap
        d1a, d1b = ev(10, 300, 200), ev(t_b, 300, 200)
        h2e, h4e = ev(t_b + to_h2, 301, 300), ev(t_b + to_h2 + h2_h4, 302, 301)
        we = ev(t_b + to_h2 + w_h2, 303, 300)
        fa, fb, h4 = fnd("d1a", d1a, ftype="D1"), fnd("d1b", d1b, ftype="D1"), fnd("h4", h4e, ftype="H4")
        fa.finding.primary_tactic = fb.finding.primary_tactic = 5
        h4.finding.primary_tactic = 8
        recs = [d1a, d1b, h2e, we, h4e, fa, fb, fnd("h2", h2e, ftype="H2"), fnd("w", we, ftype="H2"), h4]

        def kept(**kw):
            [g] = run(*recs, **kw).groups()
            return {tuple(p.finding_ids) for p in g.ranked_paths}, g.scores
        (full, sc), (no_tactic, _) = kept(), kept(oparams=O.oparams(ablations=["no_tactic"]))
        assert ("h2", "h4") not in full, (d1_gap, to_h2, h2_h4, full)
        assert ("h2", "h4") in no_tactic, (d1_gap, to_h2, h2_h4, no_tactic)
        assert ("w", "h4") not in sc
