"""Orchestrator build step 5c: contradictions, contradiction coverage,
DistinctAction, node-trust epochs, and the published witness status."""
import random

import agent_fixtures as F
import orch_fixtures as O
import test_orch_witness as TW
from microtrace.v0 import witness_pb2

from mtcore.orchestrator.engine import Engine
from mtcore.orchestrator.keys import HOST_TRANSITION, NETWORK_FLOW, PROCESS_ANCESTRY

FND, NORM, COMP = "findings.v0", "norm.events.v0", "source.completeness.v0"
PA, HT, NF = PROCESS_ANCESTRY, HOST_TRANSITION, NETWORK_FLOW
ST = witness_pb2.WitnessStatus
CONFIRMED, REJECTED, UNPROVEN, POST = (ST.Value(n) for n in ("CONFIRMED", "REJECTED", "UNPROVEN", "POST_COMPROMISE"))
CLIENT, SERVER = TW.CLIENT, TW.SERVER


def proc(t, seq, lineage="ln-1", container="containerd://c1", host=False, ingest=None, unc_ms=None, node=F.NODE):
    ne = F.ebpf(t, "proc.exec", lineage=lineage, seq=seq, container_id=container, host_ns_after=host, node=node)
    ne.time.ingest_time.CopyFrom(F.ts(ingest if ingest is not None else t + 0.2))
    if unc_ms is not None:
        ne.time.clock_uncertainty_ns = int(unc_ms * 1_000_000)
    return F.done(ne)


def sock(t, op, local, remote, node, cookie, ingest=None):
    env = TW.sock(t, op, local, remote, node=node)
    ne = env.normalized_event
    f = ne.ebpf.socket.flow
    f.node_id, f.boot_id, f.socket_cookie = node, F.BOOT, cookie
    ne.time.ingest_time.CopyFrom(F.ts(ingest if ingest is not None else t + 0.2))
    return env


def fnd(fid, *events, ftype="D1", action=None, t=None):
    env = TW.fnd(fid, *events, t=t)
    env.finding.finding_type = ftype
    if action is not None:
        env.finding.action_id = action
    return env


def run(*records, oparams=None):
    eng = Engine(oparams or O.oparams())
    for rec in records:
        if isinstance(rec, tuple):                     # (topic, env), e.g. F.loss(...)
            eng.feed(rec[1], rec[0])
        else:
            eng.feed(rec, NORM if rec.HasField("normalized_event") else FND)
    eng.finish()
    return eng


def published(eng):
    """{(source, target, type): Witness} of every published witness."""
    return {(w.source_finding_id, w.target_finding_id, w.relationship_type): w
            for _t, _k, env in eng.drain() for w in [env.witness]}


def status_of(eng, a, b, w):
    return published(eng)[(a, b, w)].status


# --- contradictions -----------------------------------------------------------------
def test_container_change_in_one_lineage_without_host_transition_is_rejected():
    e1, e2 = proc(1, 10, container="containerd://c1"), proc(5, 11, container="containerd://c2")
    out = published(run(e1, e2, fnd("f1", e1), fnd("f2", e2)))
    w = out[("f1", "f2", PA)]
    assert w.status == REJECTED and [c.decisive for c in w.contradictions] == [True]


def test_container_change_through_a_host_transition_is_continuity():
    e1, e2 = proc(1, 10, container="containerd://c1"), proc(5, 11, container="", host=True)
    out = published(run(e1, e2, fnd("f1", e1), fnd("f2", e2)))
    assert out[("f1", "f2", PA)].status == CONFIRMED and out[("f1", "f2", HT)].status == CONFIRMED


def _flow(reuse=True, loss_node=None):
    c1 = sock(1, 1, CLIENT, SERVER, "node-1", cookie=11)
    acc = sock(2, 2, SERVER, CLIENT, "node-2", cookie=21)
    recs = [c1, acc, fnd("f1", c1), fnd("f2", acc)]
    if reuse:
        recs.append(sock(1.5, 1, CLIENT, SERVER, "node-1", cookie=12))   # same tuple, other socket
    if loss_node:
        recs.append(F.loss(1.2, 1.8, source="EBPF", node=loss_node))
    return recs


def test_port_reuse_before_the_accept_rejects_the_flow_witness():
    assert status_of(run(*_flow(reuse=True)), "f1", "f2", NF) == REJECTED
    assert status_of(run(*_flow(reuse=False)), "f1", "f2", NF) == CONFIRMED


def test_suppressing_the_contradiction_with_a_recorded_loss_never_confirms():
    # P2 suppression monotonicity: delete the reusing CONNECT; the receiver
    # records the loss on its node, so the pair is unproven, not confirmed.
    w = published(run(*_flow(reuse=False, loss_node="node-1")))[("f1", "f2", NF)]
    assert w.status == UNPROVEN
    assert [(c.source, c.loss_overlap) for c in w.contradiction_coverage] == [(1, True)]
    # a loss on an unrelated node does not touch the pair
    assert status_of(run(*_flow(reuse=False, loss_node="node-3")), "f1", "f2", NF) == CONFIRMED


def test_contradiction_coverage_is_decided_only_after_the_watermark_passes_the_interval_and_beta():
    e1, e2 = proc(1, 10), proc(5, 11)
    eng = Engine(O.oparams(), {FND: 1})
    for env in (e1, e2):
        eng.feed(env, NORM)
    for env in (fnd("f1", e1), fnd("f2", e2)):
        eng.feed(env, FND)
    eng.feed(O.hb(FND, 0, 10, 10), FND)                # watermark 8: both findings processed
    eng.advance()
    assert eng.processed == ["f1", "f2"] and not eng.drain()
    eng.feed(F.loss(4, 6, source="EBPF")[1], COMP)    # the loss record arrives late, before coverage is due
    eng.feed(O.hb(FND, 0, 18, 18), FND)                # watermark 16 < 5 + beta 8 + eps_bar 5
    eng.advance()
    assert not eng.drain()
    eng.feed(O.hb(FND, 0, 21, 21), FND)                # watermark 19: coverage known
    eng.advance()
    [(_t, _k, env)] = eng.drain()
    assert env.witness.status == UNPROVEN


# --- node-trust epochs -------------------------------------------------------------
def c1b(t, ingest=None):
    ev = proc(t, 99, lineage="ln-host", host=True, ingest=ingest if ingest is not None else t + 0.5)
    return [ev, fnd("c1b", ev, ftype="C1b")]


def test_evidence_received_after_the_epoch_onset_is_post_compromise():
    e1, e2 = proc(1, 10, ingest=1.2), proc(5, 11, ingest=6)       # e2 received after onset 3
    out = published(run(e1, e2, fnd("f1", e1), fnd("f2", e2), *c1b(3)))
    w = out[("f1", "f2", PA)]
    assert w.status == POST and w.key_origin[0].degraded


def test_evidence_received_before_the_epoch_stays_trusted():
    e1, e2 = proc(1, 10, ingest=1.2), proc(2, 11, ingest=2.2)
    assert status_of(run(e1, e2, fnd("f1", e1), fnd("f2", e2), *c1b(50)), "f1", "f2", PA) == CONFIRMED


def test_epoch_opening_after_the_interval_but_within_beta_leaves_it_uncovered():
    # proofs/targeted.py: onset 10 is after max(I) = 5 but before 5 + beta (8).
    e1, e2 = proc(1, 10, ingest=1.2), proc(5, 11, ingest=5.5)
    recs = [e1, e2, fnd("f1", e1), fnd("f2", e2), *c1b(10)]
    w = published(run(*recs))[("f1", "f2", PA)]
    assert w.status == UNPROVEN and w.contradiction_coverage[0].epoch_overlap
    assert status_of(run(*recs, oparams=O.oparams(ablations=["no_epoch"])), "f1", "f2", PA) == CONFIRMED


def test_trigger_processed_after_max_i_plus_beta_still_counts_when_its_onset_is_inside():
    # Trigger event at 14 s with 2 s uncertainty: onset 12 <= 5 + beta (13), but
    # the finding itself is only processed once the watermark reaches 14.
    e1, e2 = proc(1, 10, ingest=1.2), proc(5, 11, ingest=5.5)
    ev = proc(14, 99, lineage="ln-host", host=True, ingest=14.5, unc_ms=2000)
    eng = Engine(O.oparams(), {FND: 1})
    for env in (e1, e2, ev):
        eng.feed(env, NORM)
    for env in (fnd("f1", e1), fnd("f2", e2), fnd("c1b", ev, ftype="C1b")):
        eng.feed(env, FND)
    for low in (15.5, 30):                             # watermarks 13.5, then 28
        eng.feed(O.hb(FND, 0, low, low), FND)
        eng.advance()
    w = {(x.witness.source_finding_id, x.witness.target_finding_id): x.witness for _t, _k, x in eng.drain()}
    assert w[("f1", "f2")].status == UNPROVEN


def test_a_later_epoch_reaching_back_into_the_interval_revises_the_published_witness():
    # Trigger at 25 s with 13 s uncertainty (above eps_bar): onset 12 <= 13, but
    # the witness was already published CONFIRMED at watermark 19.
    e1, e2 = proc(1, 10, ingest=1.2), proc(5, 11, ingest=5.5)
    ev = proc(25, 99, lineage="ln-host", host=True, ingest=25.5, unc_ms=13000)
    eng = Engine(O.oparams(), {FND: 1})
    for env in (e1, e2, ev):
        eng.feed(env, NORM)
    for env in (fnd("f1", e1), fnd("f2", e2), fnd("c1b", ev, ftype="C1b")):
        eng.feed(env, FND)
    eng.feed(O.hb(FND, 0, 21, 21), FND)
    eng.advance()
    [first] = [e.witness for _t, _k, e in eng.drain()]
    assert first.status == CONFIRMED
    eng.feed(O.hb(FND, 0, 30, 30), FND)
    eng.advance()
    [again] = [e.witness for _t, _k, e in eng.drain()]
    assert (again.witness_id, again.status) == (first.witness_id, UNPROVEN)
    assert eng.stats["witnesses_revised"] == 1


def test_contradiction_from_degraded_evidence_is_not_decisive():
    c1 = sock(1, 1, CLIENT, SERVER, "node-1", cookie=11, ingest=1.1)
    acc = sock(2, 2, SERVER, CLIENT, "node-2", cookie=21)
    reuse = sock(1.5, 1, CLIENT, SERVER, "node-1", cookie=12, ingest=9)   # received after onset 1.4
    ev = proc(1.4, 99, lineage="ln-host", host=True, node="node-1", ingest=1.45)
    w = published(run(c1, acc, reuse, fnd("f1", c1), fnd("f2", acc), ev, fnd("c1b", ev, ftype="C1b")))[
        ("f1", "f2", NF)]
    [c] = w.contradictions
    assert c.degraded and not c.decisive
    assert w.status == UNPROVEN                       # the epoch also leaves the interval uncovered


# --- DistinctAction -----------------------------------------------------------------
def test_same_action_id_is_one_action():
    e1, e2 = proc(1, 10), proc(5, 11)
    w = published(run(e1, e2, fnd("f1", e1, action="act-1"), fnd("f2", e2, action="act-1")))[("f1", "f2", PA)]
    assert w.status == REJECTED and any(c.contradiction_id.startswith("same-action") for c in w.contradictions)
    assert status_of(run(e1, e2, fnd("f1", e1, action="act-1"), fnd("f2", e2, action="act-2")),
                     "f1", "f2", PA) == CONFIRMED


def test_without_action_ids_a_loss_near_a_finding_leaves_distinctness_unresolved():
    e1, e2 = proc(1, 10), proc(5, 11)
    base = [e1, e2, fnd("f1", e1), fnd("f2", e2)]
    assert status_of(run(*base), "f1", "f2", PA) == CONFIRMED          # disjoint inputs, no loss
    # loss at 12-14 s: outside I = [1, 5] (coverage holds) but within A + beta of f2
    assert status_of(run(*base, F.loss(12, 14, source="EBPF")), "f1", "f2", PA) == UNPROVEN
    assert status_of(run(*base, F.loss(12, 14, source="EBPF"), oparams=O.oparams(ablations=["no_distinct"])),
                     "f1", "f2", PA) == CONFIRMED


def test_a_family_gap_counts_only_for_the_families_the_checks_read():
    # degraded_ebpf: probes for forks and ptrace not attached for the whole run.
    # An exec-to-exec ancestry pair reads neither, so it is decided as without
    # the gap; a gap on exec leaves it uncovered and distinctness unresolved.
    from test_agent_gaps import family_gap
    e1, e2 = proc(1, 10), proc(5, 11)
    base = [e1, e2, fnd("f1", e1), fnd("f2", e2)]
    assert status_of(run(*base, family_gap(0, 100, ["proc.fork", "proc.ptrace"])), "f1", "f2", PA) == CONFIRMED
    assert status_of(run(*base, family_gap(0, 100, ["proc.exec"])), "f1", "f2", PA) == UNPROVEN


# --- process ancestry on the parent chain (A1) -------------------------------------
# One lineage rooted at the app (tgid 1): shell 10 (child of 1), its children
# cat 11 and curl 12, curl's child 13.
def act(t, seq, tgid, parent, family="file.read"):
    return F.done(F.ebpf(t, family, lineage="ln-app", seq=seq, tgid=tgid, parent_tgid=parent, root_tgid=1))


def test_a_sibling_in_the_same_lineage_is_not_an_ancestor():
    cat, curl = act(1, 10, 11, 10), act(3, 11, 12, 10)
    out = published(run(cat, curl, fnd("f1", cat), fnd("f2", curl)))
    assert ("f1", "f2", PA) not in out                              # unsupported: no witness at all
    # pre-A1: a shared lineage was enough (G-0)
    assert status_of(run(cat, curl, fnd("f1", cat), fnd("f2", curl),
                         oparams=O.oparams(ablations=["no_ancestry_chain"])), "f1", "f2", PA) == CONFIRMED


def test_the_parent_and_a_grandparent_through_a_recorded_birth_are_ancestors():
    shell, curl = act(1, 10, 10, 1), act(3, 11, 12, 10)
    assert status_of(run(shell, curl, fnd("f1", shell), fnd("f2", curl)), "f1", "f2", PA) == CONFIRMED
    birth = act(2, 11, 12, 10, family="proc.exec")                  # curl's exec, no finding on it
    grandchild = act(4, 12, 13, 12)
    out = run(shell, birth, grandchild, fnd("f1", shell), fnd("f3", grandchild))
    assert status_of(out, "f1", "f3", PA) == CONFIRMED


def test_a_lost_birth_on_the_chain_leaves_the_link_unproven():
    shell, grandchild = act(1, 10, 10, 1), act(4, 12, 13, 12)       # curl's fork and exec lost
    assert status_of(run(shell, grandchild, fnd("f1", shell), fnd("f3", grandchild)), "f1", "f3", PA) == UNPROVEN


def test_every_earlier_source_event_is_tried_not_only_the_latest():
    # The source finding holds the shell's event and, later, a sibling's; the
    # target is the shell's child. The latest source (the sibling) is not an
    # ancestor, the earlier one is (R7).
    shell, sib, curl = act(1, 10, 10, 1), act(2, 11, 11, 10), act(3, 12, 12, 10)
    out = run(shell, sib, curl, fnd("f1", shell, sib), fnd("f2", curl))
    assert status_of(out, "f1", "f2", PA) == CONFIRMED


# --- example trace and determinism ---------------------------------------------------
def test_example_trace_publishes_w1_confirmed_with_ebpf_coverage():
    eng = Engine(O.oparams())
    for _label, topic, env, _key in O.trace_records():
        eng.feed(env, NORM if env.HasField("normalized_event") else topic)
    eng.finish()
    [w] = [env.witness for _t, _k, env in eng.drain() if env.witness.relationship_type == PA]
    w1 = next(e.witness for label, _t, e, _k in O.trace_records() if label.startswith("W1"))
    assert (w.witness_id, w.status) == (w1.witness_id, CONFIRMED)
    assert [(c.source, c.loss_overlap, c.idle_overlap, c.epoch_overlap) for c in w.contradiction_coverage] == \
        [(c.source, c.loss_overlap, c.idle_overlap, c.epoch_overlap) for c in w1.contradiction_coverage]


def test_published_statuses_do_not_depend_on_arrival_order():
    for seed in range(4):
        recs = TW._random_set(seed) + [F.loss(100, 120, source="EBPF", node="node-1")]
        ref = {k: w.status for k, w in published(run(*recs)).items()}
        assert ref and len(set(ref.values())) > 1
        rnd = random.Random(seed)
        for _ in range(3):
            shuffled = list(recs)
            rnd.shuffle(shuffled)
            assert {k: w.status for k, w in published(run(*shuffled)).items()} == ref


def test_a_workload_set_key_supports_a_link_only_under_no_origin():
    # SensorKey (A2): a key whose value a workload sets can be forged, so it
    # never confirms; No-Origin treats it as sensor-set. No built key type is
    # workload-set yet (B5 adds trace and request IDs), so the origin is set
    # on the keys by hand.
    from mtcore.orchestrator import admit
    from mtcore.orchestrator.keys import WORKLOAD, finding_keys
    from mtcore.agents.events import Ev
    c1, acc = sock(1, 1, CLIENT, SERVER, "node-1", cookie=11), sock(2, 2, SERVER, CLIENT, "node-2", cookie=21)
    ki, kj = finding_keys([Ev(c1)]), finding_keys([Ev(acc)])
    [(w, k)] = [wk for wk in ki if wk[0] == NF]
    assert admit.decide("f1", "f2", w, k, ki, kj, O.oparams()).passes
    ki[(w, k)].origin = WORKLOAD
    d = admit.decide("f1", "f2", w, k, ki, kj, O.oparams())
    assert not d.supported and "workload-set" in d.reason
    d = admit.decide("f1", "f2", w, k, ki, kj, O.oparams(ablations=["no_origin"]))
    assert d.passes and d.origin == WORKLOAD


# --- request identity (P2, 2026-10-24) ------------------------------------------------
def _ri_params(on=True, ablations=()):
    o = O.oparams()
    gates = dict(o.params.data["orchestrator"]["gates"], REQUEST_IDENTITY=on)
    return o.with_overrides(gates=gates, ablations=list(ablations))


def gw(t, rid, origin="SENSOR", action=None):
    env = F.gateway(t, request_id=rid, origin=origin)
    env.normalized_event.action_id = action or f"act-{env.normalized_event.event_id}"
    return env


def test_request_identity_is_off_while_its_gate_is_off():
    from mtcore.orchestrator.keys import REQUEST_IDENTITY
    edge, inner = gw(1, "r1"), gw(3, "r1", origin="WORKLOAD")
    recs = [edge, inner, fnd("f1", edge, ftype="A1"), fnd("f2", inner, ftype="A1")]
    assert not [k for k in run(*recs).decisions if k[2] == REQUEST_IDENTITY]


def test_two_findings_on_one_request_have_no_request_identity_witness():
    # A1 and A2 on one gateway event: one event is never both ends.
    from mtcore.orchestrator.keys import REQUEST_IDENTITY
    e = gw(1, "r1")
    eng = run(e, fnd("f1", e, ftype="A1"), fnd("f2", e, ftype="A2"), oparams=_ri_params())
    assert [k for k in eng.decisions if k[2] == REQUEST_IDENTITY]
    assert not any(d.supported for k, d in eng.decisions.items() if k[2] == REQUEST_IDENTITY)
    assert not [k for k in published(eng) if k[2] == REQUEST_IDENTITY]


def test_a_copied_request_id_is_refused_and_confirmed_only_under_no_origin():
    # The graft (exp2-conflict-origin-cases-plan 3.2): a request on the
    # internal listener carries the edge request's minted ID, kept as
    # client-supplied (WORKLOAD).
    from mtcore.orchestrator.keys import REQUEST_IDENTITY as RI, WORKLOAD
    edge, inner = gw(1, "r1"), gw(3, "r1", origin="WORKLOAD")
    recs = [edge, inner, fnd("f1", edge, ftype="A1"), fnd("f2", inner, ftype="A1")]
    eng = run(*recs, oparams=_ri_params())
    [d] = why(eng, "f1", "f2", RI)
    assert not d.supported and "workload-set" in d.reason
    assert not [k for k in published(eng) if k[2] == RI]
    eng = run(*recs, oparams=_ri_params(ablations=["no_origin"]))
    w = published(eng)[("f1", "f2", RI)]
    assert w.status == CONFIRMED and w.join_key == "r1" and w.key_origin[0].origin == WORKLOAD
    # the copy carries an ID set upstream: it never opens a witness
    assert not why(eng, "f2", "f1", RI)[0].supported


def why(eng, a, b, w):
    return [d for (x, y, ww, _k), d in eng.decisions.items() if (x, y, ww) == (a, b, w)]


def test_no_witness_links_findings_that_share_an_entity_within_w_nw():
    # A2: entity/time compatibility replaces the witnesses. The sibling pair
    # has no witness under the full design but shares Pod and lineage.
    from mtcore.orchestrator.keys import ENTITY_COMPAT
    nw = O.oparams(ablations=["no_witness"])
    cat, curl = act(1, 10, 11, 10), act(3, 11, 12, 10)
    recs = [cat, curl, fnd("f1", cat), fnd("f2", curl)]
    assert not [k for k in published(run(*recs)) if k[:2] == ("f1", "f2")]
    out = published(run(*recs, oparams=nw))
    assert {w.status for k, w in out.items() if k[:2] == ("f1", "f2")} == {CONFIRMED}
    assert all(k[2] == ENTITY_COMPAT for k in out)
    late = act(70, 12, 12, 10)                                       # 69 s later: beyond W_nw (60 s)
    out = published(run(cat, late, fnd("f1", cat), fnd("f3", late), oparams=nw))
    assert all(w.status != CONFIRMED for k, w in out.items() if k[:2] == ("f1", "f3"))
# --- a link into the compromise itself (trigger exemption, 2026-10-23) ---------------
def escape_run(oparams=None):
    """f1 gains capabilities, then the same lineage escapes to the host (C1b):
    the escape event opens the epoch at its own time, inside the interval."""
    e1 = proc(1, 10, lineage="ln-x")
    esc = proc(5, 11, lineage="ln-x", host=True, ingest=5.5)
    return run(e1, esc, fnd("f1", e1, ftype="F1"), fnd("c1b", esc, ftype="C1b"), oparams=oparams)


def test_a_link_into_the_epoch_trigger_itself_is_covered():
    w = published(escape_run())[("f1", "c1b", PA)]
    assert w.status == CONFIRMED and not w.contradiction_coverage[0].epoch_overlap


def test_without_the_trigger_exemption_a_link_into_the_trigger_is_unproven():
    w = published(escape_run(O.oparams(ablations=["no_trigger_exemption"])))[("f1", "c1b", PA)]
    assert w.status == UNPROVEN and w.contradiction_coverage[0].epoch_overlap


def test_a_contradiction_the_epoch_degrades_still_leaves_the_link_uncovered():
    from mtcore.orchestrator import admit
    from mtcore.orchestrator.contradictions import Found
    eng = escape_run()
    [d] = [d for (a, b, w, _k), d in eng.decisions.items() if (a, b, w) == ("f1", "c1b", PA)]
    assert admit.covered(d, eng.gaps, eng.epochs, eng.p)[0]
    hidden = Found("x", "a contradiction received after the onset", degraded=True)
    is_cov, [cov] = admit.covered(d, eng.gaps, eng.epochs, eng.p, [hidden])
    assert not is_cov and cov.epoch_overlap


def test_request_identity_is_off_without_a_gates_block():
    # Review 2026-10-26: a params file with no gates entry (a new fit, a
    # slice, SAGE's) turned REQUEST_IDENTITY on. Off unless gated on (D-32).
    from mtcore.orchestrator.keys import NETWORK_FLOW, REQUEST_IDENTITY
    o = O.oparams()
    gates = {k: v for k, v in o.params.data["orchestrator"]["gates"].items() if k != "REQUEST_IDENTITY"}
    bare = o.with_overrides(gates=gates)
    assert not bare.gate(REQUEST_IDENTITY) and bare.gate(NETWORK_FLOW)
    assert _ri_params(on=True).gate(REQUEST_IDENTITY)
