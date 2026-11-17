"""Scoped loss (2026-11-17, post-hoc after the held-out Exp. 3 loss rows).

A loss record that names the witness keys of the records it lost ("keys=" in its gap scope, set by
the sender) blocks Covered and the DistinctAction fallback only for pairs and findings on one of
those keys, when the GO parameter scoped_loss is on. A loss record without keys, and every agent
rule (queries without keys), behave as before. Property 2 still holds: deleting the decisive
contradiction (a CONNECT on the pair's own flow tuple) leaves a loss record that names that tuple.
"""
import agent_fixtures as F
import orch_fixtures as O
import test_orch_admission as TA
from test_agent_gaps import index

from mtcore.agents.completeness import EBPF
from mtcore.orchestrator.keys import loss_keys

PA, NF = TA.PA, TA.NF
CONFIRMED, UNPROVEN, REJECTED = TA.CONFIRMED, TA.UNPROVEN, TA.REJECTED
SCOPED = dict(scoped_loss=True)


def keyed_loss(start, end, keys, node=None):
    rec = F.loss(start, end, source="EBPF", node=node)
    rec[1].source_completeness.gaps[0].scope = "transport/keys=" + "|".join(sorted(keys))
    return rec


def lineage_key(lineage, node=None):
    return f"L:{node or F.NODE}:{F.BOOT}:{lineage}"


# --- GapIndex ----------------------------------------------------------------------------------
def test_a_keyed_gap_applies_only_to_queries_naming_one_of_its_keys():
    gi = index(("gap", keyed_loss(0, 100, {lineage_key("ln-9")})))
    q = lambda keys: bool(gi.query({EBPF}, {F.NODE}, F.ns(10), F.ns(10), 1000, None, keys))  # noqa: E731
    assert not q(frozenset({lineage_key("ln-1")}))
    assert q(frozenset({lineage_key("ln-9"), lineage_key("ln-1")}))
    assert q(None)                       # agents name no keys: every loss counts, as before


def test_a_gap_without_keys_applies_to_every_key():
    gi = index(("gap", F.loss(0, 100, source="EBPF")))
    assert gi.query({EBPF}, {F.NODE}, F.ns(10), F.ns(10), 1000, None, frozenset({lineage_key("ln-1")}))


# --- loss keys of an event match the witness keys -----------------------------------------------
def test_loss_keys_name_the_lineage_and_the_flow_tuple():
    from mtcore.agents.events import Ev
    e = Ev(TA.proc(1, 10, lineage="ln-1"))
    assert lineage_key("ln-1") in loss_keys(e)
    c = Ev(TA.sock(1, 1, TA.CLIENT, TA.SERVER, "node-1", cookie=11))
    a = Ev(TA.sock(2, 2, TA.SERVER, TA.CLIENT, "node-2", cookie=21))
    flows = lambda ev: {k for k in loss_keys(ev) if k.startswith("F:")}  # noqa: E731
    assert flows(c) and flows(c) == flows(a)      # both ends of one connection share the key


# --- Covered and DistinctAction ----------------------------------------------------------------
def _pair():
    e1, e2 = TA.proc(1, 10, lineage="ln-1"), TA.proc(5, 11, lineage="ln-1")
    return [e1, e2, TA.fnd("f1", e1), TA.fnd("f2", e2)]


def test_loss_on_another_lineage_no_longer_blocks_the_pair_when_scoped():
    other = keyed_loss(2, 3, {lineage_key("ln-other")})
    assert TA.status_of(TA.run(*_pair(), other), "f1", "f2", PA) == UNPROVEN          # frozen: node-wide
    assert TA.status_of(TA.run(*_pair(), other, oparams=O.oparams(**SCOPED)), "f1", "f2", PA) == CONFIRMED


def test_loss_on_the_pairs_own_lineage_still_blocks_it():
    own = keyed_loss(2, 3, {lineage_key("ln-1"), lineage_key("ln-other")})
    assert TA.status_of(TA.run(*_pair(), own, oparams=O.oparams(**SCOPED)), "f1", "f2", PA) == UNPROVEN


def test_loss_without_keys_still_blocks_when_scoped():
    assert TA.status_of(TA.run(*_pair(), F.loss(2, 3, source="EBPF"), oparams=O.oparams(**SCOPED)),
                        "f1", "f2", PA) == UNPROVEN


def test_distinct_action_fallback_is_scoped_to_the_findings_own_keys():
    # loss at 12-14 s: outside I = [1, 5] but within A + beta of f2 (as in test_orch_admission)
    other = keyed_loss(12, 14, {lineage_key("ln-other")})
    assert TA.status_of(TA.run(*_pair(), other), "f1", "f2", PA) == UNPROVEN
    assert TA.status_of(TA.run(*_pair(), other, oparams=O.oparams(**SCOPED)), "f1", "f2", PA) == CONFIRMED
    own = keyed_loss(12, 14, {lineage_key("ln-1")})
    assert TA.status_of(TA.run(*_pair(), own, oparams=O.oparams(**SCOPED)), "f1", "f2", PA) == UNPROVEN


def test_property_2_deleting_the_port_reuse_contradiction_never_confirms_when_scoped():
    # The reusing CONNECT is deleted; the sender's loss record names its flow tuple, which is the
    # pair's own, so the pair stays unproven. A loss naming another tuple does not block it.
    from mtcore.agents.events import Ev
    reuse = TA.sock(1.5, 1, TA.CLIENT, TA.SERVER, "node-1", cookie=12)
    keys = loss_keys(Ev(reuse))
    recs = TA._flow(reuse=False) + [keyed_loss(1.2, 1.8, keys, node="node-1")]
    assert TA.status_of(TA.run(*recs, oparams=O.oparams(**SCOPED)), "f1", "f2", NF) == UNPROVEN
    assert TA.status_of(TA.run(*TA._flow(reuse=True), oparams=O.oparams(**SCOPED)), "f1", "f2", NF) == REJECTED
    other = TA._flow(reuse=False) + [keyed_loss(1.2, 1.8, {"F:10.9.9.9:1:10.9.9.8:2:6"}, node="node-1")]
    assert TA.status_of(TA.run(*other, oparams=O.oparams(**SCOPED)), "f1", "f2", NF) == CONFIRMED
