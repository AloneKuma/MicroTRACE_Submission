"""TGS build step 6e: the Table 5 consistency cases (tgs-contract.md
section 8). The stale-snapshot case runs through the GRE's validation
(build step 7.1)."""
import glob
import os

import agent_fixtures as F
from microtrace.v0 import common_pb2

import test_tgs_ingest as T
import test_tgs_snapshot as TS
from test_tgs_ingest import store  # noqa: F401  (memory and Postgres stores)
from test_tgs_runner import Msg, fake_kafka  # noqa: F401  (fake confluent_kafka)
from mtcore.gre import request as GR
from mtcore.gre.approver import ScriptedApprover
from mtcore.gre.store import MemoryGreStore
from mtcore.gre.validate import Gre, GreConfig, TgsGraph
from mtcore.tgs import apply as A
from mtcore.tgs import interfaces as I
from mtcore.tgs import run as R
from mtcore.tgs import snapshot as S
from mtcore.tgs.extract import finding_node
from mtcore.tgs.hashes import integrity_hash
from mtcore.tgs.hypotheses import ANALYST, generate

TGS_DIR = os.path.dirname(os.path.abspath(R.__file__))


def proc(tgid):
    k = T.pkey(tgid)
    return f"{k.node_id}/{k.boot_id}/{k.tgid}/{k.start_time_ns}"


def with_process(fid, ftype, tgid):
    env = T.finding(fid)
    env.finding.finding_type = ftype
    env.finding.entities.add(type=common_pb2.EntityType.Value("PROCESS"), uid=proc(tgid),
                             strength_class=common_pb2.StrengthClass.Value("STRENGTH_HIGH"))
    return env


def exec_event(t, parent, child):
    ne = F.ebpf(t, "proc.exec")
    ne.ebpf.process.CopyFrom(T.pkey(child))
    ne.ebpf.parent.CopyFrom(T.pkey(parent))
    ne.ebpf.exec.filename = "/bin/sh"
    return F.done(ne)


# --- observed and hypothetical edges (P1, P4) --------------------------------------------
def test_conflicting_observed_and_hypothesis_edges_never_change_the_correlation(store):
    """The GO confirmed f1 -> f2 (process 10 is the parent of process 11).
    The TGS then receives observed edges that point the other way and
    hypotheses that contradict the link. The incident records and confirmed
    edges stay exactly as the GO wrote them."""
    A.apply_batch(store, T.batch(with_process("f1", "D1", 10), with_process("f2", "B1", 11), topic=T.FND))
    A.apply_batch(store, T.batch(T.witness("w12", "f1", "f2"), topic=T.WIT))
    A.apply_batch(store, T.batch(TS.inc("in-1", members=("f1", "f2"), witnesses=("w12",)), topic=T.INC))
    before = integrity_hash(store), store.rows("incident_records")

    A.apply_batch(store, T.batch(exec_event(5, parent=11, child=10), exec_event(6, parent=11, child=10)))
    generate(store, "in-1")
    store.begin()
    store.insert_hypothesis({"hyp_id": "hyp-reverse", "incident_id": "in-1",
                             "record_sha256": store.latest_incident_record("in-1")["record_sha256"],
                             "origin": ANALYST, "template_id": "", "template_sha256": "", "stage_id": "",
                             "detail": {"claim": "f2 precedes f1"}, "seq": store.next_seq()})
    store.insert_hypothesis_edge({"hyp_id": "hyp-reverse", "src": finding_node("f2").id,
                                  "dst": finding_node("f1").id, "label": "precedes", "origin": ANALYST,
                                  "seq": store.next_seq()})
    store.commit()

    reverse = [e for e in store.rows("edges") if e["label"] == "proc.exec"]
    assert len(reverse) == 1 and reverse[0]["count"] == 2                   # the conflicting evidence is stored
    assert any(h["hyp_id"] == "hyp-reverse" for h in store.rows("hypotheses"))
    assert (integrity_hash(store), store.rows("incident_records")) == before
    assert all(e["edge_type"] != "HYPOTHESIS" for e in store.rows("edges"))
    s = I.Session(store)
    assert s.confirmed_path(finding_a="f2", finding_b="f1")["direction"] == "f1 -> f2"
    assert s.get_incident(incident_id="in-1")["incident"]["link_witness_ids"] == ["w12"]


def test_the_graph_store_has_no_way_to_update_the_go():
    """No GO update: nothing in mtcore.tgs can write to Kafka, so the TGS
    cannot feed links, scores or membership back to the orchestrator."""
    for path in glob.glob(os.path.join(TGS_DIR, "*.py")):
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        assert "Producer" not in src and ".produce(" not in src, path


# --- delayed graph updates (P2) ----------------------------------------------------------
def test_snapshots_stay_lagging_while_a_partition_is_paused(store, fake_kafka):  # noqa: F811
    """The consumer is paused on norm.events.v0 partition 1: nothing from it
    arrives. Every snapshot of an incident whose frontier needs that
    partition is lagging, never current, however much else is applied."""
    r = R.TgsRunner(store, "unused")
    i1 = TS.inc("in-1", frontier={"norm.events.v0/0": 2, "norm.events.v0/1": 1})
    p0 = [Msg(T.NORM, 0, k, T.file_read(k + 1)) for k in range(6)]
    p1 = [Msg(T.NORM, 1, k, T.file_read(k + 20, tgid=20)) for k in range(2)]

    r.consumer.queue = p0[:3] + [Msg(T.INC, 0, 0, i1)]
    r.step()
    r.consumer.queue = p0[3:]                                     # partition 1 still paused
    r.step()
    taken = S.take_snapshot(store, "in-1")
    snaps = [x for x in store.rows("snapshots") if x["incident_id"] == "in-1"]
    assert len(snaps) == 2 and {x["status"] for x in snaps} == {S.LAGGING}
    st, why = S.status(store, TS.v_c(i1))
    assert st == S.LAGGING and why == ["norm.events.v0/1 applied to -1, needs 1"]
    assert taken["status"] == S.LAGGING
    assert I.Session(store).get_incident(incident_id="in-1")["status"] == S.LAGGING

    r.consumer.queue = p1                                         # resume partition 1
    r.step()
    assert S.status(store, TS.v_c(i1)) == (S.CURRENT, [])
    assert S.take_snapshot(store, "in-1")["status"] == S.CURRENT
    ok, why = S.check_approval(store, TS.v_c(i1), taken["sid"])
    assert not ok and why == "snapshot was lagging when issued"   # a lagging snapshot never becomes approvable


# --- stale graph snapshot (P3) -----------------------------------------------------------
def test_a_newer_incident_version_makes_the_reviewed_approval_stale(store):
    """The analyst reviews in-1 version 1 and approves; the GO then applies
    version 2. The GRE rejects the approval and nothing executes."""
    key, pub = GR.new_keypair()
    A.apply_batch(store, T.batch(T.witness("w12", "f1", "f2"), topic=T.WIT))
    A.apply_batch(store, T.batch(TS.inc("in-1", members=("f1", "f2"), witnesses=("w12",)), topic=T.INC))
    req = ScriptedApprover("ap", key, store, "kind-mt").issue(
        "in-1", "isolate_pod", "shop", "pod-uid-1", "1", {"pod": "checkout-1"})
    gre = Gre(GreConfig("kind-mt", frozenset({"shop"}), {"ap": pub}), TgsGraph(store), MemoryGreStore())
    A.apply_batch(store, T.batch(TS.inc("in-1", members=("f1", "f2", "f3"), witnesses=("w12",), version=2),
                                 topic=T.INC, start=1))
    d = gre.validate(req)
    assert (d.accepted, d.reason) == (False, "graph check failed: incident changed since review (version 1 -> 2)")
    assert gre.store.nonces == {}                                 # nothing consumed, nothing executed
