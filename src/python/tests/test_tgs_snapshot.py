"""TGS build step 6b: snapshots, current/lagging/stale, the GRE approval
check, merges, and rebuild hashes (tgs-contract.md section 4)."""
import random

import agent_fixtures as F
from microtrace.v0 import envelope_pb2, incident_pb2

import test_tgs_ingest as T
from test_tgs_ingest import store  # noqa: F401  (memory and Postgres stores)
from mtcore.tgs import apply as A
from mtcore.tgs import snapshot as S
from mtcore.tgs.hashes import graph_hash, incident_hash
from mtcore.tgs.store import MemoryStore

NORM, WIT, INC = T.NORM, T.WIT, T.INC


def inc(iid, members=("f1", "f2"), witnesses=(), aliases=(), frontier=None, version=1, status="INCIDENT_OPEN"):
    env = envelope_pb2.Envelope(schema_major=0, kind=envelope_pb2.RecordKind.Value("INCIDENT"), logical_id=iid)
    i = env.incident
    i.incident_id, i.anchor_finding_id, i.version = iid, members[0], version
    i.status = incident_pb2.IncidentStatus.Value(status)
    i.finding_ids.extend(members)
    i.link_witness_ids.extend(witnesses)
    i.aliases.extend(aliases)
    for tp, off in (frontier or {}).items():
        i.input_frontier[tp] = off
    return env


def v_c(env):
    return env.incident.incident_id, env.incident.version, A.sha256(env.incident)


def events(n, start=0):
    return [(NORM, 0, start + k, T.file_read(start + k + 1)) for k in range(n)]


def snapshots(store, iid):
    return sorted((r for r in store.rows("snapshots") if r["incident_id"] == iid), key=lambda r: r["seq"])


# --- status ----------------------------------------------------------------------------
def test_an_incident_applied_after_its_inputs_has_a_current_snapshot(store):
    i1 = inc("in-1", witnesses=["wt-1"], frontier={"norm.events.v0/0": 3})
    A.apply_batch(store, events(4))
    A.apply_batch(store, [(WIT, 0, 0, T.witness("wt-1", "f1", "f2"))])
    A.apply_batch(store, [(INC, 0, 0, i1)])
    [snap] = snapshots(store, "in-1")
    assert snap["status"] == S.CURRENT and snap["record_sha256"] == v_c(i1)[2]
    assert snap["sid"] == S.sid_of(v_c(i1), snap["offsets"])
    assert snap["offsets"] == {"norm.events.v0/0": 3, "witness.decisions.v0/0": 0, "incidents.v0/0": 0}
    assert S.status(store, v_c(i1)) == (S.CURRENT, [])


def test_lagging_until_the_frontier_and_the_listed_witnesses_are_applied(store):
    i1 = inc("in-1", witnesses=["wt-1"], frontier={"norm.events.v0/0": 3})
    A.apply_batch(store, events(2))
    A.apply_batch(store, [(INC, 0, 0, i1)])
    [snap] = snapshots(store, "in-1")
    st, why = S.status(store, v_c(i1))
    assert snap["status"] == st == S.LAGGING
    assert why == ["norm.events.v0/0 applied to 1, needs 3", "witnesses not yet applied: wt-1"]
    A.apply_batch(store, events(2, start=2))
    A.apply_batch(store, [(WIT, 0, 0, T.witness("wt-1", "f1", "f2"))])
    assert S.status(store, v_c(i1)) == (S.CURRENT, [])    # re-evaluated on read
    ok, why = S.check_approval(store, v_c(i1), snap["sid"])
    assert not ok and why == "snapshot was lagging when issued"


def test_an_open_incident_revised_under_the_same_version_makes_old_approvals_stale(store):
    old = inc("in-1", members=("f1", "f2"))
    new = inc("in-1", members=("f1", "f2", "f3"))      # same version 1, different content
    A.apply_batch(store, [(INC, 0, 0, old)])
    old_sid = snapshots(store, "in-1")[0]["sid"]
    assert S.check_approval(store, v_c(old), old_sid)[0]
    A.apply_batch(store, [(INC, 0, 1, new)])
    assert S.status(store, v_c(old)) == (S.STALE, ["incident changed since review (open incident revised under version 1)"])
    ok, why = S.check_approval(store, v_c(old), old_sid)
    assert not ok and why.startswith("incident changed since review")
    new_sid = snapshots(store, "in-1")[-1]["sid"]
    assert S.check_approval(store, v_c(new), new_sid) == (True, "approval matches the latest reviewed incident state")


def test_an_amendment_makes_the_sealed_state_stale(store):
    sealed = inc("in-1", status="INCIDENT_SEALED")
    amended = inc("in-1", version=2, status="INCIDENT_AMENDED")
    A.apply_batch(store, [(INC, 0, 0, sealed), (INC, 0, 1, amended)])
    assert S.status(store, v_c(sealed))[1] == ["incident changed since review (version 1 -> 2)"]


def test_an_incident_merged_into_another_is_stale(store):
    a = inc("in-a", members=("f1", "f2"))
    A.apply_batch(store, [(INC, 0, 0, a)])
    sid = snapshots(store, "in-a")[0]["sid"]
    A.apply_batch(store, [(INC, 0, 1, inc("in-b", members=("f0", "f1", "f2"), aliases=["in-a"]))])
    assert S.status(store, v_c(a)) == (S.STALE, ["incident in-a was merged into in-b"])
    assert S.check_approval(store, v_c(a), sid) == (False, "incident in-a was merged into in-b")


def test_approval_checks_reject_unknown_or_mismatched_snapshots(store):
    a, b = inc("in-a"), inc("in-b")
    A.apply_batch(store, [(INC, 0, 0, a), (INC, 0, 1, b)])
    sid_b = snapshots(store, "in-b")[0]["sid"]
    assert S.check_approval(store, v_c(a), "sn_nope") == (False, "unknown snapshot sn_nope")
    assert S.check_approval(store, v_c(a), sid_b) == (False, "snapshot belongs to another incident state than the approval")


def test_a_snapshot_on_request_uses_the_current_offsets(store):
    i1 = inc("in-1", frontier={"norm.events.v0/0": 1})
    A.apply_batch(store, [(INC, 0, 0, i1)])
    assert snapshots(store, "in-1")[0]["status"] == S.LAGGING
    A.apply_batch(store, events(2))
    snap = S.take_snapshot(store, "in-1")
    assert snap["status"] == S.CURRENT and S.check_approval(store, v_c(i1), snap["sid"])[0]
    assert S.take_snapshot(store, "in-unknown") is None


# --- rebuild ---------------------------------------------------------------------------
def _log():
    evs = [(NORM, 0, k, T.file_read(k + 1, ingest=k + 1.5)) for k in range(12)]
    wits = [(WIT, 0, 0, T.witness("wt-1", "f1", "f2"))]
    incs = [(INC, 0, 0, inc("in-1", witnesses=["wt-1"], frontier={"norm.events.v0/0": 11})),
            (INC, 0, 1, T.incident("in-2", members=("f1",), epochs=[(F.NODE, F.BOOT, 6, "c1b")]))]
    fnd = [(T.FND, 0, 0, T.finding("f1", ("POD", "pod-1")))]
    return evs + wits + fnd + incs


def _apply_in_batches(store, recs, size):
    for k in range(0, len(recs), size):
        A.apply_batch(store, recs[k:k + size])


def test_a_rebuild_in_any_batch_size_gives_the_same_hashes(store):
    recs = _log()
    _apply_in_batches(store, recs, 1)
    want = graph_hash(store), incident_hash(store, "in-1"), incident_hash(store, "in-2")
    store.reset()
    assert store.rows("edges") == [] and store.offsets() == {}
    _apply_in_batches(store, recs, 5)
    assert (graph_hash(store), incident_hash(store, "in-1"), incident_hash(store, "in-2")) == want
    other = MemoryStore()
    _apply_in_batches(other, recs, len(recs))
    assert graph_hash(other) == want[0]


def test_a_replay_in_another_arrival_order_gives_the_same_graph_hash():
    recs = _log()
    base = MemoryStore()
    _apply_in_batches(base, recs, 3)
    want = graph_hash(base)
    for seed in range(3):
        shuffled = recs[:]
        random.Random(seed).shuffle(shuffled)
        other = MemoryStore()
        _apply_in_batches(other, shuffled, 2)
        assert graph_hash(other) == want


def test_the_hash_changes_when_the_graph_does():
    a, b = MemoryStore(), MemoryStore()
    A.apply_batch(a, events(3))
    A.apply_batch(b, events(4))
    assert graph_hash(a) != graph_hash(b)
