"""GRE build step 7.1: request signing, the scripted approver, the nonce
store and fail-closed validation (evaluation-plan.md section 5, step 7; Exp.
5 part B). Each test starts from one valid signed request and changes one
field or one condition. Every test runs on the memory stores and on
Postgres (TGS and GRE tables in one private schema)."""
import base64
import copy
import threading
import time

import pytest

import test_tgs_ingest as T
import test_tgs_snapshot as TS
from test_tgs_ingest import TEST_DSN, store  # noqa: F401  (memory and Postgres stores)
from mtcore.gre import request as R
from mtcore.gre.approver import ScriptedApprover
from mtcore.gre.store import MemoryGreStore, PgGreStore
from mtcore.gre.validate import NS, Gre, GreConfig, TgsGraph
from mtcore.tgs import apply as A
from mtcore.tgs.store import PgStore

T0 = 1_800_000_000                    # seconds; every clock in a test starts here
SKEW, TTL = 30, 900
POD_UID = "3c9e1d2a-7a61-4f0e-9d11-00000000a007"
K1, P1 = R.new_keypair()
K2, P2 = R.new_keypair()
K3, P3 = R.new_keypair()
TRUSTED = {"approver-1": P1, "approver-3": P3}


class Clock:
    def __init__(self, t=T0):
        self.t = t                    # seconds, may be fractional

    def s(self):
        return self.t

    def ns(self):
        return int(self.t * NS)


def gre_store_for(store):
    if isinstance(store, PgStore):
        g = PgGreStore(store.conn)
        g.apply_schema()
        return g
    return MemoryGreStore()


@pytest.fixture
def rig(store):
    """An incident in-1 whose ingest snapshot is current, a GRE, and an
    approver sharing one clock."""
    A.apply_batch(store, T.batch(T.witness("w12", "f1", "f2"), topic=T.WIT))
    A.apply_batch(store, T.batch(TS.inc("in-1", members=("f1", "f2"), witnesses=("w12",)), topic=T.INC))
    clock = Clock()
    config = GreConfig(cluster="kind-mt", app_namespaces=frozenset({"shop", "kube-system"}), trusted_keys=TRUSTED,
                       max_skew_s=SKEW, max_ttl_s=TTL)
    gstore = gre_store_for(store)
    gre = Gre(config, TgsGraph(store), gstore, clock=clock.ns)
    approver = ScriptedApprover("approver-1", K1, store, "kind-mt", clock=clock.s)
    return {"tgs": store, "gre": gre, "gstore": gstore, "approver": approver, "clock": clock, "config": config}


def isolate(rig, **kw):
    return rig["approver"].issue("in-1", "isolate_pod", "shop", POD_UID, "1234", {"pod": "checkout-1"}, **kw)


def resign(req, key=K1, key_id="approver-1"):
    return R.sign({k: v for k, v in req.items() if k != "approval"}, key_id, key)


# --- valid ---------------------------------------------------------------------------------
def test_a_valid_request_is_accepted_and_consumes_its_nonce(rig):
    req = isolate(rig)
    d = rig["gre"].validate(req)
    assert (d.accepted, d.reason, d.attempt) == (True, "accepted", None)
    assert rig["gstore"].attempts() == []
    assert req["evid"] == ["f1", "f2", "w12"] and req["v_c"]["version"] == 1


def test_the_signature_covers_every_field_and_the_key_id():
    req = R.sign({"version": R.VERSION, "x": 1}, "approver-1", K1)
    body = R.signed_bytes(req)
    assert body.startswith(R.SIG_CONTEXT) and b'"key_id":"approver-1"' in body and b'"sig"' not in body
    assert R.verify(req, TRUSTED) == (True, "")


# --- one-field mutations -------------------------------------------------------------------
MUTATIONS = [
    ("rid", lambda r: r.update(rid="rq-other")),
    ("gid", lambda r: r.update(gid="in-2")),
    ("sid", lambda r: r.update(sid="sn_" + "0" * 32)),
    ("v_c.version", lambda r: r["v_c"].update(version=2)),
    ("v_c.record_sha256", lambda r: r["v_c"].update(record_sha256="a" * 64)),
    ("cluster", lambda r: r.update(cluster="prod")),
    ("ns", lambda r: r.update(ns="billing")),
    ("uid", lambda r: r.update(uid="3c9e1d2a-0000-0000-0000-000000000000")),
    ("rv", lambda r: r.update(rv="9999")),
    ("act", lambda r: r.update(act="cordon_node", ns="", params={"node": "node-1"})),
    ("params", lambda r: r["params"].update(pod="checkout-2")),
    ("exp", lambda r: r.update(exp=r["exp"] + 60)),
    ("nonce", lambda r: r.update(nonce="f" * 32)),
    ("evid", lambda r: r.update(evid=["f1"])),
    ("approval.alg", lambda r: r["approval"].update(alg="RS256")),
    ("approval.sig", lambda r: r["approval"].update(sig=base64.b64encode(b"\0" * 64).decode())),
    ("approval.sig not base64", lambda r: r["approval"].update(sig="!!!")),
    ("extra field", lambda r: r.update(priority="high")),
]


@pytest.mark.parametrize("name, mutate", MUTATIONS, ids=[m[0] for m in MUTATIONS])
def test_every_one_field_change_is_rejected_without_using_the_nonce(rig, name, mutate):
    req = isolate(rig)
    bad = copy.deepcopy(req)
    mutate(bad)
    d = rig["gre"].validate(bad)
    assert not d.accepted
    assert d.reason == "approval signature does not match the request" or d.reason.startswith("malformed"), d.reason
    [a] = rig["gstore"].attempts()
    assert (a["status"], a["reason"]) == ("Rejected", d.reason)
    assert rig["gre"].validate(req).accepted                       # the nonce was not consumed


def test_a_signature_over_part_of_the_fields_is_rejected(rig):
    req = isolate(rig)
    partial = {k: req[k] for k in ("rid", "act", "uid", "nonce")}
    partial_sig = R.sign(partial, "approver-1", K1)["approval"]["sig"]
    bad = dict(req, approval=dict(req["approval"], sig=partial_sig))
    assert rig["gre"].validate(bad).reason == "approval signature does not match the request"


@pytest.mark.parametrize("key, key_id, reason", [
    (K2, "approver-1", "approval signature does not match the request"),     # wrong key under a trusted ID
    (K2, "approver-2", "unknown approval key approver-2"),                   # an untrusted key
    (K1, "approver-3", "approval signature does not match the request"),     # a trusted ID, another key
])
def test_wrong_or_swapped_keys_are_rejected(rig, key, key_id, reason):
    assert rig["gre"].validate(resign(isolate(rig), key, key_id)).reason == reason


# --- expiry and clock skew -----------------------------------------------------------------
def test_expiry_is_exclusive_at_the_boundary(rig):
    req = isolate(rig, ttl_s=60)
    rig["clock"].t = req["exp"] - 0.001                 # 1 ms before (float seconds cannot hold 1 ns here)
    assert rig["gre"].validate(req).accepted
    req2 = isolate(rig, ttl_s=60)
    rig["clock"].t = req2["exp"]
    assert rig["gre"].validate(req2).reason == "approval expired"


@pytest.mark.parametrize("ahead, ok", [(SKEW - 1, True), (SKEW + 1, False)])
def test_an_approver_clock_ahead_by_more_than_the_skew_is_rejected(rig, ahead, ok):
    rig["clock"].t = T0 + ahead                        # the approver's clock runs ahead ...
    req = isolate(rig, ttl_s=TTL)
    rig["clock"].t = T0                                 # ... of the GRE's
    d = rig["gre"].validate(req)
    assert d.accepted is ok and (ok or d.reason == "approval expiry too far ahead")


def test_a_nonce_outlives_its_request_by_the_skew(rig):
    """A second GRE whose clock lags by up to the skew still sees the
    request as unexpired; the nonce must still be there to stop a replay."""
    req = isolate(rig, ttl_s=60)
    assert rig["gre"].validate(req).accepted
    lag = Clock(req["exp"] + SKEW - 1)
    rig["gstore"].purge_nonces(lag.ns())
    slow = Gre(rig["config"], rig["gre"].graph, rig["gstore"], clock=lambda: int((lag.t - SKEW) * NS))
    assert slow.validate(req).reason == "nonce already used"
    after = int((req["exp"] + SKEW) * NS) + 1
    assert rig["gstore"].purge_nonces(after) == 0          # no outcome yet: kept for reconciliation
    done = rig["gstore"].finish_attempt({"rid": req["rid"], "gid": "in-1", "act": req["act"], "uid": req["uid"],
                                         "ts": after, "status": "Failed", "reason": "test", "request": req},
                                        nonce=req["nonce"])
    assert done["attempt_id"] and rig["gstore"].purge_nonces(after) == 1


# --- nonces --------------------------------------------------------------------------------
def test_a_reused_nonce_is_rejected(rig):
    req = isolate(rig)
    assert rig["gre"].validate(req).accepted
    d = rig["gre"].validate(req)
    assert d.reason == "nonce already used" and d.attempt["status"] == "Rejected"
    other = isolate(rig, nonce=req["nonce"])                         # a new request reusing the nonce
    assert rig["gre"].validate(other).reason == "nonce already used"


def _second_gre(rig):
    """Another GRE instance with its own connections, as deployed (gre/cli.py opens one
    for the TGS graph and one for the nonce store): sharing the first GRE's graph
    connection across threads let one GRE's read-closing rollback undo the other's
    uncommitted nonce insert (part B failure, 2026-11-16), a race no deployment has."""
    if isinstance(rig["tgs"], PgStore):
        import psycopg
        schema = rig["tgs"].conn.execute("SELECT current_schema()").fetchone()[0]
        rig["tgs"].conn.commit()
        conns = []
        for _ in range(2):
            c = psycopg.connect(TEST_DSN)
            c.execute(f"SET search_path TO {schema}")
            c.commit()
            conns.append(c)
        graph_conn, nonce_conn = conns
        return Gre(rig["config"], TgsGraph(PgStore(graph_conn)), PgGreStore(nonce_conn), clock=rig["clock"].ns), conns
    return Gre(rig["config"], rig["gre"].graph, rig["gstore"], clock=rig["clock"].ns), []


def test_concurrent_use_of_one_nonce_executes_at_most_once(rig):
    gre2, conns = _second_gre(rig)
    try:
        reqs = [isolate(rig) for _ in range(10)]
        for req in reqs:
            out, gate = [], threading.Barrier(2)

            def run(g, r=req):
                gate.wait()
                out.append(g.validate(r).accepted)

            th = [threading.Thread(target=run, args=(g,)) for g in (rig["gre"], gre2)]
            for t in th:
                t.start()
            for t in th:
                t.join()
            assert sorted(out) == [False, True]
    finally:
        for c in conns:
            c.close()


# --- graph binding -------------------------------------------------------------------------
def test_a_snapshot_lagging_at_issue_is_rejected(rig):
    tgs = rig["tgs"]
    A.apply_batch(tgs, T.batch(TS.inc("in-2", frontier={"norm.events.v0/0": 5}), topic=T.INC, start=1))
    req = rig["approver"].issue("in-2", "isolate_pod", "shop", POD_UID, "1", {"pod": "checkout-1"})
    assert rig["gre"].validate(req).reason == "graph check failed: snapshot was lagging when issued"


def test_an_unknown_snapshot_or_another_incident_state_is_rejected(rig):
    assert "unknown snapshot" in rig["gre"].validate(isolate(rig, sid="sn_" + "0" * 32)).reason
    A.apply_batch(rig["tgs"], T.batch(TS.inc("in-3", members=("f7", "f8")), topic=T.INC, start=1))
    other_sid = rig["tgs"].select("snapshots", equals={"incident_id": "in-3"})[0]["sid"]
    assert rig["gre"].validate(isolate(rig, sid=other_sid)).reason == \
        "graph check failed: snapshot belongs to another incident state than the approval"


def test_the_evidence_group_must_be_the_incident_of_v_c(rig):
    req = isolate(rig)
    assert rig["gre"].validate(resign(dict(req, gid="in-9"))).reason == "evidence group does not match v_C"


class Down:
    def check(self, v_c, sid):
        raise ConnectionError("no route to the TGS")


def test_an_unreachable_tgs_rejects(rig):
    req = isolate(rig)
    gre = Gre(rig["config"], Down(), rig["gstore"], clock=rig["clock"].ns)
    assert gre.validate(req).reason == "TGS unreachable: ConnectionError"
    assert rig["gre"].validate(req).accepted                      # the nonce was not consumed


def test_a_closed_tgs_connection_rejects(rig):
    if not isinstance(rig["tgs"], PgStore):
        return
    import psycopg
    conn = psycopg.connect(TEST_DSN)
    conn.close()
    gre = Gre(rig["config"], TgsGraph(PgStore(conn)), rig["gstore"], clock=rig["clock"].ns)
    assert gre.validate(isolate(rig)).reason.startswith("TGS unreachable")


# --- scope ---------------------------------------------------------------------------------
@pytest.mark.parametrize("act, ns, params, reason", [
    ("isolate_pod", "billing", {"pod": "api-1"}, "namespace billing is out of scope"),
    ("isolate_pod", "kube-system", {"pod": "coredns-1"}, "namespace kube-system is out of scope"),
    ("revoke_rolebinding", "shop", {"rolebinding": "rb-1"}, "action revoke_rolebinding is not permitted"),
    ("isolate_pod", "shop", {"pod": "a", "grace": "0"}, "malformed request"),
    ("scale_to_zero", "shop", {"kind": "DaemonSet", "name": "agent"}, "malformed request"),
    ("cordon_node", "shop", {"node": "node-1"}, "malformed request: cordon_node takes no namespace"),
    ("isolate_pod", "", {"pod": "a"}, "malformed request: isolate_pod needs namespace"),
])
def test_actions_namespaces_and_parameters_out_of_scope_are_rejected(rig, act, ns, params, reason):
    cfg = rig["config"]
    gre = Gre(GreConfig(cfg.cluster, cfg.app_namespaces, cfg.trusted_keys,
                        actions=frozenset(R.ACTIONS) - {"revoke_rolebinding"}, max_skew_s=SKEW, max_ttl_s=TTL),
              rig["gre"].graph, rig["gstore"], clock=rig["clock"].ns)
    req = rig["approver"].issue("in-1", act, ns, POD_UID, "1", params)
    assert gre.validate(req).reason.startswith(reason)


def test_a_cordon_needs_no_namespace(rig):
    req = rig["approver"].issue("in-1", "cordon_node", "", "node-uid-1", "77", {"node": "node-1"})
    assert rig["gre"].validate(req).accepted


def test_a_request_for_another_cluster_is_rejected(rig):
    assert rig["gre"].validate(resign(dict(isolate(rig), cluster="prod"))).reason == \
        "cluster prod is not this GRE's cluster"


# --- fail closed and records ---------------------------------------------------------------
@pytest.mark.parametrize("bad", [None, [], "req", {"version": R.VERSION}])
def test_garbage_is_rejected_and_recorded(rig, bad):
    d = rig["gre"].validate(bad)
    assert not d.accepted and d.reason.startswith("malformed request")
    assert d.attempt["status"] == "Rejected"


def test_an_error_inside_a_check_rejects(rig, monkeypatch):
    def broken(*_a, **_k):
        raise RuntimeError("disk full")

    monkeypatch.setattr(rig["gstore"], "consume_nonce", broken)
    d = rig["gre"].validate(isolate(rig))
    assert (d.accepted, d.reason) == (False, "internal error: RuntimeError")


def test_rejections_are_kept_as_a_resp_rows(rig):
    req = isolate(rig)
    rig["gre"].validate(req)
    rig["gre"].validate(req)
    rows = rig["gstore"].attempts(rid=req["rid"])
    assert [(r["rid"], r["gid"], r["act"], r["uid"], r["status"], r["reason"]) for r in rows] == [
        (req["rid"], "in-1", "isolate_pod", POD_UID, "Rejected", "nonce already used")]
    assert rows[0]["request"]["nonce"] == req["nonce"] and rows[0]["ts"] == rig["clock"].ns()


# --- deployment roles (test host only) ------------------------------------------------------
def test_the_gre_runs_on_its_own_role_and_cannot_write_the_tgs():
    import os
    if not (os.environ.get("MT_GRE_DSN") and os.environ.get("MT_TGS_READER_DSN")):
        pytest.skip("MT_GRE_DSN and MT_TGS_READER_DSN are not set (src/scripts/pg-up.sh)")
    import psycopg
    from psycopg import errors
    from mtcore.gre.validate import open_gre
    config = GreConfig(cluster="kind-mt", app_namespaces=frozenset({"shop"}), trusted_keys=TRUSTED)
    gre = open_gre(config)
    req = R.sign({"version": R.VERSION, "rid": "rq-roles", "gid": "in-none", "sid": "sn_" + "0" * 32,
                  "v_c": {"incident_id": "in-none", "version": 1, "record_sha256": "0" * 64},
                  "cluster": "kind-mt", "ns": "shop", "uid": POD_UID, "rv": "1", "act": "isolate_pod",
                  "params": {"pod": "checkout-1"}, "exp": int(time.time()) + 300, "nonce": R.new_nonce(),
                  "evid": []},
                 "approver-1", K1)
    d = gre.validate(req)
    assert d.reason == "graph check failed: unknown snapshot sn_" + "0" * 32
    assert gre.store.attempts(rid="rq-roles")[-1]["status"] == "Rejected"
    with psycopg.connect(os.environ["MT_GRE_DSN"]) as conn:
        with pytest.raises((errors.InsufficientPrivilege, errors.UndefinedTable)):
            conn.execute("DELETE FROM public.snapshots")
