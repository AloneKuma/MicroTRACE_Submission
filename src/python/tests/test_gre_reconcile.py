"""GRE build step 7.3, without a cluster: the intent journal, the four
interruption points, and reconciliation from the audit log and the target's
state. A crash is simulated by making the armed failpoint raise; the real
process kill on kind is in test_gre_kube_crash.py. Every test runs on the
memory stores and on Postgres."""
import pytest

import test_gre_execute as X
import test_tgs_ingest as T
import test_tgs_snapshot as TS
from test_gre_validate import gre_store_for
from test_tgs_ingest import store  # noqa: F401  (memory and Postgres stores)
from mtcore.gre import execute as E
from mtcore.gre.approver import ScriptedApprover
from mtcore.gre.execute import ISOLATION_LABEL, Executor
from mtcore.gre.kube import ApiError
from mtcore.gre.reconcile import Reconciler
from mtcore.gre.validate import NS, Gre, GreConfig, TgsGraph
from mtcore.tgs import apply as A

GRACE = 30


class Crash(BaseException):
    """Stands in for os._exit(137): nothing after the failpoint runs."""


class Clock:
    def __init__(self):
        self.t = 1_800_000_000 * NS

    def __call__(self):
        return self.t


class Audit:
    def __init__(self, api):
        self.api = api

    def events(self):
        return list(self.api.audit)


@pytest.fixture
def rig(store, monkeypatch):
    return make_rig(store, monkeypatch)


def make_rig(store, monkeypatch):
    A.apply_batch(store, T.batch(T.witness("w12", "f1", "f2"), topic=T.WIT))
    A.apply_batch(store, T.batch(TS.inc("in-1", members=("f1", "f2"), witnesses=("w12",)), topic=T.INC))
    api, clock = X.FakeApi(), Clock()
    api.put(X.POD, {"metadata": {"name": "checkout-1", "uid": "pod-uid", "labels": {"app": "checkout"}},
                    "spec": {"nodeName": "worker"}, "status": {}})
    gstore = gre_store_for(store)
    gre = Gre(GreConfig("kind-mt", frozenset({"shop"}), {"ap": X.PUB}), TgsGraph(store), gstore,
              clock=clock)
    ex = Executor(gre, X.FakeKube(api), clock=clock)
    approver = ScriptedApprover("ap", X.KEY, store, "kind-mt", clock=lambda: clock.t / NS)
    armed = []

    def hit(name, state=None, require=None):
        if name in armed:
            raise Crash(name)

    monkeypatch.setattr(E.failpoint, "hit", hit)
    rec = Reconciler(gstore, X.FakeKube(api), Audit(api), grace_s=GRACE, clock=clock)
    return {"api": api, "clock": clock, "ex": ex, "store": gstore, "rec": rec, "armed": armed,
            "req": lambda: approver.issue("in-1", "isolate_pod", "shop", "pod-uid",
                                          api.objects[X.POD]["metadata"]["resourceVersion"], {"pod": "checkout-1"})}


def crash_at(rig, point):
    rig["armed"].append(point)
    req = rig["req"]()
    with pytest.raises(Crash):
        rig["ex"].execute(req)
    rig["armed"].clear()
    return req


def labelled(rig):
    return rig["api"].objects[X.POD]["metadata"]["labels"].get(ISOLATION_LABEL) == "true"


def later(rig, seconds=GRACE + 1):
    rig["clock"].t += seconds * NS


def statuses(rig, req):
    return [(a["status"], a["reason"]) for a in rig["store"].attempts(rid=req["rid"])]


# --- the four interruption points ---------------------------------------------------------
def test_killed_before_the_intent_nothing_was_sent(rig):
    req = crash_at(rig, "gre.before_intent")
    assert rig["store"].open_intents() == [] and not labelled(rig) and rig["api"].audit == []
    assert rig["rec"].run() == []                                   # within the grace period
    later(rig)
    [row] = rig["rec"].run()
    assert (row["status"], row["reason"]) == ("Failed", "reconciled: the GRE stopped before planning a write, "
                                                        "so nothing was sent")
    assert rig["rec"].run() == []                                   # closed for good
    assert rig["ex"].execute(req).reason == "nonce already used"    # no second execution


def test_killed_after_the_intent_before_submission(rig):
    req = crash_at(rig, "gre.after_intent_before_submit")
    [intent] = rig["store"].open_intents()
    assert intent["user_agent"] == E.user_agent(req) and not labelled(rig)
    assert rig["rec"].run() == []
    later(rig)
    [row] = rig["rec"].run()
    assert (row["status"], row["reason"]) == ("Failed", "reconciled: no write reached the API server and the "
                                                        "target is unchanged")
    assert rig["store"].open_intents() == [] and not labelled(rig)


def test_killed_after_the_api_accepted_before_the_record(rig):
    req = crash_at(rig, "gre.after_submit_before_record")
    assert labelled(rig) and statuses(rig, req) == []
    [event] = rig["api"].audit
    [row] = rig["rec"].run()                                        # no grace needed: the audit log says so
    assert (row["status"], row["ref_audit"]) == ("Submitted", event["auditID"])
    assert row["reason"] == "reconciled: the audit log records the accepted write"
    assert rig["ex"].execute(req).reason == "nonce already used"
    assert len(rig["api"].audit) == 1                               # still exactly one write


def test_killed_before_verification_needs_no_reconciliation(rig):
    req = crash_at(rig, "gre.before_verify")
    assert statuses(rig, req) == [("Submitted", "API accepted the write")]
    later(rig)
    assert rig["rec"].run() == []


def test_a_refused_write_recorded_only_in_the_audit_log_is_failed(rig):
    rig["api"].fail_next = ApiError(403, "Forbidden", {"message": "denied"}, "a-403")
    crash_at(rig, "gre.after_submit_before_record")
    [row] = rig["rec"].run()
    assert (row["status"], row["ref_audit"], row["reason"]) == (
        "Failed", "a-403", "reconciled: the API refused the write (403)")


# --- outcomes the executor could not know ---------------------------------------------------
def test_a_lost_response_after_an_applied_write_reconciles_to_submitted(rig, monkeypatch):
    real = X.FakeKube._request

    def applied_then_lost(self, method, path, body=None, params=None):
        out = real(self, method, path, body, params)
        if method == "PATCH":
            self._audit(method, path, 200, "a-applied")
            raise ApiError(0, "no response: connection reset")
        return out

    monkeypatch.setattr(X.FakeKube, "_request", applied_then_lost)
    req = rig["req"]()
    out = rig["ex"].execute(req)
    assert out.status == "Unresolved" and labelled(rig)
    monkeypatch.setattr(X.FakeKube, "_request", real)
    [row] = rig["rec"].run()
    assert (row["status"], row["ref_audit"]) == ("Submitted", "a-applied")
    assert [s for s, _ in statuses(rig, req)] == ["Unresolved", "Submitted"]


def test_an_effect_without_an_audit_record_stays_unresolved_once(rig):
    req = crash_at(rig, "gre.after_intent_before_submit")
    pod = dict(rig["api"].objects[X.POD])
    pod["metadata"] = dict(pod["metadata"], labels={"app": "checkout", ISOLATION_LABEL: "true"})
    rig["api"].put(X.POD, pod)                                      # someone else, or a lost audit record
    later(rig)
    [row] = rig["rec"].run()
    assert (row["status"], row["reason"]) == ("Unresolved", "reconciled: no audit record of the write, but the "
                                                            "effect is present")
    assert rig["rec"].run() == []                                   # not repeated
    assert len(rig["store"].open_intents()) == 1                    # still open for evidence to arrive
    assert [s for s, _ in statuses(rig, req)] == ["Unresolved"]


def test_reconciliation_never_writes(rig):
    crash_at(rig, "gre.after_intent_before_submit")
    crash_at(rig, "gre.before_intent")
    later(rig)
    before = [c for c in rig["api"].calls if c[1] != "GET"]
    rig["rec"].run()
    assert [c for c in rig["api"].calls if c[1] != "GET"] == before
