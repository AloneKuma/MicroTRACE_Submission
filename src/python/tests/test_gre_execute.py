"""GRE build step 7.2, without a cluster: token minting per action, target
revalidation (UID, exact reviewed version, the fields each action depends
on), conditional writes and the outcome of each API answer, against a fake
API server that keeps every version. The same paths run against kind in
test_gre_kube.py."""
import copy

import pytest

from mtcore.gre import request as R
from mtcore.gre.approver import ScriptedApprover
from mtcore.gre.execute import ISOLATION_LABEL, SERVICE_ACCOUNTS, Executor
from mtcore.gre.kube import ApiError
from mtcore.gre.sim import SimApi, SimKube
from mtcore.gre.store import MemoryGreStore
from mtcore.gre.validate import Gre, GreConfig, TgsGraph
from mtcore.tgs import apply as A
from mtcore.tgs.store import MemoryStore

import test_tgs_ingest as T
import test_tgs_snapshot as TS

KEY, PUB = R.new_keypair()


# The simulated API server (mtcore/gre/sim.py), under the names the GRE tests use.
FakeApi, FakeKube = SimApi, SimKube

POD = "/api/v1/namespaces/shop/pods/checkout-1"
NODE = "/api/v1/nodes/worker2"
DEPLOY = "/apis/apps/v1/namespaces/shop/deployments/checkout"
RB = "/apis/rbac.authorization.k8s.io/v1/namespaces/shop/rolebindings/reader"


@pytest.fixture
def rig():
    tgs = MemoryStore()
    A.apply_batch(tgs, T.batch(T.witness("w12", "f1", "f2"), topic=T.WIT))
    A.apply_batch(tgs, T.batch(TS.inc("in-1", members=("f1", "f2"), witnesses=("w12",)), topic=T.INC))
    api = FakeApi()
    api.put(POD, {"metadata": {"name": "checkout-1", "uid": "pod-uid", "labels": {"app": "checkout"}},
                  "spec": {"nodeName": "worker", "serviceAccountName": "default"}, "status": {"phase": "Running"}})
    api.put(NODE, {"metadata": {"name": "worker2", "uid": "node-uid", "labels": {"role": "spare"}}, "spec": {}})
    api.put(DEPLOY, {"metadata": {"name": "checkout", "uid": "dep-uid"}, "spec": {"replicas": 2}})
    api.put(RB, {"metadata": {"name": "reader", "uid": "rb-uid"}, "roleRef": {"kind": "ClusterRole", "name": "view"},
                 "subjects": [{"kind": "ServiceAccount", "name": "default"}]})
    gre = Gre(GreConfig("kind-mt", frozenset({"shop"}), {"ap": PUB}), TgsGraph(tgs), MemoryGreStore())
    return {"api": api, "ex": Executor(gre, FakeKube(api)), "approver": ScriptedApprover("ap", KEY, tgs, "kind-mt")}


def issue(rig, act, path, params, ns="shop"):
    obj = rig["api"].objects[path]
    return rig["approver"].issue("in-1", act, ns, obj["metadata"]["uid"], obj["metadata"]["resourceVersion"], params)


def isolate(rig):
    return issue(rig, "isolate_pod", POD, {"pod": "checkout-1"})


# --- the four actions ---------------------------------------------------------------------
@pytest.mark.parametrize("act, path, params, ns, check", [
    ("isolate_pod", POD, {"pod": "checkout-1"}, "shop", lambda o: o["metadata"]["labels"][ISOLATION_LABEL] == "true"),
    ("cordon_node", NODE, {"node": "worker2"}, "", lambda o: o["spec"]["unschedulable"] is True),
    ("scale_to_zero", DEPLOY, {"kind": "Deployment", "name": "checkout"}, "shop", lambda o: o["spec"]["replicas"] == 0),
    ("revoke_rolebinding", RB, {"rolebinding": "reader"}, "shop", lambda o: o is None),
])
def test_each_action_runs_with_its_own_minted_token(rig, act, path, params, ns, check):
    out = rig["ex"].execute(issue(rig, act, path, params, ns))
    assert (out.status, out.attempt["ref_audit"]) == ("Submitted", "a-write" if act != "revoke_rolebinding" else "a-delete")
    assert check(rig["api"].objects.get(path))
    assert rig["api"].minted == [SERVICE_ACCOUNTS[act]]
    writes = [c for c in rig["api"].calls if c[1] != "GET"]
    assert [w[0] for w in writes] == [SERVICE_ACCOUNTS[act]]          # the write used the minted token only
    assert set(out.timings_ms) == {"validation", "revalidation", "submission", "rounds"}


def test_a_rejected_request_mints_nothing_and_touches_nothing(rig):
    req = isolate(rig)
    bad = dict(req, rv="1")                                          # breaks the signature
    out = rig["ex"].execute(bad)
    assert out.status == "Rejected" and rig["api"].minted == [] and rig["api"].calls == []


# --- revalidation -------------------------------------------------------------------------
def test_an_unrelated_change_after_review_does_not_reject(rig):
    req = isolate(rig)
    pod = copy.deepcopy(rig["api"].objects[POD])
    pod["status"]["phase"] = "Running"
    pod["metadata"]["annotations"] = {"note": "x"}
    rig["api"].put(POD, pod)
    out = rig["ex"].execute(req)
    assert out.status == "Submitted"
    exact = [c for c in rig["api"].calls if c[3] and c[3].get("resourceVersionMatch") == "Exact"]
    assert exact and exact[0][3]["resourceVersion"] == req["rv"]


@pytest.mark.parametrize("change, field", [
    (lambda o: o["metadata"]["labels"].update(app="other"), "labels"),
    (lambda o: o["metadata"].update(ownerReferences=[{"uid": "rs-2"}]), "owners"),
    (lambda o: o["spec"].update(serviceAccountName="admin"), "service_account"),
])
def test_a_change_to_a_field_the_action_depends_on_rejects(rig, change, field):
    req = isolate(rig)
    pod = copy.deepcopy(rig["api"].objects[POD])
    change(pod)
    rig["api"].put(POD, pod)
    out = rig["ex"].execute(req)
    assert (out.status, out.reason) == ("Rejected", f"fields the action depends on changed since review: {field}")
    assert ISOLATION_LABEL not in rig["api"].objects[POD]["metadata"]["labels"]


def test_a_recreated_target_rejects(rig):
    req = isolate(rig)
    pod = copy.deepcopy(rig["api"].objects[POD])
    pod["metadata"]["uid"] = "pod-uid-2"
    rig["api"].put(POD, pod)
    assert rig["ex"].execute(req).reason == "target UID differs from the approved one (object recreated)"


def test_a_missing_target_or_a_compacted_reviewed_version_rejects(rig):
    req = isolate(rig)
    del rig["api"].objects[POD]
    assert rig["ex"].execute(req).reason == "target no longer exists"
    rig["api"].put(POD, {"metadata": {"name": "checkout-1", "uid": "pod-uid", "labels": {}}, "spec": {}})
    old = rig["approver"].issue("in-1", "isolate_pod", "shop", "pod-uid", "42", {"pod": "checkout-1"})
    assert rig["ex"].execute(old).reason == "reviewed version 42 is no longer available to compare"


# --- write outcomes -----------------------------------------------------------------------
def test_a_change_before_every_write_ends_in_a_conflict(rig, monkeypatch):
    def meddle(req, live):
        pod = copy.deepcopy(rig["api"].objects[POD])
        pod["metadata"]["annotations"] = {"late": "1"}
        rig["api"].put(POD, pod)

    monkeypatch.setattr(rig["ex"], "_before_write", meddle)
    out = rig["ex"].execute(isolate(rig))
    assert out.status == "Failed" and out.reason.startswith("conflict") and out.attempt["ref_audit"] == "a-409"
    assert len([c for c in rig["api"].calls if c[1] == "PATCH"]) == 3            # WRITE_ROUNDS


def test_a_status_update_racing_the_write_is_absorbed(rig, monkeypatch):
    seen = []

    def once(req, live):
        if not seen:
            seen.append(1)
            pod = copy.deepcopy(rig["api"].objects[POD])
            pod["status"]["phase"] = "Pending"
            rig["api"].put(POD, pod)

    monkeypatch.setattr(rig["ex"], "_before_write", once)
    out = rig["ex"].execute(isolate(rig))
    assert (out.status, out.timings_ms["rounds"]) == ("Submitted", 2)
    assert rig["api"].minted == ["gre-isolate"]                                   # one token for the attempt


@pytest.mark.parametrize("err, status", [
    (ApiError(0, "no response: timed out"), "Unresolved"),
    (ApiError(503, "Service Unavailable", audit_id="a-503"), "Unresolved"),
    (ApiError(403, "Forbidden", {"message": "denied by ValidatingAdmissionPolicy"}), "Failed"),
    (ApiError(422, "Invalid", {"message": "bad"}), "Failed"),
])
def test_each_api_answer_maps_to_one_outcome(rig, err, status):
    rig["api"].fail_next = err
    out = rig["ex"].execute(isolate(rig))
    assert out.status == status and out.attempt["status"] == status
    assert out.attempt["ref_audit"] == err.audit_id


def test_a_failed_token_request_rejects_before_any_write(rig, monkeypatch):
    def refuse(*_a):
        raise ApiError(403, "Forbidden", {"message": "cannot create serviceaccounts/token"})

    monkeypatch.setattr(FakeKube, "mint_token", lambda self, *a: refuse())
    out = rig["ex"].execute(isolate(rig))
    assert out.status == "Rejected" and out.reason.startswith("token request failed: 403")
    assert [c for c in rig["api"].calls if c[1] != "GET"] == []


def test_every_attempt_is_one_a_resp_row(rig):
    ex = rig["ex"]
    ok = ex.execute(isolate(rig))
    ex.execute(ok.attempt["request"])
    rows = ex.gre.store.attempts()
    assert [(r["status"], r["reason"]) for r in rows] == [("Submitted", "API accepted the write"),
                                                          ("Rejected", "nonce already used")]
