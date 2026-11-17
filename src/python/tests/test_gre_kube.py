"""GRE build step 7.2 on the kind cluster microtrace-gre (gre-kind-up.sh):
the four actions through the executor, target revalidation against real
resource versions, conditional writes, and the compromised-executor cases
(minted response tokens used directly, bounded by RBAC and the
ValidatingAdmissionPolicies). Runs only where gre.env is sourced
(MT_GRE_KUBECONFIG, MT_GRE_ADMIN_KUBECONFIG, MT_KUBECTL)."""
import json
import os
import subprocess
import uuid

import pytest

from mtcore.gre import request as R
from mtcore.gre.approver import ScriptedApprover
from mtcore.gre.execute import DEFAULT_AUDIENCE, ISOLATION_LABEL, Executor
from mtcore.gre.kube import ApiError, Kube
from mtcore.gre.store import MemoryGreStore
from mtcore.gre.validate import Gre, GreConfig, TgsGraph
from mtcore.tgs import apply as A
from mtcore.tgs.store import MemoryStore

import test_tgs_ingest as T
import test_tgs_snapshot as TS

ENV = ("MT_GRE_KUBECONFIG", "MT_GRE_ADMIN_KUBECONFIG", "MT_KUBECTL")
pytestmark = pytest.mark.skipif(not all(os.environ.get(v) for v in ENV),
                                reason="no GRE kind cluster (source $MT_DEV/gre-kind/gre.env)")
SPARE_NODE = "microtrace-gre-worker2"
KEY, PUB = R.new_keypair()


def kubectl(*args, stdin=None):
    out = subprocess.run([os.environ["MT_KUBECTL"], "--kubeconfig", os.environ["MT_GRE_ADMIN_KUBECONFIG"], *args],
                         input=stdin, capture_output=True, text=True, timeout=120)
    if out.returncode:
        raise RuntimeError(f"kubectl {' '.join(args)}: {out.stderr.strip()}")
    return out.stdout


def obj(kind, name, ns="shop"):
    return json.loads(kubectl("get", kind, name, *(["-n", ns] if ns else []), "-o", "json"))


def apply(manifest):
    kubectl("apply", "-f", "-", stdin=json.dumps(manifest))


def pod_manifest(name, labels=None):
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": "shop", "labels": labels or {"app": "t"}},
            "spec": {"nodeSelector": {"microtrace.io/role": "app"}, "terminationGracePeriodSeconds": 0,
                     "containers": [{"name": "c", "image": "registry.k8s.io/pause:3.10",
                                     "imagePullPolicy": "IfNotPresent"}]}}


def make_pod(name, labels=None):
    """Create a Pod and wait until it is scheduled: a node assigned after
    review would rightly reject the approval (spec.nodeName is a field
    isolation depends on)."""
    apply(pod_manifest(name, labels))
    kubectl("-n", "shop", "wait", "--for=condition=PodScheduled", f"pod/{name}", "--timeout=60s")


@pytest.fixture
def name():
    n = "t-" + uuid.uuid4().hex[:8]
    yield n
    for kind in ("pod", "deployment", "rolebinding"):
        subprocess.run([os.environ["MT_KUBECTL"], "--kubeconfig", os.environ["MT_GRE_ADMIN_KUBECONFIG"], "-n", "shop",
                        "delete", kind, n, "--ignore-not-found", "--wait=false"], capture_output=True, timeout=60)


@pytest.fixture
def rig():
    return make_rig()


def make_rig():
    tgs = MemoryStore()
    A.apply_batch(tgs, T.batch(T.witness("w12", "f1", "f2"), topic=T.WIT))
    A.apply_batch(tgs, T.batch(TS.inc("in-1", members=("f1", "f2"), witnesses=("w12",)), topic=T.INC))
    kube = Kube.from_kubeconfig(os.environ["MT_GRE_KUBECONFIG"])
    cluster = os.environ.get("MT_GRE_CLUSTER", "microtrace-gre")
    gre = Gre(GreConfig(cluster, frozenset({"shop"}), {"ap": PUB}), TgsGraph(tgs), MemoryGreStore())
    return {"kube": kube, "ex": Executor(gre, kube), "approver": ScriptedApprover("ap", KEY, tgs, cluster),
            "tgs": tgs}


def approve(rig, act, o, params, ns="shop"):
    return rig["approver"].issue("in-1", act, ns, o["metadata"]["uid"], o["metadata"]["resourceVersion"], params)


def token_for(rig, sa):
    return rig["kube"].with_token(rig["kube"].mint_token("microtrace", sa, DEFAULT_AUDIENCE, 600))


# --- the four actions ---------------------------------------------------------------------
def test_isolate_labels_the_approved_pod(rig, name):
    make_pod(name)
    out = rig["ex"].execute(approve(rig, "isolate_pod", obj("pod", name), {"pod": name}))
    assert out.status == "Submitted", out.reason
    assert out.attempt["ref_audit"]
    assert obj("pod", name)["metadata"]["labels"][ISOLATION_LABEL] == "true"


def test_cordon_marks_the_node_unschedulable(rig):
    try:
        out = rig["ex"].execute(approve(rig, "cordon_node", obj("node", SPARE_NODE, None), {"node": SPARE_NODE}, ns=""))
        assert out.status == "Submitted", out.reason
        assert obj("node", SPARE_NODE, None)["spec"]["unschedulable"] is True
    finally:
        kubectl("uncordon", SPARE_NODE)


def test_scale_to_zero_sets_replicas(rig, name):
    kubectl("-n", "shop", "create", "deployment", name, "--image=registry.k8s.io/pause:3.10", "--replicas=1")
    out = rig["ex"].execute(approve(rig, "scale_to_zero", obj("deployment", name),
                                    {"kind": "Deployment", "name": name}))
    assert out.status == "Submitted", out.reason
    assert obj("deployment", name)["spec"]["replicas"] == 0


def test_revoke_deletes_the_rolebinding(rig, name):
    kubectl("-n", "shop", "create", "rolebinding", name, "--clusterrole=view", "--serviceaccount=shop:default")
    out = rig["ex"].execute(approve(rig, "revoke_rolebinding", obj("rolebinding", name), {"rolebinding": name}))
    assert out.status == "Submitted", out.reason
    assert name not in kubectl("-n", "shop", "get", "rolebindings", "-o", "name")


# --- revalidation against real versions -----------------------------------------------------
def test_an_annotation_after_review_still_executes(rig, name):
    make_pod(name)
    req = approve(rig, "isolate_pod", obj("pod", name), {"pod": name})
    kubectl("-n", "shop", "annotate", "pod", name, "note=reviewed")
    assert rig["ex"].execute(req).status == "Submitted"


def test_a_label_change_after_review_rejects(rig, name):
    make_pod(name)
    req = approve(rig, "isolate_pod", obj("pod", name), {"pod": name})
    kubectl("-n", "shop", "label", "pod", name, "app=other", "--overwrite")
    out = rig["ex"].execute(req)
    assert (out.status, out.reason) == ("Rejected", "fields the action depends on changed since review: labels")
    assert ISOLATION_LABEL not in obj("pod", name)["metadata"]["labels"]


def test_a_recreated_pod_with_the_same_name_rejects(rig, name):
    make_pod(name)
    req = approve(rig, "isolate_pod", obj("pod", name), {"pod": name})
    kubectl("-n", "shop", "delete", "pod", name, "--wait=true")
    make_pod(name)
    assert rig["ex"].execute(req).reason == "target UID differs from the approved one (object recreated)"


def test_a_change_between_revalidation_and_write_fails_with_a_conflict(rig, name, monkeypatch):
    make_pod(name)
    req = approve(rig, "isolate_pod", obj("pod", name), {"pod": name})
    rounds = []

    def meddle(r, live):                           # change the Pod before every write round
        rounds.append(1)
        kubectl("-n", "shop", "annotate", "pod", name, f"late={len(rounds)}", "--overwrite")

    monkeypatch.setattr(rig["ex"], "_before_write", meddle)
    out = rig["ex"].execute(req)
    assert out.status == "Failed" and out.reason.startswith("conflict") and out.attempt["ref_audit"]
    assert len(rounds) == 3
    assert ISOLATION_LABEL not in obj("pod", name)["metadata"]["labels"]


# --- compromised executor: the minted tokens used directly -----------------------------------
def _denied(call, by):
    with pytest.raises(ApiError) as e:
        call()
    if by == "rbac":
        assert e.value.status == 403 and "ValidatingAdmissionPolicy" not in e.value.message, e.value.message
    else:
        assert e.value.status in (403, 422) and "ValidatingAdmissionPolicy" in e.value.message, e.value.message
    return e.value


MERGE = "application/merge-patch+json"


def test_the_isolate_token_can_only_add_the_isolation_label(rig, name):
    make_pod(name)
    t, path = token_for(rig, "gre-isolate"), f"/api/v1/namespaces/shop/pods/{name}"
    _denied(lambda: t.request("PATCH", path, {"metadata": {"labels": {"app": "evil"}}}, None, MERGE), "policy")
    _denied(lambda: t.request("PATCH", path, {"metadata": {"labels": {ISOLATION_LABEL: "true", "x": "1"}}}, None,
                              MERGE), "policy")
    _denied(lambda: t.request("PATCH", path, {"metadata": {"labels": {ISOLATION_LABEL: "true"},
                                                           "annotations": {"x": "1"}}}, None, MERGE), "policy")
    _denied(lambda: t.request("DELETE", path), "rbac")
    _denied(lambda: t.request("PATCH", f"/api/v1/namespaces/default/pods/{name}",
                              {"metadata": {"labels": {ISOLATION_LABEL: "true"}}}, None, MERGE), "rbac")
    t.request("PATCH", path, {"metadata": {"labels": {ISOLATION_LABEL: "true"}}}, None, MERGE)   # its one action


def test_the_scale_token_can_only_scale_to_zero(rig, name):
    kubectl("-n", "shop", "create", "deployment", name, "--image=registry.k8s.io/pause:3.10", "--replicas=1")
    t, path = token_for(rig, "gre-scale"), f"/apis/apps/v1/namespaces/shop/deployments/{name}"
    _denied(lambda: t.request("PATCH", path + "/scale", {"spec": {"replicas": 3}}, None, MERGE), "policy")
    _denied(lambda: t.request("PATCH", path, {"spec": {"replicas": 0}}, None, MERGE), "rbac")


def test_the_cordon_token_cannot_relabel_the_node(rig):
    t = token_for(rig, "gre-cordon")
    _denied(lambda: t.request("PATCH", f"/api/v1/nodes/{SPARE_NODE}", {"metadata": {"labels": {"x": "1"}}}, None,
                              MERGE), "policy")


def test_the_revoke_token_cannot_reach_system_namespaces(rig):
    t = token_for(rig, "gre-revoke")
    _denied(lambda: t.request("DELETE", "/apis/rbac.authorization.k8s.io/v1/namespaces/kube-system/rolebindings/"
                                        "system:controller:bootstrap-signer"), "rbac")


def test_the_executor_can_only_mint_response_tokens(rig):
    k = rig["kube"]
    _denied(lambda: k.mint_token("microtrace", "default", DEFAULT_AUDIENCE, 600), "rbac")
    _denied(lambda: k.mint_token("kube-system", "gre-isolate", DEFAULT_AUDIENCE, 600), "rbac")
    _denied(lambda: k.get("/api/v1/namespaces/shop/pods"), "rbac")                   # no standing read
    _denied(lambda: k.request("DELETE", "/apis/admissionregistration.k8s.io/v1/"
                                        "validatingadmissionpolicybindings/gre-isolate"), "rbac")
    for sa in ("gre-isolate", "gre-scale", "gre-revoke", "gre-cordon"):
        _denied(lambda: token_for(rig, sa).request(
            "DELETE", "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/gre-isolate"), "rbac")
