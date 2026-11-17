"""GRE build step 7.4, without a cluster: the postcondition of each action,
judged from probe Pods, Pod lists and SubjectAccessReviews served by a fake
API server, and verification in the executor and in reconciliation (after a
crash at gre.before_verify). The same checks run on kind in
test_gre_kube_verify.py."""
import copy

import pytest

import test_gre_execute as X
import test_gre_reconcile as RC
from test_tgs_ingest import store  # noqa: F401  (memory and Postgres stores)
from mtcore.gre import verify as V
from mtcore.gre.kube import ApiError
from mtcore.gre.reconcile import Reconciler

PROBES = f"/api/v1/namespaces/{V.PROBE_NS}/pods"
SAR = "/apis/authorization.k8s.io/v1/subjectaccessreviews"
VIEW = "/apis/rbac.authorization.k8s.io/v1/clusterroles/view"


class Clock:
    def __init__(self):
        self.t = 0.0

    def monotonic(self):
        return self.t

    def sleep(self, s):
        self.t += s


class ProbeApi:
    """Serves what the verifier reads and creates. A probe Pod's states on
    successive reads come from `probe(pod)`; Pod lists and access reviews
    from `pods` and `sar`."""

    def __init__(self):
        self.objects = {X.POD: {"metadata": {"name": "checkout-1", "uid": "pod-uid"}, "status": {"podIP": "10.0.0.7"}},
                        VIEW: {"rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get", "list"]}]}}
        self.probe = lambda pod: [{"status": {"phase": "Pending"}}]
        self.pods = [[]]
        self.sar = lambda spec: {"allowed": False}
        self.created, self.deleted, self.minted, self.agents, self.reviews = [], [], [], [], []
        self._states = {}

    def kube(self):
        return Fake(self, "gre-executor", "microtrace-gre")


class Fake:
    def __init__(self, api, who, ua):
        self.api, self.who, self.user_agent = api, who, ua

    def mint_token(self, ns, sa, audience, seconds):
        self.api.minted.append(sa)
        return f"tok-{sa}"

    def with_token(self, token, user_agent=None):
        self.api.agents.append(user_agent)
        return Fake(self.api, token.removeprefix("tok-"), user_agent or self.user_agent)

    def get(self, path, params=None):
        return self.request("GET", path, params=params)[0]

    def request(self, method, path, body=None, params=None, content_type="application/json"):
        api = self.api
        assert self.who == V.VERIFY_SA
        if method == "POST" and path == PROBES:
            api.created.append(copy.deepcopy(body))
            api._states[body["metadata"]["name"]] = list(api.probe(body))
            return dict(body, metadata=dict(body["metadata"], uid="probe-uid")), "a-create"
        if method == "DELETE" and path.startswith(PROBES + "/"):
            api.deleted.append(path.rsplit("/", 1)[1])
            return {}, "a-del"
        if method == "GET" and path.startswith(PROBES + "/"):
            states = api._states[path.rsplit("/", 1)[1]]
            st = states.pop(0) if len(states) > 1 else states[0]
            return dict(copy.deepcopy(st), metadata={"name": path.rsplit("/", 1)[1]}), "a-get"
        if method == "GET" and path == "/api/v1/namespaces/shop/pods":
            api.reviews.append(params)
            items = api.pods.pop(0) if len(api.pods) > 1 else api.pods[0]
            return {"metadata": {"resourceVersion": "77"}, "items": items}, "a-list"
        if method == "POST" and path == SAR:
            api.reviews.append(body["spec"])
            return {"status": api.sar(body["spec"])}, "a-sar"
        if method == "GET" and path in api.objects:
            return copy.deepcopy(api.objects[path]), "a-get"
        raise ApiError(404, "Not Found", {"message": path})


@pytest.fixture
def v():
    api, clock = ProbeApi(), Clock()
    ver = V.Verifier(api.kube(), deadline_s=10, sleep=clock.sleep, monotonic=clock.monotonic)
    return {"api": api, "ver": ver, "clock": clock}


def done(*results):
    msg = "".join(f"{i + 1} {r}\n" for i, r in enumerate(results))
    return lambda pod: [{"status": {"phase": "Pending"}},
                        {"status": {"phase": "Succeeded" if results[-1] == "TIMEOUT" else "Failed",
                                    "containerStatuses": [{"state": {"terminated": {"message": msg}}}]}}]


ISOLATE = {"rid": "rq-1", "gid": "in-1", "act": "isolate_pod", "ns": "shop", "uid": "pod-uid",
           "params": {"pod": "checkout-1"}}


# --- isolate ------------------------------------------------------------------------------
def test_isolation_is_verified_by_timeouts_after_the_policy_lands(v):
    v["api"].probe = done("REFUSED", "TIMEOUT", "TIMEOUT", "TIMEOUT")
    r = v["ver"].verify(ISOLATE, {"port": 8080})
    assert (r.status, r.reason) == ("Verified", "new connections to 10.0.0.7:8080 time out "
                                                "(REFUSED TIMEOUT TIMEOUT TIMEOUT)")
    assert r.ref.startswith(f"pod {V.PROBE_NS}/gre-probe-") and r.ref.endswith("uid=probe-uid")
    [pod] = v["api"].created
    assert v["api"].deleted == [pod["metadata"]["name"]]
    env = {e["name"]: e["value"] for e in pod["spec"]["containers"][0]["env"]}
    assert env["ADDR"] == "10.0.0.7:8080" and env["NEED"] == "3"
    assert v["api"].minted == [V.VERIFY_SA] and v["api"].agents == ["microtrace-gre-verify/rq-1"]


@pytest.mark.parametrize("last", ["CONNECTED", "REFUSED"])
def test_a_reachable_pod_is_failed_never_verified(v, last):
    v["api"].probe = done(*(["TIMEOUT", last] * 5))
    r = v["ver"].verify(ISOLATE, {"port": 8080})
    assert r.status == "Failed" and r.reason.startswith("the Pod is still reachable at 10.0.0.7:8080")


@pytest.mark.parametrize("probe, reason", [
    (lambda pod: [{"status": {"phase": "Pending"}}], "postcondition not checked: the probe Pod did not finish"),
    (done("OTHER", "OTHER"), "no conclusive probe of 10.0.0.7:8080 (OTHER OTHER)"),
])
def test_an_inconclusive_probe_is_unresolved_and_cleaned_up(v, probe, reason):
    v["api"].probe = probe
    r = v["ver"].verify(ISOLATE, {"port": 8080})
    assert (r.status, r.reason) == ("Unresolved", reason)
    assert len(v["api"].deleted) == 1


def test_a_starting_pod_is_probed_once_it_has_an_ip(v, monkeypatch):
    v["api"].objects[X.POD]["status"] = {}
    v["api"].probe = done("TIMEOUT", "TIMEOUT", "TIMEOUT")
    real_sleep = v["ver"].sleep

    def sleep(s):                                                  # the IP arrives after the first wait
        v["api"].objects[X.POD]["status"] = {"podIP": "10.0.0.9"}
        real_sleep(s)

    monkeypatch.setattr(v["ver"], "sleep", sleep)
    r = v["ver"].verify(ISOLATE, {"port": 80})
    assert r.status == "Verified" and "10.0.0.9:80" in r.reason


def test_a_replaced_or_addressless_pod_is_not_probed(v):
    v["api"].objects[X.POD]["status"] = {}
    assert v["ver"].verify(ISOLATE, {"port": 80}).reason == "postcondition not checked: the Pod has no IP"
    assert v["clock"].t >= 10                                      # waited until the deadline
    v["api"].objects[X.POD]["metadata"]["uid"] = "other"
    assert v["ver"].verify(ISOLATE, {"port": 80}).reason == "postcondition not checked: the Pod was replaced"
    assert v["api"].created == []


def test_probe_pods_meet_the_restricted_level_and_use_pinned_images(v):
    v["api"].probe = done("TIMEOUT", "TIMEOUT", "TIMEOUT")
    v["ver"].verify(ISOLATE, {"port": 80})
    v["api"].probe = lambda pod: [{"status": {"conditions": [{"type": "PodScheduled", "status": "False",
                                                              "reason": "Unschedulable", "message": "cordoned"}]}}]
    v["ver"].verify(dict(ISOLATE, act="cordon_node"), {"node": "w2"})
    for pod in v["api"].created:
        s = pod["spec"]
        assert pod["metadata"]["namespace"] == V.PROBE_NS
        assert s["securityContext"]["runAsNonRoot"] and s["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"
        assert s["automountServiceAccountToken"] is False and s["restartPolicy"] == "Never"
        [c] = s["containers"]
        assert c["image"] in (V.PROBE_IMAGE, V.PAUSE_IMAGE)
        assert c["securityContext"] == {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}}


# --- cordon -------------------------------------------------------------------------------
CORDON = dict(ISOLATE, act="cordon_node", ns="", params={"node": "w2"})


def test_cordon_is_verified_when_a_pinned_pod_is_unschedulable(v):
    v["api"].probe = lambda pod: [{"status": {"phase": "Pending"}}, {"status": {"phase": "Pending", "conditions": [
        {"type": "PodScheduled", "status": "False", "reason": "Unschedulable",
         "message": "0/3 nodes are available: 1 node(s) were unschedulable"}]}}]
    r = v["ver"].verify(CORDON, {"node": "w2"})
    assert (r.status, r.reason) == ("Verified", "a Pod pinned to w2 stays Pending: 0/3 nodes are available: "
                                                "1 node(s) were unschedulable")
    [pod] = v["api"].created
    terms = pod["spec"]["affinity"]["nodeAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"]
    assert terms["nodeSelectorTerms"][0]["matchFields"][0]["values"] == ["w2"]
    assert "nodeName" not in pod["spec"]                          # the scheduler must decide
    assert len(v["api"].deleted) == 1


def test_a_pinned_pod_that_schedules_fails_the_cordon(v):
    v["api"].probe = lambda pod: [{"spec": {"nodeName": "w2"}, "status": {"phase": "Pending"}}]
    assert v["ver"].verify(CORDON, {"node": "w2"}).status == "Failed"


# --- scale --------------------------------------------------------------------------------
SCALE = dict(ISOLATE, act="scale_to_zero", params={"kind": "Deployment", "name": "checkout"})
SEL = {"matchLabels": {"app": "checkout"}, "matchExpressions": [{"key": "tier", "operator": "In", "values": ["a", "b"]}]}


def pod(name, terminating=False):
    m = {"name": name}
    if terminating:
        m["deletionTimestamp"] = "2026-10-11T00:00:00Z"
    return {"metadata": m}


def test_scale_is_verified_once_no_pod_matches(v):
    v["api"].pods = [[pod("a"), pod("b")], [pod("a", True)], []]
    r = v["ver"].verify(SCALE, {"selector": SEL})
    assert (r.status, r.reason) == ("Verified", "no Pod matches app=checkout,tier in (a,b)")
    assert r.ref == "pods shop labelSelector=app=checkout,tier in (a,b) at resourceVersion 77"
    assert v["api"].reviews[0] == {"labelSelector": "app=checkout,tier in (a,b)"}


def test_running_pods_fail_and_terminating_ones_are_unresolved(v):
    v["api"].pods = [[pod("a"), pod("b", True)]]
    r = v["ver"].verify(SCALE, {"selector": SEL})
    assert (r.status, r.reason) == ("Failed", "1 Pod(s) matching app=checkout,tier in (a,b) still run: a")
    v["api"].pods = [[pod("b", True)]]
    assert v["ver"].verify(SCALE, {"selector": SEL}).status == "Unresolved"


def test_an_empty_selector_is_never_verified(v):
    r = v["ver"].verify(SCALE, {"selector": {}})
    assert (r.status, r.reason) == ("Unresolved", "postcondition not checked: the workload has an empty selector")
    assert v["api"].reviews == []                                  # it would have listed every Pod


# --- revoke -------------------------------------------------------------------------------
REVOKE = dict(ISOLATE, act="revoke_rolebinding", params={"rolebinding": "reader"})
RB_PLAN = {"subjects": [{"kind": "ServiceAccount", "name": "app", "namespace": "shop"}, {"kind": "User", "name": "eve"}],
           "role_ref": {"kind": "ClusterRole", "name": "view"}}


def test_revocation_is_verified_when_no_subject_can(v):
    r = v["ver"].verify(REVOKE, RB_PLAN)
    assert (r.status, r.reason) == ("Verified", "can-i get core/configmaps in shop: no, for every subject of reader")
    sa, user = v["api"].reviews
    assert sa["user"] == "system:serviceaccount:shop:app" and "system:serviceaccounts:shop" in sa["groups"]
    assert user["user"] == "eve"
    assert sa["resourceAttributes"] == {"namespace": "shop", "verb": "get", "group": "", "resource": "configmaps"}


def test_a_grant_still_cached_for_this_binding_is_failed(v):
    v["api"].sar = lambda spec: {"allowed": True,
                                 "reason": 'RBAC: allowed by RoleBinding "reader/shop" of ClusterRole "view"'}
    r = v["ver"].verify(REVOKE, RB_PLAN)
    assert r.status == "Failed" and r.reason.startswith("reader still grants get core/configmaps in shop")
    assert v["clock"].t >= 10                                      # retried until the deadline


def test_a_grant_from_another_binding_is_unresolved(v):
    v["api"].sar = lambda spec: {"allowed": spec.get("user") == "eve",
                                 "reason": 'RBAC: allowed by ClusterRoleBinding "everyone" of ClusterRole "view"'}
    assert v["ver"].verify(REVOKE, RB_PLAN).status == "Unresolved"


def test_a_role_with_only_wildcards_tests_a_concrete_permission():
    assert V._granted({"rules": [{"nonResourceURLs": ["/x"], "verbs": ["get"]},
                                 {"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]}, "shop") == \
        {"namespace": "shop", "verb": "get", "group": "", "resource": "pods"}


def test_api_errors_and_a_missing_plan_are_unresolved(v):
    assert V.Verifier(v["api"].kube()).verify(ISOLATE, None).status == "Unresolved"
    v["api"].objects.pop(VIEW)
    r = v["ver"].verify(REVOKE, RB_PLAN)
    assert r.status == "Unresolved" and r.reason.startswith("postcondition not checked: 404")


# --- plans --------------------------------------------------------------------------------
def test_the_plan_keeps_what_the_write_may_remove():
    assert V.plan("isolate_pod", {"spec": {"containers": [{"ports": [{"containerPort": 8080}]}]}}) == {"port": 8080}
    assert V.plan("isolate_pod", {"spec": {"containers": [{}]}}) == {"port": V.DEFAULT_PORT}
    assert V.plan("cordon_node", {"metadata": {"name": "w2"}}) == {"node": "w2"}
    assert V.plan("scale_to_zero", {"spec": {"selector": SEL}}) == {"selector": SEL}
    rb = {"roleRef": RB_PLAN["role_ref"], "subjects": RB_PLAN["subjects"]}
    assert V.plan("revoke_rolebinding", rb) == RB_PLAN


# --- in the executor and in reconciliation ------------------------------------------------
class Scripted:
    """A verifier that answers from a list, recording what it was asked."""

    def __init__(self, *results):
        self.results, self.asked = list(results), []

    def verify(self, req, pc):
        self.asked.append((req["rid"], pc))
        return self.results.pop(0) if len(self.results) > 1 else self.results[0]


VERIFIED = V.Result("Verified", "new connections to 10.0.0.7:80 time out", "pod microtrace-probe/p uid=u")
UNSURE = V.Result("Unresolved", "postcondition not checked: the probe Pod did not finish", "pod microtrace-probe/p")


@pytest.fixture
def rig(store, monkeypatch):
    r = RC.make_rig(store, monkeypatch)
    r["ver"] = Scripted(VERIFIED)
    r["ex"].verifier = r["ver"]
    r["rec"].verifier = r["ver"]
    return r


def test_the_executor_verifies_after_the_submitted_row(rig):
    req = rig["req"]()
    out = rig["ex"].execute(req)
    assert (out.status, out.attempt["ref_verify"]) == ("Verified", VERIFIED.ref)
    rows = rig["store"].attempts(rid=req["rid"])
    assert [(a["status"], bool(a["ref_audit"]), a["ref_verify"]) for a in rows] == [
        ("Submitted", True, ""), ("Verified", True, VERIFIED.ref)]
    assert rows[0]["ref_audit"] == rows[1]["ref_audit"]
    assert rig["ver"].asked == [(req["rid"], {"port": V.DEFAULT_PORT})]
    assert "verification" in out.timings_ms
    assert rig["store"].pending_verification() == [] and rig["rec"].run() == []


def test_a_crash_before_verification_is_verified_by_reconciliation(rig):
    req = RC.crash_at(rig, "gre.before_verify")
    assert rig["ver"].asked == []
    [p] = rig["store"].pending_verification()
    assert p["rid"] == req["rid"] and p["ref_audit"]
    [row] = rig["rec"].run()
    assert (row["status"], row["reason"]) == ("Verified", "reconciled: " + VERIFIED.reason)
    assert rig["rec"].run() == []


def test_a_write_reconciled_as_submitted_is_verified_in_the_same_run(rig):
    req = RC.crash_at(rig, "gre.after_submit_before_record")
    assert [r["status"] for r in rig["rec"].run()] == ["Submitted", "Verified"]
    assert [a["status"] for a in rig["store"].attempts(rid=req["rid"])] == ["Submitted", "Verified"]


def test_an_inconclusive_check_is_retried_without_repeating_its_row(rig):
    rig["ver"].results = [UNSURE, UNSURE, VERIFIED]
    req = rig["req"]()
    assert rig["ex"].execute(req).status == "Unresolved"
    assert rig["rec"].run() == []                                   # inconclusive again: no new row
    [row] = rig["rec"].run()
    assert row["status"] == "Verified"
    assert [a["status"] for a in rig["store"].attempts(rid=req["rid"])] == ["Submitted", "Unresolved", "Verified"]
    assert len(rig["ver"].asked) == 3


def test_a_failed_postcondition_is_final(rig):
    rig["ver"].results = [V.Result("Failed", "the Pod is still reachable at 10.0.0.7:80 (REFUSED)", "pod p")]
    req = rig["req"]()
    assert rig["ex"].execute(req).status == "Failed"
    assert rig["rec"].run() == [] and len(rig["ver"].asked) == 1


def test_rejected_and_failed_writes_are_never_verified(rig):
    rig["api"].fail_next = ApiError(403, "Forbidden", {"message": "denied"})
    req = rig["req"]()
    assert rig["ex"].execute(req).status == "Failed"
    assert rig["ex"].execute(req).status == "Rejected"
    assert rig["ver"].asked == [] and rig["store"].pending_verification() == []


def test_without_a_verifier_the_outcome_stays_submitted(rig):
    rig["ex"].verifier = None
    rec = Reconciler(rig["store"], rig["rec"].kube, rig["rec"].audit, clock=rig["clock"])
    assert rig["ex"].execute(rig["req"]()).status == "Submitted"
    assert rec.run() == [] and len(rig["store"].pending_verification()) == 1
