"""GRE build step 7.4 on the kind cluster: each action's postcondition is
observed by behaviour (probe Pods, the scheduler, Pod lists,
SubjectAccessReviews), the accepted-but-ineffective case (the isolation
NetworkPolicy removed, as with a plugin that does not enforce it) is never
Verified, a connection opened before isolation is probed and reported, and
the gre-verify token is bounded by RBAC, its admission policy and the
restricted Pod Security level. Needs the GRE cluster (gre.env)."""
import json
import os
import time

import pytest

import test_gre_kube as K
from test_gre_kube import name  # noqa: F401  (a unique object name, cleaned up after)
from mtcore.gre import verify as V
from mtcore.gre.execute import Executor
from mtcore.gre.kube import ApiError

pytestmark = K.pytestmark
PORT = 8080
ISOLATE_POLICY = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                  "metadata": {"name": "microtrace-isolate", "namespace": "shop"},
                  "spec": {"podSelector": {"matchLabels": {"microtrace.io/isolated": "true"}},
                           "policyTypes": ["Ingress", "Egress"]}}


@pytest.fixture
def rig():
    r = K.make_rig()
    ver = V.Verifier(r["kube"], deadline_s=90)
    return dict(r, ver=ver, ex=Executor(r["ex"].gre, r["kube"], verifier=ver))


def make_server(name):
    """A target Pod that accepts connections (agnhost netexec on PORT)."""
    m = K.pod_manifest(name)
    m["spec"]["containers"][0].update(image=V.PROBE_IMAGE, args=["netexec", f"--http-port={PORT}"],
                                      ports=[{"containerPort": PORT}])
    K.apply(m)
    K.kubectl("-n", "shop", "wait", "--for=condition=Ready", f"pod/{name}", "--timeout=120s")


def probe_pods():
    return json.loads(K.kubectl("-n", V.PROBE_NS, "get", "pods", "-l", V.PROBE_LABEL, "-o", "json"))["items"]


def addr(name):
    return f"{K.obj('pod', name)['status']['podIP']}:{PORT}"


def report(key, value):
    """Exp. 5 observations that are reported, not asserted."""
    if os.environ.get("MT_DEV"):
        path = os.path.join(os.environ["MT_DEV"], "gre-kind", "verify-report.jsonl")
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"time": time.time(), key: value}) + "\n")
    print(key, value)


# --- isolate ------------------------------------------------------------------------------
def test_isolation_is_verified_by_probe_connections(rig, name):
    make_server(name)
    _ref, before = rig["ver"].connect(rig["ver"].actor("pre-" + name), "pre-" + name, addr(name))
    assert before and before[-1] == "CONNECTED", before          # reachable before the action
    out = rig["ex"].execute(K.approve(rig, "isolate_pod", K.obj("pod", name), {"pod": name}))
    assert out.status == "Verified", out.reason
    assert out.attempt["ref_verify"].startswith(f"pod {V.PROBE_NS}/gre-probe-")
    assert out.timings_ms["verification"] > 0
    assert probe_pods() == []


def test_a_connection_opened_before_isolation_is_probed_and_reported(rig, name):
    """Kubernetes NetworkPolicy governs new connections; whether Calico also
    cuts an established one is observed here and reported for Exp. 5."""
    make_server(name)
    client = f"{name}-ll"
    ip = addr(name).split(":")[0]
    # The echoed body has no newline, so a status line follows it on the same
    # line: match it anywhere in the line.
    script = (f"(while true; do printf 'GET /echo?msg=x HTTP/1.1\\r\\nHost: t\\r\\n\\r\\n'; sleep 1; done) "
              f"| nc {ip} {PORT} | while IFS= read -r l; do case \"$l\" in *HTTP/1.1\\ 200*) "
              f"echo \"$(date +%s) $l\";; esac; done")
    spec = {"containers": [V._container(V.PROBE_IMAGE, ["/bin/sh", "-c", script])], "restartPolicy": "Never",
            "automountServiceAccountToken": False, "terminationGracePeriodSeconds": 0,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "runAsGroup": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}}}
    K.apply({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": client, "namespace": V.PROBE_NS}, "spec": spec})
    try:
        K.kubectl("-n", V.PROBE_NS, "wait", "--for=condition=Ready", f"pod/{client}", "--timeout=120s")
        time.sleep(4)
        out = rig["ex"].execute(K.approve(rig, "isolate_pod", K.obj("pod", name), {"pod": name}))
        assert out.status == "Verified", out.reason
        t_iso = time.time()
        time.sleep(10)
        stamps = [int(ln.split()[0]) for ln in K.kubectl("-n", V.PROBE_NS, "logs", client).splitlines()
                  if ln.split() and ln.split()[0].isdigit()]
        assert sum(t < t_iso for t in stamps) >= 3, f"the connection did not stay open before isolation: {stamps}"
        after = [t for t in stamps if t > t_iso + 2]
        report("long_lived_connection_after_isolation",
               {"responses_before": len(stamps) - len(after), "responses_after": len(after),
                "survives": bool(after)})
    finally:
        K.kubectl("-n", V.PROBE_NS, "delete", "pod", client, "--ignore-not-found", "--wait=false")


def test_an_accepted_but_ineffective_isolation_is_never_verified(rig, name):
    make_server(name)
    K.kubectl("-n", "shop", "delete", "networkpolicy", "microtrace-isolate")
    try:
        out = rig["ex"].execute(K.approve(rig, "isolate_pod", K.obj("pod", name), {"pod": name}))
        assert K.obj("pod", name)["metadata"]["labels"][K.ISOLATION_LABEL] == "true"     # the write was accepted
        assert out.status == "Failed", out.reason
        assert out.reason.startswith(f"the Pod is still reachable at {addr(name)}")
        statuses = [a["status"] for a in rig["ex"].gre.store.attempts(rid=out.attempt["rid"])]
        assert statuses == ["Submitted", "Failed"]
    finally:
        K.apply(ISOLATE_POLICY)
    assert probe_pods() == []


# --- cordon, scale, revoke ----------------------------------------------------------------
def test_cordon_is_verified_by_an_unschedulable_pinned_pod(rig):
    try:
        out = rig["ex"].execute(K.approve(rig, "cordon_node", K.obj("node", K.SPARE_NODE, None),
                                          {"node": K.SPARE_NODE}, ns=""))
        assert out.status == "Verified", out.reason
        assert out.reason.startswith(f"a Pod pinned to {K.SPARE_NODE} stays Pending")
    finally:
        K.kubectl("uncordon", K.SPARE_NODE)
    assert probe_pods() == []


def test_scale_to_zero_is_verified_when_the_pods_are_gone(rig, name):
    K.kubectl("-n", "shop", "create", "deployment", name, "--image=registry.k8s.io/pause:3.10", "--replicas=2")
    K.kubectl("-n", "shop", "rollout", "status", f"deployment/{name}", "--timeout=120s")
    out = rig["ex"].execute(K.approve(rig, "scale_to_zero", K.obj("deployment", name),
                                      {"kind": "Deployment", "name": name}))
    assert out.status == "Verified", out.reason
    assert K.kubectl("-n", "shop", "get", "pods", "-l", f"app={name}", "-o", "name").strip() == ""


def test_revocation_is_verified_by_an_access_review(rig, name):
    # A subject nothing else grants to, so the review isolates this binding.
    K.kubectl("-n", "shop", "create", "rolebinding", name, "--clusterrole=view", f"--serviceaccount=shop:{name}")
    ok = rig["ver"].actor("pre").request("POST", "/apis/authorization.k8s.io/v1/subjectaccessreviews", {
        "apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview",
        "spec": {"user": f"system:serviceaccount:shop:{name}",
                 "resourceAttributes": {"namespace": "shop", "verb": "get", "resource": "configmaps"}}})[0]
    assert ok["status"]["allowed"]                                   # granted before the action
    out = rig["ex"].execute(K.approve(rig, "revoke_rolebinding", K.obj("rolebinding", name), {"rolebinding": name}))
    assert out.status == "Verified", out.reason


# --- the verifier's own token, used directly ---------------------------------------------
def probe_pod(image=V.PROBE_IMAGE, ns=V.PROBE_NS, **spec):
    base = {"containers": [V._container(image, ["/bin/sh", "-c", "true"])], "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "runAsGroup": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}}}
    base.update(spec)
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"generateName": "evil-", "namespace": ns}, "spec": base}


def test_the_verify_token_can_only_run_pinned_restricted_probes(rig, name):
    K.make_pod(name)
    t = rig["ver"].actor("evil")
    pods = f"/api/v1/namespaces/{V.PROBE_NS}/pods"
    K._denied(lambda: t.request("POST", pods, probe_pod(image="busybox:1.36")), "policy")
    K._denied(lambda: t.request("POST", pods, probe_pod(automountServiceAccountToken=True)), "policy")
    priv = probe_pod()
    priv["spec"]["containers"][0]["securityContext"] = {"privileged": True}
    with pytest.raises(ApiError) as e:
        t.request("POST", pods, priv)
    assert e.value.status == 403 and "PodSecurity" in e.value.message, e.value.message
    K._denied(lambda: t.request("POST", "/api/v1/namespaces/shop/pods", probe_pod(ns="shop")), "rbac")
    K._denied(lambda: t.request("DELETE", f"/api/v1/namespaces/shop/pods/{name}"), "rbac")
    K._denied(lambda: t.request("PATCH", f"/api/v1/namespaces/shop/pods/{name}",
                                {"metadata": {"labels": {K.ISOLATION_LABEL: "true"}}}, None, K.MERGE), "rbac")
    K._denied(lambda: t.request("DELETE", "/apis/rbac.authorization.k8s.io/v1/namespaces/shop/rolebindings/"
                                          "checkout-reader"), "rbac")
    created, _ = t.request("POST", pods, probe_pod())               # its one kind of write
    t.request("DELETE", f"{pods}/{created['metadata']['name']}")
