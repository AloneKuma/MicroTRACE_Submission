"""GRE build step 7.5 on the kind cluster: each guard switched off in turn,
with its case run once with the guard and once without. Outcomes are read
from the API server's audit log and the objects themselves, not from the
GRE's A_resp. Each pair is appended to $MT_DEV/gre-kind/ablation-report.jsonl
for Exp. 5 (Table V). Needs the GRE cluster (gre.env)."""
import copy
import dataclasses
import json
import os
import pathlib
import time

import pytest

import test_gre_kube as K
import test_tgs_ingest as T
import test_tgs_snapshot as TS
from test_gre_kube import name  # noqa: F401  (a unique object name, cleaned up after)
from mtcore.gre import verify as V
from mtcore.gre.execute import ISOLATION_LABEL, user_agent
from mtcore.gre.kube import ApiError
from mtcore.gre.reconcile import KindAuditLog
from mtcore.tgs import apply as A

pytestmark = K.pytestmark
BROAD = pathlib.Path(__file__).resolve().parents[2] / "k8s" / "gre" / "ablation-broad.yaml"


def rig(ablate=()):
    r = K.make_rig()
    gre = r["ex"].gre
    gre.config = dataclasses.replace(gre.config, ablate=frozenset(ablate))
    r["ex"].verifier = V.AcceptanceVerifier() if "postcondition" in ablate else V.Verifier(r["kube"], deadline_s=90)
    return r


def accepted_writes(req, settle=20):
    """The request's accepted writes in the audit log, which is written
    asynchronously: read until the count stops changing."""
    ua, seen, last, end = user_agent(req), None, -1, time.time() + settle
    while time.time() < end:
        seen = [e for e in KindAuditLog().events() if e.get("userAgent") == ua and e.get("stage") == "ResponseComplete"
                and e.get("verb") in ("patch", "update", "delete") and 200 <= e["responseStatus"]["code"] < 300]
        if len(seen) == last:
            return seen
        last = len(seen)
        time.sleep(2)
    return seen


def report(guard, case, on, off):
    row = {"time": time.time(), "guard": guard, "case": case, "guard_on": on, "guard_off": off}
    if os.environ.get("MT_DEV"):
        with open(os.path.join(os.environ["MT_DEV"], "gre-kind", "ablation-report.jsonl"), "a",
                  encoding="utf-8") as fh:
            fh.write(json.dumps(row) + "\n")
    print(row)


def issue(r, name):
    return K.approve(r, "isolate_pod", K.obj("pod", name), {"pod": name})


def unlabel(name):
    K.kubectl("-n", "shop", "label", "pod", name, f"{ISOLATION_LABEL}-")


# --- nonce: Repeated nonce -> at most one execution ---------------------------------------
@pytest.mark.parametrize("ablate", [(), ("nonce",)])
def test_a_replay_after_the_effect_is_undone(name, ablate):
    K.make_pod(name)
    r = rig(ablate)
    req = issue(r, name)
    first = r["ex"].execute(req)
    unlabel(name)                                                   # an operator lifts the isolation
    second = r["ex"].execute(copy.deepcopy(req))
    n = len(accepted_writes(req))
    if ablate:
        assert n == 2 and second.status in ("Verified", "Submitted"), second.reason
        report("nonce", "Repeated nonce: at most one execution", None, {"executions": n})
    else:
        assert n == 1 and (first.status, second.reason) == ("Verified", "nonce already used")
        report("nonce", "Repeated nonce: at most one execution", {"executions": n}, None)


# --- snapshot: Stale graph snapshot -> reject ---------------------------------------------
@pytest.mark.parametrize("ablate", [(), ("snapshot",)])
def test_an_approval_whose_snapshot_went_stale(name, ablate):
    K.make_pod(name)
    r = rig(ablate)
    req = issue(r, name)
    A.apply_batch(r["tgs"], T.batch(TS.inc("in-1", members=("f1", "f2"), witnesses=("w12",), version=2),
                                    topic=T.INC, start=1))          # the incident moved on after approval
    out = r["ex"].execute(req)
    n = len(accepted_writes(req))
    if ablate:
        assert n == 1, out.reason
    else:
        assert n == 0 and out.status == "Rejected" and out.reason.startswith("graph check failed")
    report("snapshot", "Stale graph snapshot: reject", None if ablate else {"executions": n, "reason": out.reason},
           {"executions": n} if ablate else None)


# --- revalidation: Target UID/version conflict -> reject or revalidate ----------------------
@pytest.mark.parametrize("ablate", [(), ("revalidation",)])
def test_a_target_recreated_after_review(name, ablate):
    K.make_pod(name)
    r = rig(ablate)
    req = issue(r, name)
    K.kubectl("-n", "shop", "delete", "pod", name, "--wait=true")
    K.make_pod(name)                                                # same name, another object
    out = r["ex"].execute(req)
    new = K.obj("pod", name)
    hit = new["metadata"].get("labels", {}).get(ISOLATION_LABEL) == "true"
    assert new["metadata"]["uid"] != req["uid"]
    if ablate:
        assert hit, out.reason                                      # the wrong Pod was isolated
    else:
        assert not hit and out.reason == "target UID differs from the approved one (object recreated)"
    report("revalidation", "Target UID/version conflict: reject or revalidate",
           None if ablate else {"wrong_object_written": hit}, {"wrong_object_written": hit} if ablate else None)


@pytest.mark.parametrize("ablate", [(), ("revalidation",)])
def test_a_change_between_check_and_write(name, ablate, monkeypatch):
    K.make_pod(name)
    r = rig(ablate)
    req = issue(r, name)
    monkeypatch.setattr(r["ex"], "_before_write",
                        lambda q, live: K.kubectl("-n", "shop", "label", "pod", name, "app=other", "--overwrite"))
    out = r["ex"].execute(req)
    hit = K.obj("pod", name)["metadata"]["labels"].get(ISOLATION_LABEL) == "true"
    assert hit is bool(ablate), out.reason
    report("revalidation", "Target changed between check and write", None if ablate else {"written": hit},
           {"written": hit} if ablate else None)


# --- postcondition: Accepted but ineffective action -> not verified ------------------------
@pytest.mark.parametrize("ablate", [(), ("postcondition",)])
def test_an_ineffective_isolation(name, ablate):
    K.make_pod(name)
    r = rig(ablate)
    K.kubectl("-n", "shop", "delete", "networkpolicy", "microtrace-isolate")
    try:
        out = r["ex"].execute(issue(r, name))
    finally:
        K.apply({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                 "metadata": {"name": "microtrace-isolate", "namespace": "shop"},
                 "spec": {"podSelector": {"matchLabels": {ISOLATION_LABEL: "true"}},
                          "policyTypes": ["Ingress", "Egress"]}})
    assert out.status == ("Verified" if ablate else "Failed"), out.reason
    report("postcondition", "Accepted but ineffective action: not verified",
           None if ablate else {"status": out.status}, {"status": out.status} if ablate else None)


# --- permissions: Compromised executor -> bounded by RBAC and admission ---------------------
@pytest.fixture
def broad():
    K.kubectl("apply", "-f", str(BROAD))
    try:
        yield
    finally:
        K.kubectl("delete", "-f", str(BROAD), "--ignore-not-found")


def misuse(r, sa, name):
    """What a compromised executor tries with the token it can mint: a label
    outside the action's class, and deleting the Pod. Returns the attempts
    the API server allowed."""
    t = K.token_for(r, sa)
    path = f"/api/v1/namespaces/shop/pods/{name}"
    allowed = []
    for what, call in (("relabel", lambda: t.request("PATCH", path, {"metadata": {"labels": {"app": "evil"}}}, None,
                                                     K.MERGE)),
                       ("delete", lambda: t.request("DELETE", path))):
        try:
            call()
            allowed.append(what)
        except ApiError as e:
            assert e.status in (403, 422), e.message
    return allowed


def test_with_narrow_identities_a_compromised_executor_is_bounded(name):
    K.make_pod(name)
    r = rig()
    assert r["ex"].execute(issue(r, name)).status == "Verified"
    allowed = misuse(r, "gre-isolate", name)
    assert allowed == []
    with pytest.raises(ApiError):
        K.token_for(r, "gre-broad")                                 # not installed outside ablation runs
    report("permissions", "Compromised executor: bounded by RBAC and admission", {"allowed": allowed}, None)


def test_with_broad_permissions_a_compromised_executor_is_not(name, broad):
    K.make_pod(name)
    r = rig(("permissions",))
    out = r["ex"].execute(issue(r, name))
    assert out.status == "Verified", out.reason                     # the action itself still works
    events = accepted_writes(out.attempt["request"])
    assert [e["user"]["username"] for e in events] == ["system:serviceaccount:microtrace:gre-broad"]
    allowed = misuse(r, "gre-broad", name)
    assert allowed == ["relabel", "delete"]
    report("permissions", "Compromised executor: bounded by RBAC and admission", None, {"allowed": allowed})
