"""Privilege-bounded execution of an accepted request (build step 7.2;
evaluation-plan.md section 5, step 7; paper Phase 4, Step 4).

For a request that validate.Gre accepted:
1. mint a TokenRequest token for the action's own ServiceAccount (audience
   bound, at least 600 s, the Kubernetes minimum), used for this attempt
   only;
2. revalidate the target with that token: it exists, its UID is the
   approved one, and if its resourceVersion moved since review, the fields
   the action depends on are unchanged between the reviewed version (an
   exact-version read) and now. A reviewed version the API server no longer
   holds cannot be compared, so it rejects;
3. write with the *current* resourceVersion as the precondition, so an
   unrelated change (a Pod status update) does not reject, but any change
   between revalidation and write does (409). A 409 is a certain
   non-execution, so steps 2 and 3 are repeated, at most WRITE_ROUNDS
   times; a controller updating status between read and write would
   otherwise fail most actions on busy objects.

Before the write, any failure rejects and nothing is written. After it:
Submitted (the API accepted), Failed (the API refused), or Unresolved (no
answer, or a server error: the write may have happened). Each outcome is
one A_resp row with the write's Audit-Id as ref_audit.

7.3, interrupted submissions. Before the first write an intent is stored
durably; every write carries the User-Agent microtrace-gre/<rid>/<nonce>,
which the API server's audit log records. The outcome row closes the
intent and the nonce in one transaction. A GRE that dies anywhere leaves
an open intent or an unclosed nonce, which reconcile.py resolves from the
audit log and the resource state, never by writing again. Failpoints
(mtcore.failpoint) mark the four interruption points:
  gre.before_intent                before the durable intent
  gre.after_intent_before_submit   after it, before a write is sent
  gre.after_submit_before_record   after the API answered, before the outcome row
  gre.before_verify                after the outcome row, before verification (7.4)

7.5, guard ablation (GreConfig.ablate). "revalidation": the target is read
but not compared with the reviewed object, and the write carries no
resourceVersion or uid precondition, so a recreated or changed target is
written. "permissions": every action uses the one broad ServiceAccount
gre-broad (src/k8s/gre/ablation-broad.yaml: wide RBAC, no admission
policy), installed only for ablation runs.

7.4, verification. With a verifier, a Submitted write is followed by the
action's postcondition check (verify.py), planned with the intent before
the write; its result is a second A_resp row, Verified, Failed or
Unresolved, with ref_verify. Without one (the 7.2 tests, and the
no-postcondition ablation) the outcome stays Submitted.
"""
import time
from dataclasses import dataclass, field

from mtcore import failpoint
from mtcore.gre import verify as V
from mtcore.gre.kube import ApiError

ISOLATION_LABEL = "microtrace.io/isolated"
SERVICE_ACCOUNTS = {"isolate_pod": "gre-isolate", "cordon_node": "gre-cordon", "scale_to_zero": "gre-scale",
                    "revoke_rolebinding": "gre-revoke"}
BROAD_SA = "gre-broad"               # the "permissions" ablation only
DEFAULT_AUDIENCE = "https://kubernetes.default.svc.cluster.local"
TOKEN_SECONDS = 600
WRITE_ROUNDS = 3
MERGE = "application/merge-patch+json"


@dataclass
class Target:
    path: str            # the object
    list_path: str       # its collection, for the exact-version read
    name: str


@dataclass
class Outcome:
    status: str          # Rejected, Submitted, Failed, Unresolved
    reason: str
    attempt: dict = None
    timings_ms: dict = field(default_factory=dict)


def target(req):
    ns, p, act = req["ns"], req["params"], req["act"]
    if act == "isolate_pod":
        return Target(f"/api/v1/namespaces/{ns}/pods/{p['pod']}", f"/api/v1/namespaces/{ns}/pods", p["pod"])
    if act == "cordon_node":
        return Target(f"/api/v1/nodes/{p['node']}", "/api/v1/nodes", p["node"])
    if act == "scale_to_zero":
        plural = {"Deployment": "deployments", "StatefulSet": "statefulsets"}[p["kind"]]
        base = f"/apis/apps/v1/namespaces/{ns}/{plural}"
        return Target(f"{base}/{p['name']}", base, p["name"])
    if act == "revoke_rolebinding":
        base = f"/apis/rbac.authorization.k8s.io/v1/namespaces/{ns}/rolebindings"
        return Target(f"{base}/{p['rolebinding']}", base, p["rolebinding"])
    raise ValueError(act)


def relevant(act, obj):
    """The fields an action depends on (evaluation-plan.md step 7): a change
    to any of them since review means the analyst approved something else."""
    m, s = obj.get("metadata", {}), obj.get("spec", {})
    if act == "isolate_pod":
        return {"labels": m.get("labels", {}), "owners": m.get("ownerReferences", []),
                "node": s.get("nodeName"), "service_account": s.get("serviceAccountName")}
    if act == "cordon_node":
        return {"labels": m.get("labels", {}), "spec": s}
    if act == "scale_to_zero":
        return {"replicas": s.get("replicas"), "selector": s.get("selector"), "template": s.get("template")}
    if act == "revoke_rolebinding":
        return {"role_ref": obj.get("roleRef"), "subjects": obj.get("subjects", []), "labels": m.get("labels", {})}
    raise ValueError(act)


class Executor:
    def __init__(self, gre, kube, sa_namespace="microtrace", audience=DEFAULT_AUDIENCE, clock=time.time_ns,
                 verifier=None):
        self.gre, self.kube, self.sa_namespace, self.audience, self.clock = gre, kube, sa_namespace, audience, clock
        self.verifier = verifier

    def execute(self, req):
        t0 = time.perf_counter()
        d = self.gre.validate(req)
        timings = {"validation": _ms(t0)}
        if not d.accepted:
            return Outcome("Rejected", d.reason, d.attempt, timings)
        t1 = time.perf_counter()
        ablate = self.gre.config.ablate
        sa = BROAD_SA if "permissions" in ablate else SERVICE_ACCOUNTS[req["act"]]
        try:
            token = self.kube.mint_token(self.sa_namespace, sa, self.audience, TOKEN_SECONDS)
        except ApiError as e:
            return self._done(req, "Rejected", f"token request failed: {e.status} {e.message}", timings)
        actor, tgt, intent = self.kube.with_token(token), target(req), None
        for rnd in range(1, WRITE_ROUNDS + 1):
            why, live = self._revalidate(actor, req, tgt)
            timings["revalidation"] = _ms(t1)
            if why:
                return self._done(req, "Rejected", why, timings, intent=intent)
            if intent is None:
                failpoint.hit("gre.before_intent", state={"rid": req["rid"]})
                intent = self._plan(req, sa, tgt, live)
                actor = self.kube.with_token(token, user_agent=intent["user_agent"])
            self._before_write(req, live)
            failpoint.hit("gre.after_intent_before_submit", state={"rid": req["rid"], "round": rnd})
            t2 = time.perf_counter()
            try:
                _obj, audit_id = self._write(actor, req, tgt, live, precondition="revalidation" not in ablate)
            except ApiError as e:
                timings["submission"] = _ms(t2)
                if e.status == 409 and rnd < WRITE_ROUNDS:
                    t1 = time.perf_counter()
                    continue                     # refused, so not executed: revalidate and write again
                failpoint.hit("gre.after_submit_before_record", state={"rid": req["rid"], "status": e.status})
                if e.status == 0 or e.status >= 500:
                    return self._done(req, "Unresolved", f"outcome unknown: {e.status} {e.message}", timings,
                                      e.audit_id, intent)
                if e.status == 409:
                    return self._done(req, "Failed", f"conflict: the target changed before the write in each of "
                                      f"{WRITE_ROUNDS} rounds ({e.message})", timings, e.audit_id, intent)
                return self._done(req, "Failed", f"API refused the write: {e.status} {e.message}", timings,
                                  e.audit_id, intent)
            timings["submission"] = _ms(t2)
            timings["rounds"] = rnd
            failpoint.hit("gre.after_submit_before_record", state={"rid": req["rid"], "status": 200})
            out = self._done(req, "Submitted", "API accepted the write", timings, audit_id, intent)
            failpoint.hit("gre.before_verify", state={"rid": req["rid"]})
            if self.verifier is None or out.attempt is None:
                return out                       # an unrecorded outcome is verified by reconciliation
            t3 = time.perf_counter()
            res = self.verifier.verify(req, intent["postcondition"])
            timings["verification"] = _ms(t3)
            try:
                row = self.gre.store.finish_verification(V.row(req, res, audit_id, self.clock()),
                                                         intent["intent_id"])
            except Exception:
                row = None                       # still pending; reconciliation verifies again
            return Outcome(res.status, res.reason, row, timings)

    def _plan(self, req, sa, tgt, live):
        """Store the intent durably, with what verification will need, and
        return it with the User-Agent that tags its writes in the audit log."""
        return self.gre.store.record_intent({
            "rid": req["rid"], "nonce": req["nonce"], "act": req["act"], "service_account": sa, "path": tgt.path,
            "user_agent": user_agent(req), "planned_at": self.clock(), "request": req,
            "postcondition": V.plan(req["act"], live)})

    def _revalidate(self, actor, req, tgt):
        """(reason, None) to reject, or (None, live object)."""
        try:
            live = actor.get(tgt.path)
        except ApiError as e:
            if e.status == 404:
                return "target no longer exists", None
            return f"cannot read the target: {e.status} {e.message}", None
        if "revalidation" in self.gre.config.ablate:
            return None, live
        uid, rv = live["metadata"]["uid"], live["metadata"]["resourceVersion"]
        if uid != req["uid"]:
            return "target UID differs from the approved one (object recreated)", None
        if rv == req["rv"]:
            return None, live
        try:
            items = actor.get(tgt.list_path, {"fieldSelector": f"metadata.name={tgt.name}",
                                              "resourceVersion": req["rv"],
                                              "resourceVersionMatch": "Exact"})["items"]
        except ApiError as e:
            if e.status == 410:
                return f"reviewed version {req['rv']} is no longer available to compare", None
            return f"cannot read the reviewed version: {e.status} {e.message}", None
        reviewed = next((i for i in items if i["metadata"]["uid"] == req["uid"]), None)
        if reviewed is None:
            return f"the approved object did not exist at version {req['rv']}", None
        before, now = relevant(req["act"], reviewed), relevant(req["act"], live)
        changed = sorted(k for k in before if before[k] != now[k])
        if changed:
            return f"fields the action depends on changed since review: {', '.join(changed)}", None
        return None, live

    def _before_write(self, req, live):
        """Between revalidation and write; tests and failpoints hook here."""

    def _write(self, actor, req, tgt, live, precondition=True):
        act = req["act"]
        if not precondition:
            return self._write_unconditional(actor, act, tgt)
        rv = live["metadata"]["resourceVersion"]
        if act == "isolate_pod":
            return actor.request("PATCH", tgt.path, {"metadata": {"resourceVersion": rv,
                                                                  "labels": {ISOLATION_LABEL: "true"}}}, None, MERGE)
        if act == "cordon_node":
            return actor.request("PATCH", tgt.path, {"metadata": {"resourceVersion": rv},
                                                     "spec": {"unschedulable": True}}, None, MERGE)
        if act == "scale_to_zero":
            return actor.request("PATCH", tgt.path + "/scale", {"metadata": {"resourceVersion": rv},
                                                                "spec": {"replicas": 0}}, None, MERGE)
        if act == "revoke_rolebinding":
            return actor.request("DELETE", tgt.path, {"apiVersion": "v1", "kind": "DeleteOptions",
                                                      "preconditions": {"uid": req["uid"], "resourceVersion": rv}})
        raise ValueError(act)

    def _write_unconditional(self, actor, act, tgt):
        """The "revalidation" ablation: the same writes with no precondition."""
        if act == "isolate_pod":
            return actor.request("PATCH", tgt.path, {"metadata": {"labels": {ISOLATION_LABEL: "true"}}}, None, MERGE)
        if act == "cordon_node":
            return actor.request("PATCH", tgt.path, {"spec": {"unschedulable": True}}, None, MERGE)
        if act == "scale_to_zero":
            return actor.request("PATCH", tgt.path + "/scale", {"spec": {"replicas": 0}}, None, MERGE)
        if act == "revoke_rolebinding":
            return actor.request("DELETE", tgt.path)
        raise ValueError(act)

    def _done(self, req, status, reason, timings, audit_id="", intent=None):
        row = {"rid": req["rid"], "gid": req["gid"], "act": req["act"], "uid": req["uid"], "ts": self.clock(),
               "status": status, "reason": reason, "ref_audit": audit_id, "ref_verify": "", "request": req}
        try:
            attempt = self.gre.store.finish_attempt(row, intent["intent_id"] if intent else None, req["nonce"])
        except Exception:
            attempt = None                       # the open intent or nonce is left for reconciliation
        return Outcome(status, reason, attempt, timings)


def user_agent(req):
    """The tag of a request's writes in the audit log (the nonce is unique)."""
    return f"microtrace-gre/{req['rid']}/{req['nonce']}"


def _ms(t0):
    return round((time.perf_counter() - t0) * 1000, 3)
