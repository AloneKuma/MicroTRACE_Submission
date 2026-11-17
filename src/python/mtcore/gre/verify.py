"""Postcondition verification (build step 7.4; evaluation-plan.md section 5,
step 7; paper Phase 4, Step 4: "API acceptance establishes submission;
verification requires an observed action-specific postcondition").

After a Submitted write the GRE mints a token for gre-verify, a fifth
ServiceAccount that can only run probes, and observes the action's effect
by behaviour, not by reading back the field it wrote:

  isolate_pod         a probe Pod's new TCP connections to the target time
                      out (CONNECTED or REFUSED means the Pod is reachable)
  cordon_node         a probe Pod pinned to the node (node affinity on
                      metadata.name, so the scheduler decides) is reported
                      Unschedulable
  scale_to_zero       no Pod matches the workload's selector
  revoke_rolebinding  a SubjectAccessReview for each subject of the deleted
                      binding, on a permission its role grants, says no

Each check ends Verified (observed), Failed (the opposite observed: the
target is reachable, the probe Pod was scheduled, Pods still run, the
binding still grants), or Unresolved (nothing conclusive before the
deadline). Unresolved is never promoted by guessing; reconciliation runs
it again later.

What a check needs that may be gone after the write (the binding's
subjects, the workload's selector) is planned from the revalidated object
and stored with the intent before the write (`plan`). Probe Pods run in
the namespace microtrace-probe under the restricted Pod Security level,
from the pinned images only (the gre-verify admission policy), and are
deleted after each check. The verifier's requests carry the User-Agent
microtrace-gre-verify/<rid>, so reconciliation never mistakes them for
the action's write.
"""
import time
import uuid
from dataclasses import dataclass

from mtcore.gre.kube import ApiError

VERIFY_SA = "gre-verify"
PROBE_NS = "microtrace-probe"
PROBE_IMAGE = ("registry.k8s.io/e2e-test-images/agnhost:2.53"
               "@sha256:99c6b4bb4a1e1df3f0b3752168c89358794d02258ebebc26bf21c29399011a85")
PAUSE_IMAGE = "registry.k8s.io/pause:3.10"
PROBE_LABEL = "microtrace.io/probe"
DEFAULT_PORT = 80                # any port tells reachable (CONNECTED or REFUSED) from dropped (TIMEOUT)
REACHABLE = ("CONNECTED", "REFUSED")

# One probe Pod tries up to TRIES connections and stops after NEED
# consecutive timeouts; NetworkPolicy takes a moment to reach the node, so
# earlier answers do not count against it. One line per try, "<i> <result>".
CONNECT_SCRIPT = r"""
n=0; i=0
while [ "$i" -lt "$TRIES" ]; do
  i=$((i+1))
  r=$(/agnhost connect --timeout="${TIMEOUT}s" "$ADDR" 2>&1) && r=CONNECTED
  r=$(echo "$r" | head -n 1 | cut -d: -f1 | cut -d' ' -f1)
  echo "$i ${r:-NONE}" | tee -a /dev/termination-log
  if [ "$r" = TIMEOUT ]; then n=$((n+1)); [ "$n" -ge "$NEED" ] && exit 0; else n=0; sleep 1; fi
done
exit 1
"""


@dataclass
class Result:
    status: str          # Verified, Failed, Unresolved
    reason: str
    ref: str             # ref_verify: the probe's identity and observation


def plan(act, live):
    """What verifying `act` on the revalidated object `live` needs later;
    stored with the intent, before the write."""
    if act == "isolate_pod":
        ports = [p["containerPort"] for c in live.get("spec", {}).get("containers", [])
                 for p in c.get("ports", []) if p.get("protocol", "TCP") == "TCP"]
        return {"port": ports[0] if ports else DEFAULT_PORT}
    if act == "cordon_node":
        return {"node": live["metadata"]["name"]}
    if act == "scale_to_zero":
        return {"selector": live.get("spec", {}).get("selector", {})}
    if act == "revoke_rolebinding":
        return {"subjects": live.get("subjects", []), "role_ref": live.get("roleRef", {})}
    raise ValueError(act)


def selector_string(sel):
    """A LabelSelector as the labelSelector query parameter."""
    parts = [f"{k}={v}" for k, v in sorted(sel.get("matchLabels", {}).items())]
    for e in sel.get("matchExpressions", []):
        k, op, vals = e["key"], e["operator"], ",".join(e.get("values", []))
        parts.append({"In": f"{k} in ({vals})", "NotIn": f"{k} notin ({vals})", "Exists": k,
                      "DoesNotExist": f"!{k}"}[op])
    if not parts:
        raise ValueError("empty selector: it would match every Pod")
    return ",".join(parts)


def row(req, result, ref_audit, ts):
    """The A_resp row of a verification."""
    return {"rid": req["rid"], "gid": req["gid"], "act": req["act"], "uid": req["uid"], "ts": ts,
            "status": result.status, "reason": result.reason, "ref_audit": ref_audit, "ref_verify": result.ref,
            "request": req}


class AcceptanceVerifier:
    """The "postcondition" ablation (7.5): API acceptance is taken as
    containment, as a GRE without postcondition checks would report it."""

    def verify(self, req, postcondition):
        return Result("Verified", "postcondition check ablated: API acceptance taken as containment",
                      "ablated: no check")


class Verifier:
    def __init__(self, kube, sa_namespace="microtrace", audience=None, deadline_s=60.0, poll_s=1.0, tries=10,
                 need=3, connect_timeout_s=2, sleep=time.sleep, monotonic=time.monotonic):
        from mtcore.gre.execute import DEFAULT_AUDIENCE
        self.kube, self.sa_namespace, self.audience = kube, sa_namespace, audience or DEFAULT_AUDIENCE
        self.deadline_s, self.poll_s, self.tries, self.need = deadline_s, poll_s, tries, need
        self.connect_timeout_s, self.sleep, self.monotonic = connect_timeout_s, sleep, monotonic

    def actor(self, rid):
        from mtcore.gre.execute import TOKEN_SECONDS
        token = self.kube.mint_token(self.sa_namespace, VERIFY_SA, self.audience, TOKEN_SECONDS)
        return self.kube.with_token(token, user_agent=f"microtrace-gre-verify/{rid}")

    def verify(self, req, postcondition):
        if not postcondition:
            return Result("Unresolved", "postcondition not checked: no plan was stored with the intent", "")
        try:
            actor = self.actor(req["rid"])
            check = {"isolate_pod": self._isolate, "cordon_node": self._cordon, "scale_to_zero": self._scale,
                     "revoke_rolebinding": self._revoke}[req["act"]]
            return check(actor, req, postcondition)
        except ApiError as e:
            return Result("Unresolved", f"postcondition not checked: {e.status} {e.message}", "")

    # --- isolate ------------------------------------------------------------------------
    def _isolate(self, actor, req, pc):
        path = f"/api/v1/namespaces/{req['ns']}/pods/{req['params']['pod']}"
        end = self.monotonic() + self.deadline_s
        while True:                      # a Pod still starting gets its IP shortly
            pod = actor.get(path)
            if pod["metadata"]["uid"] != req["uid"]:
                return Result("Unresolved", "postcondition not checked: the Pod was replaced", "")
            ip = pod.get("status", {}).get("podIP")
            if ip:
                break
            if self.monotonic() >= end:
                return Result("Unresolved", "postcondition not checked: the Pod has no IP", "")
            self.sleep(self.poll_s)
        addr = f"{ip}:{pc['port']}"
        ref, results = self.connect(actor, req["rid"], addr)
        if results is None:
            return Result("Unresolved", "postcondition not checked: the probe Pod did not finish", ref)
        tail = results[-self.need:]
        summary = " ".join(results)
        if len(tail) == self.need and all(r == "TIMEOUT" for r in tail):
            return Result("Verified", f"new connections to {addr} time out ({summary})", ref)
        if results and results[-1] in REACHABLE:
            return Result("Failed", f"the Pod is still reachable at {addr} ({summary})", ref)
        return Result("Unresolved", f"no conclusive probe of {addr} ({summary or 'no output'})", ref)

    def connect(self, actor, rid, addr):
        """Run one connection probe Pod against addr; (ref, results), with
        results None if it did not finish before the deadline."""
        env = {"ADDR": addr, "TRIES": str(self.tries), "NEED": str(self.need),
               "TIMEOUT": str(self.connect_timeout_s)}
        spec = {"containers": [_container(PROBE_IMAGE, ["/bin/sh", "-c", CONNECT_SCRIPT], env)]}
        name, ref = self._create_probe(actor, rid, "connect", spec)
        try:
            pod = self._wait(actor, name, lambda p: p.get("status", {}).get("phase") in ("Succeeded", "Failed"))
            if pod is None:
                return ref, None
            term = pod["status"].get("containerStatuses", [{}])[0].get("state", {}).get("terminated", {})
            lines = [ln.split() for ln in term.get("message", "").splitlines()]
            return ref, [ln[1] for ln in lines if len(ln) == 2]
        finally:
            self._delete_probe(actor, name)

    # --- cordon -------------------------------------------------------------------------
    def _cordon(self, actor, req, pc):
        node = pc["node"]
        spec = {"containers": [_container(PAUSE_IMAGE)],
                "affinity": {"nodeAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": {
                    "nodeSelectorTerms": [{"matchFields": [{"key": "metadata.name", "operator": "In",
                                                            "values": [node]}]}]}}}}
        name, ref = self._create_probe(actor, req["rid"], "schedule", spec)
        try:
            def decided(p):
                return p.get("spec", {}).get("nodeName") or _unschedulable(p)
            pod = self._wait(actor, name, decided)
        finally:
            self._delete_probe(actor, name)
        if pod is None:
            return Result("Unresolved", f"the scheduler did not decide on a Pod pinned to {node}", ref)
        if pod.get("spec", {}).get("nodeName"):
            return Result("Failed", f"a Pod pinned to {node} was scheduled there", ref)
        return Result("Verified", f"a Pod pinned to {node} stays Pending: {_unschedulable(pod)}", ref)

    # --- scale to zero ------------------------------------------------------------------
    def _scale(self, actor, req, pc):
        if not pc["selector"].get("matchLabels") and not pc["selector"].get("matchExpressions"):
            return Result("Unresolved", "postcondition not checked: the workload has an empty selector", "")
        sel = selector_string(pc["selector"])
        path = f"/api/v1/namespaces/{req['ns']}/pods"
        end = self.monotonic() + self.deadline_s
        while True:
            lst = actor.get(path, {"labelSelector": sel})
            pods = lst.get("items", [])
            ref = f"pods {req['ns']} labelSelector={sel} at resourceVersion " \
                  f"{lst.get('metadata', {}).get('resourceVersion', '')}"
            if not pods:
                return Result("Verified", f"no Pod matches {sel}", ref)
            if self.monotonic() >= end:
                break
            self.sleep(self.poll_s)
        live = [p["metadata"]["name"] for p in pods if not p["metadata"].get("deletionTimestamp")]
        if live:
            return Result("Failed", f"{len(live)} Pod(s) matching {sel} still run: {', '.join(sorted(live))}", ref)
        return Result("Unresolved", f"{len(pods)} Pod(s) matching {sel} are still terminating", ref)

    # --- revoke -------------------------------------------------------------------------
    def _revoke(self, actor, req, pc):
        ns, binding = req["ns"], req["params"]["rolebinding"]
        rr = pc["role_ref"]
        role_path = (f"/apis/rbac.authorization.k8s.io/v1/clusterroles/{rr['name']}" if rr.get("kind") == "ClusterRole"
                     else f"/apis/rbac.authorization.k8s.io/v1/namespaces/{ns}/roles/{rr['name']}")
        attrs = _granted(actor.get(role_path), ns)
        if attrs is None:
            return Result("Unresolved", f"{rr.get('kind')} {rr.get('name')} grants no resource permission to test",
                          "")
        who = [_reviewer(s, ns) for s in pc["subjects"]]
        if not who:
            return Result("Unresolved", "the binding had no subjects to test", "")
        what = f"{attrs['verb']} {attrs.get('group') or 'core'}/{attrs['resource']} in {ns}"
        mine = f'RoleBinding "{binding}/{ns}"'
        end = self.monotonic() + self.deadline_s
        while True:
            allowed = []
            for spec in who:
                st = actor.request("POST", "/apis/authorization.k8s.io/v1/subjectaccessreviews",
                                   {"apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview",
                                    "spec": dict(spec, resourceAttributes=attrs)})[0].get("status", {})
                if st.get("allowed"):
                    allowed.append((_name(spec), st.get("reason", "")))
            ref = f"SubjectAccessReview {what} as {', '.join(_name(s) for s in who)}"
            if not allowed:
                return Result("Verified", f"can-i {what}: no, for every subject of {binding}", ref)
            if self.monotonic() >= end:
                break
            self.sleep(self.poll_s)
        if any(mine in reason for _, reason in allowed):
            return Result("Failed", f"{binding} still grants {what} to {allowed[0][0]}", ref)
        return Result("Unresolved", f"{what} is still allowed for {allowed[0][0]}, by another grant: "
                                    f"{allowed[0][1]}", ref)

    # --- probe Pods ---------------------------------------------------------------------
    def _create_probe(self, actor, rid, kind, spec):
        name = f"gre-probe-{uuid.uuid4().hex[:10]}"
        pod = {"apiVersion": "v1", "kind": "Pod",
               "metadata": {"name": name, "namespace": PROBE_NS, "labels": {PROBE_LABEL: kind},
                            "annotations": {"microtrace.io/rid": rid}},
               "spec": dict(spec, restartPolicy="Never", automountServiceAccountToken=False,
                            terminationGracePeriodSeconds=0, enableServiceLinks=False,
                            securityContext={"runAsNonRoot": True, "runAsUser": 65534, "runAsGroup": 65534,
                                             "seccompProfile": {"type": "RuntimeDefault"}})}
        created, _ = actor.request("POST", f"/api/v1/namespaces/{PROBE_NS}/pods", pod)
        return name, f"pod {PROBE_NS}/{name} uid={created['metadata']['uid']}"

    def _wait(self, actor, name, done):
        end = self.monotonic() + self.deadline_s
        while True:
            pod = actor.get(f"/api/v1/namespaces/{PROBE_NS}/pods/{name}")
            if done(pod):
                return pod
            if self.monotonic() >= end:
                return None
            self.sleep(self.poll_s)

    def _delete_probe(self, actor, name):
        try:
            actor.request("DELETE", f"/api/v1/namespaces/{PROBE_NS}/pods/{name}",
                          {"apiVersion": "v1", "kind": "DeleteOptions", "gracePeriodSeconds": 0})
        except ApiError:
            pass                         # left for the namespace's cleanup; it holds only probe Pods


def _container(image, command=None, env=None):
    c = {"name": "probe", "image": image, "imagePullPolicy": "IfNotPresent",
         "terminationMessagePolicy": "FallbackToLogsOnError",
         "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
         "resources": {"requests": {"cpu": "10m", "memory": "16Mi"}, "limits": {"memory": "64Mi"}}}
    if command:
        c["command"] = command
    if env:
        c["env"] = [{"name": k, "value": v} for k, v in sorted(env.items())]
    return c


def _unschedulable(pod):
    for c in pod.get("status", {}).get("conditions", []):
        if c.get("type") == "PodScheduled" and c.get("status") == "False" and c.get("reason") == "Unschedulable":
            return c.get("message", "Unschedulable")
    return ""


def _granted(role, ns):
    """resourceAttributes of one permission the role grants, or None."""
    for r in role.get("rules", []):
        if not r.get("resources") or not r.get("verbs"):
            continue                     # nonResourceURLs
        verb, res = r["verbs"][0], r["resources"][0]
        attrs = {"namespace": ns, "verb": "get" if verb == "*" else verb,
                 "group": "" if r.get("apiGroups", [""])[0] == "*" else r.get("apiGroups", [""])[0],
                 "resource": "pods" if res == "*" else res.split("/")[0]}
        if "/" in res:
            attrs["subresource"] = res.split("/", 1)[1]
        if r.get("resourceNames"):
            attrs["name"] = r["resourceNames"][0]
        return attrs
    return None


def _reviewer(subject, ns):
    """SubjectAccessReview user and groups of one binding subject."""
    kind, name = subject.get("kind"), subject.get("name")
    if kind == "ServiceAccount":
        sns = subject.get("namespace") or ns
        return {"user": f"system:serviceaccount:{sns}:{name}",
                "groups": ["system:serviceaccounts", f"system:serviceaccounts:{sns}", "system:authenticated"]}
    if kind == "User":
        return {"user": name, "groups": ["system:authenticated"]}
    return {"groups": [name]}


def _name(spec):
    return spec.get("user") or f"group {spec['groups'][0]}"
