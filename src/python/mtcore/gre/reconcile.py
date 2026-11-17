"""Reconciliation of interrupted submissions (build step 7.3;
evaluation-plan.md section 5, step 7; paper Phase 4, Step 4).

Run when a GRE restarts, and again later for anything still Unresolved. It
never writes to the target and never resubmits: it only reads the API
server's audit log and the target's current state, and appends an A_resp
row that closes the intent (and nonce) it answers.

For each open intent (no outcome, or only Unresolved):
- an audit event of an accepted write carrying the intent's User-Agent:
  Submitted, with that event's audit ID;
- only refused writes (4xx) in the audit log: Failed;
- no write in the audit log, once the intent is older than the grace
  period: Failed if the target shows no effect (the write never reached the
  API server), Unresolved if the effect is there or the target cannot be
  read (the audit record may be lost; the outcome stays open, never
  guessed).
For each accepted request with no intent and no outcome (the GRE stopped
before it planned a write, and a write is only sent after its intent is
durable), once older than the grace period: Failed.

7.4: with a verifier, every intent whose write is Submitted (by the
executor or by this reconciliation) and not yet Verified or Failed is
verified: the GRE stopped before verification, or the last check was
inconclusive. A repeated inconclusive check appends no new row.

The audit source is anything with events(): the kind cluster's log file is
read through `docker exec` (KindAuditLog); tests pass a list.
"""
import json
import subprocess
import time

from mtcore.gre.execute import DEFAULT_AUDIENCE, ISOLATION_LABEL, SERVICE_ACCOUNTS, TOKEN_SECONDS, target, user_agent
from mtcore.gre import verify as V
from mtcore.gre.kube import ApiError

NS = 10**9
WRITE_VERBS = {"patch", "update", "delete"}


class KindAuditLog:
    """The kind API server's audit log (src/k8s/gre/kind-config.yaml),
    filtered to GRE-tagged requests."""

    def __init__(self, node="microtrace-gre-control-plane", path="/var/log/kubernetes/kube-apiserver-audit.log",
                 docker="docker"):
        self.node, self.path, self.docker = node, path, docker

    def events(self):
        out = subprocess.run([self.docker, "exec", self.node, "grep", "-F", '"userAgent":"microtrace-gre/', self.path],
                             capture_output=True, text=True, timeout=60)
        if out.returncode not in (0, 1):                 # 1: no match
            raise RuntimeError(f"cannot read the audit log: {out.stderr.strip()}")
        return [json.loads(line) for line in out.stdout.splitlines() if line.strip()]


class Reconciler:
    def __init__(self, store, kube, audit, grace_s=30, sa_namespace="microtrace", audience=DEFAULT_AUDIENCE,
                 clock=time.time_ns, verifier=None):
        self.store, self.kube, self.audit, self.grace_s, self.verifier = store, kube, audit, grace_s, verifier
        self.sa_namespace, self.audience, self.clock = sa_namespace, audience, clock

    def run(self):
        """Append one outcome per open intent or unclosed nonce that can be
        decided now; returns the rows appended."""
        now = self.clock()
        cutoff = now - self.grace_s * NS
        writes = {}
        for e in self.audit.events():
            if e.get("stage") == "ResponseComplete" and e.get("verb") in WRITE_VERBS:
                writes.setdefault(e.get("userAgent", ""), []).append(e)
        done = []
        for intent in self.store.open_intents():
            row = self._intent(intent, writes.get(intent["user_agent"], []), cutoff)
            if row is not None:
                done.append(row)
        for n in self.store.unclosed_nonces(cutoff):
            req = n["request"]
            if isinstance(req, str):
                req = json.loads(req)
            done.append(self._finish(req, "Failed", "reconciled: the GRE stopped before planning a write, "
                                                    "so nothing was sent", nonce=n["nonce"]))
        if self.verifier is not None:
            for p in self.store.pending_verification():
                row = self._verify(p)
                if row is not None:
                    done.append(row)
        return done

    def _verify(self, intent):
        req = intent["request"] if isinstance(intent["request"], dict) else json.loads(intent["request"])
        pc = intent["postcondition"]
        if isinstance(pc, str):
            pc = json.loads(pc)
        res = self.verifier.verify(req, pc)
        if res.status == "Unresolved" and intent["verified_status"] == "Unresolved":
            return None                                  # still inconclusive; do not repeat the row
        res = V.Result(res.status, "reconciled: " + res.reason, res.ref)
        return self.store.finish_verification(V.row(req, res, intent["ref_audit"], self.clock()), intent["intent_id"])

    def _intent(self, intent, events, cutoff):
        req = intent["request"] if isinstance(intent["request"], dict) else json.loads(intent["request"])
        ok = [e for e in events if 200 <= e["responseStatus"]["code"] < 300]
        if ok:
            note = "" if len(ok) == 1 else f" ({len(ok)} accepted writes recorded)"
            return self._finish(req, "Submitted", "reconciled: the audit log records the accepted write" + note,
                                intent, ok[-1]["auditID"])
        if events:
            last = events[-1]
            return self._finish(req, "Failed", f"reconciled: the API refused the write "
                                f"({last['responseStatus']['code']})", intent, last["auditID"])
        if intent["planned_at"] >= cutoff:
            return None                                  # a write may still be on its way to the audit log
        effect = self._effect(req)
        if effect is False:
            return self._finish(req, "Failed", "reconciled: no write reached the API server and the target is "
                                               "unchanged", intent)
        why = "the effect is present" if effect else "the target cannot be read"
        if self._latest_status(intent) == "Unresolved":
            return None                                  # still open; do not repeat the row
        return self._finish(req, "Unresolved", f"reconciled: no audit record of the write, but {why}", intent)

    def _effect(self, req):
        """True, False, or None (cannot tell) for the action's effect."""
        try:
            actor = self.kube.with_token(self.kube.mint_token(self.sa_namespace, SERVICE_ACCOUNTS[req["act"]],
                                                              self.audience, TOKEN_SECONDS))
            obj = actor.get(target(req).path)
        except ApiError as e:
            if e.status == 404 and req["act"] == "revoke_rolebinding":
                return True
            return None
        if obj["metadata"]["uid"] != req["uid"]:
            return True if req["act"] == "revoke_rolebinding" else None
        act = req["act"]
        if act == "isolate_pod":
            return obj["metadata"].get("labels", {}).get(ISOLATION_LABEL) == "true"
        if act == "cordon_node":
            return obj.get("spec", {}).get("unschedulable") is True
        if act == "scale_to_zero":
            return obj.get("spec", {}).get("replicas") == 0
        return False                                     # the RoleBinding still exists

    def _latest_status(self, intent):
        if intent.get("resolved_attempt_id") is None:
            return None
        rows = [a for a in self.store.attempts(rid=intent["rid"]) if a["attempt_id"] == intent["resolved_attempt_id"]]
        return rows[0]["status"] if rows else None

    def _finish(self, req, status, reason, intent=None, audit_id="", nonce=None):
        row = {"rid": req["rid"], "gid": req["gid"], "act": req["act"], "uid": req["uid"], "ts": self.clock(),
               "status": status, "reason": reason, "ref_audit": audit_id, "ref_verify": "", "request": req}
        return self.store.finish_attempt(row, intent["intent_id"] if intent else None,
                                         nonce or (intent["nonce"] if intent else req["nonce"]))


__all__ = ["KindAuditLog", "Reconciler", "user_agent"]
