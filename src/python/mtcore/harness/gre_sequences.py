"""Randomised GRE sequences (build step 8e; evaluation-plan.md section 4,
Exp. 5 part B: "Randomised sequences (property-based) check: every write
matches a valid, fresh approval; each nonce leads to at most one
execution; Verified only after a passing probe").

One sequence is a seeded random walk over a simulated cluster
(mtcore/gre/sim.py) with the real validator, executor, stores, approver
and reconciler. Steps: issue an approval (sometimes tampered), execute any
issued request (replays happen by drawing an old one), sometimes killing
the GRE at a random interruption point or changing the target between its
check and its write, let time pass, move the incident
on (older approvals go stale), recreate, relabel or annotate a target,
lift an isolation, stop or restore NetworkPolicy enforcement, reconcile.
After the last step time passes and reconciliation runs until quiet.

The properties are graded from the simulated API server's audit log, the
world's own history and the probe log, never from the GRE's A_resp alone:

  fresh_approval  every accepted write was made under a request that is
                  validly signed, unexpired at the write, bound to the
                  incident's latest version at the write, and aimed at the
                  object approved, unchanged in the fields the action
                  depends on
  one_execution   each nonce has at most one accepted write
  verified_probe  every Verified row follows a passing probe of that request
  settled         after the final reconciliation every accepted request has
                  a final outcome (Verified, Failed or Unresolved, or
                  Rejected), no intent is open and nothing awaits verification

Only isolate_pod is drawn: its target can be recreated, relabelled and
restored, and its postcondition can be made to fail, which covers every
guard the properties grade. "permissions" is graded on kind
(test_gre_kube_ablation.py), not here.

    python -m mtcore.harness.gre_sequences --seeds 200 --steps 40 [--ablate GUARD]
"""
import argparse
import copy
import dataclasses
import json
import random
import sys
from contextlib import contextmanager

from microtrace.v0 import envelope_pb2, incident_pb2

from mtcore import failpoint
from mtcore.gre import request as R
from mtcore.gre import verify as V
from mtcore.gre.approver import ScriptedApprover
from mtcore.gre.execute import ISOLATION_LABEL, Executor, relevant, user_agent
from mtcore.gre.reconcile import Reconciler
from mtcore.gre.sim import SimApi, SimKube
from mtcore.gre.store import MemoryGreStore
from mtcore.gre.validate import GUARDS, NS, Gre, GreConfig, TgsGraph
from mtcore.tgs import apply as A
from mtcore.tgs.store import MemoryStore

PROPERTIES = ("fresh_approval", "one_execution", "verified_probe", "settled")
POINTS = ("gre.before_intent", "gre.after_intent_before_submit", "gre.after_submit_before_record",
          "gre.before_verify")
INCIDENT, CLUSTER, NAMESPACE = "in-1", "sim", "shop"
PODS = ("p0", "p1", "p2")
T0 = 1_800_000_000
TTL_S = 300
GRACE_S = 30
STEP_WEIGHTS = {"issue": 6, "execute": 8, "advance": 3, "incident": 1, "recreate": 1, "relabel": 1, "annotate": 1,
                "undo": 2, "policy": 1, "reconcile": 2}


class Crash(BaseException):
    """A GRE killed at a failpoint: nothing after it runs."""


class Clock:
    def __init__(self):
        self.ns = T0 * NS

    def __call__(self):
        return self.ns


class SimVerifier:
    """The isolation probe against the simulated cluster: new connections
    are blocked exactly when the approved Pod still exists, carries the
    isolation label, and NetworkPolicy is enforced. Every probe is logged."""

    def __init__(self, world):
        self.world = world

    def verify(self, req, postcondition):
        pod = self.world.api.objects.get(pod_path(req["params"]["pod"]))
        if pod is None or pod["metadata"]["uid"] != req["uid"]:
            self.world.probes.append({"rid": req["rid"], "passed": None, "ts": self.world.clock()})
            return V.Result("Unresolved", "postcondition not checked: the Pod was replaced", "")
        passed = self.world.enforced and pod["metadata"].get("labels", {}).get(ISOLATION_LABEL) == "true"
        self.world.probes.append({"rid": req["rid"], "passed": passed, "ts": self.world.clock()})
        ref = f"sim-probe {len(self.world.probes)}"
        if passed:
            return V.Result("Verified", "new connections time out (sim)", ref)
        return V.Result("Failed", "the Pod is still reachable (sim)", ref)


def pod_path(name):
    return f"/api/v1/namespaces/{NAMESPACE}/pods/{name}"


def incident_record(version):
    env = envelope_pb2.Envelope(schema_major=0, kind=envelope_pb2.RecordKind.Value("INCIDENT"), logical_id=INCIDENT)
    inc = env.incident
    inc.incident_id, inc.anchor_finding_id, inc.version = INCIDENT, "f1", version
    inc.status = incident_pb2.IncidentStatus.Value("INCIDENT_OPEN")
    inc.finding_ids.extend(["f1", "f2"])
    return env


class World:
    def __init__(self, seed, ablate=()):
        self.rng = random.Random(seed)
        self.clock = Clock()
        self.api = SimApi(clock=self.clock)
        self.tgs = MemoryStore()
        self.version, self.offset = 0, 0
        self.versions = []                       # (from_ns, version): the incident's latest version over time
        self.next_incident()
        self.uids = 0
        for p in PODS:
            self.create_pod(p)
        self.enforced = True
        self.probes, self.issued, self.log = [], [], []
        key, pub = R.new_keypair()
        self.other_key, _ = R.new_keypair()
        self.keys = {"ap": pub}
        config = GreConfig(CLUSTER, frozenset({NAMESPACE}), self.keys, ablate=frozenset(ablate))
        self.store = MemoryGreStore()
        gre = Gre(config, TgsGraph(self.tgs), self.store, clock=self.clock)
        kube = SimKube(self.api)
        verifier = V.AcceptanceVerifier() if "postcondition" in ablate else SimVerifier(self)
        self.ex = Executor(gre, kube, clock=self.clock, verifier=verifier)
        self.rec = Reconciler(self.store, kube, self, grace_s=GRACE_S, clock=self.clock, verifier=verifier)
        self.approver = ScriptedApprover("ap", key, self.tgs, CLUSTER, clock=lambda: self.clock() / NS)
        self.key = key

    # the reconciler's audit source
    def events(self):
        return list(self.api.audit)

    def next_incident(self):
        self.version += 1
        A.apply_batch(self.tgs, [("incidents.v0", 0, self.offset, incident_record(self.version))])
        self.offset += 1
        self.versions.append((self.clock(), self.version))

    def latest_version_at(self, ts):
        return [v for t, v in self.versions if t <= ts][-1]

    def create_pod(self, name):
        self.uids += 1
        self.api.put(pod_path(name), {"metadata": {"name": name, "uid": f"uid-{name}-{self.uids}",
                                                   "labels": {"app": "shop"}},
                                      "spec": {"nodeName": "worker"}, "status": {"podIP": "10.0.0.1"}})

    def change(self, name, fn):
        pod = copy.deepcopy(self.api.objects[pod_path(name)])
        fn(pod)
        self.api.put(pod_path(name), pod)


@contextmanager
def crash_at(point):
    real = failpoint.hit

    def hit(name, state=None, require=None):
        if name == point:
            raise Crash(name)

    failpoint.hit = hit
    try:
        yield
    finally:
        failpoint.hit = real


def step(w, kind):
    rng = w.rng
    if kind == "issue":
        name = rng.choice(PODS)
        pod = w.api.objects[pod_path(name)]
        req = w.approver.issue(INCIDENT, "isolate_pod", NAMESPACE, pod["metadata"]["uid"],
                               pod["metadata"]["resourceVersion"], {"pod": name}, ttl_s=TTL_S)
        tamper = rng.random()
        if tamper < 0.1:
            req = dict(req, params={"pod": rng.choice([p for p in PODS if p != name])})   # breaks the signature
        elif tamper < 0.15:
            req = R.sign(req, "ap", w.other_key)                    # signed with an untrusted key
        w.issued.append(req)
        return f"issue {req['rid']} {name}" + (" tampered" if tamper < 0.15 else "")
    if kind == "execute":
        if not w.issued:
            return "execute (nothing issued)"
        req = copy.deepcopy(rng.choice(w.issued))
        if rng.random() < 0.2:
            point = rng.choice(POINTS)
            with crash_at(point):
                try:
                    out = w.ex.execute(req)
                    return f"execute {req['rid']} -> {out.status} (failpoint {point} not reached)"
                except Crash:
                    return f"execute {req['rid']} killed at {point}"
        if rng.random() < 0.15:                  # the target changes between the check and the write, once
            name, fired = req["params"]["pod"], []

            def meddle(r, live):
                if not fired and pod_path(name) in w.api.objects:
                    fired.append(1)
                    w.change(name, lambda p: p["metadata"]["labels"].update(app="raced"))

            w.ex._before_write = meddle
            try:
                out = w.ex.execute(req)
            finally:
                del w.ex._before_write
            return f"execute {req['rid']} with a change before the write -> {out.status}: {out.reason}"
        out = w.ex.execute(req)
        return f"execute {req['rid']} -> {out.status}: {out.reason}"
    if kind == "advance":
        s = rng.choice((1, 5, 20, 40, 120))
        w.clock.ns += s * NS
        return f"advance {s} s"
    if kind == "incident":
        w.next_incident()
        return f"incident moves to version {w.version}"
    name = rng.choice(PODS)
    if kind == "recreate":
        w.create_pod(name)
        return f"recreate {name}"
    if kind == "relabel":
        w.change(name, lambda p: p["metadata"]["labels"].update(app=rng.choice(("shop", "other"))))
        return f"relabel {name}"
    if kind == "annotate":
        w.change(name, lambda p: p["metadata"].setdefault("annotations", {}).update(n=str(rng.random())))
        return f"annotate {name}"
    if kind == "undo":
        w.change(name, lambda p: p["metadata"]["labels"].pop(ISOLATION_LABEL, None))
        return f"lift isolation of {name}"
    if kind == "policy":
        w.enforced = not w.enforced
        return f"NetworkPolicy {'enforced' if w.enforced else 'not enforced'}"
    if kind == "reconcile":
        rows = w.rec.run()
        return f"reconcile -> {[r['status'] for r in rows]}"
    raise ValueError(kind)


def finish(w):
    for _ in range(3):
        w.clock.ns += (GRACE_S + 1) * NS
        w.log.append(f"final reconcile -> {[r['status'] for r in w.rec.run()]}")


def check(w):
    """Violations of each property, graded from the audit log and the world."""
    by_ua = {}
    for req in w.issued:
        by_ua.setdefault(user_agent(req), req)
    out = {p: [] for p in PROPERTIES}
    accepted = [e for e in w.api.audit if e["responseStatus"]["code"] == 200 and e["verb"] != "get"]
    per_nonce = {}
    for e in accepted:
        req = by_ua.get(e["userAgent"])
        if req is None:
            out["fresh_approval"].append(f"write {e['auditID']} matches no issued request")
            continue
        per_nonce.setdefault(req["nonce"], []).append(e["auditID"])
        why = _unfresh(w, req, e)
        if why:
            out["fresh_approval"].append(f"{req['rid']} write {e['auditID']}: {why}")
    for nonce, ids in per_nonce.items():
        if len(ids) > 1:
            out["one_execution"].append(f"nonce {nonce[:12]} executed {len(ids)} times ({', '.join(ids)})")
    for a in w.store.attempts():
        if a["status"] == "Verified":
            if not any(p["rid"] == a["rid"] and p["passed"] and p["ts"] <= a["ts"] for p in w.probes):
                out["verified_probe"].append(f"{a['rid']} Verified without a passing probe ({a['reason']})")
    out["settled"] = _unsettled(w)
    return out


def _unfresh(w, req, e):
    ok, why = R.verify(req, w.keys)
    if not ok:
        return f"invalid approval ({why})"
    if e["ts"] >= req["exp"] * NS:
        return "approval expired at the write"
    if req["v_c"]["version"] != w.latest_version_at(e["ts"]):
        return f"approval bound to incident version {req['v_c']['version']}, latest was {w.latest_version_at(e['ts'])}"
    before = e["objectBefore"]
    if before is None or before["metadata"]["uid"] != req["uid"]:
        return "wrote another object than the approved one"
    reviewed = w.api.at(pod_path(req["params"]["pod"]), int(req["rv"]))
    changed = sorted(k for k, v in relevant("isolate_pod", reviewed).items()
                     if relevant("isolate_pod", before)[k] != v)
    if changed:
        return f"target changed since review: {', '.join(changed)}"
    return None


def _unsettled(w):
    bad = [f"intent {i['rid']} still open" for i in w.store.open_intents()
           if i.get("resolved_attempt_id") is None]
    bad += [f"nonce of {n['rid']} never closed" for n in w.store.unclosed_nonces(w.clock() + 1)]
    bad += [f"{p['rid']} awaits verification" for p in w.store.pending_verification()
            if p.get("verified_status") != "Unresolved"]
    final = {"Verified", "Failed", "Unresolved"}
    rows = w.store.attempts()
    for a in rows:
        if a["status"] == "Submitted" and not any(b["rid"] == a["rid"] and b["status"] in final
                                                  and b["attempt_id"] > a["attempt_id"] for b in rows):
            bad.append(f"{a['rid']} ends Submitted")
    return bad


@dataclasses.dataclass
class Report:
    seed: int
    ablate: tuple
    log: list
    violations: dict
    coverage: dict                               # what the sequence exercised, so a clean run is not vacuous

    @property
    def ok(self):
        return not any(self.violations.values())


def run(seed, steps=40, ablate=()):
    w = World(seed, ablate)
    kinds, weights = zip(*STEP_WEIGHTS.items())
    for _ in range(steps):
        w.clock.ns += 10**6                      # each step at its own time, so the audit log orders them
        w.log.append(step(w, w.rng.choices(kinds, weights)[0]))
    finish(w)
    return Report(seed, tuple(ablate), w.log, check(w), coverage(w))


def coverage(w):
    c = {"accepted_writes": sum(e["responseStatus"]["code"] == 200 for e in w.api.audit),
         "refused_writes": sum(e["responseStatus"]["code"] != 200 for e in w.api.audit),
         "passing_probes": sum(bool(p["passed"]) for p in w.probes),
         "failing_probes": sum(p["passed"] is False for p in w.probes)}
    for line in w.log:
        if " killed at " in line:
            k = "killed:" + line.rsplit(" ", 1)[1]
            c[k] = c.get(k, 0) + 1
    for a in w.store.attempts():
        k = a["status"] if a["status"] != "Rejected" else "Rejected:" + a["reason"].split(":")[0]
        c[k] = c.get(k, 0) + 1
    return c


def main(argv=None):
    ap = argparse.ArgumentParser(description="Randomised GRE sequences (Exp. 5 part B).")
    ap.add_argument("--seeds", type=int, default=200)
    ap.add_argument("--first-seed", type=int, default=0)
    ap.add_argument("--steps", type=int, default=40)
    ap.add_argument("--ablate", action="append", default=[], choices=GUARDS)
    a = ap.parse_args(argv)
    counts, first, cover = {p: 0 for p in PROPERTIES}, {}, {}
    for seed in range(a.first_seed, a.first_seed + a.seeds):
        r = run(seed, a.steps, a.ablate)
        for k, n in r.coverage.items():
            cover[k] = cover.get(k, 0) + n
        for p, v in r.violations.items():
            if v:
                counts[p] += 1
                first.setdefault(p, {"seed": seed, "example": v[0]})
    print(json.dumps({"seeds": a.seeds, "steps": a.steps, "ablated": sorted(a.ablate),
                      "sequences_violating": counts, "first_violation": first,
                      "coverage": dict(sorted(cover.items()))}, indent=1))
    return 0 if not any(counts.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
