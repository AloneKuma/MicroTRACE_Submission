#!/usr/bin/env python3
"""Offline pipeline fixture: real components and a real broker, SYNTHETIC inputs, no cluster.

This checks the slice's logic end to end before a cluster exists. The audit
input is a synthetic JSON audit log written to a temporary directory (read by
the real audit collector, including a lumberjack-style rename rotation and a
deleted backup). The context input comes from a scripted producer standing in
for the context collector. It is not cluster evidence.

Expected outcomes (UNFROZEN-SLICE, N_H3 = 8):
  P  positive: 3 list scopes + 10 distinct gets = 13 -> FIRED, one incident
     OPEN -> SEALED (CLUSTER_CONTEXT idle-excluded at seal) -> AMENDED when a
     WATCH_RELIST_GAP known after the seal arrives.
  Q  below threshold: 1 list scope + 2 gets = 3 -> NOT_FIRED.
  R  controller-like: repeated list of one namespace -> score 1 per window -> NOT_FIRED.
  G  gap known before evaluation: collector stopped and its file rotated away
     -> ABSTAINED with DROPPED_BEFORE.
  Replay of the downstream stages from the raw topics reproduces finding,
  evaluation and incident IDs, outcomes and incident versions.
"""

import json
import math
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import mtslice as M  # noqa: E402

B = os.environ.get("MT_BOOTSTRAP", "127.0.0.1:19092")
RUN = "fixture-" + uuid.uuid4().hex[:8]
P = M.load_params()
W = P["W_H3_s"]


def sa(ns, name):
    return f"system:serviceaccount:{ns}:{name}"


class AuditLog:
    def __init__(self, d):
        self.d = d
        self.path = os.path.join(d, "audit.log")
        self.lock = threading.Lock()

    def write(self, user, verb, resource, ns="", name="", code=200, extra=None, uid=None):
        t = M.rfc3339(M.now())
        ev = {"kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": "Metadata", "auditID": str(uuid.uuid4()),
              "stage": "ResponseComplete", "verb": verb,
              "requestURI": f"/api/v1/{'namespaces/' + ns + '/' if ns else ''}{resource}{'/' + name if name else ''}",
              "user": {"username": user, "uid": uid or ("uid-" + user), "groups": ["system:authenticated"],
                       "extra": extra or {}},
              "sourceIPs": ["172.18.0.1"], "userAgent": "fixture/0",
              "objectRef": {"resource": resource, "namespace": ns, "name": name, "apiVersion": "v1"},
              "responseStatus": {"metadata": {}, "code": code},
              "requestReceivedTimestamp": t, "stageTimestamp": t}
        with self.lock:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(ev) + "\n")

    def rotate(self, stamp):
        with self.lock:
            os.rename(self.path, os.path.join(self.d, f"audit-{stamp}.log"))
            open(self.path, "a").close()


class ContextStub:
    """Scripted stand-in for the context collector (fixture only)."""

    def __init__(self, run):
        self.bus = M.Bus(B, "fixture-context")
        self.run = run
        self.scope = "pods;context-collector=fixture-context"
        self.cov_end = M.now() - 1
        self.paused = False
        self.stop = False
        self.pod_uid = "11111111-2222-4333-8444-" + uuid.uuid4().hex[:12]

    def start(self):
        o = M.context_pb2.ObjectObservation(kind="Pod", namespace="fx-a", name="fx-enum-pod", uid=self.pod_uid,
                                            resource_version="100", change_type=M.context_pb2.ADDED,
                                            watch_stream_id="fixture/pods/1", watch_stream_seq=1)
        o.observed_time.CopyFrom(M.ts(M.now() - 5))
        self.bus.send("context.cluster.v0", M.key_for("context.cluster.v0", {"OBJECT_UID": o.uid}),
                      M.envelope(self.run, "context-collector", "CONTEXT_OBSERVATION", "CLUSTER_CONTEXT",
                                 "context_observation", o, logical_id=M.event_id("CLUSTER_CONTEXT",
                                                                                 f"{o.uid}/100/ADDED", "watch")))
        threading.Thread(target=self.loop, daemon=True).start()

    def completeness(self, s, e, status, gaps=()):
        sc = M.completeness_msg("CLUSTER_CONTEXT", self.scope, s, e, status, gaps)
        self.bus.send("source.completeness.v0",
                      M.key_for("source.completeness.v0", {"SOURCE_NAME": "CLUSTER_CONTEXT", "SCOPE": self.scope}),
                      M.envelope(self.run, "context-collector", "SOURCE_COMPLETENESS", "CLUSTER_CONTEXT",
                                 "source_completeness", sc))

    def loop(self):
        while not self.stop:
            time.sleep(1)
            if self.paused:
                continue
            end = M.now() - 1
            self.completeness(self.cov_end, end, "NO_KNOWN_GAP")
            self.cov_end = end
            self.bus.heartbeat(self.run, "context-collector", "context.cluster.v0", end, "CLUSTER_CONTEXT")

    def resume_with_gap(self):
        t = M.now()
        wg = M.context_pb2.WatchGap(resource="pods", last_resource_version="100", relist_resource_version="900",
                                    reason=M.context_pb2.GONE_410, watch_stream_id="fixture/pods/2")
        wg.gap_start.CopyFrom(M.ts(self.cov_end))
        wg.gap_end.CopyFrom(M.ts(t))
        self.bus.broadcast("context.cluster.v0", M.envelope(self.run, "context-collector", "CONTEXT_WATCH_GAP",
                                                            "CLUSTER_CONTEXT", "context_watch_gap", wg))
        self.completeness(self.cov_end, t, "INCOMPLETE",
                          [M.gap("WATCH_RELIST_GAP", "pods", "fixture 410", self.cov_end, t)])
        self.cov_end = t
        self.paused = False


def wait_until(pred, timeout, what):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.5)
    raise AssertionError(f"timeout waiting for {what}")


def jsonl(path):
    if not os.path.exists(path):
        return []
    return [json.loads(x) for x in open(path, encoding="utf-8") if x.strip()]


def align(offset=1.0):
    t = M.now()
    nxt = math.floor(t / W) * W + W
    time.sleep(max(0.0, nxt + offset - t))


def main():
    root = tempfile.mkdtemp(prefix="mt-slice-fixture-")
    audit_dir, out = os.path.join(root, "audit"), os.path.join(root, "out")
    os.makedirs(audit_dir)
    os.makedirs(out)
    key = os.path.join(root, "key")
    with open(key, "wb") as fh:
        fh.write(os.urandom(32))
    log = AuditLog(audit_dir)
    log.write("system:kube-controller-manager", "get", "leases", "kube-system", "kcm")
    run = M.Run(RUN, "fixture-descriptor", P)
    common = ["--bootstrap", B, "--run-id", RUN, "--descriptor-sha256", "fixture-descriptor"]
    py = sys.executable
    procs = {}

    def start(name, script, extra):
        procs[name] = subprocess.Popen([py, os.path.join(HERE, script)] + common + extra)

    def collector(resume):
        start("collector", "audit_collector.py", ["--dir", audit_dir, "--out", out, "--key", key,
                                                  "--instance", "fixture-audit", "--policy-sha256", "fixture"]
              + (["--resume"] if resume else []))

    ctx = ContextStub(run)
    ctx.start()
    try:
        scenario(ctx, log, procs, start, collector, out, audit_dir, common, py, root)
    except Exception:
        for name in ("agent.jsonl", "orchestrator.jsonl", "normalizer.jsonl", "slice-collector.jsonl"):
            rows = jsonl(os.path.join(out, name))
            print(f"--- {name} ({len(rows)} rows, last 12)")
            for r in rows[-12:]:
                print(json.dumps(r, sort_keys=True))
        for p in procs.values():
            if p.poll() is None:
                p.kill()
        raise


def scenario(ctx, log, procs, start, collector, out, audit_dir, common, py, root):
    collector(False)
    for name, script in (("normalizer", "normalizer.py"), ("restreamer", "restreamer.py"),
                         ("agent", "agent_h3.py"), ("orchestrator", "orchestrator.py")):
        start(name, script, ["--instance", f"fixture-{name}", "--group", f"{RUN}-{name}", "--out", out])

    stop_bg = threading.Event()

    def background():
        while not stop_bg.is_set():
            log.write("system:kube-scheduler", "get", "leases", "kube-system", "sched")
            time.sleep(0.2)
    threading.Thread(target=background, daemon=True).start()

    pos = {"authentication.kubernetes.io/credential-id": ["JTI=0f3c1a2b-4d5e-4f60-8a71-92b3c4d5e6f7"],
           "authentication.kubernetes.io/pod-uid": [ctx.pod_uid],
           "authentication.kubernetes.io/pod-name": ["fx-enum-pod"]}
    P_, Q_, R_, G_ = sa("fx-a", "fx-enum"), sa("fx-a", "fx-low"), sa("kube-system", "fx-controller"), sa("fx-a", "fx-gap")

    # ---- positive, negative and controller-like controls in one window
    align(1.0)
    for ns in ("fx-a", "fx-b", "fx-c"):
        log.write(P_, "list", "secrets", ns, extra=pos)
    for ns, n in (("fx-a", 4), ("fx-b", 3), ("fx-c", 3)):
        for i in range(n):
            log.write(P_, "get", "secrets", ns, f"s{i}", extra=pos)
    log.write(Q_, "list", "secrets", "fx-a")
    log.write(Q_, "get", "secrets", "fx-a", "s0")
    log.write(Q_, "get", "secrets", "fx-a", "s1")

    def controller():
        for _ in range(12):
            log.write(R_, "list", "secrets", "fx-a")
            time.sleep(2)
    threading.Thread(target=controller, daemon=True).start()

    time.sleep(8)
    ctx.paused = True  # context producer goes idle after the positive events were enriched
    orch_log = os.path.join(out, "orchestrator.jsonl")
    wait_until(lambda: any(r.get("status") == "INCIDENT_SEALED" for r in jsonl(orch_log)), 150, "positive seal")
    ctx.resume_with_gap()
    wait_until(lambda: any(r.get("status") == "INCIDENT_AMENDED" for r in jsonl(orch_log)), 60, "amendment")

    # ---- gap known before evaluation
    align(1.0)
    for i in range(4):
        log.write(G_, "get", "secrets", "fx-a", f"g{i}")
    time.sleep(3)
    procs["collector"].send_signal(signal.SIGTERM)
    procs["collector"].wait(30)
    for ns in ("fx-a", "fx-b", "fx-c"):
        log.write(G_, "list", "secrets", ns)
    for i in range(6):
        log.write(G_, "get", "secrets", "fx-b", f"h{i}")
    time.sleep(1)
    log.rotate("2026-09-27T00-00-01.000")
    time.sleep(1)
    log.rotate("2026-09-27T00-00-02.000")
    os.remove(os.path.join(audit_dir, "audit-2026-09-27T00-00-01.000.log"))  # maxbackup=1 removes the oldest
    time.sleep(1)
    collector(True)
    agent_log = os.path.join(out, "agent.jsonl")
    wait_until(lambda: any(r.get("principal") == "uid-" + G_ and r.get("outcome") for r in jsonl(agent_log)),
               120, "gap window evaluation")
    time.sleep(W + 2 * P["lateness_s"] + 2)
    stop_bg.set()
    time.sleep(3)

    # ---- stop live stages, then replay downstream stages sequentially
    for name in ("collector",):
        open(os.path.join(out, "collector.stop"), "w").close()
        procs[name].wait(60)
    for name, stopf in (("normalizer", "normalizer.stop"), ("restreamer", "restreamer.stop"),
                        ("agent", "agent.stop"), ("orchestrator", "orchestrator.stop")):
        open(os.path.join(out, stopf), "w").close()
        procs[name].wait(60)
    ctx.stop = True
    for stopf in ("normalizer.stop", "restreamer.stop", "agent.stop", "orchestrator.stop"):
        os.remove(os.path.join(out, stopf))
    for name, script in (("normalizer", "normalizer.py"), ("restreamer", "restreamer.py"),
                         ("agent", "agent_h3.py"), ("orchestrator", "orchestrator.py")):
        subprocess.run([py, os.path.join(HERE, script)] + common +
                       ["--instance", f"fixture-{name}-replay", "--group", f"{RUN}-{name}-replay", "--out", out,
                        "--replay"], check=True, timeout=300)

    # ---- assertions
    agent = [r for r in jsonl(agent_log) if "outcome" in r]
    agent_r = [r for r in jsonl(os.path.join(out, "agent-replay.jsonl")) if "outcome" in r]
    by = lambda rows, who: sorted({r["outcome"] for r in rows if r["principal"] == "uid-" + who})
    results = {"P": by(agent, P_), "Q": by(agent, Q_), "R": by(agent, R_), "G": by(agent, G_)}
    orch = jsonl(orch_log)
    orch_r = jsonl(os.path.join(out, "orchestrator-replay.jsonl"))
    seq = lambda rows: [(r["incident_id"], r["version"], r["status"], tuple(r["at_seal_excluded"]),
                         tuple(r["current_excluded"]), r["amendments"]) for r in rows]
    ev = lambda rows, lim: sorted((r["evaluation_id"], r["outcome"], r["finding_id"]) for r in rows
                                  if r["window_end"] <= lim)
    lim = min(max(r["window_end"] for r in agent), max(r["window_end"] for r in agent_r))
    report = {"run": RUN, "outcomes": results, "incident_versions_live": seq(orch),
              "incident_versions_replay": seq(orch_r),
              "evaluations_equal": ev(agent, lim) == ev(agent_r, lim),
              "incidents_equal": seq(orch) == seq(orch_r), "evaluations_compared": len(ev(agent, lim))}
    print(json.dumps(report, indent=1))
    ok = (results["P"] == ["FIRED"] and results["Q"] == ["NOT_FIRED"] and results["R"] == ["NOT_FIRED"]
          and "ABSTAINED" in results["G"] and report["evaluations_equal"] and report["incidents_equal"]
          and [x[2] for x in seq(orch)] == ["INCIDENT_OPEN", "INCIDENT_SEALED", "INCIDENT_AMENDED"])
    for p in procs.values():
        if p.poll() is None:
            p.kill()
    shutil.rmtree(root, ignore_errors=True)
    print("FIXTURE_PIPELINE " + ("PASS" if ok else "FAIL"))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
