#!/usr/bin/env python3
"""Normalizer: raw.audit.v0 + context.cluster.v0 -> norm.events.v0.

Each audit record becomes a NormalizedEvent with the same logical event ID,
event time = stageTimestamp (AUDIT_STAGE), the principal EntityRef, and
AuditDerived fields copied from the source (nothing inferred from names).

Token-bound Pod: when user.extra carries a Pod binding, the Pod UID is
resolved against the watched Pod history for the event time. A POD entity is
added only if the history shows that UID alive at that time and no WatchGap
covers the time; it is labelled token-bound (strength CONTEXT), never the
proven caller. Otherwise the event carries JOIN_UNCERTAIN (or
WATCH_RELIST_GAP) and no POD entity.

An audit event waits until the context watermark reaches its event time.
Live idle rule (wall clock, the only non-replayable input here): if every
context partition is at end-of-partition and no context record arrived for
max_idle_s, context is treated as idle and waiting events are emitted with
JOIN_UNCERTAIN/SOURCE_IDLE.
"""

import argparse
import os

import mtslice as M

EXTRA = "authentication.kubernetes.io/"
ET = M.common_pb2.EntityType.Value


def principal_entity(user):
    name = user.username
    if not name:
        return None, None
    if name.startswith("system:serviceaccount:"):
        _, _, ns, sa = name.split(":", 3)
        return M.common_pb2.EntityRef(type=ET("SERVICE_ACCOUNT"), uid=user.uid or name, namespace=ns, name=sa,
                                      strength_class=M.common_pb2.STRENGTH_HIGH), "SERVICE_ACCOUNT"
    return M.common_pb2.EntityRef(type=ET("USER"), uid=user.uid or name, name=name,
                                  strength_class=M.common_pb2.STRENGTH_HIGH), "USER"


def extra1(user, key):
    v = user.extra.get(EXTRA + key)
    return v.values[0] if v is not None and v.values else None


class Normalizer:
    def __init__(self, args):
        self.args = args
        self.params = M.load_params()
        self.out_prefix = "replay." if args.replay else ""
        self.bus = M.Bus(args.bootstrap, args.instance)
        self.run_ctx = M.Run(args.run_id, args.descriptor_sha256, self.params)
        self.loop = M.Loop(args.bootstrap, args.group, ["raw.audit.v0", "context.cluster.v0"],
                           os.path.join(args.out, "normalizer.stop"), replay=args.replay)
        self.wm = M.Watermarks(self.loop.partitions())
        self.pods = {}        # uid -> {"first": t, "deleted": t|None, "name", "ns"}
        self.gaps = []        # (start, end) WatchGap intervals
        self.pending = []     # (event_time, env)
        self.last_ctx_wall = M.now()
        self.log = M.JsonLog(os.path.join(args.out, f"normalizer{'-replay' if args.replay else ''}.jsonl"))
        self.counts = {"normalized": 0, "pod_resolved": 0, "join_uncertain": 0, "late": 0}

    def ctx_wm(self):
        return self.wm.topic("context.cluster.v0")

    def audit_wm(self):
        return self.wm.topic("raw.audit.v0")

    def handle(self, topic, part, offset, env):
        if topic == "context.cluster.v0":
            self.last_ctx_wall = M.now()  # any record, heartbeats included, shows the source is alive
        if env.kind == M.RK("HEARTBEAT"):
            self.wm.update(topic, part, env.heartbeat.producer_instance, M.epoch(env.heartbeat.low_watermark))
            return
        if topic == "context.cluster.v0":
            if env.kind == M.RK("CONTEXT_OBSERVATION"):
                o = env.context_observation
                t = M.epoch(o.observed_time)
                p = self.pods.setdefault(o.uid, {"first": t, "deleted": None, "name": o.name, "ns": o.namespace})
                p["first"] = min(p["first"], t)
                if o.change_type == M.context_pb2.DELETED:
                    p["deleted"] = t
            elif env.kind == M.RK("CONTEXT_WATCH_GAP"):
                g = env.context_watch_gap
                iv = (M.epoch(g.gap_start), M.epoch(g.gap_end))
                if iv not in self.gaps:
                    self.gaps.append(iv)
            return
        if env.kind != M.RK("RAW_AUDIT"):
            return
        a = env.raw_audit
        t = M.epoch(a.stage_timestamp)
        if self.last_emitted is not None and t < self.last_emitted_wm:
            self.counts["late"] += 1
        self.pending.append((t, env))

    last_emitted = None
    last_emitted_wm = float("-inf")

    def tick(self):
        cw = self.ctx_wm()
        ctx_idle = (not self.args.replay and
                    all(("context.cluster.v0", p) in self.loop.eof for p in self.wm.partitions["context.cluster.v0"])
                    and M.now() - self.last_ctx_wall > self.params["max_idle_s"])
        ready, keep = [], []
        for t, env in self.pending:
            if (cw is not None and t <= cw) or ctx_idle:
                ready.append((t, env))
            else:
                keep.append((t, env))
        self.pending = keep
        for t, env in sorted(ready, key=lambda x: (x[0], x[1].logical_id)):
            self.emit(t, env, idle=cw is None or t > cw)
        aw = self.audit_wm()
        if aw is not None:
            lw = min([aw] + [t for t, _ in self.pending])
            self.last_emitted_wm = lw
            self.bus.heartbeat(self.run_ctx, "normalizer", self.out_prefix + "norm.events.v0", lw, "AUDIT")

    def idle(self):
        # Replay stops at end of input. Events still waiting for context stay
        # unemitted, exactly as they were when the live normalizer stopped.
        return True

    def resolve_pod(self, a, t, idle):
        uid = extra1(a.user, "pod-uid")
        if not uid:
            return None, None
        for s, e in self.gaps:
            if s <= t <= e:
                return None, M.gap("WATCH_RELIST_GAP", "token-bound-pod", "event time inside a context WatchGap")
        if idle:
            return None, M.gap("SOURCE_IDLE", "token-bound-pod", "context source idle past max_idle_s")
        p = self.pods.get(uid)
        if p and p["first"] <= t and (p["deleted"] is None or t <= p["deleted"]):
            return M.common_pb2.EntityRef(type=ET("POD"), uid=uid, namespace=p["ns"], name=p["name"],
                                          strength_class=M.common_pb2.STRENGTH_CONTEXT), None
        return None, M.gap("JOIN_UNCERTAIN", "token-bound-pod", "bound Pod UID not alive in watched history")

    def emit(self, t, env, idle):
        a = env.raw_audit
        ne = M.normalized_pb2.NormalizedEvent(event_id=env.logical_id, source=M.SRC("AUDIT"),
                                              source_native_id=a.audit_id, source_stage=a.stage,
                                              action_id=a.audit_id, normalizer_version=M.VERSION,
                                              context_version=f"pods-history@{self.ctx_wm() or 0:.3f}")
        ne.time.source_time.CopyFrom(a.stage_timestamp)
        ne.time.event_time.CopyFrom(a.stage_timestamp)
        ne.time.ingest_time.CopyFrom(M.ts(M.now()) if not self.args.replay else a.stage_timestamp)
        ne.time.event_time_basis = M.common_pb2.AUDIT_STAGE
        ne.audit.CopyFrom(a)
        d = ne.audit_derived
        cred = extra1(a.user, "credential-id")
        if cred and cred.startswith("JTI="):
            d.used_credential_id = cred[4:]
        for f, k in (("bound_pod_uid", "pod-uid"), ("bound_pod_name", "pod-name"),
                     ("unverified_node_name", "node-name"), ("unverified_node_uid", "node-uid")):
            v = extra1(a.user, k)
            if v:
                setattr(d, f, v)
        d.authentication_failed = a.response_code == 401 and not a.user.username
        if a.source_ips:
            d.observed_source = a.source_ips[-1]
        principal, kind = principal_entity(a.user)
        if principal is not None:
            d.principal.CopyFrom(principal)
            ne.entities.add().CopyFrom(principal)
        pod, g = self.resolve_pod(a, t, idle)
        if pod is not None:
            ne.entities.add().CopyFrom(pod)
            self.counts["pod_resolved"] += 1
        if g is not None:
            ne.completeness.gaps.add().CopyFrom(g)
            self.counts["join_uncertain"] += 1
        if principal is not None:
            key = {"ENTITY_TYPE_NAME": kind, "ENTITY_UID": principal.uid}
        elif d.observed_source:
            key = {"ENTITY_TYPE_NAME": "UNAUTHENTICATED_SOURCE", "ENTITY_UID": d.observed_source}
        else:
            return  # no key component: not routed (kafka-contract.md section 1)
        out = M.envelope(self.run_ctx, "normalizer", "NORMALIZED_EVENT", "AUDIT", "normalized_event", ne,
                         logical_id=env.logical_id, completeness=ne.completeness)
        self.bus.send(self.out_prefix + "norm.events.v0", M.key_for("norm.events.v0", key), out)
        self.counts["normalized"] += 1
        self.last_emitted = t

    def run(self):
        self.loop.run(self.handle, tick=self.tick, idle=self.idle)
        self.bus.flush()
        self.log.write({"final_counts": self.counts, "audit_wm": self.audit_wm(), "ctx_wm": self.ctx_wm()})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bootstrap", required=True)
    ap.add_argument("--instance", required=True)
    ap.add_argument("--group", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--descriptor-sha256", required=True)
    ap.add_argument("--replay", action="store_true")
    Normalizer(ap.parse_args()).run()


if __name__ == "__main__":
    main()
