"""Time-indexed cluster state from context.cluster.v0.

Answers "as known at t": the latest observation of an object whose
observation (knowledge) time is at or before t. Observation time is when the
state became known, not when it changed (context.proto), so a lookup never
uses a state observed after the event it explains.
"""
import bisect
from collections import defaultdict

from microtrace.v0 import context_pb2

from mtcore.agents.events import ts_ns

CT = context_pb2.ChangeType
DELETED = CT.Value("DELETED")


class Obs:
    __slots__ = ("t", "o")

    def __init__(self, t, o):
        self.t, self.o = t, o


class ContextHistory:
    def __init__(self):
        self.by_uid = defaultdict(list)     # uid -> [Obs] sorted by t
        self.times = defaultdict(list)      # uid -> [t] parallel to by_uid
        self.watch_gaps = []                # (api_group, resource, namespace, lo, hi)
        self.seen = set()

    def add_observation(self, o, logical_id=None):
        ident = logical_id or (o.uid, o.resource_version, o.change_type, o.watch_stream_id, o.watch_stream_seq)
        if ident in self.seen or not o.uid:
            return False
        self.seen.add(ident)
        t = ts_ns(o.observed_time)
        if t is None:
            return False
        i = bisect.bisect_right(self.times[o.uid], t)
        self.times[o.uid].insert(i, t)
        self.by_uid[o.uid].insert(i, Obs(t, o))
        return True

    def add_watch_gap(self, g):
        self.watch_gaps.append((g.api_group, g.resource, g.namespace, ts_ns(g.gap_start), ts_ns(g.gap_end)))

    # objects ----------------------------------------------------------
    def at(self, uid, t):
        """Latest observation of uid known at t, or None (also None if deleted)."""
        ts = self.times.get(uid)
        if not ts:
            return None
        i = bisect.bisect_right(ts, t) - 1
        if i < 0:
            return None
        o = self.by_uid[uid][i].o
        return None if o.change_type == DELETED else o

    def ever_seen(self, uid):
        return bool(self.times.get(uid))

    def pod(self, uid, t):
        o = self.at(uid, t)
        return o if o is not None and o.WhichOneof("summary") == "pod" else None

    def container(self, pod_uid, name, t):
        o = self.pod(pod_uid, t)
        if o is None:
            return None
        for c in o.pod.containers:
            if c.name == name:
                return c
        return None

    def workload(self, pod_uid, t):
        """Owning workload name (first owner reference), or None."""
        o = self.pod(pod_uid, t)
        if o is None or not o.pod.owners:
            return None
        return o.pod.owners[0].name or None

    def rbac_objects(self, t):
        """Every RBAC object state known at t: {uid: ObjectObservation}."""
        out = {}
        for uid in self.by_uid:
            o = self.at(uid, t)
            if o is not None and o.WhichOneof("summary") == "rbac":
                out[uid] = o
        return out

    def history(self, uid):
        return [x.o for x in self.by_uid.get(uid, [])]

    def watch_gap_overlaps(self, api_group, lo, hi, resources=None):
        for g_group, g_res, _ns, glo, ghi in self.watch_gaps:
            if g_group != api_group or (resources is not None and g_res not in resources):
                continue
            if (ghi is None or ghi >= lo) and (glo is None or glo <= hi):
                return True
        return False
