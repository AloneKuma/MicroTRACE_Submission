"""Pod image history from context.cluster.v0, for enabling witnesses.

The orchestrator reads cluster context (decided 2026-10-09) to tie a running
container to the image digest an admission decision named: a Pod watch
observation lists each container's image_id. As in the agents' context
history, a lookup at time t uses only observations known at or before t
(observation time is knowledge time), so a later observation never explains
an earlier event. Each answer carries the observation's event ID, which
becomes witness evidence.
"""
import bisect

from microtrace.v0 import context_pb2

from mtcore.agents.events import ts_ns

DELETED = context_pb2.ChangeType.Value("DELETED")


class PodImages:
    def __init__(self):
        self.times = {}        # pod UID -> [observed time] sorted
        self.obs = {}          # pod UID -> [(observation, event ID)] parallel to times
        self.seen = set()

    def add(self, env):
        """Index one ContextObservation envelope; returns False if not a new Pod observation."""
        o = env.context_observation
        ident = env.logical_id or (o.uid, o.resource_version, o.change_type, o.watch_stream_seq)
        t = ts_ns(o.observed_time)
        if ident in self.seen or not o.uid or t is None or o.WhichOneof("summary") not in ("pod", None):
            return False
        self.seen.add(ident)
        ts = self.times.setdefault(o.uid, [])
        i = bisect.bisect_right(ts, t)
        ts.insert(i, t)
        self.obs.setdefault(o.uid, []).insert(i, (o, env.logical_id))
        return True

    def image_at(self, pod_uid, container_name, t):
        """(image digest, observation event ID) for the container as known at
        t, or None (unknown, deleted, or no such container)."""
        ts = self.times.get(pod_uid)
        if not ts or t is None:
            return None
        i = bisect.bisect_right(ts, t) - 1
        if i < 0:
            return None
        o, eid = self.obs[pod_uid][i]
        if o.change_type == DELETED or o.WhichOneof("summary") != "pod":
            return None
        for c in o.pod.containers:
            if c.name == container_name and c.image_id:
                return c.image_id, eid
        return None

    def evict(self, before_ns):
        """Keep, per Pod, the latest observation before before_ns (it still
        answers later lookups) and everything after it."""
        for uid in list(self.times):
            ts = self.times[uid]
            i = max(bisect.bisect_left(ts, before_ns) - 1, 0)
            if i:
                del ts[:i]
                del self.obs[uid][:i]
