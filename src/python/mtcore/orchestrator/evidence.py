"""Evidence index: the normalized events behind findings, by event ID.

Findings carry only input_event_ids; witness checks need each event's
corrected time, clock uncertainty, off-node ingest time, node and boot,
node_seq, lineage, flow and other join keys. The orchestrator therefore
reads norm.events.v0 and keeps every event until no finding that could still
be linked can cite it: an event older than the processing frontier minus the
largest posting horizon (W_w + eps_bar + 2A) and the A slack between a
finding and its events is dropped (proofs/README.md, Lemma 1).

Events are held as agents.events.Ev, so field access matches the agents'.
Every CONNECT is also indexed by its connection tuple, finding input or not,
so a second connection on a reused tuple can contradict a flow witness.
"""
from mtcore.agents.events import Ev, ts_ns
from mtcore.orchestrator.keys import flow_key


class EvidenceIndex:
    def __init__(self):
        self.events = {}         # event ID -> Ev
        self.connects = {}       # flow tuple -> [Ev] (CONNECT events)
        self.stats = {"events": 0, "duplicates": 0, "evicted": 0}

    def add(self, env, topic="norm.events.v0", partition=0, offset=0):
        """Index one NormalizedEvent envelope; returns False for a duplicate."""
        ev = Ev(env, topic, partition, offset)
        eid = ev.id
        if not eid or eid in self.events:
            self.stats["duplicates"] += 1
            return False
        self.events[eid] = ev
        self.stats["events"] += 1
        fk, role = flow_key(ev)
        if fk is not None and role == "source":
            self.connects.setdefault(fk, []).append(ev)
        return True

    def get(self, event_id):
        return self.events.get(event_id)

    def for_finding(self, finding):
        """(present Evs in input order, missing event IDs)."""
        have, missing = [], []
        for eid in finding.input_event_ids:
            ev = self.events.get(eid)
            (have if ev is not None else missing).append(ev if ev is not None else eid)
        return have, missing

    def evict(self, before_ns):
        """Drop events whose event time is before before_ns (unknown time: kept
        until an explicit end of input)."""
        drop = [k for k, e in self.events.items() if e.t is not None and e.t < before_ns]
        for k in drop:
            del self.events[k]
        for fk in list(self.connects):
            kept = [e for e in self.connects[fk] if e.t is None or e.t >= before_ns]
            if kept:
                self.connects[fk] = kept
            else:
                del self.connects[fk]
        self.stats["evicted"] += len(drop)
        return len(drop)


def ingest_ns(ev):
    """Off-node receipt time (TimeInfo.ingest_time), used for node-trust epochs."""
    return ts_ns(ev.ne.time.ingest_time) if ev.ne.HasField("time") and ev.ne.time.HasField("ingest_time") else None
