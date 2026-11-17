"""Consumer watermark over producer heartbeats (kafka-contract.md section 4).

- Each producer instance heartbeats every partition it may write; its
  low_watermark promises no later record there with an earlier event time.
- Partition watermark = minimum over the partition's *active* instances.
- Consumer watermark = minimum over input partitions, minus the lateness
  allowance, applied here once and nowhere else (design-spec.md, sealing).
- An instance silent for longer than max_idle is excluded. Silence is
  measured on the heartbeats' emitted_at against the newest emitted_at seen
  on any input, so a replay excludes exactly what the live run excluded.
  Each exclusion is recorded so incidents open over it can say so.
- Knowledge time (step 7g). A coverage or context record counts as known at a
  decision only if its receipt time (Kafka LogAppendTime) is not after the
  archived time of the watermark update that makes the decision. That time
  is knowledge_time(w): for every instance, the emitted_at of the first
  heartbeat (in its partition's log order) whose low watermark reaches
  w + lateness; the newest of these over all instances. It is read from
  the archived heartbeats alone, so it is the same whether the consumer
  read them in one batch or many, before or after a restart. The last
  instance to reach w does not count if it had been silent for longer than
  max_idle when the others had all reached it: the watermark passed w
  without it (max-idle exclusion). Producer clocks
  and the broker clock (LogAppendTime) may disagree; the rule does not need
  them to agree. Skew moves the line between "known" and "late" by up to
  the skew, the same way on every replay: determinism, not clock accuracy,
  is the goal. A record on the late side still reaches the decision through
  the late paths (re-evaluation, amendments).
"""
from dataclasses import dataclass, field

from mtcore.agents.events import ts_ns

INF = 1 << 62


@dataclass
class _Instance:
    low: int
    emitted: int
    producer_id: str
    steps: list = field(default_factory=list)   # (low, emitted, previous emitted) at each rise of low


@dataclass(frozen=True)
class Exclusion:
    topic: str
    partition: int
    instance: str
    producer_id: str
    since: int          # emitted_at of the instance's last heartbeat


class Watermarks:
    def __init__(self, partitions, lateness_ns, max_idle_ns):
        """partitions: topic -> partition count for every input topic."""
        self.partitions = dict(partitions)
        self.lateness_ns = lateness_ns
        self.max_idle_ns = max_idle_ns
        self.slots = {}         # (topic, partition) -> {instance: _Instance}
        self.now = None         # newest emitted_at seen
        self.value = None       # watermark last returned (never moves back)
        self.pruned = None      # history forgotten for thresholds at or below this

    def observe(self, topic, hb):
        """Record one Heartbeat read from topic (ignored for non-input topics)."""
        if topic not in self.partitions:
            return
        low, emitted = ts_ns(hb.low_watermark) or 0, ts_ns(hb.emitted_at) or 0
        slot = self.slots.setdefault((topic, hb.partition), {})
        cur = slot.get(hb.producer_instance)
        if cur is None:
            slot[hb.producer_instance] = _Instance(low, emitted, hb.producer_id, [(low, emitted, None)])
        else:
            if low > cur.low:
                cur.steps.append((low, emitted, cur.emitted))
            cur.low, cur.emitted = max(cur.low, low), max(cur.emitted, emitted)
        self.now = emitted if self.now is None else max(self.now, emitted)

    def _idle(self, inst):
        return self.now - inst.emitted > self.max_idle_ns

    def partition_low(self, topic, partition):
        """Minimum low watermark over active instances; None if no instance ever
        reported; "idle" if every instance is currently excluded."""
        slot = self.slots.get((topic, partition))
        if not slot:
            return None
        lows = [i.low for i in slot.values() if not self._idle(i)]
        return min(lows) if lows else "idle"

    def watermark(self):
        """Event-time watermark (lateness applied), or None until every input
        partition has reported. Monotonic: never returns less than before."""
        lows = []
        for topic, n in sorted(self.partitions.items()):
            for p in range(n):
                low = self.partition_low(topic, p)
                if low is None:
                    return self.value
                if low != "idle":
                    lows.append(low)
        if lows:
            wm = min(lows) - self.lateness_ns
            if self.value is None or wm > self.value:
                self.value = wm
        return self.value

    def knowledge_time(self, w):
        """Archived time of the watermark update that brought the watermark
        to w (module doc), or INF when no heartbeat reaches w (end of input,
        an explicit advance, offline replay): then every side record read so
        far is known."""
        if w is None or w >= INF:
            return INF
        target = w + self.lateness_ns
        reach = []                 # (emitted, previous emitted) of each instance's first rise to the target
        for _tp, slot in sorted(self.slots.items()):
            for _name, inst in sorted(slot.items()):
                for low, emitted, prev in inst.steps:
                    if low >= target:
                        reach.append((emitted, prev))
                        break
        reach.sort()
        # The last instance to arrive was max-idle excluded, and did not hold
        # the update, if it had been silent max_idle when the others arrived.
        while len(reach) > 1 and self.max_idle_ns:
            emitted, prev = reach[-1]
            if prev is None or reach[-2][0] - prev <= self.max_idle_ns:
                break
            reach.pop()
        return reach[-1][0] if reach else INF

    def prune(self, below):
        """Forget rises to a low at or below `below` + lateness: no decision
        at a watermark above `below` can use them."""
        cut = below + self.lateness_ns
        self.pruned = below if self.pruned is None else max(self.pruned, below)
        for slot in self.slots.values():
            for inst in slot.values():
                inst.steps = [s for s in inst.steps if s[0] > cut]

    def exclusions(self):
        """Instances currently excluded by max-idle, in a stable order."""
        out = []
        for (topic, p), slot in sorted(self.slots.items()):
            for name, inst in sorted(slot.items()):
                if self._idle(inst):
                    out.append(Exclusion(topic, p, name, inst.producer_id, inst.emitted))
        return out
