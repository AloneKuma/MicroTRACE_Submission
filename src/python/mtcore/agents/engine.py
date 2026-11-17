"""Agent engine: windows, watermark, abstention, and emission.

Pure Python, no Kafka. The online runner (run.py) and the offline replay feed
it the same envelopes, so both produce the same findings and evaluations.

Window modes (parameter register, "Window alignment"):
- instant:  one evaluation per input event, window [t, t].
- tumbling: count rules; windows [k*W, (k+1)*W) aligned to the Unix epoch.
- anchored: join rules; an anchor event at t opens [t, t+W].
Every window is evaluated once, when the watermark passes its end, so late
completeness and context records are seen first. Events older than the
flushed watermark are counted as late and not evaluated.

Knowledge time (step 7g): a completeness or context record fed with its
receipt time (LogAppendTime) is known to a window only if received no later
than knowledge_time(hi + 1), the emitted_at of the newest of the heartbeats
(one per input partition, the first in log order to reach the threshold)
that let the watermark pass the window's end. It does not depend on how far
the side topics had been read, so a restarted agent re-reading them to the
end evaluates its windows as the uninterrupted run did. Records without a
receipt time (offline) are known when read.
"""
import heapq
from collections import defaultdict
from dataclasses import dataclass, field

from microtrace.v0 import common_pb2, envelope_pb2

from mtcore.agents import emit, routing
from mtcore.agents.completeness import GapIndex, record_abstain_reasons
from mtcore.agents.context import ContextHistory
from mtcore.agents.events import Ev, ts_ns

GR = common_pb2.GapReason
SRC = common_pb2.Source
KIND = envelope_pb2.RecordKind
INF = 1 << 62


@dataclass
class FindingSpec:
    entities: list = field(default_factory=list)
    attributes: dict = field(default_factory=dict)
    artifacts: list = field(default_factory=list)      # parameter-set artifact names used
    gaps: list = field(default_factory=list)           # Gap messages carried on the finding
    action_id: str = None
    event_start: int = None
    event_end: int = None
    detection_path: str = "PREDICATE"
    ml_status: str = "ML_NOT_APPLICABLE"
    anomaly_score: float = None
    model_version: str = None
    inputs: list = None                                 # evidence events; default: all window inputs


@dataclass
class Outcome:
    outcome: int
    reasons: list = field(default_factory=list)        # GapReason values (ABSTAINED)
    features: dict = field(default_factory=dict)
    finding: FindingSpec = None
    inputs: list = None                                 # events evaluated; default: window events


def fired(spec, features=None, inputs=None):
    return Outcome(emit.FIRED, features=features or {}, finding=spec, inputs=inputs)


def not_fired(features=None, inputs=None):
    return Outcome(emit.NOT_FIRED, features=features or {}, inputs=inputs)


def abstain(*reasons, features=None, inputs=None):
    return Outcome(emit.ABSTAINED, reasons=[GR.Value(r) if isinstance(r, str) else r for r in reasons],
                   features=features or {}, inputs=inputs)


class Rule:
    """One finding type. Subclasses set the class attributes and evaluate()."""
    id = ""
    name = ""
    agent = ""
    tactic = None                 # rulebook primary_tactic, or None (unmapped)
    topic = ""
    sources = frozenset()         # Source values the rule requires (completeness)
    families = None               # eBPF event families it requires (rulebook inputs); None: all
    mode = "instant"              # instant | tumbling | anchored
    window = None                 # parameter symbol for tumbling/anchored
    lookback = None               # anchored: parameter symbol for the window's reach before the anchor
    gate = None                   # parameter symbol for conditional types

    @property
    def slot(self):
        """Engine state name; two rule objects may share a finding type (G1a)."""
        return type(self).__name__

    def accepts(self, ev):
        return True

    def anchor(self, ev, ctx):
        """anchored mode: does ev open a window?"""
        return True

    def window_ns(self, ctx):
        return ctx.params.window_ns(self.window) if self.window else 0

    def lookback_ns(self, ctx):
        return ctx.params.window_ns(self.lookback) if self.lookback else 0

    def evaluate(self, ctx, key, lo, hi, evs):
        raise NotImplementedError


class Ctx:
    """What a rule may read: parameters, context history, gaps, ML scorer."""

    def __init__(self, params, scorer=None):
        self.params = params
        self.context = ContextHistory()
        self.gaps = GapIndex(params.shipped_sources())
        self.scorer = scorer
        self.fired_keys = defaultdict(list)   # (rule id, key hex) -> [(t, finding_id)]
        # Per-key memory a rule keeps across instant evaluations (C1b: a
        # lineage seen outside host namespaces). Windows are evaluated in
        # event-time order, so it does not depend on arrival order.
        self.memo = {}
        self.anchor = None


class Engine:
    def __init__(self, rules, params, scorer=None, input_partitions=None, auto_advance=True):
        self.rules = list(rules)
        self.ctx = Ctx(params, scorer)
        self.params = params
        # The watermark waits only on topics with an active rule: a topic whose
        # rules are all gated off may have no producer at all
        # (credential.instance.v0 while G_G1b is off).
        self.topics = sorted({r.topic for r in self.rules if not r.gate or params.gate(r.gate)})
        # topic -> partition count; the watermark needs a heartbeat on each.
        self.input_partitions = input_partitions or {}
        self.hb = {}                                   # (topic, partition) -> low watermark ns
        self.hb_steps = defaultdict(list)              # (topic, partition) -> [(low, emitted, offset)] at each rise
        self.side = []                                 # heap of (receipt, seq, kind, payload, logical id)
        self.side_seq = 0
        self.known = -INF                              # side records received up to here are applied
        self.watermark = None                          # flushed event-time watermark
        self.buffers = defaultdict(lambda: defaultdict(list))   # rule id -> key -> [Ev]
        self.pending = {}                              # window id -> (hi, lo, rule, key, anchor)
        self.seen = {}                                 # (topic, logical id) -> event time
        self.stats = defaultdict(int)
        self.out = []                                  # (topic, key bytes, Envelope)
        # The online runner advances explicitly, after the completeness and
        # context topics have caught up; offline replay advances on heartbeats.
        self.auto_advance = auto_advance
        self.max_window_ns = max([r.window_ns(self.ctx) + r.lookback_ns(self.ctx) for r in self.rules if r.window]
                                 + [0])
        # slot -> how far before the watermark a future anchor may still reach
        self.reach = {r.slot: r.lookback_ns(self.ctx) for r in self.rules if r.mode == "anchored"}

    # input --------------------------------------------------------------
    def feed(self, env, topic, partition=0, offset=0, key=None, receipt_ns=None):
        """Accept one envelope read from topic (key: its Kafka key bytes, if
        known; receipt_ns: LogAppendTime of a side record, module doc);
        results accumulate in self.out."""
        if env.schema_major != emit.SCHEMA_MAJOR:
            self.stats["schema_major_rejected"] += 1
            return
        kind = env.WhichOneof("payload")
        if kind == "heartbeat":
            self._heartbeat(topic, env.heartbeat, offset)
            return
        if kind in ("source_completeness", "context_observation", "context_watch_gap"):
            if receipt_ns is None:
                self._apply_side(kind, getattr(env, kind), env.logical_id or None)
            else:
                self.side_seq += 1
                heapq.heappush(self.side, (receipt_ns, self.side_seq, kind, getattr(env, kind), env.logical_id or None))
                if receipt_ns <= self.known:
                    self.learn(self.known)
            return
        if kind != "normalized_event":
            self.stats["ignored_" + kind] += 1
            return
        # One event is restreamed to several agent topics; a duplicate is the
        # same logical ID on the same topic (replay, receiver retry).
        ident = (topic, env.logical_id or env.normalized_event.event_id)
        if ident in self.seen:
            self.stats["duplicates"] += 1
            return
        ev = Ev(env, topic, partition, offset)
        self.seen[ident] = ev.t if ev.t is not None else 0
        self.ctx.gaps.observe(ev.source, ev.node, ev.t)
        if ev.kind == "context":
            self.ctx.context.add_observation(ev.ne.context)
        for rule in self.rules:
            if rule.topic == topic and rule.accepts(ev):
                self._place(rule, ev, key)

    def _place(self, rule, ev, key=None):
        if key is None:
            key = routing.key_bytes(rule.topic, ev)
        if key is None:
            self.stats[f"{rule.id}:unroutable"] += 1
            return
        if ev.t is None:
            self._evaluate(rule, key, None, None, [ev], forced=abstain("FIELD_ABSENT"))
            return
        if self.watermark is not None and ev.t < self.watermark:
            self.stats[f"{rule.id}:late"] += 1
            return
        self.buffers[rule.slot][key].append(ev)
        if rule.mode == "instant":
            self.pending[(rule.slot, key, ev.t, ev.id)] = (ev.t, ev.t, rule, key, ev)
        elif rule.mode == "tumbling":
            w = rule.window_ns(self.ctx)
            lo = (ev.t // w) * w
            self.pending.setdefault((rule.slot, key, lo, ""), (lo + w - 1, lo, rule, key, None))
        elif rule.mode == "anchored" and rule.anchor(ev, self.ctx):
            w = rule.window_ns(self.ctx)
            self.pending[(rule.slot, key, ev.t, ev.id)] = (ev.t + w, ev.t - rule.lookback_ns(self.ctx), rule, key, ev)
        # Windows are evaluated once the watermark is past their end (hi < wm),
        # and only events with t < wm are late, so an on-time event never
        # lands in a window that was already evaluated. A look-back reaches
        # only buffered events: _evict keeps them for as long as an on-time
        # anchor could still reach them.

    def _apply_side(self, kind, msg, logical_id):
        if kind == "source_completeness":
            self.ctx.gaps.add_source_completeness(msg, logical_id)
        elif kind == "context_observation":
            self.ctx.context.add_observation(msg, logical_id)
        else:
            self.ctx.context.add_watch_gap(msg)

    def learn(self, k):
        """Apply every buffered side record received at or before k."""
        self.known = max(self.known, k)
        while self.side and self.side[0][0] <= self.known:
            _r, _s, kind, msg, lid = heapq.heappop(self.side)
            self._apply_side(kind, msg, lid)

    def knowledge_time(self, w):
        """Archived time of the watermark update that brought the watermark
        to w: per input partition the emitted_at of the first heartbeat whose
        low reaches w + lateness, the newest over partitions. INF (all read
        side records known) when a partition has none: end of input, offline."""
        if w >= INF:
            return INF
        target, best = w + self.params.lateness_ns, None
        for topic in self.topics:
            for p in range(self.input_partitions.get(topic, 0)):
                first = next((e for low, e, _o in self.hb_steps.get((topic, p), ()) if low >= target), None)
                if first is None:
                    return INF
                best = first if best is None else max(best, first)
        return INF if best is None else best

    def _heartbeat(self, topic, hb, offset=0):
        if topic not in self.topics:
            return
        t = ts_ns(hb.low_watermark) or 0
        k = (topic, hb.partition)
        if t > self.hb.get(k, 0):
            self.hb_steps[k].append((t, ts_ns(hb.emitted_at) or 0, offset))
        self.hb[k] = max(self.hb.get(k, 0), t)
        if self.auto_advance:
            self.advance()

    def input_watermark(self):
        """Minimum over every input partition, minus lateness; None until all report."""
        lows = []
        for topic in self.topics:
            n = self.input_partitions.get(topic)
            if n is None:
                return None
            for p in range(n):
                if (topic, p) not in self.hb:
                    return None
                lows.append(self.hb[(topic, p)])
        return min(lows) - self.params.lateness_ns if lows else None

    def advance(self, wm=None):
        """Flush every window whose end is at or before the watermark."""
        wm = self.input_watermark() if wm is None else wm
        if wm is None or (self.watermark is not None and wm <= self.watermark):
            return
        ready = sorted((item for item in self.pending.items() if item[1][0] < wm),
                       key=lambda it: (it[1][0], it[1][1], it[1][2].id, it[1][2].slot, it[1][3], it[0][3]))
        for wid, (hi, lo, rule, key, anchor) in ready:
            del self.pending[wid]
            evs = [anchor] if rule.mode == "instant" else [
                e for e in self.buffers[rule.slot][key] if lo <= e.t <= hi]
            self.learn(self.knowledge_time(hi + 1))      # the update that passed hi
            self._evaluate(rule, key, lo, hi, evs, anchor=anchor)
        self.watermark = wm
        self.learn(self.knowledge_time(wm))
        cut = wm + self.params.lateness_ns               # later windows end at or after wm
        for k in self.hb_steps:
            self.hb_steps[k] = [s for s in self.hb_steps[k] if s[0] > cut]
        self._evict(wm)

    def output_low_watermark(self):
        """Promise for heartbeats on the output topics: no later finding or
        evaluation has an event time before this (None until known)."""
        if self.watermark is None:
            return None
        open_lo = [lo for _hi, lo, _r, _k, _a in self.pending.values()]
        return min([self.watermark] + open_lo)

    def needed_offsets(self):
        """(topic, partition) -> oldest offset an open window still needs:
        its buffered events, and the heartbeats that will set its knowledge
        time (every rise above the watermark). Committing no further than
        this lets a restarted agent rebuild its windows from Kafka and
        evaluate them with the same knowledge (design-spec 5, replay rule)."""
        out = {}
        for keys in self.buffers.values():
            for evs in keys.values():
                for e in evs:
                    k = (e.topic, e.partition)
                    out[k] = min(out.get(k, e.offset), e.offset)
        for k, steps in self.hb_steps.items():
            for _low, _e, off in steps[:1]:
                out[k] = min(out.get(k, off), off)
        return out

    def finish(self):
        """End of input: flush every open window (offline replay)."""
        self.advance(INF)

    def _evict(self, wm):
        """Drop buffered events no open window can still use, and bound the
        dedup set and gap index (anything older than the watermark is late
        and no longer evaluated)."""
        self.seen = {k: t for k, t in self.seen.items() if t >= wm}
        self.ctx.gaps.prune(wm - 2 * self.max_window_ns - self.params.lateness_ns)
        for rid, keys in self.buffers.items():
            open_lo = {}
            for hi, lo, rule, key, _a in self.pending.values():
                if rule.slot == rid:
                    open_lo[key] = min(open_lo.get(key, INF), lo)
            for key in list(keys):
                # Keep events an open window or a not-yet-arrived anchor
                # (t >= wm, reaching back by its look-back) may still use.
                keep = min(open_lo.get(key, INF), wm - self.reach.get(rid, 0))
                keys[key] = [e for e in keys[key] if e.t >= keep]
                if not keys[key]:
                    del keys[key]

    # evaluation ------------------------------------------------------------
    def _evaluate(self, rule, key, lo, hi, evs, anchor=None, forced=None):
        ctx = self.ctx
        key_hex = key.hex()
        if forced is not None:
            res = forced
        elif rule.gate and not ctx.params.gate(rule.gate):
            res = abstain("CONDITIONAL_JOIN_UNVALIDATED")
        else:
            reasons = record_abstain_reasons(evs)
            unc = max((e.unc for e in evs), default=0)
            nodes = {e.node for e in evs if e.node}
            reasons += ctx.gaps.query(set(rule.sources), nodes or None, lo, hi, unc, rule.families)
            if reasons:
                res = abstain(*sorted(set(reasons)))
            else:
                ctx.anchor = anchor      # anchored mode: the event that opened the window
                res = rule.evaluate(ctx, key, lo, hi, evs) if rule.mode != "instant" else \
                    rule.evaluate(ctx, key, lo, hi, [anchor or evs[0]])
        if res is None:
            return      # the rule has nothing to evaluate here (G1a's model view with ML off)
        inputs = res.inputs if res.inputs is not None else evs
        fid = None
        if res.outcome == emit.FIRED:
            spec = res.finding
            fin = spec.inputs if spec.inputs is not None else inputs
            topic, k, env = emit.build_finding(rule, spec, fin, self.params)
            fid = env.finding.finding_id
            ctx.fired_keys[(rule.id, key_hex)].append((hi, fid))
            self.out.append((topic, k, env))
            self.stats[f"{rule.id}:fired"] += 1
        elif res.outcome == emit.ABSTAINED:
            self.stats[f"{rule.id}:abstained"] += 1
        else:
            self.stats[f"{rule.id}:not_fired"] += 1
        self.out.append(emit.build_evaluation(rule, key_hex, lo, hi, res.outcome, res.reasons,
                                              inputs, res.features, fid, self.params))

    def drain(self):
        out, self.out = self.out, []
        return out

    def open_state(self):
        """Counts of open state (failpoint summaries, Exp. 5)."""
        return {"pending_windows": len(self.pending),
                "buffered_events": sum(len(v) for keys in self.buffers.values() for v in keys.values())}


def run_offline(rules, params, records, scorer=None):
    """Evaluate records [(topic, Envelope[, key])] in order, then flush everything.

    Returns (findings, evaluations, stats) with findings and evaluations as
    lists of message objects in emission order.
    """
    eng = Engine(rules, params, scorer)
    for rec in records:
        topic, env = rec[0], rec[1]
        eng.feed(env, topic, key=rec[2] if len(rec) > 2 else None)
    eng.finish()
    findings, evaluations = [], []
    for _topic, _key, env in eng.drain():
        if env.HasField("finding"):
            findings.append(env.finding)
        else:
            evaluations.append(env.rule_evaluation)
    return findings, evaluations, eng.stats
