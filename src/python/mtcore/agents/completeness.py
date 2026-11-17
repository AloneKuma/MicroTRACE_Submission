"""Index of known observation gaps (source.completeness.v0 and record gaps).

Rulebook common abstention: a Completeness gap overlapping the rule's window on
a required input (DROPPED_BEFORE, TRUNCATED, SOURCE_IDLE, POLICY_EXCLUDED,
DELIVERY_UNKNOWN) means "no finding". An unset interval bound is open-ended.
A gap that names no source covers every source. Scope "node=<id>/..." limits
an eBPF gap to that node's events (the shipper's node ID is the eBPF node_id).
A gap whose own scope is "family=<f1>,<f2>" (probes not attached for those
eBPF event families) covers only a query that reads one of them: the rule's
required input families (Rule.families), or the families a witness check
reads. A query that names no families is covered, as before.
A gap whose scope also carries "keys=<k1>|<k2>" (2026-11-17, scoped loss: the
witness keys of the records it lost, mtcore.orchestrator.keys.loss_keys) covers
only a query that names one of those keys; a query that names no keys (every
agent rule) and a gap without keys behave as before.
A source-less node gap (the receiver's SOURCE_IDLE) covers what that node
ships: with a shipped-sources declaration (params `shipped_sources`), its eBPF
events and the other sources declared for it; without one, every source.

Open-ended gaps (no end time) are closed in two ways:
- a later record for the same source, scope, reason and start that has an
  end (the receiver's closing SOURCE_IDLE record, ship-contract.md);
- the next event the agent sees from that node and source after the gap's
  start: eBPF events match by node; other sources carry no shipping node, so
  an event of the same source closes that source's gap, and a gap that names
  no source is closed only by an eBPF event of its node. The index keeps the
  event times it has seen, so the end is the same whether the event arrives
  before or after the gap record. Windows are evaluated after the watermark,
  by which time every on-time event has been seen, so the result does not
  depend on arrival order (late events excepted).
"""
import bisect
import re
from collections import defaultdict

from microtrace.v0 import common_pb2, stream_pb2

from mtcore.agents.events import ts_ns

G = common_pb2.GapReason
ABSTAIN_REASONS = {G.Value("DROPPED_BEFORE"), G.Value("TRUNCATED"), G.Value("SOURCE_IDLE"),
                   G.Value("POLICY_EXCLUDED"), G.Value("DELIVERY_UNESTABLISHED")}
SRC = common_pb2.Source
EBPF, UNSPEC = SRC.Value("EBPF"), SRC.Value("SOURCE_UNSPECIFIED")
_NODE = re.compile(r"(?:^|/)node=([^/]+)")
_FAMILY = re.compile(r"(?:^|/)family=([^/]+)")
_KEYS = re.compile(r"(?:^|/)keys=([^/]*)")


def _families(scope):
    """eBPF event families a gap's own scope names, or None (all)."""
    m = _FAMILY.search(scope or "")
    return frozenset(f for f in m.group(1).split(",") if f) if m else None


def _loss_keys(scope):
    """Witness keys of the lost records a gap's own scope names, or None (unknown: any)."""
    m = _KEYS.search(scope or "")
    return frozenset(k for k in m.group(1).split("|") if k) if m else None


class _Gap:
    __slots__ = ("source", "node", "scope", "lo", "hi", "reason", "closed_at", "families", "keys")

    def __init__(self, source, node, scope, lo, hi, reason, families=None, keys=None):
        self.source, self.node, self.scope, self.lo, self.hi, self.reason = source, node, scope, lo, hi, reason
        self.families = families     # frozenset of eBPF families, or None (every family)
        self.keys = keys             # frozenset of loss keys of the lost records, or None (unknown)
        self.closed_at = None        # end found from a later event (open gaps only)

    @property
    def end(self):
        return self.hi if self.hi is not None else self.closed_at

    def overlaps(self, lo, hi, unc=0):
        """Does the gap meet window [lo, hi] widened by clock uncertainty unc?
        A recorded end is inclusive (the last lost record may lie on it). An
        end found from a delivered event is exclusive and is compared with the
        unwidened window: that event and the lost ones share one node clock."""
        if self.hi is not None:
            after_start = self.hi >= lo - unc
        elif self.closed_at is not None:
            after_start = self.closed_at > lo
        else:
            after_start = True
        return after_start and (self.lo is None or self.lo <= hi + unc)


BUCKET_NS = 60 * 10**9      # time buckets of the bounded-gap index (lookup speed only)
MAX_GAP_BUCKETS = 1024      # a longer bounded gap is checked on every query instead
MAX_QUERY_BUCKETS = 4096    # a longer query window scans every gap instead


class GapIndex:
    def __init__(self, shipped=None):
        """shipped: node ID (or "default") -> set of Source values that node's
        shipper carries (Params.shipped_sources); None when undeclared."""
        self.shipped = shipped
        self.gaps = []
        self.open = defaultdict(list)    # (source, scope, reason, start) -> gaps with no recorded end
        self.seen = set()
        self.times = defaultdict(list)   # (source, eBPF node or None) -> sorted event times
        # Lookup index (2026-11-17; transit loss adds thousands of gaps and query() scanned them all
        # on every rule evaluation). Gaps bounded on both sides when added go into the time buckets
        # they span; every other gap (open start or end, closed later, or very long) is checked on
        # every query, exactly as before. query() applies the same per-gap checks to the candidates,
        # and a gap can overlap a window only if they share a bucket, so its result is unchanged.
        self._buckets = defaultdict(list)    # bucket number -> bounded gaps spanning it
        self._always = []                    # gaps checked on every query
        self._bounded = []                   # gaps held in the buckets

    def add_source_completeness(self, sc, logical_id=None):
        """Index one SourceCompleteness; returns False for a duplicate."""
        ident = logical_id or sc.SerializeToString(deterministic=True)
        if ident in self.seen:
            return False
        self.seen.add(ident)
        m = _NODE.search(sc.scope)
        node = m.group(1) if m else None
        lo, hi = ts_ns(sc.interval_start), ts_ns(sc.interval_end)
        if sc.status == stream_pb2.CompletenessStatus.Value("DELIVERY_UNKNOWN"):
            self._add(_Gap(sc.source, node, sc.scope, lo, hi, G.Value("DELIVERY_UNESTABLISHED")))
        for g in sc.gaps:
            glo = ts_ns(getattr(g, "from")) if g.HasField("from") else lo
            ghi = ts_ns(g.to) if g.HasField("to") else hi
            if ghi is not None and self._close(sc.source, sc.scope, g.reason, glo, ghi):
                continue
            self._add(_Gap(sc.source, node, sc.scope, glo, ghi, g.reason, _families(g.scope), _loss_keys(g.scope)))
        return True

    def _add(self, g):
        self.gaps.append(g)
        if g.hi is None:
            self.open[(g.source, g.scope, g.reason, g.lo)].append(g)
        self._index(g)

    def _index(self, g):
        if g.lo is None or g.hi is None or g.hi < g.lo:
            self._always.append(g)
            return
        b0, b1 = g.lo // BUCKET_NS, g.hi // BUCKET_NS
        if b1 - b0 >= MAX_GAP_BUCKETS:
            self._always.append(g)
            return
        self._bounded.append(g)
        for b in range(b0, b1 + 1):
            self._buckets[b].append(g)

    def _candidates(self, lo, hi, unc):
        """Every gap that may overlap [lo, hi] widened by unc (query() still checks each). A bucketed
        gap is bounded, so Gap.overlaps reduces to the two comparisons below: those outside the
        window are left out here, the rest go to query() unchanged."""
        if lo is None or hi is None:
            return self.gaps
        wlo, whi = lo - unc, hi + unc
        b0, b1 = wlo // BUCKET_NS, whi // BUCKET_NS
        if b1 - b0 >= MAX_QUERY_BUCKETS or b1 < b0:
            return self.gaps
        out, ids = list(self._always), set()
        for b in range(b0, b1 + 1):
            for g in self._buckets.get(b, ()):
                if g.hi < wlo or g.lo > whi:
                    continue
                if g.lo // BUCKET_NS != g.hi // BUCKET_NS:      # spans buckets: may repeat
                    if id(g) in ids:
                        continue
                    ids.add(id(g))
                out.append(g)
        return out

    def _close(self, source, scope, reason, lo, hi):
        """A bounded record for an open gap (same source, scope, reason, start)
        ends it; returns True if one was closed. The open gaps are indexed by
        that key: a scan of every gap per record made applying a side-topic
        backlog quadratic (minutes for a restarted agent re-reading ~80k
        completeness records, step 8f)."""
        found = self.open.pop((source, scope, reason, lo), [])
        for g in found:
            g.hi = hi
        return bool(found)

    def observe(self, source, node, t):
        """Record an event of source at time t (node: its eBPF node, else None)."""
        if t is not None:
            bisect.insort(self.times[(source, node)], t)

    def _keys(self, g):
        """History keys whose events end open gap g."""
        if g.source == UNSPEC:      # a node's idle gap: only events placed on that node
            return [k for k in self.times if k[1] is not None and (g.node is None or k[1] == g.node)]
        if g.source == EBPF:
            return [k for k in self.times if k[0] == EBPF and (g.node is None or k[1] == g.node)]
        return [(g.source, None)]

    def _settle(self, g):
        """End of open gap g from the event history: the first event after its start."""
        if g.hi is not None:
            return
        best = g.closed_at
        for k in self._keys(g):
            ts = self.times.get(k)
            if not ts:
                continue
            i = bisect.bisect_right(ts, g.lo) if g.lo is not None else 0
            if i < len(ts) and (best is None or ts[i] < best):
                best = ts[i]
        g.closed_at = best

    def prune(self, before_ns):
        """Forget gaps that ended before before_ns (open-ended gaps stay)."""
        for g in self.gaps:          # fix every end before its events are forgotten
            self._settle(g)
        self.gaps = [g for g in self.gaps if g.end is None or g.end >= before_ns]
        self.open = defaultdict(list)
        for g in self.gaps:
            if g.hi is None:
                self.open[(g.source, g.scope, g.reason, g.lo)].append(g)
        bounded = {id(g) for g in self._bounded}
        self._buckets, self._always, self._bounded = defaultdict(list), [], []
        for g in self.gaps:              # keep each gap where it was: bounded ones stay in buckets
            if id(g) in bounded:
                self._index(g)
            else:
                self._always.append(g)
        for k in list(self.times):
            ts = self.times[k]
            del ts[:bisect.bisect_left(ts, before_ns)]
            if not ts:
                del self.times[k]

    def query(self, sources, nodes, lo, hi, unc=0, families=None, keys=None):
        """Abstaining gap reasons overlapping [lo, hi] (widened by unc) for the given sources.

        nodes: eBPF node IDs the evaluation used (None if unknown/irrelevant).
        families: eBPF event families the evaluation reads (None: all), so a
        family-scoped gap on other families does not apply.
        keys: loss keys the evaluation depends on (None: any), so a key-scoped
        gap whose lost records carry none of them does not apply.
        """
        out = set()
        for g in self._candidates(lo, hi, unc):
            if g.reason not in ABSTAIN_REASONS:
                continue
            if g.families is not None and families is not None and not (g.families & families):
                continue
            if g.keys is not None and keys is not None and not (g.keys & keys):
                continue
            self._settle(g)
            if not g.overlaps(lo, hi, unc):
                continue
            if g.source != UNSPEC and g.source not in sources:
                continue
            carried = self._carried(g)
            if carried is not None:
                if not self._node_gap_hits(g, carried, sources, nodes):
                    continue
            else:
                ebpf_only = g.source == EBPF or (g.source == UNSPEC and sources <= {EBPF})
                if ebpf_only and nodes and g.node is not None and g.node not in nodes:
                    continue
            out.add(g.reason)
        return sorted(out)

    def _carried(self, g):
        """Sources a source-less node gap covers, from the shipped-sources
        declaration (None: no declaration applies, so it covers every source)."""
        if g.source != UNSPEC or g.node is None or self.shipped is None:
            return None
        return self.shipped.get(g.node, self.shipped.get("default"))

    @staticmethod
    def _node_gap_hits(g, carried, sources, nodes):
        """A node's idle gap stops only what that node ships: its eBPF events
        (when the evaluation's eBPF nodes are unknown, any), and each other
        source the node is declared to ship."""
        if EBPF in sources and EBPF in carried and (not nodes or g.node in nodes):
            return True
        return any(s in carried for s in sources if s != EBPF)


def record_abstain_reasons(evs):
    """Abstaining gaps declared on the input records themselves."""
    out = set()
    for ev in evs:
        for g in ev.record_gaps():
            if g.reason in ABSTAIN_REASONS:
                out.add(g.reason)
    return sorted(out)
