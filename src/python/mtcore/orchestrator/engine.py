"""Orchestrator engine: intake, watermark and the processing order.

Pure Python, no Kafka; the Kafka runner and offline replay feed it the same
envelopes, so both make the same decisions.

- Findings are processed in corrected event-time order (event_start) with a
  stable finding-ID tie-break, never in arrival or offset order
  (kafka-contract.md section 3), once the watermark passes their time: by
  then every normalized event at or before it has been read.
- A finding re-emitted with the same ID and payload is a duplicate (agents
  re-emit after a restart; only publish_time differs). Two different
  payloads under one ID are an error and stop the engine (kafka-contract.md,
  "Logical IDs").
- The processing frontier is the event time of the last finding processed.
  Evidence older than the frontier minus the largest posting horizon and A
  can no longer support a link and is evicted.
- Input positions: every finding keeps the Kafka position of its first
  payload and of its input events, and every witness the positions of its
  contradiction events, so each incident version can state its required
  input frontier (design-spec.md section 9).
- Knowledge time (step 7g). Coverage (source.completeness.v0) and context
  (context.cluster.v0) records carry their receipt time (LogAppendTime) and
  wait in a buffer. A decision at watermark threshold w (a finding processed
  at its order time, a pair finalized at its coverage due time, a group
  sealed at its last extension) knows exactly the records received no later
  than watermarks.knowledge_time(w). advance() takes findings and due pairs
  in one threshold order and learns before each, so a run that advances in
  many steps and a replay that advances once make the same decisions. A
  record learned after its decision takes the late path: published
  witnesses are re-decided (Property 4) and sealed incidents amended.
  A record without a receipt time (offline files) is learned when read:
  the file order is then the archive.

Later build steps attach witness search (5b), admission (5c), groups and
paths (5d) and sealing (5e) to process().
"""
import heapq

from mtcore.agents.completeness import GapIndex
from mtcore.agents.events import ts_ns
from microtrace.v0 import common_pb2, envelope_pb2, stream_pb2, witness_pb2

from mtcore.orchestrator import admit, contradictions, emit, groups
from mtcore.orchestrator.context import PodImages
from mtcore.orchestrator.epochs import EpochIndex
from mtcore.orchestrator.evidence import EvidenceIndex
from mtcore.orchestrator.index import WitnessIndex
from mtcore.orchestrator.keys import BUILT, ENABLING, ENTITY_COMPAT, finding_keys
from mtcore.orchestrator.lineage import ProcessTree
from mtcore.orchestrator.seal import IncidentBook
from mtcore.orchestrator.watermark import Watermarks
from mtcore.orchestrator.witness import to_enabling_witness, to_witness

FINDINGS = "findings.v0"
NORM = "norm.events.v0"
COMPLETENESS = "source.completeness.v0"
CONTEXT = "context.cluster.v0"
CRED = "credential.instance.v0"
SCHEMA_MAJOR = 0
INF = 1 << 62


CONFIRMED = witness_pb2.WitnessStatus.Value("CONFIRMED")
UNSPEC = common_pb2.Source.Value("SOURCE_UNSPECIFIED")
IDLE = common_pb2.GapReason.Value("SOURCE_IDLE")
DELIVERY_UNKNOWN = stream_pb2.CompletenessStatus.Value("DELIVERY_UNKNOWN")


class PayloadConflict(ValueError):
    """Two different payloads arrived under one logical ID."""


def _payload_bytes(finding):
    f = type(finding)()
    f.CopyFrom(finding)
    f.ClearField("publish_time")
    return f.SerializeToString(deterministic=True)


class Engine:
    def __init__(self, oparams, input_partitions=None):
        """oparams: OrchParams; input_partitions: topic -> partition count of
        the heartbeat-bearing inputs (findings.v0, norm.events.v0 and, with
        G_G1b on, credential.instance.v0). Unknown in offline replay, where
        finish() releases everything."""
        self.p = oparams
        self.watermarks = Watermarks(input_partitions or {}, oparams.lateness_ns, oparams.max_idle_ns)
        self.evidence = EvidenceIndex()
        self.gaps = GapIndex(oparams.params.shipped_sources())
        self.findings = {}            # finding ID -> Finding (first payload kept)
        self._payload = {}            # finding ID -> payload bytes, for the conflict check
        self.pending = {}             # finding ID -> order time, awaiting the watermark
        self.processed = []           # finding IDs in processing order
        self.pos = {}                 # finding ID -> ("topic/partition", offset) of its first payload
        self.need = {}                # finding ID -> {"topic/partition": offset} it cites (itself, its inputs)
        self.nodes_of = {}            # finding ID -> sorted (node, boot) of its eBPF inputs
        self.wit_need = {}            # witness ID -> {"topic/partition": offset} of its contradiction events
        self.frontier = None          # event time of the last finding processed
        self.watermark = None
        # witness search (5b)
        self.enabled = tuple(w for w in BUILT if oparams.gate(w))
        if oparams.ablated("no_witness"):        # A2: entity/time compatibility replaces the witnesses
            self.enabled = tuple(w for w in self.enabled if w in ENABLING) + (ENTITY_COMPAT,)
        self.index = WitnessIndex(oparams.horizon_ns)
        self.keys = {}                # finding ID -> {(type, key): KeyEvents}
        self.order_t = {}             # finding ID -> order time, for processed findings
        self.decisions = {}           # (source, target, type, key) -> admit.PairDecision (latest)
        # link admission (5c)
        self.epochs = EpochIndex(oparams.beta_onset_ns, enabled=not oparams.ablated("no_epoch"))
        # Process ancestry on the parent chain (A1); the ablation keeps the shared lineage.
        self.tree = None if oparams.ablated("no_ancestry_chain") else ProcessTree()
        self.events_of = {}           # finding ID -> its input Evs
        self.awaiting = {}            # decision key -> watermark at which its coverage is known
        self.status = {}              # decision key -> WitnessStatus of the published witness
        # groups and paths (5d)
        self.images = PodImages()     # Pod container images from context.cluster.v0
        self.published = {}           # decision key -> latest published Witness
        self.commit_seq = {}          # (source, target) -> order in which the link was first CONFIRMED
        # incidents (5e)
        self.book = IncidentBook(oparams)
        self.idle = {}                # (source name, scope, start) -> end ns or None: SOURCE_IDLE intervals
        self.idle_versions = []       # (receipt, source name, scope, start, end): each SOURCE_IDLE record as learned
        # knowledge time (7g)
        self.side = []                # heap of (receipt ns, seq, Envelope): side records not yet known
        self.side_seq = 0
        self.known = -INF             # side records received up to here are applied
        self._dues = None             # heap of (due, decision key) during advance()
        self.stats = {"findings": 0, "duplicate_findings": 0, "schema_major_rejected": 0,
                      "late_findings": 0, "findings_without_time": 0, "missing_evidence": 0,
                      "pairs_tested": 0, "witnesses": 0, "witnesses_revised": 0}
        self.out = []                 # (topic, key bytes, Envelope)

    # input ------------------------------------------------------------------
    def feed(self, env, topic, partition=0, offset=0, key=None, receipt_ns=None):
        """receipt_ns: the record's LogAppendTime, for coverage and context
        records (module doc); None learns the record now."""
        if env.schema_major != SCHEMA_MAJOR:
            self.stats["schema_major_rejected"] += 1
            return
        kind = env.WhichOneof("payload")
        if kind == "heartbeat":
            self.watermarks.observe(topic, env.heartbeat)
        elif kind == "normalized_event" and topic in (NORM, CRED):
            if self.evidence.add(env, topic, partition, offset) and self.tree is not None:
                self.tree.observe(self.evidence.get(env.normalized_event.event_id))
        elif kind in ("source_completeness", "context_observation"):
            if receipt_ns is None:
                self._apply_side(env, -INF)
            else:
                self.side_seq += 1
                heapq.heappush(self.side, (receipt_ns, self.side_seq, env))
                if receipt_ns <= self.known:          # inside a past decision's knowledge: learned now
                    self.learn(self.known)
        elif kind == "finding":
            self._finding(env.finding, (f"{topic}/{partition}", offset))
        else:
            self.stats["ignored_" + (kind or "empty")] = self.stats.get("ignored_" + (kind or "empty"), 0) + 1

    def _finding(self, f, pos=None, done=False):
        fid = f.finding_id
        payload = _payload_bytes(f)
        if fid in self._payload:
            if self._payload[fid] != payload:
                raise PayloadConflict(f"finding {fid} arrived with two different payloads")
            self.stats["duplicate_findings"] += 1
            return
        self._payload[fid] = payload
        self.findings[fid] = f
        if done:                       # restart replay: processed and forgotten before the checkpoint
            return
        if pos is not None:
            self.pos[fid] = pos
        self.stats["findings"] += 1
        t = order_time(f)
        if t is None:
            self.stats["findings_without_time"] += 1
            t = INF                    # cannot be ordered: processed at end of input only
        if self.frontier is not None and t < self.frontier:
            self.stats["late_findings"] += 1
        self.pending[fid] = t

    def _apply_side(self, env, receipt):
        if env.HasField("source_completeness"):
            sc = env.source_completeness
            if self.gaps.add_source_completeness(sc, env.logical_id or None):
                self._note_idle(sc, receipt)
                self._recheck_completeness(sc)
        else:
            self.images.add(env)

    def learn(self, k):
        """Apply every buffered side record received at or before k."""
        self.known = max(self.known, k)
        while self.side and self.side[0][0] <= self.known:
            receipt, _seq, env = heapq.heappop(self.side)
            self._apply_side(env, receipt)

    def learn_at(self, w):
        """Learn what is known at a decision made at watermark threshold w."""
        self.learn(self.watermarks.knowledge_time(w))

    # progress ---------------------------------------------------------------
    def advance(self, wm=None):
        """Process every pending finding and finalize every awaiting pair whose
        time is at or before the watermark (default: the input watermark), in
        one threshold order (ties: findings first), learning side records up
        to each threshold's knowledge time before deciding."""
        wm = self.watermarks.watermark() if wm is None else wm
        if wm is None:
            return
        self.watermark = wm if self.watermark is None else max(self.watermark, wm)
        ready = sorted((t, fid) for fid, t in self.pending.items() if t <= self.watermark)
        self._dues = [(t, k) for k, t in self.awaiting.items() if t <= self.watermark]
        heapq.heapify(self._dues)
        i = 0
        while i < len(ready) or self._dues:
            if i < len(ready) and (not self._dues or ready[i][0] <= self._dues[0][0]):
                t, fid = ready[i]
                i += 1
                del self.pending[fid]
                self.frontier = t if self.frontier is None else max(self.frontier, t)
                self.learn_at(t)
                self.process(self.findings[fid], t)
            else:
                t, k = heapq.heappop(self._dues)
                if self.awaiting.get(k) != t:
                    continue
                del self.awaiting[k]
                self.learn_at(t)
                self._finalize(k)
        self._dues = None
        self.learn_at(self.watermark)
        self.watermarks.prune(self.watermark - 2 * (self.p.max_horizon_ns() + self.p.A_ns))
        if self.frontier is not None and self.frontier < INF:
            self.evidence.evict(self.frontier - self.p.max_horizon_ns() - self.p.A_ns)
            self.index.sweep(self.frontier)
            if not self.p.ablated("no_index"):
                old = self.frontier - self.p.max_horizon_ns()
                waiting = {f for k in self.awaiting for f in k[:2]}
                gone = {f for f, t in self.order_t.items() if t < old} - waiting
                for fid in gone:
                    del self.order_t[fid]
                    self.keys.pop(fid, None)
                    self.events_of.pop(fid, None)
                if gone:          # no later finding can pair with these
                    keep = lambda k: k[0] not in gone and k[1] not in gone  # noqa: E731
                    self.decisions = {k: d for k, d in self.decisions.items() if keep(k)}
                    self.status = {k: s for k, s in self.status.items() if keep(k)}
                    self.published = {k: w for k, w in self.published.items() if keep(k)}
                    self.commit_seq = {pr: n for pr, n in self.commit_seq.items() if keep(pr)}

    def process(self, finding, t):
        """One finding in processing order: index it, retrieve candidates that
        share a key, and test each candidate pair in both directions."""
        fid = finding.finding_id
        self.processed.append(fid)
        evs, missing = self.evidence.for_finding(finding)
        if missing:
            self.stats["missing_evidence"] += len(missing)
        need = dict([self.pos[fid]]) if fid in self.pos else {}
        self.need[fid] = positions(need, evs)
        self.nodes_of[fid] = sorted({(e.ebpf.node_id, e.ebpf.boot_id) for e in evs
                                     if e.ebpf is not None and e.ebpf.node_id})
        keys = finding_keys(evs, self.enabled, self.images)
        self.keys[fid] = keys
        self.order_t[fid] = t
        self.events_of[fid] = evs
        for node, boot in self.epochs.observe(finding, evs):
            self._recheck_epoch(node, boot)
        if self.p.ablated("no_index"):           # Exp. 4: exhaustive search, same rules
            cands = set(self.keys) - {fid}
        else:
            cands = set()
            for wk in sorted(keys):
                cands.update(self.index.lookup_and_add(wk[0], wk[1], t, fid, self.frontier))
        for g in sorted(cands):
            shared = sorted(set(self.keys.get(g, {})) & set(keys))
            for w, k in shared:
                for a, b in ((g, fid), (fid, g)):
                    if w in ENABLING:
                        d = admit.decide_enabling(a, b, w, k, self.keys[a], self.keys[b])
                        self.decisions[(a, b, w, k)] = d
                        if d.supported:
                            self._publish_enabling((a, b, w, k), d)
                        continue
                    d = admit.decide(a, b, w, k, self.keys[a], self.keys[b], self.p, tree=self.tree)
                    self.decisions[(a, b, w, k)] = d
                    self.stats["pairs_tested"] += 1
                    if d.supported:              # matched evidence: a witness will be published
                        due = admit.coverage_due(d, self.p) if d.delta_ns is not None else -INF
                        self.awaiting[(a, b, w, k)] = due
                        if self._dues is not None and due <= self.watermark:
                            heapq.heappush(self._dues, (due, (a, b, w, k)))

    # link admission (5c) ------------------------------------------------------
    def _finalize(self, k):
        a, b, w, key = k
        p = self.p
        d_ev = self.decisions[k]
        d_tr = admit.decide(a, b, w, key, self.keys[a], self.keys[b], p, is_degraded=self.epochs.degraded,
                            tree=self.tree)
        d = d_tr if d_tr.supported else d_ev
        timed = d.delta_ns is not None
        found = contradictions.find(d, self.evidence, self.epochs.degraded) if d_tr.supported and timed else []
        is_cov, coverage = admit.covered(d, self.gaps, self.epochs, p, found) if timed else (False, [])
        if w == ENTITY_COMPAT:                   # No-Witness: no witness to contradict or cover
            found, is_cov, coverage = [], timed, []
        fa, fb = self.findings[a], self.findings[b]
        distinct = admit.distinct_action(fa, fb, self.events_of.get(a, []), self.events_of.get(b, []),
                                         self.order_t[a], self.order_t[b], self.gaps, p)
        st = admit.status(d_tr, d_ev, found, is_cov, distinct, p)
        wit = to_witness(d, p, degraded=not d_tr.supported)
        wit.status = st
        wit.contradiction_coverage.extend(coverage)
        for c in found:
            wit.contradictions.add(contradiction_id=c.cid, decisive=c.decisive, detail=c.detail,
                                   evidence_event_ids=c.evidence_ids, origin=common_pb2.KeyOrigin.Value("SENSOR"),
                                   degraded=c.degraded)
        if distinct is False:
            wit.contradictions.add(contradiction_id=f"same-action:{a}:{b}", decisive=True,
                                   detail="both findings record the same action", origin=common_pb2.KeyOrigin.Value("SENSOR"))
        need = positions({}, (self.evidence.get(eid) for c in found for eid in c.evidence_ids))
        self._publish(k, wit, need)

    def _publish(self, k, wit, need=None):
        if self.status.get(k) == wit.status:
            return                       # re-check without a change: nothing to republish
        if k in self.status:
            self.stats["witnesses_revised"] += 1
        topic, key, env = emit.witness_record(wit, self.p.version)
        self.wit_need[wit.witness_id] = need or {}
        self.status[k] = wit.status
        self.published[k] = env.witness
        if wit.status == CONFIRMED and k[:2] not in self.commit_seq:
            self.commit_seq[k[:2]] = len(self.commit_seq)
        self.out.append((topic, key, env))
        self.stats["witnesses"] += 1

    def _publish_enabling(self, k, d):
        a, b, w, key = k
        self._publish(k, to_enabling_witness(d, self.keys[b][(w, key)].context[d.target_ev.id]))

    def _recheck_completeness(self, sc):
        """A loss or idle record arrived: re-decide every published direct
        witness whose contradiction interval it overlaps (Property 4). A link
        that loses its CONFIRMED status leaves the groups (retraction)."""
        lo = ts_ns(sc.interval_start)
        hi = ts_ns(sc.interval_end)
        open_end = False
        for g in sc.gaps:
            if g.HasField("from"):
                glo = ts_ns(getattr(g, "from"))
                lo = glo if lo is None else min(lo, glo)
            if g.HasField("to"):
                ghi = ts_ns(g.to)
                hi = ghi if hi is None else max(hi, ghi)
            else:
                open_end = True           # an open-ended gap reaches every later interval
        if open_end:
            hi = None
        for k in sorted(self.status, key=repr):
            if k[2] in ENABLING or k not in self.decisions or self.decisions[k].delta_ns is None:
                continue
            ilo, ihi = admit.interval(self.decisions[k])
            if (hi is None or ilo <= hi) and (lo is None or ihi >= lo):
                self._finalize(k)

    def groups(self):
        """Current groups ([groups.GroupView]), sorted by anchor."""
        return groups.compute(self)

    # incidents (5e) -----------------------------------------------------------
    def _note_idle(self, sc, receipt=-INF):
        """Record SOURCE_IDLE intervals as source exclusions for incidents. A
        node's source-less idle gap excludes that node's eBPF; a closing
        record (same source, scope, start) sets the end. Each record is also
        kept as a version with its receipt time, for the at-seal set."""
        name = common_pb2.Source.Name(sc.source) if sc.source != UNSPEC else "EBPF"
        for g in sc.gaps:
            if g.reason != IDLE:
                continue
            lo = ts_ns(getattr(g, "from")) if g.HasField("from") else ts_ns(sc.interval_start)
            hi = ts_ns(g.to) if g.HasField("to") else ts_ns(sc.interval_end)
            k = (name, sc.scope, lo)
            self.idle_versions.append((receipt, name, sc.scope, lo, hi))
            if k not in self.idle or (hi is not None and (self.idle[k] is None or hi > self.idle[k])):
                self.idle[k] = hi

    def incidents_hook(self, now_ns):
        """Hand the current groups to the incident book and queue the incident
        records it returns (open, sealed, amended). Called by the runner after
        each advance; now_ns stamps amendments."""
        if self.watermark is None:
            return
        excl = [(name, lo, hi) for (name, _scope, lo), hi in sorted(self.idle.items(), key=repr)]
        for inc in self.book.update(self.groups(), self.watermark, excl, now_ns, known_at=self.exclusions_known_at):
            self.out.append(emit.incident_record(inc, self.p.version))

    def exclusions_known_at(self, w):
        """The SOURCE_IDLE intervals known at a decision at threshold w, each
        as its latest version received by then (an ongoing one if its closing
        record came later): what an incident sealing at w froze, whenever it
        was read."""
        k = self.watermarks.knowledge_time(w)
        latest = {}
        for r, name, scope, lo, hi in self.idle_versions:
            if r <= k:
                cur = latest.get((name, scope, lo))
                if cur is None or (hi is not None and (cur[2] is None or hi > cur[2])):
                    latest[(name, scope, lo)] = (name, lo, hi)
        return sorted(set(latest.values()), key=repr)

    def output_low_watermark(self):
        """Heartbeat promise for the output topics: no later witness or
        incident record has an event time before this. Witnesses awaiting
        coverage and open incidents can still be published with earlier
        times, so they hold it back. Revisions of already published records
        (re-evaluation, amendments) carry their original times and are
        updates by ID, not new records."""
        if self.watermark is None:
            return None
        lows = [self.watermark]
        lows += [self.decisions[k].source_ev.t for k in self.awaiting
                 if self.decisions[k].source_ev is not None and self.decisions[k].source_ev.t is not None]
        lows += [st.view.event_start for st in self.book.live.values() if not st.sealed]
        lows += [t for t in self.pending.values() if t < INF]
        return min(lows)

    def _recheck_epoch(self, node, boot):
        """An epoch on (node, boot) opened or moved earlier: re-decide every
        published witness with evidence from that node whose contradiction
        interval plus beta reaches the onset (Property 4, epoch arrival)."""
        tau = self.epochs.onset(node, boot)
        for k in sorted(self.status, key=repr):
            if k not in self.decisions:
                continue
            d = self.decisions[k]
            on_node = any(e is not None and e.ebpf is not None and (e.ebpf.node_id, e.ebpf.boot_id) == (node, boot)
                          for e in (d.source_ev, d.target_ev))
            if on_node and d.delta_ns is not None and tau <= admit.interval(d)[1] + self.p.beta_ns:
                self._finalize(k)

    def links(self):
        """{(source, target)} with at least one CONFIRMED witness."""
        return {(a, b) for (a, b, _w, _k), s in self.status.items() if s == CONFIRMED}

    def witness_status(self, a, b, w):
        """Statuses published for (source, target, type), any key."""
        return sorted(s for (x, y, ww, _k), s in self.status.items() if (x, y, ww) == (a, b, w))

    def passing(self):
        """{(source, target, witness type)} whose Supported and TimeValid hold."""
        return {(a, b, w) for (a, b, w, _k), d in self.decisions.items() if d.passes}

    # restart (7g) ------------------------------------------------------------
    def held(self):
        """Finding IDs the open state still needs: pending, still posted
        (posting not yet past t + H_w), or an end of an awaiting pair."""
        return set(self.pending) | set(self.order_t) | {f for k in self.awaiting for f in k[:2]}

    def held_offsets(self):
        """(topic, partition) -> smallest input offset still held: the held
        findings' first payloads and every retained evidence event. Anything
        earlier is evicted and cannot affect a later decision."""
        out = {}

        def low(tp, off):
            out[tp] = min(out.get(tp, off), off)
        for fid in self.held():
            if fid in self.pos:
                tp, off = self.pos[fid]
                topic, part = tp.rsplit("/", 1)
                low((topic, int(part)), off)
        for ev in self.evidence.events.values():
            low((ev.topic, ev.partition), ev.offset)
        return out

    def checkpoint_state(self):
        """State a restart cannot rebuild from the held records: the watermark
        and its heartbeat history (knowledge times), node-trust epochs (their
        triggers may be evicted), the process tree (its fork and exec records may
        be evicted), and the incident book (versions, seal snapshots,
        amendments, aliases)."""
        return {"watermarks": self.watermarks, "epochs": self.epochs, "book": self.book, "tree": self.tree}

    def restore(self, state):
        self.watermarks, self.epochs, self.book = state["watermarks"], state["epochs"], state["book"]
        if "tree" in state:
            self.tree = state["tree"]
        self.book.p = self.p

    def skip(self, env):
        """Restart replay of a finding the checkpoint no longer held: keep it
        for duplicate detection only."""
        self._finding(env.finding, done=True)

    # side-state pruning (7g) ----------------------------------------------------
    def side_bound(self):
        """(B, K_floor) for pruning applied side records, or None before the
        first advance.

        T_old is the oldest event time any decision still to be made can
        look at: the watermark (new on-time findings lie after it), pending
        and still-posted findings, retained evidence events, and the open
        period start of every live or absorbed incident (amendments compare
        exclusions with event_start..seal). Every coverage query of a pair
        among these findings spans its two events, at most A + eps_bar from
        the findings' order times; enabling and context lookups use evidence
        times. B = T_old - (max H_w + A + lateness + eps_bar) is below all of
        them, so a closed gap or idle interval ending before B, or a Pod
        observation superseded by one observed before B, cannot change a
        later decision. Late data older than the evidence horizon is outside
        this argument (Exp. 5 scores it separately).

        K_floor = knowledge_time(T_old) bounds the knowledge time of every
        decision still to be made from below; an idle interval is pruned
        only once its closing version was received by then, so no later
        seal can still see it as ongoing. Without heartbeat history at
        T_old, K_floor is -INF and idle intervals are kept."""
        if self.watermark is None:
            return None
        ts = [self.watermark] + [t for t in self.pending.values() if t < INF] + list(self.order_t.values())
        ts += [e.t for e in self.evidence.events.values() if e.t is not None]
        ts += [st.view.event_start for st in (*self.book.live.values(), *self.book.absorbed.values())]
        t_old = min(ts)
        b = t_old - (self.p.max_horizon_ns() + self.p.A_ns + self.p.lateness_ns + self.p.eps_bar_ns)
        cut = self.watermarks.pruned
        k_floor = self.watermarks.knowledge_time(t_old) if cut is None or t_old > cut else -INF
        return b, (-INF if k_floor >= INF else k_floor)

    def prune_side(self, bound):
        """Forget applied side state no later decision can use (side_bound):
        gaps ended before B, Pod observations superseded before B, and idle
        intervals closed before B by a version received by K_floor."""
        b, k_floor = bound
        self.gaps.prune(b)
        self.images.evict(b)
        closed = {}
        for r, name, scope, lo, hi in self.idle_versions:
            k = (name, scope, lo)
            if hi is not None and hi == self.idle.get(k):
                closed[k] = min(closed.get(k, r), r)
        drop = {k for k, r in closed.items() if self.idle[k] < b and r <= k_floor}
        for k in drop:
            del self.idle[k]
        self.idle_versions = [v for v in self.idle_versions if (v[1], v[2], v[3]) not in drop]

    def side_keep(self, log, bound):
        """The entries of a checkpoint side log, (topic, partition, offset,
        receipt, bytes), that a restart must re-feed: every record not yet
        applied, and every applied one prune_side would still hold."""
        b, k_floor = bound
        parsed = []
        for e in log:
            env = envelope_pb2.Envelope()
            env.ParseFromString(e[4])
            parsed.append((e, env, e[3] is None or e[3] <= self.known))
        closes = {}                  # (source, scope, reason, start) -> (end, receipt) of a bounded version
        newest = {}                  # Pod UID -> (observed time, index) of the newest observation before B
        for i, (e, env, applied) in enumerate(parsed):
            if not applied:
                continue
            if env.HasField("source_completeness"):
                sc = env.source_completeness
                for key, _lo, hi in _gap_ranges(sc):
                    if hi is not None:
                        r = e[3] if e[3] is not None else -INF
                        cur = closes.get(key)
                        if cur is None or hi > cur[0]:
                            closes[key] = (hi, r)
            elif env.HasField("context_observation"):
                o = env.context_observation
                t = ts_ns(o.observed_time)
                if o.uid and t is not None and t < b and (t, i) > newest.get(o.uid, (-INF, -1)):
                    newest[o.uid] = (t, i)
        out = []
        for i, (e, env, applied) in enumerate(parsed):
            if not applied:
                out.append(e)
            elif env.HasField("source_completeness"):
                sc = env.source_completeness
                ranges = list(_gap_ranges(sc))
                if sc.status == DELIVERY_UNKNOWN:
                    ranges.append((None, None, ts_ns(sc.interval_end)))
                for key, _lo, hi in ranges:
                    end, r = (hi, e[3] if e[3] is not None else -INF) if hi is not None else closes.get(key, (None, None))
                    if end is None or end >= b or (key is not None and key[2] == IDLE and r > k_floor):
                        out.append(e)
                        break
            else:
                o = env.context_observation
                t = ts_ns(o.observed_time)
                if not o.uid or t is None or o.WhichOneof("summary") not in ("pod", None):
                    continue
                if (t, i) >= newest.get(o.uid, (-INF, -1)):
                    out.append(e)
        return out

    def open_state(self):
        """Counts of open state (failpoint summaries)."""
        live = self.book.live.values()
        return {"pending_findings": len(self.pending), "pending_pairs": len(self.awaiting),
                "open_groups": sum(1 for s in live if not s.sealed), "unretired_incidents": sum(1 for s in live if s.sealed)}

    def finish(self):
        """End of input (offline replay): process everything still pending."""
        self.advance(INF)

    def drain(self):
        out, self.out = self.out, []
        return out


def _gap_ranges(sc):
    """((source, scope, reason, start), start, end) per gap of a
    SourceCompleteness, bounds as GapIndex reads them (end None: open)."""
    lo, hi = ts_ns(sc.interval_start), ts_ns(sc.interval_end)
    for g in sc.gaps:
        glo = ts_ns(getattr(g, "from")) if g.HasField("from") else lo
        ghi = ts_ns(g.to) if g.HasField("to") else hi
        yield (sc.source, sc.scope, g.reason, glo), glo, ghi


def positions(need, evs):
    """Raise need ("topic/partition" -> offset) to cover every Ev in evs
    (None entries skipped); returns need."""
    for e in evs:
        if e is None or not e.topic:
            continue
        tp = f"{e.topic}/{e.partition}"
        need[tp] = max(need.get(tp, -1), e.offset)
    return need


def order_time(f):
    """A finding's processing time: its corrected event start."""
    return ts_ns(f.event_start) if f.HasField("event_start") else None
