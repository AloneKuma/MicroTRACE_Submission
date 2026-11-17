"""Incidents: open, seal, amend and merge (build step 5e).

The engine hands the book its current groups (step 5d) after each advance;
the book returns the incident records to publish on incidents.v0.

- **Open.** A new group is published as INCIDENT_OPEN, version 1. While open,
  a changed group is republished under the *same* version: open records are
  provisional and the latest one per incident ID (Kafka keeps per-key order)
  is the current view. Holding the version keeps the sealed record's version,
  and so `sealed_prediction_version`, the same whether the live run published
  zero or ten open revisions first (design-spec.md section 5, replay).
- **Seal** when `watermark >= last_extension`. The watermark already carries
  the lateness allowance; it is not added again (design-spec.md, "Do not add
  the lateness allowance a second time"). `watermark_time` is the seal time
  `last_extension`, the first watermark at which the seal was due, so a
  replay that advances in other steps writes the same record.
  `sealed_prediction_version = "snapshot-<version>"` names the frozen
  at-seal prediction; published metrics read only that record.
- **Exclusions.** Every incident open over an exclusion interval records it
  (kafka-contract.md section 4). An exclusion is (source name, start, end;
  end None while ongoing) and applies to an incident whose open period,
  event_start to its seal time (to the watermark while open), overlaps it.
  A bare source name applies to every incident. Exclusions known while open
  are frozen into `at_seal_excluded_sources` at seal;
  `current_excluded_sources` adds those learned later and only grows, so a
  flapping source does not churn amendments. With `known_at` (the engine,
  step 7g), "known while open" is exact: the at-seal set is every exclusion,
  as its latest version known at the seal's knowledge time, that meets
  event_start to last_extension, independent of when the book was called.
- **Retirement.** A sealed incident is dropped from the book once the
  watermark passes its seal time plus the largest posting horizon and its
  group is no longer reported: the engine has forgotten its findings and no
  exclusion can still overlap its open period, so it cannot change.
- **Amend.** After seal, any change (members, links, paths, span, a merge, a
  newly excluded source, a node-trust epoch, the input frontier) is an
  amendment: version + 1, INCIDENT_AMENDED, one
  `Amendment` appended. The sealed snapshot (`sealed_prediction_version`,
  `watermark_time`, `at_seal_excluded_sources`) never changes.
- **Merge.** The incident ID is `incident_id(anchor)`, so a group whose anchor
  changes gets a new ID. A group absorbs every live incident whose anchor is
  one of its members; their IDs (and aliases) become its aliases. If no
  constituent was sealed, the merged incident is open (version stays 1).
  Otherwise it is amended: it keeps its own frozen snapshot if its ID was
  already sealed, else inherits the earliest-sealed constituent's (ties:
  smallest ID); the version is one more than the highest constituent
  version, and the amendment names the merged IDs. Each constituent's own
  INCIDENT_SEALED record on Kafka stays the at-seal prediction for
  evaluation. An absorbed incident's last record is not retracted; analysts
  reach the merged incident through `aliases`.

Group input contract: `groups` holds the current view of every group that is
new or may have changed; an incident whose group is absent is unchanged
(never deleted). Output is sorted by incident ID.
"""
from dataclasses import dataclass, field

from microtrace.v0 import incident_pb2

from mtcore.orchestrator import DECISION_VERSION, ablations, emit

IS = incident_pb2.IncidentStatus
OPEN, SEALED, AMENDED = IS.Value("INCIDENT_OPEN"), IS.Value("INCIDENT_SEALED"), IS.Value("INCIDENT_AMENDED")
EPOCH_CONFIRMED = incident_pb2.NodeEpochKind.Value("NODE_EPOCH_CONFIRMED")


@dataclass
class GroupView:
    anchor_fid: str
    anchor_entity: object        # common_pb2.EntityRef or None
    finding_ids: list            # members, sorted by (order time, finding ID)
    link_witness_ids: list       # CONFIRMED DIRECT witness IDs inside the group
    ranked_paths: list           # incident_pb2.RankedPath (path_id unset)
    speculative_paths: list      # incident_pb2.RankedPath via ENABLING witnesses
    event_start: int             # ns
    event_end: int               # ns
    last_extension: int          # ns: latest event time at which a new finding could still join
    node_epochs: list = field(default_factory=list)      # (node, boot, tau_N ns, trigger finding ID)
    input_frontier: dict = field(default_factory=dict)   # "topic/partition" -> offset


@dataclass
class _Incident:
    iid: str
    view: GroupView
    version: int = 1
    status: int = OPEN
    aliases: set = field(default_factory=set)
    excluded: set = field(default_factory=set)      # open: seen so far; sealed: current
    at_seal: tuple = ()
    seal_time: int = None
    snapshot: str = ""
    amendments: list = field(default_factory=list)
    published: bytes = None                         # last record published (content check)
    published_view: GroupView = None                # its group, for the amendment reason
    merged: list = field(default_factory=list)      # IDs absorbed since the last record

    @property
    def sealed(self):
        return self.status != OPEN


class IncidentBook:
    def __init__(self, oparams):
        ablations.validate(oparams.ablations)
        self.p = oparams
        self.live = {}          # incident ID -> _Incident
        self.absorbed = {}      # incident ID -> _Incident merged into another (revived if its anchor returns)

    def update(self, groups, watermark_ns, excluded_sources, now_ns, known_at=None):
        """Apply the groups, seal what is due, and return the Incident records
        to publish (IDs filled, sorted by incident ID). known_at(w): the
        exclusions known at a decision at threshold w (module doc)."""
        exclusions = [(x, None, None) if isinstance(x, str) else tuple(x) for x in (excluded_sources or ())]
        for v in sorted(groups, key=lambda g: g.anchor_fid):
            self._apply(v)
        out = []
        for iid in sorted(self.live):
            st = self.live[iid]
            if not st.sealed:
                st.excluded |= _overlapping(exclusions, st.view.event_start, watermark_ns)
                if watermark_ns is not None and watermark_ns >= st.view.last_extension:
                    if known_at is not None:
                        e = st.view.last_extension
                        st.excluded = _overlapping(known_at(e), st.view.event_start, e)
                    self._seal(st)
            excluded = _overlapping(exclusions, st.view.event_start, st.seal_time if st.sealed else watermark_ns)
            rec = self._publishable(st, excluded, now_ns)
            if rec is not None:
                out.append(rec)
        if watermark_ns is not None:
            horizon = self.p.max_horizon_ns()
            current = {v.anchor_fid for v in groups}

            def retire(st):           # sealed, past the horizon, and its group no longer reported
                return st.sealed and watermark_ns > st.seal_time + horizon and st.view.anchor_fid not in current
            for iid in [i for i, st in self.live.items() if retire(st)]:
                del self.live[iid]
            self.absorbed = {i: st for i, st in self.absorbed.items() if not retire(st)}
        return out

    # groups -> incidents ------------------------------------------------------
    def _apply(self, v):
        iid = emit.incident_id(v.anchor_fid)
        members = set(v.finding_ids)
        parts = [s for i, s in sorted(self.live.items()) if i != iid and s.view.anchor_fid in members]
        st = self.live.get(iid) or self.absorbed.pop(iid, None)
        if st is None:
            st = _Incident(iid, v)
        if parts:
            self._merge(st, parts)
        st.view = v
        self.live[iid] = st

    def _merge(self, st, parts):
        for s in parts:
            del self.live[s.iid]
            self.absorbed[s.iid] = s
            st.aliases |= {s.iid} | s.aliases
            st.excluded |= s.excluded
            st.merged.append(s.iid)
        st.aliases.discard(st.iid)
        sealed = sorted((s for s in [st, *parts] if s.sealed), key=lambda s: (s.seal_time, s.iid))
        if sealed and not st.sealed:          # inherit the earliest-sealed constituent's frozen snapshot
            first = sealed[0]
            st.status, st.at_seal, st.seal_time, st.snapshot = SEALED, first.at_seal, first.seal_time, first.snapshot
            st.amendments = list(first.amendments)
            st.published_view = first.published_view
            st.published = st.published or b"\x00merged"     # any content differs: forces an amendment
        st.version = max(s.version for s in [st, *parts])

    def _seal(self, st):
        st.status = SEALED
        st.seal_time = st.view.last_extension
        st.at_seal = tuple(sorted(st.excluded))
        st.snapshot = f"snapshot-{st.version}"
        st.published = None                   # the seal record is always published

    # records ------------------------------------------------------------------
    def _publishable(self, st, excluded, now_ns):
        newly = sorted(excluded - st.excluded) if st.sealed else []
        if st.sealed:
            st.excluded |= excluded
        rec = self._record(st)
        body = rec.SerializeToString(deterministic=True)
        if body == st.published:
            return None
        if st.published is not None and st.sealed:     # a change after seal: amendment
            st.version += 1
            st.status = AMENDED
            am = incident_pb2.Amendment(version=st.version, reason=self._reason(st, newly))
            am.late_finding_ids.extend(self._late(st))
            am.amended_at.CopyFrom(emit.ts(now_ns))
            st.amendments.append(am)
            rec = self._record(st)
            body = rec.SerializeToString(deterministic=True)
        st.published, st.published_view, st.merged = body, st.view, []
        return rec

    def _late(self, st):
        old = set(st.published_view.finding_ids) if st.published_view else set()
        return [f for f in st.view.finding_ids if f not in old]

    def _reason(self, st, newly):
        old, new = st.published_view, st.view
        parts = []
        if st.merged:
            parts.append("merged " + ", ".join(sorted(st.merged)) + " after seal")
        if old is not None:
            if set(new.finding_ids) - set(old.finding_ids):
                parts.append("findings joined after seal")
            if set(old.finding_ids) - set(new.finding_ids):
                parts.append("findings left after seal")
            if _links(old) != _links(new):
                parts.append("links or paths revised after seal")
            if (old.event_start, old.event_end) != (new.event_start, new.event_end):
                parts.append("event span revised after seal")
            if old.node_epochs != new.node_epochs:
                parts.append("node-trust epoch recorded after seal")
        if newly:
            names = ", ".join(s.lower() for s in newly)
            parts.append(f"{names} source{'s' if len(newly) > 1 else ''} excluded by max-idle after seal")
        return "; ".join(parts or ["revised after seal"]) + "; analyst view only"

    def _record(self, st):
        v = st.view
        inc = incident_pb2.Incident(incident_id=st.iid, anchor_finding_id=v.anchor_fid, version=st.version,
                                    status=st.status, decision_version=DECISION_VERSION)
        if v.anchor_entity is not None:
            inc.anchor_entity.CopyFrom(v.anchor_entity)
        inc.aliases.extend(sorted(st.aliases))
        inc.finding_ids.extend(v.finding_ids)
        inc.link_witness_ids.extend(sorted(v.link_witness_ids))
        for src, dst in ((v.ranked_paths, inc.ranked_paths), (v.speculative_paths, inc.speculative_paths)):
            for p in src:
                q = dst.add()
                q.CopyFrom(p)
                q.path_id = emit.path_id(q.finding_ids)
        inc.event_start.CopyFrom(emit.ts(v.event_start))
        inc.event_end.CopyFrom(emit.ts(v.event_end))
        sc = inc.source_completeness
        sc.SetInParent()
        if st.sealed:
            inc.watermark_time.CopyFrom(emit.ts(st.seal_time))
            inc.sealed_prediction_version = st.snapshot
            sc.at_seal_excluded_sources.extend(st.at_seal)
        sc.current_excluded_sources.extend(sorted(st.excluded))
        inc.amendments.extend(st.amendments)
        for node, boot, tau, trigger in v.node_epochs:
            e = inc.node_epochs.add(node_id=node, boot_id=boot, trigger_finding_id=trigger, kind=EPOCH_CONFIRMED)
            e.tau_n.CopyFrom(emit.ts(tau))
        inc.input_frontier.update(v.input_frontier)
        return inc


def _links(v):
    paths = lambda ps: [(tuple(p.finding_ids), tuple(p.witness_ids)) for p in ps]  # noqa: E731
    return sorted(v.link_witness_ids), paths(v.ranked_paths), paths(v.speculative_paths)


def _overlapping(exclusions, lo, hi):
    """Source names whose exclusion interval meets [lo, hi] (None: unbounded)."""
    out = set()
    for name, xlo, xhi in exclusions:
        if (xlo is None or hi is None or xlo <= hi) and (xhi is None or lo is None or xhi >= lo):
            out.add(name)
    return out
