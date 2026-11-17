"""Observability degradation: drop the events a degraded profile loses.

A degraded observability profile loses events in seeded gap windows:

  degraded_gateway  gateway observer outages
                    (observer_outage_duration_seconds each, observer_loss_percentage of the run)
  degraded_audit    audit feed gaps
                    (feed_gap_duration_seconds each, event_loss_percentage of the run)
  degraded_ebpf     per-node probe gaps
                    (probe_gap_duration_seconds each, probe_loss_percentage of the run)
                    plus whole-run loss of syscall_families_lost
  degraded_context  watch gaps
                    (watch_gap_duration_seconds each, watch_gap_percentage of the run),
                    each starting at a watch event: watch traffic is bursty
                    (Pod creation, churn), and a gap matters only when it
                    covers one

A scenario step can also lose its own evidence in any profile (catalogue
step field `unobserved: [source, ...]`): add_step_window() opens a short
SOURCE_IDLE window on the source scope of each of the step's events, so the
events are dropped and the gap is declared like any other outage.

Dropped events never reach the base stream or the truth writer, so an
opportunity whose evidence fell in a gap is labelled UNOBSERVABLE. Each window
is declared as a timed Gap on the source's SourceCompleteness record, with the
actual dropped count per family.
"""
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from microtrace.v0 import common_pb2

from .rng import Streams
from .simtime import ns_to_timestamp

# Profile syscall-family names -> eBPF capture families they remove.
_SYSCALL_FAMILY_TO_EBPF: Dict[str, Tuple[str, ...]] = {
    "ptrace": ("proc.ptrace",),
    "clone": ("proc.fork",),
    "fork": ("proc.fork",),
    "exec": ("proc.exec",),
}

_SOURCE_NAME_BY_ENUM: Dict[int, str] = {
    common_pb2.EBPF: "ebpf",
    common_pb2.GATEWAY: "gateway",
    common_pb2.AUDIT: "audit",
    common_pb2.CLUSTER_CONTEXT: "context",
    common_pb2.KYVERNO: "kyverno",
    common_pb2.DB_AUDIT: "db_audit",
    common_pb2.PATH_FLOW: "path_flow",
}

# Catalogue `unobserved` source names -> degrader source names.
UNOBSERVED_SOURCES: Dict[str, Tuple[str, ...]] = {
    "ebpf": ("ebpf",),
    "gateway": ("gateway",),
    "audit": ("audit",),
    "kyverno": ("kyverno",),
    "context": ("context",),
    "offnode": ("db_audit", "path_flow"),
}

# A step window covers the event and this much after it: tight, so a
# feed-wide source (audit, gateway) loses as little else as possible.
STEP_WINDOW_NS: int = 1_000_000


@dataclass(frozen=True)
class GapWindow:
    """One interval in which a source (optionally one node) delivers nothing."""
    source: str          # "gateway", "audit", "ebpf", "context"
    scope: str           # completeness scope ("node=<uid>", "gateway=1", ...)
    start_ns: int
    end_ns: int          # exclusive
    reason: int          # common_pb2 GapReason
    detail: str = ""     # "" -> "<profile> window"


def _param(profile: dict, key: str, default):
    val = profile.get(key, default)
    if isinstance(val, dict):
        val = val.get("frozen") if val.get("frozen") is not None else val.get(
            "pilot_default", default)
    return val


class Degrader:
    """Decides which rendered events a degraded profile drops.

    Args:
        world:        World (nodes, run_start_ns, run_duration_ns).
        profile_name: observability profile name.
        profile:      generator_spec["observability_profiles"][profile_name].
        seed:         run seed string; windows are a pure function of it.
    """

    def __init__(self, world, profile_name: str, profile: Optional[dict], seed: str):
        self._profile_name = profile_name
        self._profile = profile or {}
        self._start = world.run_start_ns
        self._end = world.run_start_ns + world.run_duration_ns
        self._streams = Streams(f"{seed}:degrade")
        self.windows: List[GapWindow] = []
        self.step_windows: List[GapWindow] = []      # from unobserved scenario steps
        self.lost_families: Tuple[str, ...] = ()
        # (scope, family_or_source) -> dropped event count
        self.dropped: Dict[Tuple[str, str], int] = {}

        name = profile_name
        p = self._profile
        if name == "degraded_gateway":
            self._place("gateway", "gateway=1", common_pb2.SOURCE_IDLE,
                        _param(p, "observer_outage_duration_seconds", 5),
                        _param(p, "observer_loss_percentage", 15))
        elif name == "degraded_audit":
            self._place("audit", "audit-collector=1", common_pb2.DROPPED_BEFORE,
                        _param(p, "feed_gap_duration_seconds", 10),
                        _param(p, "event_loss_percentage", 10))
        elif name == "degraded_ebpf":
            for node in world.nodes:
                self._place("ebpf", f"node={node.uid}", common_pb2.SOURCE_IDLE,
                            _param(p, "probe_gap_duration_seconds", 10),
                            _param(p, "probe_loss_percentage", 20))
            lost = []
            for fam in p.get("syscall_families_lost", []) or []:
                lost.extend(_SYSCALL_FAMILY_TO_EBPF.get(fam, (fam,)))
            self.lost_families = tuple(sorted(set(lost)))
        elif name == "degraded_context":
            anchors = sorted({
                o.observed_time.seconds * 1_000_000_000 + o.observed_time.nanos
                for o in world.context_observations
            })
            self._place("context", "context-collector=1", common_pb2.WATCH_RELIST_GAP,
                        _param(p, "watch_gap_duration_seconds", 15),
                        _param(p, "watch_gap_percentage", 10), anchors=anchors)

        self._by_scope: Dict[Tuple[str, str], List[GapWindow]] = {}
        for w in self.windows:
            self._by_scope.setdefault((w.source, w.scope), []).append(w)

    # ------------------------------------------------------------------
    # Window placement
    # ------------------------------------------------------------------

    def _place(self, source: str, scope: str, reason: int,
               length_s: float, percentage: float,
               anchors: Optional[List[int]] = None) -> None:
        """Place non-overlapping windows covering ``percentage`` of the run.

        With ``anchors``, each window starts at an anchor time (a window then
        always covers the anchored event).
        """
        length = int(float(length_s) * 1_000_000_000)
        span = self._end - self._start
        if length <= 0 or span <= length or float(percentage) <= 0:
            return
        count = max(1, round(float(percentage) / 100.0 * span / length))
        rng = self._streams.get(f"windows.{source}.{scope}")
        placed: List[Tuple[int, int]] = []
        attempts = 0
        while len(placed) < count and attempts < count * 50:
            attempts += 1
            if anchors:
                s = anchors[int(rng.integers(len(anchors)))]
            else:
                s = self._start + int(rng.integers(0, span - length))
            e = s + length
            if any(s < pe and ps < e for ps, pe in placed):
                continue
            placed.append((s, e))
        for s, e in sorted(placed):
            self.windows.append(GapWindow(source, scope, s, e, reason))

    def add_step_window(self, ne, unobserved) -> bool:
        """Open a step window on ne's source scope if its source is listed
        in `unobserved` (catalogue names). Returns True when one applies."""
        source, scope, _family = self._scope_family(ne)
        wanted = {s for name in unobserved for s in UNOBSERVED_SOURCES[name]}
        if source is None or source not in wanted:
            return False
        t = ne.time.event_time.seconds * 1_000_000_000 + ne.time.event_time.nanos
        w = GapWindow(source, scope, t, t + STEP_WINDOW_NS, common_pb2.SOURCE_IDLE,
                      "scenario step unobserved")
        if w not in self._by_scope.get((source, scope), ()):
            self.windows.append(w)
            self.step_windows.append(w)
            self._by_scope.setdefault((source, scope), []).append(w)
        return True

    # ------------------------------------------------------------------
    # Filtering
    # ------------------------------------------------------------------

    @staticmethod
    def _scope_family(ne) -> Tuple[Optional[str], str, str]:
        """Return (source_name, scope, family_key) for a NormalizedEvent."""
        source = _SOURCE_NAME_BY_ENUM.get(ne.source)
        if source == "ebpf":
            return source, f"node={ne.ebpf.node_id}", ne.ebpf.event_family
        if source == "gateway":
            return source, "gateway=1", "gateway"
        if source == "audit":
            return source, "audit-collector=1", "audit"
        if source == "context":
            return source, "context-collector=1", "context"
        if source == "kyverno":
            return source, "kyverno=1", "kyverno"
        if source == "db_audit":
            return source, "db-audit-collector=1", "db_audit"
        if source == "path_flow":
            return source, "path-flow-collector=1", "path_flow"
        return None, "", ""

    def keep(self, ne) -> bool:
        """Return False (and count the drop) when the profile loses this event."""
        if not self.windows and not self.lost_families:
            return True
        source, scope, family = self._scope_family(ne)
        if source is None:
            return True
        drop = source == "ebpf" and family in self.lost_families
        if not drop:
            t = ne.time.event_time.seconds * 1_000_000_000 + ne.time.event_time.nanos
            drop = any(w.start_ns <= t < w.end_ns
                       for w in self._by_scope.get((source, scope), ()))
        if drop:
            key = (scope, family)
            self.dropped[key] = self.dropped.get(key, 0) + 1
        return not drop

    # ------------------------------------------------------------------
    # Completeness declarations
    # ------------------------------------------------------------------

    def gaps(self, source: str, scope: str) -> List["common_pb2.Gap"]:
        """Timed Gap messages for one source scope."""
        out = []
        if source == "ebpf" and self.lost_families:
            out.append(common_pb2.Gap(
                reason=common_pb2.SOURCE_IDLE,
                scope="family=" + ",".join(self.lost_families),
                detail="probes not attached for the whole run",
                **{"from": ns_to_timestamp(self._start)},
                to=ns_to_timestamp(self._end),
            ))
        for w in self._by_scope.get((source, scope), ()):
            out.append(common_pb2.Gap(
                reason=w.reason,
                scope=f"source={source}",
                detail=w.detail or f"{self._profile_name} window",
                **{"from": ns_to_timestamp(w.start_ns)},
                to=ns_to_timestamp(w.end_ns),
            ))
        return out

    def dropped_counts(self, scope: str) -> Dict[str, int]:
        """family_or_source -> events dropped in this scope."""
        return {fam: n for (sc, fam), n in self.dropped.items() if sc == scope and n}
