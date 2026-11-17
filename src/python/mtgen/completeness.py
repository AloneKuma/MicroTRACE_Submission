"""Source completeness and heartbeat production.

Produces SourceCompleteness records (source.completeness.v0) per source and
scope from the observability profile, plus one Heartbeat per producer per
partition.

SourceCompleteness (stream.proto):
  source        Source enum
  scope         e.g. "node=<uid>", "audit-collector=1"
  interval_*    the run window
  status        NO_KNOWN_GAP or INCOMPLETE
  gaps          Gap messages for known degradation
  counters      optional counter snapshot

Heartbeat (stream.proto):
  producer_id, producer_instance, topic, partition
  low_watermark = interval_end (promise: nothing earlier will arrive)
  emitted_at    = interval_end

The generator writes heartbeats and completeness records into the base stream
alongside NormalizedEvents; the emitter (phase 2.6) is responsible for routing
them onto the correct Kafka topics and partitions.
"""
from typing import Dict, List, Optional

from microtrace.v0 import common_pb2, stream_pb2
from mtgen.simtime import ns_to_timestamp

# Source enum values by name (mirrors common.proto Source enum)
_SOURCE_BY_NAME: dict = {
    "ebpf": common_pb2.EBPF,
    "gateway": common_pb2.GATEWAY,
    "kyverno": common_pb2.KYVERNO,
    "audit": common_pb2.AUDIT,
    "context": common_pb2.CLUSTER_CONTEXT,
    "db_audit": common_pb2.DB_AUDIT,
    "path_flow": common_pb2.PATH_FLOW,
}

# Default producer IDs by source name
_PRODUCER_BY_SOURCE: dict = {
    "ebpf": "node-sensor",
    "gateway": "gateway-observer",
    "kyverno": "kyverno-exporter",
    "audit": "audit-collector",
    "context": "context-collector",
    "db_audit": "db-audit-collector",
    "path_flow": "path-flow-collector",
}

# Topics each producer writes completeness records to
_TOPIC_BY_SOURCE: dict = {
    "ebpf": "source.completeness.v0",
    "gateway": "source.completeness.v0",
    "kyverno": "source.completeness.v0",
    "audit": "source.completeness.v0",
    "context": "source.completeness.v0",
    "db_audit": "source.completeness.v0",
    "path_flow": "source.completeness.v0",
}

_PRODUCER_VERSION: str = "mtgen.v0"


class CompletenessRenderer:
    """Produces SourceCompleteness and Heartbeat records from the observability profile.

    Args:
        world:  World-like object with .nodes (NodeState list), .run_start_ns,
                and .run_duration_ns.
        profile_name: Observability profile name from the generator spec
                      (e.g. "clean", "degraded_gateway", "degraded_audit",
                      "degraded_ebpf", "degraded_context").
        profile:      Resolved (unfrozen-expanded) observability profile dict
                      from generator_spec["observability_profiles"][name].
        degrader:     Optional mtgen.degrade.Degrader. When given, gaps are
                      its timed windows and dropped counters its actual drops.
    """

    def __init__(self, world, profile_name: str = "clean", profile: dict = None,
                 degrader=None):
        self._degrader = degrader
        self._nodes: list = list(world.nodes)
        self._run_start_ns: int = world.run_start_ns
        self._run_end_ns: int = world.run_start_ns + world.run_duration_ns
        self._profile_name: str = profile_name
        self._profile: dict = profile or {}

    def render_completeness(
        self,
        event_counts: Optional[Dict[str, Dict[str, int]]] = None,
    ) -> List["stream_pb2.SourceCompleteness"]:
        """Produce one SourceCompleteness per source × scope for this run.

        Scope naming:
          eBPF         -> one per node: "node=<uid>"
          gateway      -> one: "gateway=1"
          kyverno      -> one: "kyverno=1"
          audit        -> one: "audit-collector=1"
          context      -> one: "context-collector=1"
          db_audit     -> one: "db-audit-collector=1"
          path_flow    -> one: "path-flow-collector=1"

        Parameters
        ----------
        event_counts:
            Optional mapping of scope -> {family_or_source_name: count}.
            When provided, the counters map on each SourceCompleteness record
            is populated with emitted counts and, for lossy profiles,
            "dropped:<family>" counts.  Keys use the family name for eBPF
            (e.g. "proc.exec") and the source name for other sources
            (e.g. "gateway", "audit").
        """
        results = []
        counts = event_counts or {}

        # eBPF: one per node
        for node in self._nodes:
            scope = f"node={node.uid}"
            sc = self._make_completeness(source_name="ebpf", scope=scope)
            self._fill_counters(sc, counts.get(scope, {}), "ebpf")
            results.append(sc)

        # One record for each other source
        for src in ("gateway", "kyverno", "audit", "context", "db_audit", "path_flow"):
            scope = _default_scope(src)
            sc = self._make_completeness(source_name=src, scope=scope)
            self._fill_counters(sc, counts.get(scope, {}), src)
            results.append(sc)

        return results

    def _fill_counters(
        self,
        sc: "stream_pb2.SourceCompleteness",
        family_counts: Dict[str, int],
        source_name: str,
    ) -> None:
        """Populate sc.counters from emitted counts plus declared dropped counts.

        For each family in family_counts, set ``sc.counters[family] = count``.
        For lossy profiles, also set ``sc.counters["dropped:<family>"]`` using
        the declared loss percentage from the profile.
        """
        for family, count in family_counts.items():
            if count > 0:
                sc.counters[family] = count

        if self._degrader is not None:
            for family, dropped in self._degrader.dropped_counts(sc.scope).items():
                sc.counters[f"dropped:{family}"] = dropped
            return

        # Compute dropped counts from the observability profile loss percentage
        loss_pct = self._loss_percentage(source_name)
        if loss_pct > 0:
            for family, count in family_counts.items():
                dropped = round(count * loss_pct / 100.0)
                if dropped > 0:
                    sc.counters[f"dropped:{family}"] = dropped

    def _loss_percentage(self, source_name: str) -> float:
        """Return the declared loss percentage for this source under the profile."""
        name = self._profile_name
        profile = self._profile
        if name == "degraded_gateway" and source_name == "gateway":
            return float(_param_val(profile, "observer_loss_percentage", 0))
        if name == "degraded_audit" and source_name == "audit":
            return float(_param_val(profile, "event_loss_percentage", 0))
        if name == "degraded_ebpf" and source_name == "ebpf":
            return float(_param_val(profile, "probe_loss_percentage", 0))
        return 0.0

    def render_heartbeats(self) -> List["stream_pb2.Heartbeat"]:
        """Produce one Heartbeat per producer at the run interval end.

        Each producer gets a single heartbeat on partition 0 of its topic.
        The low_watermark is set to the run end (no earlier records will arrive
        after the generator finishes).
        """
        results = []
        end_ts = ns_to_timestamp(self._run_end_ns)

        # eBPF: one heartbeat per node sensor
        for node in self._nodes:
            results.append(stream_pb2.Heartbeat(
                producer_id="node-sensor",
                producer_instance=f"node-sensor/{node.uid}",
                topic="raw.ebpf.v0",
                partition=0,
                low_watermark=end_ts,
                emitted_at=end_ts,
                producer_seq=1,
            ))

        # One heartbeat per other producer
        for src, producer_id in _PRODUCER_BY_SOURCE.items():
            if src == "ebpf":
                continue
            topic = _raw_topic(src)
            results.append(stream_pb2.Heartbeat(
                producer_id=producer_id,
                producer_instance=f"{producer_id}/1",
                topic=topic,
                partition=0,
                low_watermark=end_ts,
                emitted_at=end_ts,
                producer_seq=1,
            ))

        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_completeness(
        self,
        source_name: str,
        scope: str,
    ) -> "stream_pb2.SourceCompleteness":
        if self._degrader is not None:
            gaps = self._degrader.gaps(source_name, scope)
            status = stream_pb2.INCOMPLETE if gaps else stream_pb2.NO_KNOWN_GAP
        else:
            gaps, status = self._profile_gaps(source_name)
        source_enum = _SOURCE_BY_NAME.get(source_name, common_pb2.SOURCE_UNSPECIFIED)

        sc = stream_pb2.SourceCompleteness(
            source=source_enum,
            scope=scope,
            interval_start=ns_to_timestamp(self._run_start_ns),
            interval_end=ns_to_timestamp(self._run_end_ns),
            status=status,
        )
        for g in gaps:
            sc.gaps.append(g)
        return sc

    def _profile_gaps(self, source_name: str):
        """Return (gaps, CompletenessStatus) for this source under the current profile.

        The clean profile has no gaps. Degraded profiles set INCOMPLETE and add
        a gap describing what was lost.
        """
        profile = self._profile
        name = self._profile_name

        if name == "clean" or not profile:
            return [], stream_pb2.NO_KNOWN_GAP

        gaps: list = []
        status = stream_pb2.NO_KNOWN_GAP

        if name == "degraded_gateway" and source_name == "gateway":
            pct = _param_val(profile, "observer_loss_percentage", 15)
            gaps.append(common_pb2.Gap(
                reason=common_pb2.SOURCE_IDLE,
                scope="source=gateway",
                detail=f"observer_loss_percentage={pct}",
            ))
            status = stream_pb2.INCOMPLETE

        elif name == "degraded_audit" and source_name == "audit":
            pct = _param_val(profile, "event_loss_percentage", 10)
            gaps.append(common_pb2.Gap(
                reason=common_pb2.DROPPED_BEFORE,
                scope="source=audit",
                detail=f"event_loss_percentage={pct}",
            ))
            status = stream_pb2.INCOMPLETE

        elif name == "degraded_ebpf" and source_name == "ebpf":
            families = profile.get("syscall_families_lost", [])
            gaps.append(common_pb2.Gap(
                reason=common_pb2.SOURCE_IDLE,
                scope="source=ebpf",
                detail=f"families_lost={','.join(families)}",
            ))
            status = stream_pb2.INCOMPLETE

        elif name == "degraded_context" and source_name == "context":
            secs = _param_val(profile, "watch_gap_duration_seconds", 15)
            gaps.append(common_pb2.Gap(
                reason=common_pb2.WATCH_RELIST_GAP,
                scope="source=context",
                detail=f"watch_gap_duration_seconds={secs}",
            ))
            status = stream_pb2.INCOMPLETE

        return gaps, status


# ---------------------------------------------------------------------------
# Internal utility functions
# ---------------------------------------------------------------------------

def _param_val(profile: dict, key: str, default):
    """Extract a scalar value from a possibly-unfrozen parameter dict."""
    val = profile.get(key, default)
    if isinstance(val, dict):
        # {pilot_default: X, frozen: null} shape
        return val.get("pilot_default", default)
    return val


def _default_scope(source_name: str) -> str:
    """Return the default scope string for a non-eBPF source."""
    scopes = {
        "gateway": "gateway=1",
        "kyverno": "kyverno=1",
        "audit": "audit-collector=1",
        "context": "context-collector=1",
        "db_audit": "db-audit-collector=1",
        "path_flow": "path-flow-collector=1",
    }
    return scopes.get(source_name, source_name)


def _raw_topic(source_name: str) -> str:
    """Return the raw topic name for a source."""
    topics = {
        "gateway": "raw.gateway.v0",
        "kyverno": "raw.kyverno.v0",
        "audit": "raw.audit.v0",
        "context": "context.cluster.v0",
        "db_audit": "raw.dbaudit.v0",
        "path_flow": "raw.pathflow.v0",
    }
    return topics.get(source_name, "source.completeness.v0")
