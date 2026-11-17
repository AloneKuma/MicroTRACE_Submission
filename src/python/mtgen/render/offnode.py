"""Off-node renderer: Activity -> NormalizedEvent wrapping DbAuditRecord or PathFlowRecord.

Handles activities that represent off-node telemetry:

  db_query          -> DbAuditRecord  + OffNodeDerived
  path_flow         -> PathFlowRecord + OffNodeDerived
  egress_transfer   -> PathFlowRecord + OffNodeDerived (alias; same parameters)

Both record types carry OffNodeDerived, which attributes the source address to
a Pod (POD_ADDRESS), a node host-network context (NODE_HOST_CONTEXT), or marks
it ambiguous (AMBIGUOUS) when the PodIP history is not resolved.

H5 is excluded (off-node volume anomaly); however the background workload and
Experiment 3 (off-node outage) both emit DbAuditRecord and PathFlowRecord.
"""

from mtgen.minting import UuidMinter
from typing import List, Optional

from microtrace.v0 import common_pb2, ebpf_pb2, normalized_pb2, offnode_pb2
from .common import (
    CAPTURE_MANIFEST_VERSION, CONTEXT_VERSION, NORMALIZER_VERSION,
    completeness_gap, empty_completeness, event_id, make_time_info,
)
from mtgen.activity import Activity
from mtgen.history import Ambiguous, WorldHistory
from mtgen.simtime import ns_to_timestamp

_DB_OBSERVER_ID: str = "db-audit-collector.v0"
_PATH_OBSERVER_ID: str = "path-flow-collector.v0"
_AUDIT_POLICY_VERSION: str = "db-audit-policy.v0"
_EXPORT_CONFIG_VERSION: str = "flow-export.v0"
_ADDRESS_MAP_VERSION: str = "addrmap.v0"

# Default db engine label
_DB_ENGINE: str = "postgresql/pgaudit@16"

# IP protocol
_IPPROTO_TCP: int = 6


class OffNodeRenderer:
    """Renders db_query and path_flow/egress_transfer Activities into NormalizedEvents.

    Args:
        world_history:  WorldHistory for PodIP -> pod_uid time-indexed lookups.
        node_map:       Optional dict of node_uid -> NodeState; used for
                        NODE_HOST_CONTEXT classification. May be empty or None.
    """

    def __init__(
        self,
        world_history: WorldHistory,
        node_map: Optional[dict] = None,
    ):
        self._history = world_history
        self._node_map: dict = node_map or {}
        self._ids = UuidMinter("offnode")

    def render(self, activity: Activity) -> List["normalized_pb2.NormalizedEvent"]:
        """Render one Activity.

        Supported kinds:
          db_query          -> DbAuditRecord
          path_flow         -> PathFlowRecord
          egress_transfer   -> PathFlowRecord (alias for off-node path records)

        Returns an empty list for unsupported activity kinds.
        """
        kind = activity.kind
        if kind == "db_query":
            return [self._render_db_audit(activity)]
        if kind in ("path_flow", "egress_transfer"):
            return [self._render_path_flow(activity)]
        return []

    # ------------------------------------------------------------------
    # DbAuditRecord
    # ------------------------------------------------------------------

    def _render_db_audit(self, activity: Activity) -> "normalized_pb2.NormalizedEvent":
        """db_query Activity -> DbAuditRecord + OffNodeDerived.

        Activity.parameters:
          client_ip         str   source IP address (default "10.0.0.1")
          client_port       int   source port (default 54321)
          db_user           str   database user (default "app")
          database          str   database name (default "appdb")
          object_name       str   schema-qualified table name (default "")
          statement_class   str   SELECT / INSERT / UPDATE / DELETE (default "SELECT")
          succeeded         bool  (default True)
          rows_returned     int   optional rows returned
          bytes_returned    int   optional bytes returned
          engine            str   engine/plugin version string
          record_id         str   explicit record ID (auto-generated if absent)
        """
        p = activity.parameters
        client_ip = p.get("client_ip", "10.0.0.1")
        client_port = int(p.get("client_port", 54321))
        db_user = p.get("db_user", "app")
        database = p.get("database", "appdb")
        object_name = p.get("object_name", "")
        statement_class = p.get("statement_class", "SELECT")
        succeeded = bool(p.get("succeeded", True))
        engine = p.get("engine", _DB_ENGINE)
        record_id = p.get("record_id") or self._ids.mint("db", activity.time_ns, client_ip, client_port, object_name)

        client_ep = ebpf_pb2.Endpoint(ip=client_ip, port=client_port, protocol=_IPPROTO_TCP)
        ts = ns_to_timestamp(activity.time_ns)

        rec = offnode_pb2.DbAuditRecord(
            record_id=record_id,
            engine=engine,
            audit_policy_version=_AUDIT_POLICY_VERSION,
            database=database,
            object_name=object_name,
            statement_class=statement_class,
            client=client_ep,
            db_user=db_user,
            succeeded=succeeded,
            server_time=ts,
        )

        rows_returned = p.get("rows_returned")
        if rows_returned is not None:
            rec.rows_returned = int(rows_returned)
        bytes_returned = p.get("bytes_returned")
        if bytes_returned is not None:
            rec.bytes_returned = int(bytes_returned)

        gaps: list = []
        derived = self._make_offnode_derived(client_ip, "", activity.time_ns, gaps)

        completeness = (
            common_pb2.Completeness(gaps=gaps) if gaps else empty_completeness()
        )

        native_id = record_id
        ev_id = event_id("db_audit", native_id, "statement")

        return normalized_pb2.NormalizedEvent(
            event_id=ev_id,
            source=common_pb2.DB_AUDIT,
            source_native_id=native_id,
            source_stage="statement",
            time=make_time_info(activity.time_ns, common_pb2.DB_AUDIT_SERVER),
            db_audit=rec,
            offnode_derived=derived,
            completeness=completeness,
            normalizer_version=NORMALIZER_VERSION,
            context_version=CONTEXT_VERSION,
            capture_manifest_version=CAPTURE_MANIFEST_VERSION,
        )

    # ------------------------------------------------------------------
    # PathFlowRecord
    # ------------------------------------------------------------------

    def _actor_pod_ip(self, activity: Activity) -> str:
        """IP of the acting Pod at activity time, or "" when not a known Pod."""
        pod = self._history.at("Pod", activity.actor_uid, activity.time_ns)
        if pod is None or pod is Ambiguous:
            return ""
        ips = getattr(pod, "pod_ips", None) or []
        return ips[0] if ips else ""

    def _target_pod_ip(self, activity: Activity) -> str:
        """IP of the step's target Pod (target_pod / target_service_or_pod), or ""."""
        p = activity.parameters
        uid = p.get("target_pod") or p.get("target_service_or_pod")
        pod = self._history.at("Pod", uid, activity.time_ns) if uid else None
        if pod is None or pod is Ambiguous:
            return ""
        ips = getattr(pod, "pod_ips", None) or []
        return ips[0] if ips else ""

    def _render_path_flow(self, activity: Activity) -> "normalized_pb2.NormalizedEvent":
        """path_flow / egress_transfer Activity -> PathFlowRecord + OffNodeDerived.

        Activity.parameters:
          src_ip            str   source IP (default: the acting Pod's IP, else "10.0.0.1")
          src_port          int   source port (default 45000)
          dst_ip            str   destination IP (default: destination, then remote_ip, then
                                  the target_pod's IP, then "1.2.3.4")
          dst_port          int   destination port (default 443)
          octets            int   bytes source-to-destination (default 0)
          packets           int   packets (default 0)
          bytes_out         int   alias for octets when octets absent
          end_reason        str   IDLE_TIMEOUT/ACTIVE_TIMEOUT/END_OF_FLOW (default END_OF_FLOW)
          sampled           bool  (default False)
          flow_id           str   exporter_flow_id (auto-generated if absent)
          observer_id       str   observer identifier
          duration_ns       int   flow duration in ns (default 1 s); flow_end = time_ns + duration_ns
        """
        p = activity.parameters
        src_ip = p.get("src_ip") or self._actor_pod_ip(activity) or "10.0.0.1"
        src_port = int(p.get("src_port", 45000))
        # Scenarios name the far end "destination" (or a target Pod role);
        # workload flows "dst_ip".
        dst_ip = (p.get("dst_ip") or p.get("destination") or p.get("remote_ip")
                  or self._target_pod_ip(activity) or "1.2.3.4")
        dst_port = int(p.get("dst_port", 443))
        octets = int(p.get("octets", p.get("bytes_out", 0)))
        packets = int(p.get("packets", 0))
        sampled = bool(p.get("sampled", False))
        observer_id = p.get("observer_id", _PATH_OBSERVER_ID)
        flow_id = p.get("flow_id") or self._ids.mint("flow", activity.time_ns, src_ip, src_port, dst_ip, dst_port)
        duration_ns = int(p.get("duration_ns", 1_000_000_000))

        end_reason_str = p.get("end_reason", "END_OF_FLOW").upper()
        end_reason_map = {
            "IDLE_TIMEOUT": offnode_pb2.IDLE_TIMEOUT,
            "ACTIVE_TIMEOUT": offnode_pb2.ACTIVE_TIMEOUT,
            "END_OF_FLOW": offnode_pb2.END_OF_FLOW,
            "FORCED_END": offnode_pb2.FORCED_END,
            "LACK_OF_RESOURCES": offnode_pb2.LACK_OF_RESOURCES,
        }
        end_reason = end_reason_map.get(end_reason_str, offnode_pb2.END_OF_FLOW)

        flow_start_ns = activity.time_ns
        flow_end_ns = activity.time_ns + duration_ns

        src_ep = ebpf_pb2.Endpoint(ip=src_ip, port=src_port, protocol=_IPPROTO_TCP)
        dst_ep = ebpf_pb2.Endpoint(ip=dst_ip, port=dst_port, protocol=_IPPROTO_TCP)

        rec = offnode_pb2.PathFlowRecord(
            observer_id=observer_id,
            exporter_flow_id=flow_id,
            export_config_version=_EXPORT_CONFIG_VERSION,
            src=src_ep,
            dst=dst_ep,
            octets=octets,
            packets=packets,
            flow_start=ns_to_timestamp(flow_start_ns),
            flow_end=ns_to_timestamp(flow_end_ns),
            end_reason=end_reason,
            sampled=sampled,
        )

        # Determine remote class for OffNodeDerived
        dst_class = _classify_remote(dst_ip, self._history, activity.time_ns)

        gaps: list = []
        derived = self._make_offnode_derived(src_ip, dst_class, activity.time_ns, gaps)

        completeness = (
            common_pb2.Completeness(gaps=gaps) if gaps else empty_completeness()
        )

        native_id = f"{observer_id}/{flow_id}"
        ev_id = event_id("path_flow", native_id, "export")

        return normalized_pb2.NormalizedEvent(
            event_id=ev_id,
            source=common_pb2.PATH_FLOW,
            source_native_id=native_id,
            source_stage="export",
            time=make_time_info(activity.time_ns, common_pb2.PATH_OBSERVER_FLOW),
            path_flow=rec,
            offnode_derived=derived,
            completeness=completeness,
            normalizer_version=NORMALIZER_VERSION,
            context_version=CONTEXT_VERSION,
            capture_manifest_version=CAPTURE_MANIFEST_VERSION,
        )

    # ------------------------------------------------------------------
    # OffNodeDerived construction
    # ------------------------------------------------------------------

    def _make_offnode_derived(
        self,
        source_ip: str,
        remote_class: str,
        time_ns: int,
        gaps: list,
    ) -> "offnode_pb2.OffNodeDerived":
        """Derive OffNodeDerived from the source IP via PodIP history.

        source_address_class:
          POD_ADDRESS       -> unambiguous Pod holder
          AMBIGUOUS         -> ambiguous (multiple holders); JOIN_UNCERTAIN gap added
          NODE_HOST_CONTEXT -> IP is a node IP not held by any hostNetwork Pod
        """
        ip_state = self._history.at("PodIP", source_ip, time_ns)

        derived_kw: dict = {
            "source_address": source_ip,
            "address_map_version": _ADDRESS_MAP_VERSION,
            "remote_class": remote_class,
        }

        if ip_state is Ambiguous:
            derived_kw["source_address_class"] = offnode_pb2.AMBIGUOUS
            gaps.append(completeness_gap(
                reason=common_pb2.JOIN_UNCERTAIN,
                scope="field=pod_uid",
                detail=f"source IP {source_ip!r} ambiguous at event time",
            ))
        elif ip_state is not None:
            derived_kw["source_address_class"] = offnode_pb2.POD_ADDRESS
            derived_kw["pod_uid"] = ip_state.uid
            # node_uid from pod -> infra lookup (best-effort; absent when not tracked)
        else:
            # Not a Pod IP; treat as node host-network context
            derived_kw["source_address_class"] = offnode_pb2.NODE_HOST_CONTEXT

        return offnode_pb2.OffNodeDerived(**derived_kw)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _classify_remote(ip: str, history: WorldHistory, time_ns: int) -> str:
    """Classify a remote IP as cluster_pod, cluster_service, or external."""
    if not ip:
        return ""
    state = history.at("PodIP", ip, time_ns)
    if state is Ambiguous or state is not None:
        return "cluster_pod"
    return "external"
