"""Emitter: Envelope builder, producer-node assignment, shipper files, base stream.

Responsibilities
----------------
1. Accept the full render output (NormalizedEvents, raw context observations,
   source-completeness records, heartbeats, ground-truth actions) plus a World
   and RunContext.
2. Set entities[0] on each NormalizedEvent (renderers leave it empty).
3. Build one Envelope per record with a stable logical_id.
4. Assign each envelope to a "sending node":
   - eBPF    → the node that observed the event (ne.ebpf.node_id)
   - gateway → gateway infra node (= control-plane node)
   - audit / kyverno / context → control-plane node
   - db_audit / path_flow → "off-node" (virtual, no Kubernetes node)
5. Classify each envelope into PRIORITY or NORMAL lane (escape-class eBPF
   families get PRIORITY).
6. Write per-node shipper input files (JSON lines) under out_dir/shipper/.
7. Write canonical base.pb (length-delimited Envelopes ordered by
   node_key, lane, event_time_ns, logical_id).
8. Return EmitResult with SHA-256 hashes and stream statistics.
"""
from __future__ import annotations

import datetime
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import mtcodec
from google.protobuf import json_format
from microtrace.v0 import (
    common_pb2,
    context_pb2,
    dataset_pb2,
    envelope_pb2,
    normalized_pb2,
    stream_pb2,
)

from mtgen.envelopes import (
    build_envelope,
    deserialize_length_delimited,
    serialize_length_delimited,
)
from mtgen.render.context import context_native_id

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PRODUCER_VERSION: str = "mtgen.v0"
_SCHEMA_MAJOR: int = 0
_SCHEMA_MINOR: int = 0

# eBPF event families that route to the PRIORITY lane
_ESCAPE_FAMILIES: frozenset = frozenset({
    "ns.change",
    "ipc.runtime_socket",
    "proc.ptrace",
    "bpf.call",
})

# Lane numeric values (from ship.proto: PRIORITY=1, NORMAL=2)
_LANE_PRIORITY: int = 1
_LANE_NORMAL: int = 2
_LANE_NAME: Dict[int, str] = {_LANE_PRIORITY: "PRIORITY", _LANE_NORMAL: "NORMAL"}

# Entity type int → string name (from common.proto EntityType enum)
_ENTITY_TYPE_NAMES: Dict[int, str] = {
    common_pb2.POD: "POD",
    common_pb2.PROCESS: "PROCESS",
    common_pb2.PROCESS_LINEAGE: "PROCESS_LINEAGE",
    common_pb2.NODE: "NODE",
    common_pb2.SERVICE_ACCOUNT: "SERVICE_ACCOUNT",
    common_pb2.USER: "USER",
    common_pb2.HOST_PROCESS: "HOST_PROCESS",
    common_pb2.HTTP_REQUEST: "HTTP_REQUEST",
    common_pb2.AUDIT_ACTION: "AUDIT_ACTION",
    common_pb2.NETWORK_ENDPOINT: "NETWORK_ENDPOINT",
}

# Source enum int → string name (from common.proto Source enum)
_SOURCE_NAMES: Dict[int, str] = {
    common_pb2.EBPF: "EBPF",
    common_pb2.GATEWAY: "GATEWAY",
    common_pb2.AUDIT: "AUDIT",
    common_pb2.KYVERNO: "KYVERNO",
    common_pb2.CLUSTER_CONTEXT: "CLUSTER_CONTEXT",
    common_pb2.DB_AUDIT: "DB_AUDIT",
    common_pb2.PATH_FLOW: "PATH_FLOW",
}

# Context object kind → EntityType int
_CONTEXT_KIND_TO_ENTITY: Dict[str, int] = {
    "Pod": common_pb2.POD,
    "Node": common_pb2.NODE,
    "ServiceAccount": common_pb2.SERVICE_ACCOUNT,
}

# Producer → raw topic (for heartbeat routing)
_HEARTBEAT_TOPIC: Dict[str, str] = {
    "node-sensor": "raw.ebpf.v0",
    "gateway-observer": "raw.gateway.v0",
    "audit-collector": "raw.audit.v0",
    "kyverno-exporter": "raw.kyverno.v0",
    "context-collector": "context.cluster.v0",
    "db-audit-collector": "raw.dbaudit.v0",
    "path-flow-collector": "raw.pathflow.v0",
}

# Sentinel node key for off-node observers (db_audit / path_flow)
_OFF_NODE_KEY: str = "off-node"


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class EmitResult:
    """Output of one Emitter.emit() call.

    Attributes:
        base_stream_path:  Path to canonical base.pb
        base_stream_sha256: SHA-256 hex of base.pb
        total_envelopes:   Number of Envelopes written to base.pb
        logical_id_count:  Distinct logical_id values
        shipper_paths:     node_key -> Path of shipper input file
        events_per_source: source name -> count of NORMALIZED_EVENTs
    """
    base_stream_path: Path
    base_stream_sha256: str
    total_envelopes: int
    logical_id_count: int
    shipper_paths: Dict[str, Path] = field(default_factory=dict)
    events_per_source: Dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Internal record wrapper
# ---------------------------------------------------------------------------

@dataclass
class _Rec:
    """One record pending emission."""
    envelope: "envelope_pb2.Envelope"
    node_key: str       # e.g. node uid or "off-node"
    topic: str
    key_type: str       # KeyType enum name, e.g. "KEY_PRIMARY_ENTITY"
    key_components: List[str]  # one string value per declared component
    lane: int           # _LANE_PRIORITY or _LANE_NORMAL
    event_time_ns: int  # for ordering


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class Emitter:
    """Builds and writes the canonical base stream, shipper files.

    Parameters
    ----------
    world : World
        Built, finalised world instance.  Only .nodes and .infra are accessed.
    run_context : dataset_pb2.RunContext
        RunContext embedded in every Envelope.
    producer_version : str
        Producer version tag written into every Envelope (default "mtgen.v0").
    """

    def __init__(
        self,
        world,
        run_context: "dataset_pb2.RunContext",
        producer_version: str = _PRODUCER_VERSION,
    ) -> None:
        self._world = world
        self._run_context = run_context
        self._producer_version = producer_version

        # Control-plane node uid (first node = ctrl plane in world.py)
        nodes = list(world.nodes)
        self._ctrl_node_uid: str = nodes[0].uid if nodes else ""

        # eBPF-node uid set for quick membership test
        self._node_uids: frozenset = frozenset(n.uid for n in nodes)

    def emit(
        self,
        ne_list: List["normalized_pb2.NormalizedEvent"],
        context_obs: List["context_pb2.ObjectObservation"],
        sc_records: List["stream_pb2.SourceCompleteness"],
        heartbeats: List["stream_pb2.Heartbeat"],
        gta_protos: List["dataset_pb2.GroundTruthAction"],
        out_dir: Path,
    ) -> EmitResult:
        """Build all output artifacts for one run.

        Parameters
        ----------
        ne_list :      NormalizedEvents from all renderers.
        context_obs :  Raw ObjectObservation protos from world.context_observations.
        sc_records :   SourceCompleteness protos from CompletenessRenderer.
        heartbeats :   Heartbeat protos from CompletenessRenderer.
        gta_protos :   GroundTruthAction protos from TruthResult.actions.
        out_dir :      Root of the run directory; shipper/ created inside.
        """
        out_dir = Path(out_dir)
        shipper_dir = out_dir / "shipper"
        shipper_dir.mkdir(parents=True, exist_ok=True)

        recs: List[_Rec] = []
        events_per_source: Dict[str, int] = {}

        # 1. NormalizedEvents
        for ne in ne_list:
            _set_entities(ne)
            rec = self._ne_to_rec(ne)
            recs.append(rec)
            src_name = _SOURCE_NAMES.get(ne.source, "UNKNOWN")
            events_per_source[src_name] = events_per_source.get(src_name, 0) + 1

        # 2. Raw context observations
        for obs in context_obs:
            recs.append(self._context_obs_to_rec(obs))

        # 3. Source completeness
        for sc in sc_records:
            recs.append(self._sc_to_rec(sc))

        # 4. Heartbeats
        for hb in heartbeats:
            recs.append(self._heartbeat_to_rec(hb))

        # 5. Ground truth actions
        for gta in gta_protos:
            recs.append(self._gta_to_rec(gta))

        # Sort for the canonical base stream
        recs.sort(key=lambda r: (r.node_key, r.lane, r.event_time_ns, r.envelope.logical_id))

        # Write base stream
        base_path = out_dir / "base.pb"
        base_sha256, total = _write_base_stream(recs, base_path)

        # Write shipper input files (grouped by node_key, ordered within node)
        shipper_paths = _write_shipper_files(recs, shipper_dir)

        logical_ids = {r.envelope.logical_id for r in recs}

        return EmitResult(
            base_stream_path=base_path,
            base_stream_sha256=base_sha256,
            total_envelopes=total,
            logical_id_count=len(logical_ids),
            shipper_paths=shipper_paths,
            events_per_source=events_per_source,
        )

    # ------------------------------------------------------------------
    # Record builders
    # ------------------------------------------------------------------

    def _ne_to_rec(self, ne: "normalized_pb2.NormalizedEvent") -> _Rec:
        logical_id = ne.event_id
        node_key = self._node_key_for_source(ne.source, ne)
        lane = _lane_for_ne(ne)

        env = build_envelope(
            kind=envelope_pb2.NORMALIZED_EVENT,
            logical_id=logical_id,
            source=ne.source,
            run_context=self._run_context,
            producer_id=_producer_id_for_source(ne.source),
            producer_version=self._producer_version,
            schema_major=_SCHEMA_MAJOR,
            schema_minor=_SCHEMA_MINOR,
            payload=ne,
        )

        # Key components for norm.events.v0
        entities = list(ne.entities)
        if entities:
            type_name = _ENTITY_TYPE_NAMES.get(entities[0].type, "POD")
            key_components = [type_name, entities[0].uid or logical_id]
        else:
            key_components = ["POD", logical_id]

        time_ns = _ne_time_ns(ne)
        return _Rec(
            envelope=env,
            node_key=node_key,
            topic="norm.events.v0",
            key_type="KEY_PRIMARY_ENTITY",
            key_components=key_components,
            lane=lane,
            event_time_ns=time_ns,
        )

    def _context_obs_to_rec(self, obs: "context_pb2.ObjectObservation") -> _Rec:
        logical_id = mtcodec.logical_id("event", {
            "source": "CLUSTER_CONTEXT",
            "source_native_id": context_native_id(obs),
            "source_stage": "watch",
            "payload_version": "raw.v0",
        })
        time_ns = obs.observed_time.seconds * 1_000_000_000 + obs.observed_time.nanos

        env = build_envelope(
            kind=envelope_pb2.CONTEXT_OBSERVATION,
            logical_id=logical_id,
            source=common_pb2.CLUSTER_CONTEXT,
            run_context=self._run_context,
            producer_id="context-collector",
            producer_version=self._producer_version,
            schema_major=_SCHEMA_MAJOR,
            schema_minor=_SCHEMA_MINOR,
            payload=obs,
        )
        return _Rec(
            envelope=env,
            node_key=self._ctrl_node_uid,
            topic="context.cluster.v0",
            key_type="KEY_OBJECT_UID",
            key_components=[obs.uid],
            lane=_LANE_NORMAL,
            event_time_ns=time_ns,
        )

    def _sc_to_rec(self, sc: "stream_pb2.SourceCompleteness") -> _Rec:
        source_name = _SOURCE_NAMES.get(sc.source, "UNKNOWN")
        native_id = f"{source_name}/{sc.scope}"
        logical_id = mtcodec.logical_id("event", {
            "source": "completeness",
            "source_native_id": native_id,
            "source_stage": "window",
            "payload_version": "v0",
        })
        # completeness records report on the run interval end
        time_ns = (sc.interval_end.seconds * 1_000_000_000 + sc.interval_end.nanos
                   if sc.HasField("interval_end") else 0)

        node_key = self._node_key_for_sc(sc)

        env = build_envelope(
            kind=envelope_pb2.SOURCE_COMPLETENESS,
            logical_id=logical_id,
            source=sc.source,
            run_context=self._run_context,
            producer_id=_producer_id_for_source(sc.source),
            producer_version=self._producer_version,
            schema_major=_SCHEMA_MAJOR,
            schema_minor=_SCHEMA_MINOR,
            payload=sc,
        )
        return _Rec(
            envelope=env,
            node_key=node_key,
            topic="source.completeness.v0",
            key_type="KEY_SOURCE_SCOPE",
            key_components=[source_name, sc.scope],
            lane=_LANE_NORMAL,
            event_time_ns=time_ns,
        )

    def _heartbeat_to_rec(self, hb: "stream_pb2.Heartbeat") -> _Rec:
        native_id = f"{hb.producer_instance}@{hb.topic}"
        logical_id = mtcodec.logical_id("event", {
            "source": "heartbeat",
            "source_native_id": native_id,
            "source_stage": "emitted",
            "payload_version": "v0",
        })
        time_ns = hb.emitted_at.seconds * 1_000_000_000 + hb.emitted_at.nanos
        topic = _HEARTBEAT_TOPIC.get(hb.producer_id, "source.completeness.v0")
        node_key = self._node_key_for_heartbeat(hb)

        env = build_envelope(
            kind=envelope_pb2.HEARTBEAT,
            logical_id=logical_id,
            source=common_pb2.SOURCE_UNSPECIFIED,
            run_context=self._run_context,
            producer_id=hb.producer_id,
            producer_version=self._producer_version,
            schema_major=_SCHEMA_MAJOR,
            schema_minor=_SCHEMA_MINOR,
            payload=hb,
        )
        return _Rec(
            envelope=env,
            node_key=node_key,
            topic=topic,
            key_type="KEY_PRODUCER_INSTANCE",
            key_components=[hb.producer_instance],
            lane=_LANE_NORMAL,
            event_time_ns=time_ns,
        )

    def _gta_to_rec(self, gta: "dataset_pb2.GroundTruthAction") -> _Rec:
        logical_id = mtcodec.logical_id("ground_truth", {
            "run_id": gta.run_id,
            "action_seq": str(gta.action_seq),
        })
        time_ns = gta.started_at.seconds * 1_000_000_000 + gta.started_at.nanos

        env = build_envelope(
            kind=envelope_pb2.GROUND_TRUTH_ACTION,
            logical_id=logical_id,
            source=common_pb2.SOURCE_UNSPECIFIED,
            run_context=self._run_context,
            producer_id="scenario-harness",
            producer_version=self._producer_version,
            schema_major=_SCHEMA_MAJOR,
            schema_minor=_SCHEMA_MINOR,
            payload=gta,
        )
        return _Rec(
            envelope=env,
            node_key=self._ctrl_node_uid,
            topic="ground.truth.v0",
            key_type="KEY_RUN",
            key_components=[gta.run_id],
            lane=_LANE_NORMAL,
            event_time_ns=time_ns,
        )

    # ------------------------------------------------------------------
    # Node-key helpers
    # ------------------------------------------------------------------

    def _node_key_for_source(
        self,
        source: int,
        ne: "normalized_pb2.NormalizedEvent",
    ) -> str:
        if source == common_pb2.EBPF:
            nid = ne.ebpf.node_id
            return nid if nid in self._node_uids else self._ctrl_node_uid
        if source in (common_pb2.DB_AUDIT, common_pb2.PATH_FLOW):
            return _OFF_NODE_KEY
        return self._ctrl_node_uid

    def _node_key_for_sc(self, sc: "stream_pb2.SourceCompleteness") -> str:
        if sc.source in (common_pb2.DB_AUDIT, common_pb2.PATH_FLOW):
            return _OFF_NODE_KEY
        if sc.source == common_pb2.EBPF:
            # scope = "node=<uid>"; extract uid
            scope = sc.scope
            if scope.startswith("node="):
                nid = scope[5:]
                if nid in self._node_uids:
                    return nid
        return self._ctrl_node_uid

    def _node_key_for_heartbeat(self, hb: "stream_pb2.Heartbeat") -> str:
        pid = hb.producer_id
        if pid == "node-sensor":
            # producer_instance = "node-sensor/<node-uid>"
            parts = hb.producer_instance.split("/", 1)
            if len(parts) == 2 and parts[1] in self._node_uids:
                return parts[1]
        if pid in ("db-audit-collector", "path-flow-collector"):
            return _OFF_NODE_KEY
        return self._ctrl_node_uid


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _set_entities(ne: "normalized_pb2.NormalizedEvent") -> None:
    """Mutate ne to put the primary entity at entities[0], if not already set.

    A renderer may add only secondary entities (the eBPF acting PROCESS or
    HOST_PROCESS); the primary entity then goes in front of them.
    """
    if any(e.type not in _SECONDARY_ENTITY_TYPES for e in ne.entities):
        return  # already set by a renderer

    source = ne.source

    if source == common_pb2.EBPF:
        # Prefer pod_uid from EbpfDerived, fall back to node_id
        pod_uid = ""
        if ne.HasField("ebpf_derived"):
            pod_uid = ne.ebpf_derived.pod_uid
        if pod_uid:
            etype = common_pb2.POD
            uid = pod_uid
        else:
            etype = common_pb2.NODE
            uid = ne.ebpf.node_id

    elif source == common_pb2.AUDIT:
        # Use the derived principal (type USER) when available; it carries the
        # correct UID and is checked by the identity verifier.  Fall back to
        # AUDIT_ACTION so the entity UID is never fabricated from event_id.
        if ne.HasField("audit_derived") and ne.audit_derived.HasField("principal"):
            p = ne.audit_derived.principal
            etype = p.type   # USER
            uid = p.uid if p.uid else ne.event_id
        else:
            etype = common_pb2.AUDIT_ACTION
            uid = ne.audit.audit_id if ne.audit.audit_id else ne.event_id

    elif source == common_pb2.GATEWAY:
        # Primary entity is the HTTP request object; request_id is its native id.
        uid = ne.gateway.request_id if ne.gateway.request_id else ne.event_id
        etype = common_pb2.HTTP_REQUEST

    elif source == common_pb2.KYVERNO:
        # Primary entity is the admitted Pod
        uid = ne.kyverno.resource_uid if ne.kyverno.resource_uid else ne.event_id
        etype = common_pb2.POD

    elif source == common_pb2.CLUSTER_CONTEXT:
        obs = ne.context
        kind = obs.kind
        etype = _CONTEXT_KIND_TO_ENTITY.get(kind, common_pb2.POD)
        uid = obs.uid if obs.uid else ne.event_id

    elif source == common_pb2.DB_AUDIT:
        if ne.HasField("offnode_derived") and ne.offnode_derived.pod_uid:
            uid = ne.offnode_derived.pod_uid
            etype = common_pb2.POD
        elif ne.HasField("offnode_derived") and ne.offnode_derived.source_address:
            uid = ne.offnode_derived.source_address
            etype = common_pb2.NETWORK_ENDPOINT
        else:
            uid = ne.event_id
            etype = common_pb2.AUDIT_ACTION

    elif source == common_pb2.PATH_FLOW:
        if ne.HasField("offnode_derived") and ne.offnode_derived.pod_uid:
            uid = ne.offnode_derived.pod_uid
            etype = common_pb2.POD
        elif ne.HasField("offnode_derived") and ne.offnode_derived.source_address:
            uid = ne.offnode_derived.source_address
            etype = common_pb2.NETWORK_ENDPOINT
        else:
            uid = ne.event_id
            etype = common_pb2.AUDIT_ACTION

    else:
        etype = common_pb2.POD
        uid = ne.event_id

    secondary = list(ne.entities)
    del ne.entities[:]
    ne.entities.add(
        type=etype,
        uid=uid,
        strength_class=common_pb2.STRENGTH_HIGH,
    )
    ne.entities.extend(secondary)


_SECONDARY_ENTITY_TYPES = (common_pb2.PROCESS, common_pb2.HOST_PROCESS)


def _lane_for_ne(ne: "normalized_pb2.NormalizedEvent") -> int:
    """Return PRIORITY lane for escape-class eBPF families, NORMAL otherwise."""
    if ne.source == common_pb2.EBPF and ne.ebpf.event_family in _ESCAPE_FAMILIES:
        return _LANE_PRIORITY
    return _LANE_NORMAL


def _ne_time_ns(ne: "normalized_pb2.NormalizedEvent") -> int:
    ts = ne.time.event_time
    return ts.seconds * 1_000_000_000 + ts.nanos


def _producer_id_for_source(source: int) -> str:
    _pid = {
        common_pb2.EBPF: "node-sensor",
        common_pb2.GATEWAY: "gateway-observer",
        common_pb2.AUDIT: "audit-collector",
        common_pb2.KYVERNO: "kyverno-exporter",
        common_pb2.CLUSTER_CONTEXT: "context-collector",
        common_pb2.DB_AUDIT: "db-audit-collector",
        common_pb2.PATH_FLOW: "path-flow-collector",
    }
    return _pid.get(source, "mtgen")


# ---------------------------------------------------------------------------
# File writers
# ---------------------------------------------------------------------------

def _write_base_stream(recs: List[_Rec], path: Path) -> Tuple[str, int]:
    """Write length-delimited Envelopes to path and return (sha256_hex, count)."""
    hasher = hashlib.sha256()
    count = 0
    with open(path, "wb") as f:
        for r in recs:
            data = serialize_length_delimited(r.envelope)
            f.write(data)
            hasher.update(data)
            count += 1
    return hasher.hexdigest(), count


def _write_shipper_files(
    recs: List[_Rec],
    shipper_dir: Path,
) -> Dict[str, Path]:
    """Write per-node shipper input files; return {node_key: path}."""
    # Group by node_key (preserve the sorted order from the base stream)
    by_node: Dict[str, List[_Rec]] = {}
    for r in recs:
        by_node.setdefault(r.node_key, []).append(r)

    paths: Dict[str, Path] = {}
    for node_key, node_recs in by_node.items():
        # Within node: sort by (lane, event_time_ns, logical_id)
        node_recs_sorted = sorted(
            node_recs,
            key=lambda r: (r.lane, r.event_time_ns, r.envelope.logical_id),
        )

        # Safe filename: replace UUID hyphens, truncate UIDs
        safe_key = node_key.replace("/", "_").replace(" ", "_")
        fname = f"node-{safe_key[:12]}.jsonl" if node_key != _OFF_NODE_KEY else "off-node.jsonl"
        fpath = shipper_dir / fname
        paths[node_key] = fpath

        # Watermark lines (src/go/cmd/shipper/main.go handleLine): records on
        # a lane are in event-time order, so a record's event time is a valid
        # low watermark. Declared at lane start, every _WATERMARK_EVERY
        # records, and at lane end.
        with open(fpath, "w", encoding="utf-8", newline="\n") as f:
            prev_lane = None
            n_in_lane = 0
            last_ns = 0
            for r in node_recs_sorted:
                if r.lane != prev_lane:
                    if prev_lane is not None:
                        f.write(_watermark_line(prev_lane, last_ns))
                    prev_lane, n_in_lane = r.lane, 0
                if n_in_lane % _WATERMARK_EVERY == 0:
                    f.write(_watermark_line(r.lane, r.event_time_ns))
                line = _shipper_line(r)
                f.write(json.dumps(line, separators=(",", ":")) + "\n")
                n_in_lane += 1
                last_ns = r.event_time_ns
            if prev_lane is not None:
                f.write(_watermark_line(prev_lane, last_ns))

    return paths


_WATERMARK_EVERY = 1000


def _rfc3339_ns(ns: int) -> str:
    """RFC 3339 UTC timestamp with nanoseconds (Go time.RFC3339Nano parses it)."""
    secs, frac = divmod(ns, 1_000_000_000)
    base = datetime.datetime.fromtimestamp(secs, datetime.timezone.utc)
    return base.strftime("%Y-%m-%dT%H:%M:%S") + f".{frac:09d}Z"


def _watermark_line(lane: int, ns: int) -> str:
    return json.dumps(
        {"lane": _LANE_NAME[lane], "watermark": _rfc3339_ns(ns)},
        separators=(",", ":"),
    ) + "\n"


def write_context_history(rows, path: Path) -> str:
    """Write ContextHistoryRow records as sorted JSONL; return SHA-256 hex."""
    out = [
        json.dumps(
            {
                "run_id": r.run_id,
                "entity_type": r.entity_type,
                "entity_uid": r.entity_uid,
                "valid_from": r.valid_from,
                "valid_to": r.valid_to,
                "observed_from": r.observed_from,
                "parent_uid": r.parent_uid,
                "attributes": r.attributes,
                "history_version": r.history_version,
                "ambiguity_reason": r.ambiguity_reason,
            },
            sort_keys=True, separators=(",", ":"), default=str,
        )
        for r in rows
    ]
    out.sort()
    data = ("\n".join(out) + ("\n" if out else "")).encode("utf-8")
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def _shipper_line(r: _Rec) -> dict:
    """Build one shipper JSON line dict from a _Rec."""
    env_dict = json_format.MessageToDict(
        r.envelope,
        preserving_proto_field_name=True,
    )
    # Map fields come out in the runtime's hash order; sort the keys so
    # builds are byte-identical.
    env_dict = json.loads(json.dumps(env_dict, sort_keys=True))
    return {
        "lane": _LANE_NAME[r.lane],
        "topic": r.topic,
        "key_type": r.key_type,
        "key_components": r.key_components,
        "envelope": env_dict,
    }


# ---------------------------------------------------------------------------
# Manifest writer helper
# ---------------------------------------------------------------------------

def write_manifest(
    manifest: dict,
    run_dir: Path,
    seeds_restricted: bool = True,
) -> Tuple[Path, str]:
    """Write build manifest JSON to run_dir/manifest.json.

    Seeds are written separately to run_dir/restricted/seeds/manifest.json
    when seeds_restricted=True (the manifest itself omits them).

    Returns (manifest_path, manifest_sha256).
    """
    run_dir = Path(run_dir)
    seeds = manifest.pop("seeds", {})

    if seeds_restricted:
        seeds_dir = run_dir / "restricted" / "seeds"
        seeds_dir.mkdir(parents=True, exist_ok=True)
        seeds_path = seeds_dir / "manifest.json"
        seeds_path.write_text(
            json.dumps({"seeds": seeds}, indent=2), encoding="utf-8", newline="\n"
        )

    manifest_path = run_dir / "manifest.json"
    manifest_text = json.dumps(manifest, indent=2, sort_keys=True)
    manifest_path.write_text(manifest_text, encoding="utf-8", newline="\n")

    sha256 = hashlib.sha256(manifest_text.encode("utf-8")).hexdigest()
    manifest["seeds"] = seeds  # restore for caller
    return manifest_path, sha256


# ---------------------------------------------------------------------------
# Truth hash helper
# ---------------------------------------------------------------------------

def compute_truth_sha256(run_dir: Path) -> str:
    """Compute SHA-256 of the concatenated truth files under restricted/.

    Hash input: truth_actions.pb + truth_findings.pb + truth_links.pb
    (in that fixed order).
    """
    restricted = Path(run_dir) / "restricted"
    hasher = hashlib.sha256()
    for fname in ("truth_actions.pb", "truth_findings.pb", "truth_links.pb"):
        p = restricted / fname
        if p.exists():
            hasher.update(p.read_bytes())
    return hasher.hexdigest()
