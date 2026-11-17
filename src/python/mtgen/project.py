"""Parquet projector for a generated run.

Writes tables under <run_dir>/parquet/:
  events.parquet, context_history.parquet, coverage.parquet, runs.parquet
  restricted/truth_actions.parquet, truth_findings.parquet,
  truth_links.parquet, template_provenance.parquet (empty until phase 3)

Usage::

    from mtgen.project import project_run, detector_view
    parquet_dir = project_run(run_dir)
    det = detector_view(pyarrow.parquet.read_table(parquet_dir / "events.parquet"))

    # CLI
    python -m mtgen project <run_dir>
"""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

import pyarrow as pa
import pyarrow.parquet as pq
from google.protobuf import json_format

import mtgen  # noqa: F401 — registers gen/ on sys.path
from microtrace.v0 import (
    common_pb2,
    dataset_pb2,
    envelope_pb2,
    normalized_pb2,
    witness_pb2,
    finding_pb2,
)

# ---------------------------------------------------------------------------
# Enum lookup tables
# ---------------------------------------------------------------------------

_SPLIT_NAMES: Dict[int, str] = {
    dataset_pb2.DATA_SPLIT_UNSPECIFIED: "DATA_SPLIT_UNSPECIFIED",
    dataset_pb2.FEASIBILITY: "FEASIBILITY",
    dataset_pb2.PILOT: "PILOT",
    dataset_pb2.RESEARCH: "RESEARCH",
    dataset_pb2.HELD_OUT: "HELD_OUT",
    dataset_pb2.SYNTHETIC_EXAMPLE: "SYNTHETIC_EXAMPLE",
}

_SOURCE_NAMES: Dict[int, str] = {
    common_pb2.SOURCE_UNSPECIFIED: "SOURCE_UNSPECIFIED",
    common_pb2.EBPF: "EBPF",
    common_pb2.GATEWAY: "GATEWAY",
    common_pb2.KYVERNO: "KYVERNO",
    common_pb2.AUDIT: "AUDIT",
    common_pb2.CLUSTER_CONTEXT: "CLUSTER_CONTEXT",
    common_pb2.DB_AUDIT: "DB_AUDIT",
    common_pb2.PATH_FLOW: "PATH_FLOW",
}

_TIME_BASIS_NAMES: Dict[int, str] = {
    common_pb2.TIME_BASIS_UNSPECIFIED: "TIME_BASIS_UNSPECIFIED",
    common_pb2.AUDIT_REQUEST_RECEIVED: "AUDIT_REQUEST_RECEIVED",
    common_pb2.AUDIT_STAGE: "AUDIT_STAGE",
    common_pb2.EBPF_MONOTONIC_CORRECTED: "EBPF_MONOTONIC_CORRECTED",
    common_pb2.GATEWAY_OBSERVATION: "GATEWAY_OBSERVATION",
    common_pb2.KYVERNO_ADMISSION: "KYVERNO_ADMISSION",
    common_pb2.WATCH_OBSERVATION: "WATCH_OBSERVATION",
    common_pb2.TIME_BASIS_UNKNOWN: "TIME_BASIS_UNKNOWN",
    common_pb2.DB_AUDIT_SERVER: "DB_AUDIT_SERVER",
    common_pb2.PATH_OBSERVER_FLOW: "PATH_OBSERVER_FLOW",
}

_PROTECTION_NAMES: Dict[int, str] = {
    common_pb2.PROTECTION_CLASS_UNSPECIFIED: "PROTECTION_CLASS_UNSPECIFIED",
    common_pb2.ORDINARY: "ORDINARY",
    common_pb2.PROTECTED_RBAC_BODY: "PROTECTED_RBAC_BODY",
    common_pb2.PROTECTED_HTTP_BODY: "PROTECTED_HTTP_BODY",
    common_pb2.PROTECTED_RAW_RECORD: "PROTECTED_RAW_RECORD",
}

_GAP_REASON_NAMES: Dict[int, str] = {
    common_pb2.GAP_REASON_UNSPECIFIED: "GAP_REASON_UNSPECIFIED",
    common_pb2.TRUNCATED: "TRUNCATED",
    common_pb2.DROPPED_BEFORE: "DROPPED_BEFORE",
    common_pb2.SOURCE_IDLE: "SOURCE_IDLE",
    common_pb2.JOIN_UNCERTAIN: "JOIN_UNCERTAIN",
    common_pb2.POLICY_EXCLUDED: "POLICY_EXCLUDED",
    common_pb2.BODY_STRIPPED: "BODY_STRIPPED",
    common_pb2.WATCH_RELIST_GAP: "WATCH_RELIST_GAP",
    common_pb2.FIELD_ABSENT: "FIELD_ABSENT",
    common_pb2.EXPORT_ERROR: "EXPORT_ERROR",
    common_pb2.COLLECTOR_LAG: "COLLECTOR_LAG",
    common_pb2.PROVIDER_LIMIT: "PROVIDER_LIMIT",
    common_pb2.CONDITIONAL_JOIN_UNVALIDATED: "CONDITIONAL_JOIN_UNVALIDATED",
    common_pb2.DELIVERY_UNESTABLISHED: "DELIVERY_UNESTABLISHED",
}

_ENTITY_TYPE_NAMES: Dict[int, str] = {
    common_pb2.ENTITY_TYPE_UNSPECIFIED: "ENTITY_TYPE_UNSPECIFIED",
    common_pb2.POD: "POD",
    common_pb2.CONTAINER: "CONTAINER",
    common_pb2.PROCESS: "PROCESS",
    common_pb2.PROCESS_LINEAGE: "PROCESS_LINEAGE",
    common_pb2.NODE: "NODE",
    common_pb2.SERVICE_ACCOUNT: "SERVICE_ACCOUNT",
    common_pb2.USER: "USER",
    common_pb2.GROUP: "GROUP",
    common_pb2.NAMESPACE: "NAMESPACE",
    common_pb2.IMAGE: "IMAGE",
    common_pb2.HTTP_REQUEST: "HTTP_REQUEST",
    common_pb2.AUDIT_ACTION: "AUDIT_ACTION",
    common_pb2.RBAC_OBJECT: "RBAC_OBJECT",
    common_pb2.TOKEN_INSTANCE: "TOKEN_INSTANCE",
    common_pb2.FILE_OBJECT: "FILE_OBJECT",
    common_pb2.NETWORK_ENDPOINT: "NETWORK_ENDPOINT",
    common_pb2.FLOW: "FLOW",
    common_pb2.HOST_PROCESS: "HOST_PROCESS",
    common_pb2.UNAUTHENTICATED_SOURCE: "UNAUTHENTICATED_SOURCE",
}

_STRENGTH_NAMES: Dict[int, str] = {
    common_pb2.STRENGTH_CLASS_UNSPECIFIED: "STRENGTH_CLASS_UNSPECIFIED",
    common_pb2.STRENGTH_HIGH: "STRENGTH_HIGH",
    common_pb2.STRENGTH_MEDIUM: "STRENGTH_MEDIUM",
    common_pb2.STRENGTH_LOW: "STRENGTH_LOW",
    common_pb2.STRENGTH_CONTEXT: "STRENGTH_CONTEXT",
}

_TRUTH_EXPECTATION_NAMES: Dict[int, str] = {
    dataset_pb2.TRUTH_EXPECTATION_UNSPECIFIED: "TRUTH_EXPECTATION_UNSPECIFIED",
    dataset_pb2.PRESENT: "PRESENT",
    dataset_pb2.ABSENT: "ABSENT",
    dataset_pb2.UNOBSERVABLE: "UNOBSERVABLE",
}

_WITNESS_TYPE_NAMES: Dict[int, str] = {
    witness_pb2.WITNESS_TYPE_UNSPECIFIED: "WITNESS_TYPE_UNSPECIFIED",
    witness_pb2.NETWORK_FLOW: "NETWORK_FLOW",
    witness_pb2.REQUEST_IDENTITY: "REQUEST_IDENTITY",
    witness_pb2.CREDENTIAL_READ_TO_USE: "CREDENTIAL_READ_TO_USE",
    witness_pb2.PROCESS_ANCESTRY: "PROCESS_ANCESTRY",
    witness_pb2.HOST_TRANSITION: "HOST_TRANSITION",
    witness_pb2.ADMISSION_INSTANCE: "ADMISSION_INSTANCE",
    witness_pb2.CONTROL_PLANE_CAUSALITY_INSTANCE: "CONTROL_PLANE_CAUSALITY_INSTANCE",
    witness_pb2.HOST_CONTEXT: "HOST_CONTEXT",
    witness_pb2.CONTROL_PLANE_CAUSALITY_CLASS: "CONTROL_PLANE_CAUSALITY_CLASS",
    witness_pb2.IMAGE_CLASS: "IMAGE_CLASS",
}

_TACTIC_NAMES: Dict[int, str] = {
    finding_pb2.TACTIC_UNSPECIFIED: "TACTIC_UNSPECIFIED",
    finding_pb2.INITIAL_ACCESS: "INITIAL_ACCESS",
    finding_pb2.EXECUTION: "EXECUTION",
    finding_pb2.PERSISTENCE: "PERSISTENCE",
    finding_pb2.PRIVILEGE_ESCALATION: "PRIVILEGE_ESCALATION",
    finding_pb2.CREDENTIAL_ACCESS: "CREDENTIAL_ACCESS",
    finding_pb2.DISCOVERY: "DISCOVERY",
    finding_pb2.LATERAL_MOVEMENT: "LATERAL_MOVEMENT",
    finding_pb2.EXFILTRATION: "EXFILTRATION",
}

# Map NormalizedEvent record oneof field name → proto message class name
_RECORD_TYPE_TO_MSG: Dict[str, str] = {
    "ebpf": "RawEbpfRecord",
    "audit": "AuditEvent",
    "gateway": "GatewayObservation",
    "kyverno": "AdmissionDecision",
    "context": "ObjectObservation",
    "db_audit": "DbAuditRecord",
    "path_flow": "PathFlowRecord",
}

# Map NormalizedEvent derived oneof field name → proto message class name
_DERIVED_TYPE_TO_MSG: Dict[str, str] = {
    "audit_derived": "AuditDerived",
    "ebpf_derived": "EbpfDerived",
    "admission_derived": "AdmissionDerived",
    "offnode_derived": "OffNodeDerived",
}

# ---------------------------------------------------------------------------
# Arrow sub-schemas
# ---------------------------------------------------------------------------

_ENTITY_REF_TYPE = pa.struct([
    ("type", pa.string()),
    ("uid", pa.string()),
    ("namespace", pa.string()),
    ("name", pa.string()),
    ("strength_class", pa.string()),
])

_GAP_TYPE = pa.struct([
    ("reason", pa.string()),
    ("scope", pa.string()),
    ("detail", pa.string()),
    ("from", pa.string()),
    ("to", pa.string()),
])

_FLOW_KEY_TYPE = pa.struct([
    ("src_addr", pa.string()),
    ("src_port", pa.int32()),
    ("dst_addr", pa.string()),
    ("dst_port", pa.int32()),
    ("protocol", pa.string()),
])

# ---------------------------------------------------------------------------
# Table schemas (public, used by tests)
# ---------------------------------------------------------------------------

EVENTS_SCHEMA = pa.schema([
    ("logical_id", pa.string()),
    ("event_id", pa.string()),
    ("run_id", pa.string()),
    ("split", pa.string()),
    ("capture_profile", pa.string()),
    ("parameter_set_version", pa.string()),
    ("descriptor_set_sha256", pa.string()),
    ("schema_major", pa.uint32()),
    ("schema_minor", pa.uint32()),
    ("producer_id", pa.string()),
    ("producer_version", pa.string()),
    ("source_family", pa.string()),
    ("record_type", pa.string()),
    ("source_native_id", pa.string()),
    ("source_stage", pa.string()),
    ("action_id", pa.string()),
    ("source_time", pa.timestamp("us", tz="UTC")),
    ("event_time", pa.timestamp("us", tz="UTC")),
    ("ingest_time", pa.timestamp("us", tz="UTC")),
    ("time_basis", pa.string()),
    ("event_time_uncertain", pa.bool_()),
    ("clock_uncertainty_ns", pa.uint64()),
    ("clock_model_version", pa.string()),
    ("node_uid", pa.string()),
    ("namespace", pa.string()),
    ("pod_uid", pa.string()),
    ("container_id", pa.string()),
    ("process_key", pa.string()),
    ("principal_id", pa.string()),
    ("request_id", pa.string()),
    ("flow_key", _FLOW_KEY_TYPE),
    ("entity_refs", pa.list_(_ENTITY_REF_TYPE)),
    ("record_payload", pa.string()),
    ("derived_context", pa.string()),
    ("evidence_archive_id", pa.string()),
    ("evidence_object_key", pa.string()),
    ("evidence_sha256", pa.string()),
    ("evidence_protection", pa.string()),
    ("completeness_gaps", pa.list_(_GAP_TYPE)),
    ("normalizer_version", pa.string()),
    ("context_version", pa.string()),
    ("capture_manifest_version", pa.string()),
])

# Columns dropped in detector_view: routing, version, and hash columns.
# "version" = any column whose name ends with _version or is descriptor_set_sha256,
#             schema_major, schema_minor.
# "hash"    = any column whose name ends with _sha256.
# "routing" = run_id, split, producer_id, producer_version.
_DETECTOR_DROP = frozenset({
    "run_id", "split",
    "producer_id", "producer_version",
    "parameter_set_version", "descriptor_set_sha256",
    "schema_major", "schema_minor",
    "normalizer_version", "context_version", "capture_manifest_version",
    "evidence_sha256",
})

RUNS_SCHEMA = pa.schema([
    ("run_id", pa.string()),
    ("split", pa.string()),
    ("world_version", pa.string()),
    ("generator_version", pa.string()),
    ("scenario_family", pa.string()),
    ("service_count", pa.int32()),
    ("pod_instance_count", pa.int32()),
    ("container_instance_count", pa.int32()),
    ("logical_node_count", pa.int32()),
    ("seed_ref", pa.string()),
    ("base_stream_sha256", pa.string()),
    ("truth_sha256", pa.string()),
    ("manifest_sha256", pa.string()),
])

CONTEXT_HISTORY_SCHEMA = pa.schema([
    ("run_id", pa.string()),
    ("entity_type", pa.string()),
    ("entity_uid", pa.string()),
    ("valid_from", pa.int64()),
    ("valid_to", pa.int64()),
    ("observed_from", pa.int64()),
    ("parent_uid", pa.string()),
    ("attributes", pa.string()),
    ("history_version", pa.string()),
    ("ambiguity_reason", pa.string()),
])

COVERAGE_SCHEMA = pa.schema([
    ("run_id", pa.string()),
    ("source_family", pa.string()),
    ("scope", pa.string()),
    ("interval_start", pa.string()),
    ("interval_end", pa.string()),
    ("status", pa.string()),
    ("gap_reason", pa.string()),
    ("fault_id", pa.string()),
])

TRUTH_ACTIONS_SCHEMA = pa.schema([
    ("run_id", pa.string()),
    ("action_seq", pa.uint64()),
    ("scenario_id", pa.string()),
    ("variant_id", pa.string()),
    ("step_label", pa.string()),
    ("is_attack", pa.bool_()),
    ("expected_finding_types", pa.list_(pa.string())),
    ("intended_tactic", pa.string()),
    ("actors", pa.list_(_ENTITY_REF_TYPE)),
    ("targets", pa.list_(_ENTITY_REF_TYPE)),
    ("started_at", pa.timestamp("us", tz="UTC")),
    ("ended_at", pa.timestamp("us", tz="UTC")),
    ("harness_version", pa.string()),
    ("harness_outcome", pa.string()),
    ("rendered_event_ids", pa.list_(pa.string())),
])

TRUTH_FINDINGS_SCHEMA = pa.schema([
    ("run_id", pa.string()),
    ("opportunity_id", pa.string()),
    ("action_seq", pa.uint64()),
    ("finding_type", pa.string()),
    ("window_start", pa.timestamp("us", tz="UTC")),
    ("window_end", pa.timestamp("us", tz="UTC")),
    ("expected_state", pa.string()),
    ("evidence_requirements", pa.list_(pa.string())),
    ("reason", pa.string()),
    ("truth_version", pa.string()),
    ("evidence_event_ids", pa.list_(pa.string())),
])

TRUTH_LINKS_SCHEMA = pa.schema([
    ("run_id", pa.string()),
    ("link_id", pa.string()),
    ("from_action_seq", pa.uint64()),
    ("to_action_seq", pa.uint64()),
    ("witness_type", pa.string()),
    ("expected_state", pa.string()),
    ("shared_keys", pa.list_(pa.string())),
    ("reason", pa.string()),
    ("truth_version", pa.string()),
])

TEMPLATE_PROVENANCE_SCHEMA = pa.schema([
    ("event_id", pa.string()),
    ("field_paths", pa.list_(pa.string())),
    ("origin_class", pa.string()),
    ("source_dataset", pa.string()),
    ("release_version", pa.string()),
    ("archive_sha256", pa.string()),
    ("original_file", pa.string()),
    ("original_record_id", pa.string()),
    ("template_pool", pa.string()),
    ("transform_version", pa.string()),
    ("license_status", pa.string()),
])

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def project_run(run_dir: Path) -> Path:
    """Project a generated run into Parquet tables.

    Reads base.pb, manifest.json, context_history.jsonl, and the restricted
    truth files; writes Parquet under <run_dir>/parquet/.

    Returns
    -------
    Path
        The parquet directory created.
    """
    run_dir = Path(run_dir)
    parquet_dir = run_dir / "parquet"
    restricted_dir = parquet_dir / "restricted"
    parquet_dir.mkdir(parents=True, exist_ok=True)
    restricted_dir.mkdir(exist_ok=True)

    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))

    # events
    events_tbl = _project_events(run_dir)
    pq.write_table(events_tbl, parquet_dir / "events.parquet")

    # context_history
    ch_tbl = _project_context_history(run_dir)
    pq.write_table(ch_tbl, parquet_dir / "context_history.parquet")

    # coverage
    cov_tbl = _project_coverage(run_dir)
    pq.write_table(cov_tbl, parquet_dir / "coverage.parquet")

    # runs (one row, derived from manifest + context_history)
    runs_tbl = _project_runs(run_dir, manifest, ch_tbl)
    pq.write_table(runs_tbl, parquet_dir / "runs.parquet")

    # restricted truth tables
    _project_truth_actions(run_dir, restricted_dir)
    _project_truth_findings(run_dir, restricted_dir)
    _project_truth_links(run_dir, restricted_dir)
    _project_template_provenance(restricted_dir)

    return parquet_dir


def detector_view(events_table: pa.Table) -> pa.Table:
    """Return the detector-visible projection of an events table.

    Drops run_id, split, producer_*, and every version and hash column.
    Keeps event_id/logical_id as opaque references only.

    Parameters
    ----------
    events_table:
        A table with the EVENTS_SCHEMA schema.

    Returns
    -------
    pa.Table
        Subset of events_table with restricted/routing columns removed.
    """
    keep = [
        name for name in events_table.schema.names
        if name not in _DETECTOR_DROP
    ]
    return events_table.select(keep)


# ---------------------------------------------------------------------------
# events projection
# ---------------------------------------------------------------------------

def _project_events(run_dir: Path) -> pa.Table:
    """Read base.pb and project all NORMALIZED_EVENT envelopes to events rows."""
    rows: List[dict] = []
    for env in _iter_envelopes(run_dir / "base.pb"):
        if env.kind != envelope_pb2.NORMALIZED_EVENT:
            continue
        rows.append(_env_to_event_row(env))

    if not rows:
        return pa.table({name: pa.array([], type=f.type)
                         for name, f in zip(EVENTS_SCHEMA.names, EVENTS_SCHEMA)},
                        schema=EVENTS_SCHEMA)

    return _rows_to_table(rows, EVENTS_SCHEMA)


def _env_to_event_row(env: "envelope_pb2.Envelope") -> dict:
    """Project one NORMALIZED_EVENT Envelope to an events row dict."""
    ne = env.normalized_event
    run = env.run

    record_field = ne.WhichOneof("record")
    derived_field = ne.WhichOneof("derived")

    # Record payload: JSON with @type annotation
    if record_field:
        record_msg = getattr(ne, record_field)
        msg_name = _RECORD_TYPE_TO_MSG.get(record_field, record_field)
        record_payload = _proto_to_json_str(record_msg, msg_name)
    else:
        record_payload = "{}"

    # Derived context: JSON with @type annotation, or None
    derived_context = None
    if derived_field:
        derived_msg = getattr(ne, derived_field)
        msg_name = _DERIVED_TYPE_TO_MSG.get(derived_field, derived_field)
        derived_context = _proto_to_json_str(derived_msg, msg_name)

    # Identity columns from entity list
    node_uid, namespace, pod_uid, container_id, process_key, principal_id, request_id = (
        _extract_identities(ne)
    )

    flow_key = _extract_flow_key(ne)
    entity_refs = _entity_refs_list(ne)
    gaps = _completeness_gaps_list(ne.completeness)

    ev = ne.evidence_ref
    time = ne.time

    return {
        "logical_id": env.logical_id,
        "event_id": ne.event_id,
        "run_id": run.run_id,
        "split": _SPLIT_NAMES.get(run.split, str(run.split)),
        "capture_profile": run.capture_profile,
        "parameter_set_version": run.parameter_set_version,
        "descriptor_set_sha256": run.descriptor_set_sha256,
        "schema_major": env.schema_major,
        "schema_minor": env.schema_minor,
        "producer_id": env.producer_id,
        "producer_version": env.producer_version,
        "source_family": _SOURCE_NAMES.get(env.source, str(env.source)),
        "record_type": record_field or "",
        "source_native_id": ne.source_native_id or None,
        "source_stage": ne.source_stage or None,
        "action_id": ne.action_id if ne.HasField("action_id") else None,
        "source_time": _ts_to_us(time.source_time),
        "event_time": _ts_to_us_required(time.event_time),
        "ingest_time": _ts_to_us_required(time.ingest_time),
        "time_basis": _TIME_BASIS_NAMES.get(
            time.event_time_basis, str(time.event_time_basis)
        ),
        "event_time_uncertain": time.event_time_uncertain,
        "clock_uncertainty_ns": time.clock_uncertainty_ns,
        "clock_model_version": time.clock_model_version or None,
        "node_uid": node_uid,
        "namespace": namespace,
        "pod_uid": pod_uid,
        "container_id": container_id,
        "process_key": process_key,
        "principal_id": principal_id,
        "request_id": request_id,
        "flow_key": flow_key,
        "entity_refs": entity_refs,
        "record_payload": record_payload,
        "derived_context": derived_context,
        "evidence_archive_id": ev.archive_id or "",
        "evidence_object_key": ev.object_key or "",
        "evidence_sha256": ev.sha256_hex or "",
        "evidence_protection": _PROTECTION_NAMES.get(ev.protection, str(ev.protection)),
        "completeness_gaps": gaps,
        "normalizer_version": ne.normalizer_version or "",
        "context_version": ne.context_version or "",
        "capture_manifest_version": ne.capture_manifest_version or "",
    }


# ---------------------------------------------------------------------------
# context_history projection
# ---------------------------------------------------------------------------

def _project_context_history(run_dir: Path) -> pa.Table:
    """Read context_history.jsonl and project to context_history table."""
    path = run_dir / "context_history.jsonl"
    rows: List[dict] = []
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            rows.append({
                "run_id": str(obj.get("run_id", "")),
                "entity_type": str(obj.get("entity_type", "")),
                "entity_uid": str(obj.get("entity_uid", "")),
                "valid_from": int(obj.get("valid_from", 0)),
                "valid_to": int(obj.get("valid_to", 0)),
                "observed_from": int(obj.get("observed_from", 0)),
                "parent_uid": str(obj.get("parent_uid", "") or ""),
                "attributes": json.dumps(
                    obj.get("attributes", {}), separators=(",", ":")
                ),
                "history_version": str(obj.get("history_version", "")),
                "ambiguity_reason": str(obj.get("ambiguity_reason", "") or ""),
            })

    if not rows:
        return pa.table(
            {name: pa.array([], type=f.type)
             for name, f in zip(CONTEXT_HISTORY_SCHEMA.names, CONTEXT_HISTORY_SCHEMA)},
            schema=CONTEXT_HISTORY_SCHEMA,
        )
    return _rows_to_table(rows, CONTEXT_HISTORY_SCHEMA)


# ---------------------------------------------------------------------------
# coverage projection
# ---------------------------------------------------------------------------

def _project_coverage(run_dir: Path) -> pa.Table:
    """Read restricted/coverage.jsonl and project to coverage table."""
    path = run_dir / "restricted" / "coverage.jsonl"
    rows: List[dict] = []
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            rows.append({
                "run_id": str(obj.get("run_id", "")),
                "source_family": str(obj.get("source_family", "")),
                "scope": str(obj.get("scope", "")),
                "interval_start": str(obj.get("interval_start", "")),
                "interval_end": str(obj.get("interval_end", "")),
                "status": str(obj.get("status", "")),
                "gap_reason": str(obj.get("gap_reason", "")),
                "fault_id": str(obj.get("fault_id", "")),
            })

    if not rows:
        return pa.table(
            {name: pa.array([], type=f.type)
             for name, f in zip(COVERAGE_SCHEMA.names, COVERAGE_SCHEMA)},
            schema=COVERAGE_SCHEMA,
        )
    return _rows_to_table(rows, COVERAGE_SCHEMA)


# ---------------------------------------------------------------------------
# runs projection
# ---------------------------------------------------------------------------

def _project_runs(
    run_dir: Path, manifest: dict, ch_tbl: pa.Table
) -> pa.Table:
    """Build the single-row runs table from the manifest and context_history."""
    run_id = manifest.get("run_id", "")
    split_name = manifest.get("split", "PILOT")
    world_name = manifest.get("world_name", "")
    gen_spec_ver = manifest.get("generator_spec_version", "generator-spec.v0")
    world_version = f"{world_name}/{gen_spec_ver}"
    generator_version = manifest.get("generator_version", "")

    is_held_out = (split_name == "HELD_OUT")

    # scenario_family and seed_ref: restricted for HELD_OUT
    if is_held_out:
        scenario_family = None
        seed_ref = None
    else:
        scenario_family = ",".join(manifest.get("scenario_ids", []))
        seed_ref = _read_seed_ref(run_dir)

    # entity counts from context_history
    entity_counts = _count_entities(ch_tbl)
    service_count = entity_counts.get("ServiceAccount", 0)
    pod_instance_count = entity_counts.get("Pod", 0)
    container_instance_count = entity_counts.get("Container", 0)
    logical_node_count = entity_counts.get("Node", 0)

    hashes = manifest.get("hashes", {})
    base_stream_sha256 = hashes.get("base_stream_sha256", "")
    truth_sha256 = hashes.get("truth_sha256", "")
    manifest_sha256 = hashlib.sha256(
        (run_dir / "manifest.json").read_bytes()
    ).hexdigest()

    row = {
        "run_id": [run_id],
        "split": [split_name],
        "world_version": [world_version],
        "generator_version": [generator_version],
        "scenario_family": [scenario_family],
        "service_count": [service_count],
        "pod_instance_count": [pod_instance_count],
        "container_instance_count": [container_instance_count],
        "logical_node_count": [logical_node_count],
        "seed_ref": [seed_ref],
        "base_stream_sha256": [base_stream_sha256],
        "truth_sha256": [truth_sha256],
        "manifest_sha256": [manifest_sha256],
    }
    arrays = []
    for field in RUNS_SCHEMA:
        val = row[field.name]
        arrays.append(pa.array(val, type=field.type))
    return pa.table(
        {field.name: arr for field, arr in zip(RUNS_SCHEMA, arrays)},
        schema=RUNS_SCHEMA,
    )


def _read_seed_ref(run_dir: Path) -> Optional[str]:
    """Read the generator seed from restricted/seeds/manifest.json."""
    path = run_dir / "restricted" / "seeds" / "manifest.json"
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
        seed = data.get("seeds", {}).get("generator_seed")
        if seed is not None:
            return str(seed)
    return None


def _count_entities(ch_tbl: pa.Table) -> Dict[str, int]:
    """Count distinct entity_uids per entity_type in the context_history table."""
    counts: Dict[str, set] = {}
    if ch_tbl.num_rows == 0:
        return {}
    for et, uid in zip(
        ch_tbl.column("entity_type").to_pylist(),
        ch_tbl.column("entity_uid").to_pylist(),
    ):
        counts.setdefault(et, set()).add(uid)
    return {et: len(uids) for et, uids in counts.items()}


# ---------------------------------------------------------------------------
# Restricted truth tables
# ---------------------------------------------------------------------------

def _project_truth_actions(run_dir: Path, out_dir: Path) -> None:
    """Project truth_actions.pb → truth_actions.parquet."""
    pb_path = run_dir / "restricted" / "truth_actions.pb"
    rows: List[dict] = []
    if pb_path.exists():
        for msg in _read_ld_protos(pb_path, dataset_pb2.GroundTruthAction):
            tactic = (
                _TACTIC_NAMES.get(msg.intended_tactic, str(msg.intended_tactic))
                if msg.HasField("intended_tactic")
                else None
            )
            rows.append({
                "run_id": msg.run_id,
                "action_seq": msg.action_seq,
                "scenario_id": msg.scenario_id,
                "variant_id": msg.variant_id,
                "step_label": msg.step_label,
                "is_attack": msg.is_attack,
                "expected_finding_types": list(msg.expected_finding_types),
                "intended_tactic": tactic,
                "actors": [_entity_ref_dict(e) for e in msg.actors],
                "targets": [_entity_ref_dict(e) for e in msg.targets],
                "started_at": _ts_to_us(msg.started_at),
                "ended_at": _ts_to_us(msg.ended_at),
                "harness_version": msg.harness_version,
                "harness_outcome": msg.harness_outcome,
                "rendered_event_ids": list(msg.rendered_event_ids),
            })

    if not rows:
        tbl = pa.table(
            {name: pa.array([], type=f.type)
             for name, f in zip(TRUTH_ACTIONS_SCHEMA.names, TRUTH_ACTIONS_SCHEMA)},
            schema=TRUTH_ACTIONS_SCHEMA,
        )
    else:
        tbl = _rows_to_table(rows, TRUTH_ACTIONS_SCHEMA)
    pq.write_table(tbl, out_dir / "truth_actions.parquet")


def _project_truth_findings(run_dir: Path, out_dir: Path) -> None:
    """Project truth_findings.pb → truth_findings.parquet."""
    pb_path = run_dir / "restricted" / "truth_findings.pb"
    rows: List[dict] = []
    if pb_path.exists():
        for msg in _read_ld_protos(pb_path, dataset_pb2.FindingOpportunity):
            rows.append({
                "run_id": msg.run_id,
                "opportunity_id": msg.opportunity_id,
                "action_seq": msg.action_seq,
                "finding_type": msg.finding_type,
                "window_start": _ts_to_us(msg.window_start),
                "window_end": _ts_to_us(msg.window_end),
                "expected_state": _TRUTH_EXPECTATION_NAMES.get(
                    msg.expected_state, str(msg.expected_state)
                ),
                "evidence_requirements": list(msg.evidence_requirements),
                "reason": msg.reason,
                "truth_version": msg.truth_version,
                "evidence_event_ids": list(msg.evidence_event_ids),
            })

    if not rows:
        tbl = pa.table(
            {name: pa.array([], type=f.type)
             for name, f in zip(TRUTH_FINDINGS_SCHEMA.names, TRUTH_FINDINGS_SCHEMA)},
            schema=TRUTH_FINDINGS_SCHEMA,
        )
    else:
        tbl = _rows_to_table(rows, TRUTH_FINDINGS_SCHEMA)
    pq.write_table(tbl, out_dir / "truth_findings.parquet")


def _project_truth_links(run_dir: Path, out_dir: Path) -> None:
    """Project truth_links.pb → truth_links.parquet."""
    pb_path = run_dir / "restricted" / "truth_links.pb"
    rows: List[dict] = []
    if pb_path.exists():
        for msg in _read_ld_protos(pb_path, dataset_pb2.ActionLink):
            rows.append({
                "run_id": msg.run_id,
                "link_id": msg.link_id,
                "from_action_seq": msg.from_action_seq,
                "to_action_seq": msg.to_action_seq,
                "witness_type": _WITNESS_TYPE_NAMES.get(
                    msg.witness_type, str(msg.witness_type)
                ),
                "expected_state": _TRUTH_EXPECTATION_NAMES.get(
                    msg.expected_state, str(msg.expected_state)
                ),
                "shared_keys": list(msg.shared_keys),
                "reason": msg.reason,
                "truth_version": msg.truth_version,
            })

    if not rows:
        tbl = pa.table(
            {name: pa.array([], type=f.type)
             for name, f in zip(TRUTH_LINKS_SCHEMA.names, TRUTH_LINKS_SCHEMA)},
            schema=TRUTH_LINKS_SCHEMA,
        )
    else:
        tbl = _rows_to_table(rows, TRUTH_LINKS_SCHEMA)
    pq.write_table(tbl, out_dir / "truth_links.parquet")


def _project_template_provenance(out_dir: Path) -> None:
    """Write empty template_provenance.parquet (phase 3 not yet implemented)."""
    tbl = pa.table(
        {name: pa.array([], type=f.type)
         for name, f in zip(
             TEMPLATE_PROVENANCE_SCHEMA.names, TEMPLATE_PROVENANCE_SCHEMA
         )},
        schema=TEMPLATE_PROVENANCE_SCHEMA,
    )
    pq.write_table(tbl, out_dir / "template_provenance.parquet")


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------

def _extract_identities(
    ne: "normalized_pb2.NormalizedEvent",
) -> Tuple[
    Optional[str], Optional[str], Optional[str], Optional[str],
    Optional[str], Optional[str], Optional[str],
]:
    """Return (node_uid, namespace, pod_uid, container_id, process_key,
    principal_id, request_id) from the NormalizedEvent entity list and derived."""
    node_uid = pod_uid = container_id = process_key = None
    principal_id = request_id = namespace = None

    for ent in ne.entities:
        etype = ent.type
        uid = ent.uid or None
        ns = ent.namespace or None
        name = ent.name or None

        if ns and namespace is None:
            namespace = ns

        if etype == common_pb2.POD and pod_uid is None:
            pod_uid = uid
        elif etype == common_pb2.CONTAINER and container_id is None:
            container_id = uid
        elif etype in (common_pb2.PROCESS, common_pb2.PROCESS_LINEAGE) and process_key is None:
            process_key = uid
        elif etype == common_pb2.NODE and node_uid is None:
            node_uid = uid
        elif etype == common_pb2.USER and principal_id is None:
            principal_id = uid or name
        elif etype == common_pb2.HTTP_REQUEST and request_id is None:
            request_id = uid

    # Override principal_id from audit_derived (more authoritative)
    if ne.HasField("audit_derived"):
        ad = ne.audit_derived
        if ad.HasField("principal"):
            p = ad.principal
            principal_id = p.uid or p.name or principal_id

    # Fill pod_uid from derived fields when not in entity list
    if pod_uid is None:
        if ne.HasField("ebpf_derived") and ne.ebpf_derived.pod_uid:
            pod_uid = ne.ebpf_derived.pod_uid
        elif ne.HasField("admission_derived") and ne.admission_derived.pod_uid:
            pod_uid = ne.admission_derived.pod_uid
        elif ne.HasField("offnode_derived") and ne.offnode_derived.pod_uid:
            pod_uid = ne.offnode_derived.pod_uid

    # Fill node_uid from eBPF record node_id when not in entity list
    if node_uid is None:
        rec_field = ne.WhichOneof("record")
        if rec_field == "ebpf" and ne.ebpf.node_id:
            node_uid = ne.ebpf.node_id
        elif ne.HasField("offnode_derived") and ne.offnode_derived.node_uid:
            node_uid = ne.offnode_derived.node_uid

    return node_uid, namespace, pod_uid, container_id, process_key, principal_id, request_id


def _extract_flow_key(
    ne: "normalized_pb2.NormalizedEvent",
) -> Optional[dict]:
    """Extract a flow key struct from a NormalizedEvent, or None."""
    rec_field = ne.WhichOneof("record")
    if rec_field == "path_flow":
        pf = ne.path_flow
        return {
            "src_addr": pf.src.ip,
            "src_port": pf.src.port,
            "dst_addr": pf.dst.ip,
            "dst_port": pf.dst.port,
            "protocol": str(pf.src.protocol),
        }
    if rec_field == "db_audit":
        db = ne.db_audit
        return {
            "src_addr": db.client.ip,
            "src_port": db.client.port,
            "dst_addr": "",
            "dst_port": 0,
            "protocol": str(db.client.protocol),
        }
    if rec_field == "ebpf":
        detail = ne.ebpf.WhichOneof("detail")
        if detail == "socket":
            sd = ne.ebpf.socket
            return {
                "src_addr": sd.local.ip,
                "src_port": sd.local.port,
                "dst_addr": sd.remote.ip,
                "dst_port": sd.remote.port,
                "protocol": str(sd.local.protocol),
            }
    return None


def _entity_refs_list(ne: "normalized_pb2.NormalizedEvent") -> List[dict]:
    """Convert NormalizedEvent.entities to a list of dicts."""
    return [_entity_ref_dict(ent) for ent in ne.entities]


def _entity_ref_dict(ent: "common_pb2.EntityRef") -> dict:
    """Convert one EntityRef proto to a dict for Arrow struct encoding."""
    return {
        "type": _ENTITY_TYPE_NAMES.get(ent.type, str(ent.type)),
        "uid": ent.uid or "",
        "namespace": ent.namespace or "",
        "name": ent.name or "",
        "strength_class": _STRENGTH_NAMES.get(ent.strength_class, str(ent.strength_class)),
    }


def _completeness_gaps_list(completeness) -> List[dict]:
    """Convert Completeness.gaps to a list of dicts."""
    result = []
    for gap in completeness.gaps:
        from_ts = getattr(gap, "from")
        result.append({
            "reason": _GAP_REASON_NAMES.get(gap.reason, str(gap.reason)),
            "scope": gap.scope or "",
            "detail": gap.detail or "",
            "from": _ts_to_iso(from_ts),
            "to": _ts_to_iso(gap.to),
        })
    return result


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def _iter_envelopes(path: Path) -> Iterator["envelope_pb2.Envelope"]:
    """Yield Envelopes from a length-delimited protobuf file."""
    with open(path, "rb") as fh:
        while True:
            header = fh.read(4)
            if not header:
                break
            (length,) = struct.unpack(">I", header)
            data = fh.read(length)
            env = envelope_pb2.Envelope()
            env.ParseFromString(data)
            yield env


def _read_ld_protos(path: Path, message_class) -> List:
    """Read all length-delimited protobuf messages from path."""
    messages = []
    with open(path, "rb") as fh:
        while True:
            header = fh.read(4)
            if not header:
                break
            (length,) = struct.unpack(">I", header)
            data = fh.read(length)
            msg = message_class()
            msg.ParseFromString(data)
            messages.append(msg)
    return messages


def _ts_to_us(ts) -> Optional[int]:
    """Convert protobuf Timestamp to microseconds since epoch, or None if zero."""
    if ts.seconds == 0 and ts.nanos == 0:
        return None
    return ts.seconds * 1_000_000 + ts.nanos // 1000


def _ts_to_us_required(ts) -> int:
    """Convert protobuf Timestamp to microseconds since epoch (always a value)."""
    return ts.seconds * 1_000_000 + ts.nanos // 1000


def _ts_to_iso(ts) -> str:
    """Convert protobuf Timestamp to ISO 8601 UTC string, empty if zero."""
    import datetime
    if ts.seconds == 0 and ts.nanos == 0:
        return ""
    dt = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + \
        datetime.timedelta(seconds=ts.seconds, microseconds=ts.nanos // 1000)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _proto_to_json_str(msg, type_name: str) -> str:
    """Serialize a proto message to a JSON string with its @type field."""
    d = json_format.MessageToDict(msg, preserving_proto_field_name=True)
    d["@type"] = f"type.googleapis.com/microtrace.v0.{type_name}"
    return json.dumps(d, separators=(",", ":"))


def _rows_to_table(rows: List[dict], schema: pa.Schema) -> pa.Table:
    """Build a PyArrow Table from a list of row dicts, casting to schema."""
    columns = {}
    for field in schema:
        col_vals = [row[field.name] for row in rows]
        try:
            columns[field.name] = pa.array(col_vals, type=field.type)
        except (pa.ArrowInvalid, pa.ArrowTypeError) as exc:
            raise ValueError(
                f"column {field.name!r}: {exc}"
            ) from exc
    return pa.table(columns, schema=schema)
