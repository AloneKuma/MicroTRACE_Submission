"""Build Envelope records with RunContext and serialize length-delimited."""
import hashlib
import struct
from typing import Optional

from google.protobuf import descriptor_pb2
from google.protobuf.descriptor_pool import Default
from microtrace.v0 import envelope_pb2, dataset_pb2, common_pb2


def _descriptor_set_sha256() -> str:
    """Compute SHA-256 of the compiled descriptor set of spec/proto.

    Returns:
        64-character lowercase hex SHA-256 hash of the descriptor set bytes
    """
    pool = Default()
    descriptor_set = descriptor_pb2.FileDescriptorSet()

    descriptor_names = [
        "microtrace/v0/common.proto",
        "microtrace/v0/envelope.proto",
        "microtrace/v0/dataset.proto",
        "microtrace/v0/ebpf.proto",
        "microtrace/v0/audit.proto",
        "microtrace/v0/gateway.proto",
        "microtrace/v0/kyverno.proto",
        "microtrace/v0/offnode.proto",
        "microtrace/v0/context.proto",
        "microtrace/v0/normalized.proto",
        "microtrace/v0/finding.proto",
        "microtrace/v0/witness.proto",
        "microtrace/v0/incident.proto",
        "microtrace/v0/stream.proto",
        "microtrace/v0/keys.proto",
        "microtrace/v0/ship.proto",
    ]

    seen = set()
    for name in descriptor_names:
        try:
            fd = pool.FindFileByName(name)
            _collect_file_descriptors(fd, descriptor_set, seen)
        except KeyError:
            pass

    data = descriptor_set.SerializeToString()
    return hashlib.sha256(data).hexdigest()


def _collect_file_descriptors(
    fd, descriptor_set: descriptor_pb2.FileDescriptorSet, seen: set
):
    """Recursively collect file descriptors and their dependencies."""
    if fd.name in seen:
        return
    seen.add(fd.name)

    for dep in fd.dependencies:
        _collect_file_descriptors(dep, descriptor_set, seen)

    file_proto = descriptor_pb2.FileDescriptorProto()
    file_proto.ParseFromString(fd.serialized_pb)
    descriptor_set.file.append(file_proto)


def build_run_context(
    run_id: str,
    split: int,
    capture_profile: str,
    parameter_set_version: str,
) -> dataset_pb2.RunContext:
    """Build a RunContext message.

    Args:
        run_id: unique run identifier
        split: DataSplit enum value (1=FEASIBILITY, 2=PILOT, 3=RESEARCH, 4=HELD_OUT)
        capture_profile: capture manifest profile name
        parameter_set_version: version string of parameters applied

    Returns:
        RunContext message with descriptor_set_sha256 pre-computed
    """
    descriptor_sha256 = _descriptor_set_sha256()
    return dataset_pb2.RunContext(
        run_id=run_id,
        split=split,
        capture_profile=capture_profile,
        parameter_set_version=parameter_set_version,
        descriptor_set_sha256=descriptor_sha256,
    )


def build_envelope(
    kind: int,
    logical_id: str,
    source: int,
    run_context: dataset_pb2.RunContext,
    producer_id: str = "mtgen",
    producer_version: str = "0.1",
    schema_major: int = 0,
    schema_minor: int = 0,
    payload=None,
    completeness: Optional[common_pb2.Completeness] = None,
) -> envelope_pb2.Envelope:
    """Build an Envelope message.

    Args:
        kind: RecordKind enum value
        logical_id: stable logical ID string
        source: Source enum value
        run_context: RunContext message
        producer_id: producer identifier
        producer_version: producer version string
        schema_major: schema major version
        schema_minor: schema minor version
        payload: the oneof record (e.g., NormalizedEvent, GroundTruthAction)
        completeness: Completeness message (gaps), defaults to empty

    Returns:
        Envelope message
    """
    if completeness is None:
        completeness = common_pb2.Completeness()

    env = envelope_pb2.Envelope(
        schema_major=schema_major,
        schema_minor=schema_minor,
        producer_id=producer_id,
        producer_version=producer_version,
        kind=kind,
        logical_id=logical_id,
        source=source,
        completeness=completeness,
        run=run_context,
    )

    if payload is not None:
        field_name = _payload_field_name(kind)
        if field_name:
            # setattr does not work for proto message fields; use CopyFrom.
            getattr(env, field_name).CopyFrom(payload)

    return env


def _payload_field_name(kind: int) -> Optional[str]:
    """Map RecordKind to Envelope oneof field name."""
    kind_to_field = {
        envelope_pb2.RAW_EBPF: "raw_ebpf",
        envelope_pb2.RAW_AUDIT: "raw_audit",
        envelope_pb2.RAW_GATEWAY: "raw_gateway",
        envelope_pb2.RAW_KYVERNO: "raw_kyverno",
        envelope_pb2.CONTEXT_OBSERVATION: "context_observation",
        envelope_pb2.CONTEXT_WATCH_GAP: "context_watch_gap",
        envelope_pb2.TOKEN_FILE_VERSION: "token_file_version",
        envelope_pb2.NORMALIZED_EVENT: "normalized_event",
        envelope_pb2.FINDING: "finding",
        envelope_pb2.WITNESS: "witness",
        envelope_pb2.INCIDENT: "incident",
        envelope_pb2.HEARTBEAT: "heartbeat",
        envelope_pb2.SOURCE_COMPLETENESS: "source_completeness",
        envelope_pb2.GRAPH_EDGE: "graph_edge",
        envelope_pb2.GROUND_TRUTH_ACTION: "ground_truth_action",
        envelope_pb2.RULE_EVALUATION: "rule_evaluation",
        envelope_pb2.RAW_DB_AUDIT: "raw_db_audit",
        envelope_pb2.RAW_PATH_FLOW: "raw_path_flow",
    }
    return kind_to_field.get(kind)


def serialize_length_delimited(envelope: envelope_pb2.Envelope) -> bytes:
    """Serialize an Envelope as length-delimited bytes.

    Args:
        envelope: Envelope message

    Returns:
        length-delimited bytes: u32 big-endian length + protobuf bytes
    """
    # deterministic: map fields (e.g. SourceCompleteness.counters) in key
    # order; otherwise they follow the runtime's hash order and builds differ.
    data = envelope.SerializeToString(deterministic=True)
    length = struct.pack(">I", len(data))
    return length + data


def deserialize_length_delimited(data: bytes) -> tuple:
    """Deserialize length-delimited Envelope from bytes.

    Args:
        data: bytes starting with u32 length + protobuf

    Returns:
        (Envelope, bytes_consumed)
    """
    if len(data) < 4:
        raise ValueError("insufficient data for length field")
    length = struct.unpack(">I", data[:4])[0]
    if len(data) < 4 + length:
        raise ValueError("insufficient data for payload")

    envelope = envelope_pb2.Envelope()
    envelope.ParseFromString(data[4 : 4 + length])
    return envelope, 4 + length
