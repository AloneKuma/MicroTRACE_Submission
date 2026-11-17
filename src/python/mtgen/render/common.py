"""Shared rendering helpers: TimeInfo, EntityRef, Completeness gaps, event IDs.

Provides:
  make_time_info(event_ns, basis) -> TimeInfo
  make_entity_ref(type, uid, ns, name, strength) -> EntityRef
  completeness_gap(reason, scope, detail) -> Gap
  empty_completeness() -> Completeness
  event_id(source, native_id, stage) -> str via mtcodec
  NORMALIZER_VERSION, CONTEXT_VERSION, CAPTURE_MANIFEST_VERSION
"""
import mtcodec
from microtrace.v0 import common_pb2
from mtgen.simtime import ns_to_timestamp

NORMALIZER_VERSION: str = "mtgen.v0"
CONTEXT_VERSION: str = "context.v0"
CAPTURE_MANIFEST_VERSION: str = "capture.v0"
_CLOCK_MODEL_VERSION: str = "simclock.v0"


def make_time_info(
    event_ns: int,
    basis: int,
    uncertainty_ns: int = 0,
    event_time_uncertain: bool = False,
) -> "common_pb2.TimeInfo":
    """Build TimeInfo for a simulated event.

    source_time, event_time, and ingest_time all equal event_ns (no clock
    correction applies in the generator). clock_model_version is simclock.v0.

    Args:
        event_ns:            nanoseconds since epoch
        basis:               TimeBasis enum value
        uncertainty_ns:      clock_uncertainty_ns bound (0 for deterministic runs)
        event_time_uncertain: set True when the time source is TIME_BASIS_UNKNOWN
    """
    ts = ns_to_timestamp(event_ns)
    return common_pb2.TimeInfo(
        source_time=ts,
        event_time=ts,
        ingest_time=ts,
        clock_uncertainty_ns=uncertainty_ns,
        clock_model_version=_CLOCK_MODEL_VERSION,
        event_time_basis=basis,
        event_time_uncertain=event_time_uncertain,
    )


def make_entity_ref(
    entity_type: int,
    uid: str,
    namespace: str,
    name: str,
    strength: int,
) -> "common_pb2.EntityRef":
    """Build an EntityRef. uid is omitted when empty or None.

    Args:
        entity_type: EntityType enum value
        uid:         instance UID (may be empty to leave the optional field absent)
        namespace:   Kubernetes namespace or empty string
        name:        entity name
        strength:    StrengthClass enum value
    """
    ref = common_pb2.EntityRef(
        type=entity_type,
        namespace=namespace,
        name=name,
        strength_class=strength,
    )
    if uid:
        ref.uid = uid
    return ref


def completeness_gap(
    reason: int,
    scope: str,
    detail: str = "",
    from_ns: int = 0,
    to_ns: int = 0,
) -> "common_pb2.Gap":
    """Build a Gap message for a known observability gap.

    Args:
        reason:  GapReason enum value
        scope:   machine-readable scope (e.g. "field=peer_caller_pod_uid")
        detail:  human-readable note
        from_ns: start of the gap interval in ns (0 = unspecified)
        to_ns:   end of the gap interval in ns (0 = unspecified)
    """
    g = common_pb2.Gap(reason=reason, scope=scope, detail=detail)
    if from_ns:
        g.from_.CopyFrom(ns_to_timestamp(from_ns))
    if to_ns:
        g.to.CopyFrom(ns_to_timestamp(to_ns))
    return g


def empty_completeness() -> "common_pb2.Completeness":
    """Return an empty Completeness (no known gaps)."""
    return common_pb2.Completeness()


# Renderer source labels -> Source enum names hashed into event IDs
# (kafka-contract.md section 2; spec/tools/check_gap1.py recomputes them so).
_SOURCE_ENUM_NAMES = {
    "ebpf": "EBPF",
    "gateway": "GATEWAY",
    "kyverno": "KYVERNO",
    "audit": "AUDIT",
    "context": "CLUSTER_CONTEXT",
    "db_audit": "DB_AUDIT",
    "path_flow": "PATH_FLOW",
}

# payload_version of every NormalizedEvent ID (raw records use "raw.v0").
NORMALIZED_PAYLOAD_VERSION: str = "norm.v0"


def event_id(
    source: str,
    native_id: str,
    stage: str,
    payload_version: str = NORMALIZED_PAYLOAD_VERSION,
) -> str:
    """Compute a logical event ID via mtcodec.

    Args:
        source:          renderer source label (e.g. "gateway", "audit") or a
                         Source enum name; hashed as the enum name
        native_id:       source-native record identifier
        stage:           record stage (e.g. "ResponseComplete", "request")
        payload_version: schema version string

    Returns:
        ev_<32-hex> logical ID string
    """
    return mtcodec.logical_id("event", {
        "source": _SOURCE_ENUM_NAMES.get(source, source),
        "source_native_id": native_id,
        "source_stage": stage,
        "payload_version": payload_version,
    })
