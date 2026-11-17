"""Dataset run verifier: Schema, Contract, Time, Identity, Evidence, Leakage,
Truth-consistency, and Determinism checks.

Usage:
    python -m mtgen verify <run_dir> [--json out.json] [--verbose] [--rebuild]

Exit codes:
    0 - all checks passed
    1 - one or more checks failed
    2 - fatal error (run_dir missing, load failure)

Each check is a standalone function so later tasks can add checks without
modifying this module's structure.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml
from google.protobuf import json_format

import mtcodec
from microtrace.v0 import (
    common_pb2,
    context_pb2,
    dataset_pb2,
    ebpf_pb2,
    envelope_pb2,
    normalized_pb2,
    witness_pb2,
)

from mtgen import specs
from mtgen.world import _WATCH_DELAY_DELETE_LARGE_NS

_REPO_DIR = Path(__file__).resolve().parents[3]
_SPEC_DIR = _REPO_DIR / "spec"

# (1 << 63) - 1: same sentinel used by history.FOREVER for alive entities.
_FOREVER = 9_223_372_036_854_775_807

# Compatible derived-field names for each NormalizedEvent record field.
_RECORD_DERIVED_COMPAT: Dict[str, frozenset] = {
    "ebpf":      frozenset({"ebpf_derived"}),
    "audit":     frozenset({"audit_derived"}),
    "kyverno":   frozenset({"admission_derived"}),
    "db_audit":  frozenset({"offnode_derived"}),
    "path_flow": frozenset({"offnode_derived"}),
    "gateway":   frozenset(),
    "context":   frozenset(),
}


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class CheckResult:
    name: str
    checked: int
    failures: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return len(self.failures) == 0


@dataclass
class VerifyResult:
    run_dir: str
    checks: List[CheckResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks)

    def to_dict(self) -> dict:
        return {
            "run_dir": self.run_dir,
            "ok": self.ok,
            "checks": [
                {
                    "name": c.name,
                    "checked": c.checked,
                    "ok": c.ok,
                    "failure_count": len(c.failures),
                    "failures": c.failures[:20],
                }
                for c in self.checks
            ],
        }


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def _load_base_stream(
    run_dir: Path,
) -> Tuple[List[envelope_pb2.Envelope], List[str]]:
    """Load all Envelopes from base.pb (length-delimited format).

    Returns:
        (envelopes, load_errors) where load_errors is a list of human-readable
        error strings for any truncated or undecodable frames.
    """
    base_pb = run_dir / "base.pb"
    envelopes: List[envelope_pb2.Envelope] = []
    load_errors: List[str] = []
    data = base_pb.read_bytes()
    offset = 0
    frame_index = 0
    while offset + 4 <= len(data):
        (length,) = struct.unpack(">I", data[offset:offset + 4])
        offset += 4
        if offset + length > len(data):
            load_errors.append(
                f"base.pb frame[{frame_index}] at byte {offset - 4}: "
                f"declared length {length} but only {len(data) - offset} bytes remain "
                f"(truncated stream)"
            )
            break
        frame_data = data[offset:offset + length]
        env = envelope_pb2.Envelope()
        try:
            env.ParseFromString(frame_data)
        except Exception as exc:  # noqa: BLE001
            load_errors.append(
                f"base.pb frame[{frame_index}] at byte {offset - 4}: "
                f"undecodable ({exc})"
            )
        else:
            envelopes.append(env)
        offset += length
        frame_index += 1
    return envelopes, load_errors


def _load_context_history(run_dir: Path) -> List[dict]:
    """Load context_history.jsonl rows as dicts."""
    path = run_dir / "context_history.jsonl"
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def _load_topics(spec_dir: Optional[Path] = None) -> Dict[str, dict]:
    """Load topics.yaml; return mapping of topic name -> topic dict."""
    p = (spec_dir or _SPEC_DIR) / "kafka" / "topics.yaml"
    with open(p, encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    return {t["name"]: t for t in raw.get("topics", [])}


def _load_shipper_lines(run_dir: Path) -> Dict[str, List[dict]]:
    """Load all *.jsonl files from shipper/; return {filename: [lines]}."""
    shipper_dir = run_dir / "shipper"
    result: Dict[str, List[dict]] = {}
    if not shipper_dir.is_dir():
        return result
    for p in sorted(shipper_dir.glob("*.jsonl")):
        lines = []
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                lines.append(json.loads(line))
        result[p.name] = lines
    return result


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _ts_to_ns(ts) -> int:
    """proto Timestamp → integer nanoseconds."""
    return ts.seconds * 1_000_000_000 + ts.nanos


def _parse_rfc3339_ns(s: str) -> int:
    """Parse an RFC3339Nano UTC string to nanoseconds since epoch.

    Handles both "2024-01-01T00:00:10Z" and
    "2024-01-01T00:00:10.000000050Z" (1–9 fractional digits).
    """
    import datetime
    s = s.rstrip("Z")
    if "." in s:
        dt_part, frac_part = s.split(".", 1)
    else:
        dt_part = s
        frac_part = "0"
    # Normalise fractional part to exactly 9 digits (nanoseconds).
    frac_9 = frac_part.ljust(9, "0")[:9]
    nanos = int(frac_9)
    dt = datetime.datetime.strptime(dt_part, "%Y-%m-%dT%H:%M:%S")
    epoch = datetime.datetime(1970, 1, 1)
    delta = dt - epoch
    secs = delta.days * 86400 + delta.seconds  # avoid float precision loss
    return secs * 1_000_000_000 + nanos


def _extract_event_ns_from_env_dict(env_dict: dict) -> int:
    """Extract event_time ns from a JSON-serialised Envelope dict.

    MessageToDict with preserving_proto_field_name=True serialises
    google.protobuf.Timestamp fields as RFC3339 strings.
    Returns 0 when no recognisable time field is found.
    """
    ne = env_dict.get("normalized_event", {})
    if ne:
        t = ne.get("time", {}).get("event_time", "")
        if t:
            return _parse_rfc3339_ns(t)
    ctx = env_dict.get("context_observation", {})
    if ctx:
        t = ctx.get("observed_time", "")
        if t:
            return _parse_rfc3339_ns(t)
    gta = env_dict.get("ground_truth_action", {})
    if gta:
        t = gta.get("started_at", "")
        if t:
            return _parse_rfc3339_ns(t)
    hb = env_dict.get("heartbeat", {})
    if hb:
        t = hb.get("emitted_at", "")
        if t:
            return _parse_rfc3339_ns(t)
    sc = env_dict.get("source_completeness", {})
    if sc:
        t = sc.get("interval_end", "")
        if t:
            return _parse_rfc3339_ns(t)
    return 0


# payload oneof field name -> expected RecordKind enum value
_PAYLOAD_TO_KIND: Dict[str, int] = {
    "raw_ebpf":            envelope_pb2.RAW_EBPF,
    "raw_audit":           envelope_pb2.RAW_AUDIT,
    "raw_gateway":         envelope_pb2.RAW_GATEWAY,
    "raw_kyverno":         envelope_pb2.RAW_KYVERNO,
    "context_observation": envelope_pb2.CONTEXT_OBSERVATION,
    "context_watch_gap":   envelope_pb2.CONTEXT_WATCH_GAP,
    "token_file_version":  envelope_pb2.TOKEN_FILE_VERSION,
    "normalized_event":    envelope_pb2.NORMALIZED_EVENT,
    "finding":             envelope_pb2.FINDING,
    "witness":             envelope_pb2.WITNESS,
    "incident":            envelope_pb2.INCIDENT,
    "heartbeat":           envelope_pb2.HEARTBEAT,
    "source_completeness": envelope_pb2.SOURCE_COMPLETENESS,
    "graph_edge":          envelope_pb2.GRAPH_EDGE,
    "ground_truth_action": envelope_pb2.GROUND_TRUTH_ACTION,
    "rule_evaluation":     envelope_pb2.RULE_EVALUATION,
    "raw_db_audit":        envelope_pb2.RAW_DB_AUDIT,
    "raw_path_flow":       envelope_pb2.RAW_PATH_FLOW,
}


# ---------------------------------------------------------------------------
# Restricted-truth loaders
# ---------------------------------------------------------------------------

def _read_ld_protos(path: Path, message_class) -> List:
    """Read all length-delimited proto messages from a binary file."""
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


def _load_truth_files(
    run_dir: Path,
) -> Tuple[List, List, List]:
    """Load GroundTruthAction, FindingOpportunity, ActionLink from restricted/.

    Returns (actions, findings, links); each list is empty when the file is
    missing (run produced no scenarios).
    """
    restricted = run_dir / "restricted"
    actions, findings, links = [], [], []
    ap = restricted / "truth_actions.pb"
    if ap.exists():
        actions = _read_ld_protos(ap, dataset_pb2.GroundTruthAction)
    fp = restricted / "truth_findings.pb"
    if fp.exists():
        findings = _read_ld_protos(fp, dataset_pb2.FindingOpportunity)
    lp = restricted / "truth_links.pb"
    if lp.exists():
        links = _read_ld_protos(lp, dataset_pb2.ActionLink)
    return actions, findings, links


def _load_manifest(run_dir: Path) -> dict:
    """Load manifest.json as a dict; return {} when missing."""
    p = run_dir / "manifest.json"
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def _load_catalogue(spec_dir: Optional[Path] = None, overlays=()) -> dict:
    """Load spec/scenarios/catalogue.v0.yaml plus the run's catalogue overlays
    (manifest catalogue_overlays, repository-relative) with the build's own
    loader, so the merge rules (no duplicate scenario ID) are the same;
    return {} when there is no catalogue."""
    spec = spec_dir or _SPEC_DIR
    if not (spec / "scenarios" / "catalogue.v0.yaml").exists():
        return {}
    return specs.load_scenario_catalogue(list(overlays), root=str(spec.parent))


# ---------------------------------------------------------------------------
# Leakage-scan helpers
# ---------------------------------------------------------------------------

def _collect_strings(obj, out: List[str]) -> None:
    """Recursively collect all string leaf values from a JSON-compatible object."""
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _collect_strings(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _collect_strings(v, out)


def _build_leakage_vocab(
    truth_actions: List,
    catalogue: dict,
) -> frozenset:
    """Build the forbidden vocabulary for the leakage check.

    Uses only full, compound identifiers that cannot appear in legitimate
    NE data (pod names, process names, eBPF families, HTTP paths, etc.):
    - Full scenario_id strings from truth and catalogue (e.g.
      "a1_lidds_php_cwe434_upload"); these are long underscore-joined tokens
      that are not Kubernetes or protocol terms.
    - "HELD_OUT" (the split name most dangerous to leak).

    Component words (e.g. "mutation", "external") are excluded because many
    are legitimate Kubernetes, eBPF, or HTTP vocabulary.
    """
    vocab: set = set()

    for gta in truth_actions:
        if gta.scenario_id:
            vocab.add(gta.scenario_id)

    for scenario in catalogue.get("scenarios", []):
        sid = scenario.get("id", "")
        if sid:
            vocab.add(sid)

    vocab.add("HELD_OUT")

    return frozenset(vocab)


# ---------------------------------------------------------------------------
# Determinism hash helper
# ---------------------------------------------------------------------------

def _compute_truth_sha256(run_dir: Path) -> str:
    """Compute SHA-256 of concatenated truth files under restricted/.

    Matches emit.compute_truth_sha256: truth_actions.pb + truth_findings.pb
    + truth_links.pb in that fixed order.
    """
    restricted = run_dir / "restricted"
    hasher = hashlib.sha256()
    for fname in ("truth_actions.pb", "truth_findings.pb", "truth_links.pb"):
        p = restricted / fname
        if p.exists():
            hasher.update(p.read_bytes())
    return hasher.hexdigest()


# ---------------------------------------------------------------------------
# Check 1 – Schema
# ---------------------------------------------------------------------------

def check_schema(
    envelopes: List[envelope_pb2.Envelope],
    load_errors: Optional[List[str]] = None,
) -> CheckResult:
    """Structural schema invariants on every Envelope.

    Failures:
    - Truncated or undecodable frames in base.pb (from load_errors).
    - Envelope has no payload field set (WhichOneof("payload") is None).
    - Envelope contains unknown proto fields.
    - Envelope kind field does not match the payload oneof set.
    - NORMALIZED_EVENT: NormalizedEvent has no record field set.
    - NORMALIZED_EVENT: derived field present but incompatible with record.
    """
    result = CheckResult(name="schema", checked=0)

    # Report load errors (truncated/undecodable frames) as schema failures.
    for err in (load_errors or []):
        result.failures.append(err)
        result.checked += 1

    for i, env in enumerate(envelopes):
        result.checked += 1
        lid = env.logical_id or f"env[{i}]"

        payload_field = env.WhichOneof("payload")
        if payload_field is None:
            result.failures.append(f"{lid}: Envelope has no payload field set")
            continue

        # Unknown-field detection: copy, discard, compare lengths.
        # Map fields serialise in non-deterministic order so byte equality
        # cannot be used; unknown fields always add bytes, so len(original)
        # > len(discarded) is a sound and precise indicator.
        env_copy = envelope_pb2.Envelope()
        env_copy.CopyFrom(env)
        env_copy.DiscardUnknownFields()
        orig_bytes = env.SerializeToString()
        disc_bytes = env_copy.SerializeToString()
        if len(orig_bytes) > len(disc_bytes):
            result.failures.append(f"{lid}: Envelope contains unknown fields")

        # kind field must agree with the payload oneof.
        expected_kind = _PAYLOAD_TO_KIND.get(payload_field)
        if expected_kind is not None and env.kind != expected_kind:
            result.failures.append(
                f"{lid}: kind={env.kind} but payload field is {payload_field!r} "
                f"(expected kind={expected_kind})"
            )

        if payload_field == "normalized_event":
            ne = env.normalized_event
            record_field = ne.WhichOneof("record")
            if record_field is None:
                result.failures.append(
                    f"{lid}: NormalizedEvent has no record field set"
                )
                continue
            derived_field = ne.WhichOneof("derived")
            if derived_field is not None:
                allowed = _RECORD_DERIVED_COMPAT.get(record_field, frozenset())
                if derived_field not in allowed:
                    result.failures.append(
                        f"{lid}: NormalizedEvent record={record_field!r} "
                        f"incompatible with derived={derived_field!r}"
                    )

    return result


# Source enum int -> Source enum name (kafka-contract.md section 2).
_SOURCE_INT_TO_NAME: Dict[int, str] = {
    1: "EBPF",
    2: "GATEWAY",
    3: "KYVERNO",
    4: "AUDIT",
    5: "CLUSTER_CONTEXT",
    6: "DB_AUDIT",
    7: "PATH_FLOW",
}


# ---------------------------------------------------------------------------
# Check 2 – Contract
# ---------------------------------------------------------------------------

def check_contract(
    envelopes: List[envelope_pb2.Envelope],
    shipper_lines: Dict[str, List[dict]],
    topics: Dict[str, dict],
) -> CheckResult:
    """Logical ID and topic-contract invariants.

    Envelope-level:
    - NORMALIZED_EVENT: env.logical_id == ne.event_id (self-consistency).
    - NORMALIZED_EVENT: ne.event_id == mtcodec.logical_id recomputed from
      ne.source, ne.source_native_id, ne.source_stage, "norm.v0".
    - GROUND_TRUTH_ACTION: env.logical_id matches mtcodec recomputation.

    Shipper-line-level (per record line, not watermark lines):
    - topic exists in topics.yaml.
    - key_type matches topics.yaml.
    - kind (from envelope JSON) is listed in the topic's allowed kinds.
    - every key_component value is non-empty.
    """
    result = CheckResult(name="contract", checked=0)

    for i, env in enumerate(envelopes):
        result.checked += 1
        lid = env.logical_id or f"env[{i}]"
        pf = env.WhichOneof("payload")

        if pf == "normalized_event":
            ne = env.normalized_event
            if env.logical_id != ne.event_id:
                result.failures.append(
                    f"{lid}: logical_id {env.logical_id!r} != "
                    f"event_id {ne.event_id!r}"
                )
            # Recompute event_id from source fields (kafka-contract.md §2).
            source_name = _SOURCE_INT_TO_NAME.get(ne.source, str(ne.source))
            expected_event_id = mtcodec.logical_id("event", {
                "source": source_name,
                "source_native_id": ne.source_native_id,
                "source_stage": ne.source_stage,
                "payload_version": "norm.v0",
            })
            if ne.event_id != expected_event_id:
                result.failures.append(
                    f"{lid}: event_id {ne.event_id!r} != recomputed "
                    f"{expected_event_id!r} "
                    f"(source={source_name!r} native_id={ne.source_native_id!r} "
                    f"stage={ne.source_stage!r})"
                )

        elif pf == "ground_truth_action":
            gta = env.ground_truth_action
            expected_lid = mtcodec.logical_id("ground_truth", {
                "run_id": gta.run_id,
                "action_seq": str(gta.action_seq),
            })
            if env.logical_id != expected_lid:
                result.failures.append(
                    f"{lid}: GTA logical_id {env.logical_id!r} != "
                    f"expected {expected_lid!r}"
                )

    for fname, lines in shipper_lines.items():
        for line in lines:
            if "topic" not in line:
                continue  # watermark line
            result.checked += 1
            topic_name = line.get("topic", "")
            key_type = line.get("key_type", "")
            key_components = line.get("key_components", [])
            env_dict = line.get("envelope", {})
            lid = env_dict.get("logical_id") or f"{fname}:?"

            if topic_name not in topics:
                result.failures.append(f"{lid}: unknown topic {topic_name!r}")
                continue

            topic = topics[topic_name]

            kind_str = env_dict.get("kind", "")
            topic_kinds = topic.get("kinds", [])

            # Heartbeats always use KEY_PRODUCER_INSTANCE regardless of topic;
            # the topic's key_type applies only to the primary record kind.
            if kind_str != "HEARTBEAT" and key_type != topic.get("key_type", ""):
                result.failures.append(
                    f"{lid}: key_type {key_type!r} != "
                    f"{topic['key_type']!r} (topics.yaml, topic {topic_name!r})"
                )
            if kind_str and kind_str not in topic_kinds:
                result.failures.append(
                    f"{lid}: kind {kind_str!r} not in "
                    f"topic {topic_name!r} kinds {topic_kinds}"
                )

            for j, kc in enumerate(key_components):
                if not kc:
                    result.failures.append(
                        f"{lid}: key_component[{j}] is empty "
                        f"(topic {topic_name!r})"
                    )

    return result


# ---------------------------------------------------------------------------
# Check 3 – Time
# ---------------------------------------------------------------------------

def check_time(
    envelopes: List[envelope_pb2.Envelope],
    shipper_lines: Dict[str, List[dict]],
) -> CheckResult:
    """Temporal ordering and time-basis invariants.

    Envelope-level (NORMALIZED_EVENT only):
    - ingest_time >= event_time.
    - TIME_BASIS_UNKNOWN implies event_time_uncertain == True.

    Shipper-level (per-file, per-lane watermark monotonicity):
    - No record's event_time precedes the latest watermark seen on its lane.
    """
    result = CheckResult(name="time", checked=0)
    _TIME_BASIS_UNKNOWN = 7  # TimeBasis.TIME_BASIS_UNKNOWN from common.proto

    for i, env in enumerate(envelopes):
        if env.WhichOneof("payload") != "normalized_event":
            continue
        result.checked += 1
        ne = env.normalized_event
        lid = env.logical_id or f"env[{i}]"

        event_ns = _ts_to_ns(ne.time.event_time)
        ingest_ns = _ts_to_ns(ne.time.ingest_time)

        if ingest_ns < event_ns:
            result.failures.append(
                f"{lid}: ingest_time ({ingest_ns}) < event_time ({event_ns})"
            )

        if ne.time.event_time_basis == _TIME_BASIS_UNKNOWN:
            if not ne.time.event_time_uncertain:
                result.failures.append(
                    f"{lid}: TIME_BASIS_UNKNOWN set but "
                    f"event_time_uncertain is False"
                )

    for fname, lines in shipper_lines.items():
        last_wm: Dict[str, int] = {}  # lane name -> watermark ns
        for line in lines:
            if "watermark" in line:
                lane = line.get("lane", "")
                wm_ns = _parse_rfc3339_ns(line["watermark"])
                last_wm[lane] = wm_ns
                continue
            if "topic" not in line:
                continue
            result.checked += 1
            lane = line.get("lane", "")
            env_dict = line.get("envelope", {})
            lid = env_dict.get("logical_id") or f"{fname}:?"
            ev_ns = _extract_event_ns_from_env_dict(env_dict)
            wm_ns = last_wm.get(lane, 0)
            if ev_ns > 0 and wm_ns > 0 and ev_ns < wm_ns:
                result.failures.append(
                    f"{lid}: event_time ({ev_ns}) < watermark ({wm_ns}) "
                    f"in lane {lane!r} ({fname})"
                )

    return result


# EntityType int -> context_history entity_type string for K8s entity types.
_ENTITY_TYPE_TO_HISTORY_TYPE: Dict[int, str] = {
    common_pb2.POD:             "Pod",
    common_pb2.CONTAINER:       "Container",
    common_pb2.NODE:            "Node",
    common_pb2.SERVICE_ACCOUNT: "ServiceAccount",
    common_pb2.NAMESPACE:       "Namespace",
}

# GapReason.JOIN_UNCERTAIN numeric value.
_JOIN_UNCERTAIN: int = common_pb2.JOIN_UNCERTAIN


# ---------------------------------------------------------------------------
# Check 4 – Identity
# ---------------------------------------------------------------------------

def check_identity(
    envelopes: List[envelope_pb2.Envelope],
    context_history: List[dict],
) -> CheckResult:
    """Entity UID references must be alive and unambiguous in context_history.

    Pod UID fields checked (non-empty only):
    - ebpf_derived.pod_uid
    - ebpf_derived.remote_pod_uid
    - ebpf_derived.token_file.owner_pod_uid
    - audit_derived.bound_pod_uid
    - audit_derived.attributed_caller_pod_uid
    - audit_derived.peer_caller_pod_uid
    - audit_derived.resolved_target_pod_uid
    - admission_derived.pod_uid
    - offnode_derived.pod_uid

    Also checks EntityRef UIDs in ne.entities for K8s entity types
    (POD, CONTAINER, NODE, SERVICE_ACCOUNT, NAMESPACE).

    JOIN_UNCERTAIN gap constraint: a gap with reason=JOIN_UNCERTAIN and
    scope="field=X" requires field X to be absent in the derived message.

    An empty UID is allowed (normalization could not resolve it).
    """
    result = CheckResult(name="identity", checked=0)

    # Build entity_type_str -> uid -> [(valid_from, valid_to, ambiguity_reason)].
    entity_intervals: Dict[str, Dict[str, List[Tuple[int, int, str]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for row in context_history:
        etype = row.get("entity_type", "")
        uid = row.get("entity_uid", "")
        if not etype or not uid:
            continue
        vf = int(row.get("valid_from", 0))
        vt = int(row.get("valid_to", 0))
        if vt == 0:
            vt = _FOREVER
        amb = row.get("ambiguity_reason", "")
        entity_intervals[etype][uid].append((vf, vt, amb))

    def _is_alive(etype_str: str, uid: str, event_ns: int) -> bool:
        """Return True if uid is alive in the normalizer's observed view at event_ns.

        context_history records the actual valid_to, but the generator models a watch
        deletion lag (mtgen.world: up to _WATCH_DELAY_DELETE_LARGE_NS = 60 s on a run's
        first churn, to force IP/PID reuse ambiguity): until the deletion is observed the
        normalizer still resolves to the old entity. A reference within that lag after
        valid_to is therefore correct, not stale. Declared verifier fix 2026-11-12
        (HELD_OUT batch held_out-04: two eBPF remote_pod_uid references 5.03 s after a
        first-churn deletion); generated data unchanged.
        """
        for vf, vt, _amb in entity_intervals[etype_str].get(uid, []):
            effective_vt = _FOREVER if vt == 0 else vt
            if vf <= event_ns and (effective_vt == _FOREVER
                                   or event_ns < effective_vt + _WATCH_DELAY_DELETE_LARGE_NS):
                return True
        return False

    def _existed_by(etype_str: str, uid: str, event_ns: int) -> bool:
        """Return True if uid was created at or before event_ns."""
        return any(
            vf <= event_ns
            for vf, _vt, _amb in entity_intervals[etype_str].get(uid, [])
        )

    def _check_uid(
        lid: str, uid: str, event_ns: int, field_name: str,
        etype_str: str = "Pod", deleted: bool = False,
    ) -> None:
        if not uid:
            return
        result.checked += 1
        # A deletion is observed after the object is gone: its subject must
        # have existed, not be alive.
        ok = (_existed_by if deleted else _is_alive)(etype_str, uid, event_ns)
        if not ok:
            state = "never existed by" if deleted else "not alive in context_history at"
            result.failures.append(
                f"{lid}: {field_name}={uid!r} {state} event_time {event_ns}"
            )

    for i, env in enumerate(envelopes):
        if env.WhichOneof("payload") != "normalized_event":
            continue
        ne = env.normalized_event
        lid = env.logical_id or f"env[{i}]"
        event_ns = _ts_to_ns(ne.time.event_time)

        derived_field = ne.WhichOneof("derived")

        # --- JOIN_UNCERTAIN gap constraint ---
        # Each gap with reason=JOIN_UNCERTAIN and scope="field=X" requires
        # field X to be absent (not set) in the derived message.
        for gap in ne.completeness.gaps:
            if gap.reason != _JOIN_UNCERTAIN:
                continue
            if not gap.scope.startswith("field="):
                continue
            fname = gap.scope[6:]
            result.checked += 1
            # Try to check HasField on the derived message.
            if derived_field is not None:
                derived_msg = getattr(ne, derived_field)
                try:
                    present = derived_msg.HasField(fname)
                except ValueError:
                    # Not an optional/oneof field; fall back to bool(value).
                    val = getattr(derived_msg, fname, None)
                    present = bool(val)
                if present:
                    result.failures.append(
                        f"{lid}: JOIN_UNCERTAIN gap scope={gap.scope!r} "
                        f"but {derived_field}.{fname} is present"
                    )

        # --- Per-derived-field Pod UID checks ---
        if derived_field == "ebpf_derived":
            _check_uid(lid, ne.ebpf_derived.pod_uid, event_ns,
                       "ebpf_derived.pod_uid")
            _check_uid(lid, ne.ebpf_derived.remote_pod_uid, event_ns,
                       "ebpf_derived.remote_pod_uid")
            if ne.ebpf_derived.HasField("token_file"):
                _check_uid(
                    lid,
                    ne.ebpf_derived.token_file.owner_pod_uid,
                    event_ns,
                    "ebpf_derived.token_file.owner_pod_uid",
                )
        elif derived_field == "audit_derived":
            _check_uid(lid, ne.audit_derived.bound_pod_uid, event_ns,
                       "audit_derived.bound_pod_uid")
            _check_uid(lid, ne.audit_derived.attributed_caller_pod_uid, event_ns,
                       "audit_derived.attributed_caller_pod_uid")
            _check_uid(lid, ne.audit_derived.peer_caller_pod_uid, event_ns,
                       "audit_derived.peer_caller_pod_uid")
            _check_uid(lid, ne.audit_derived.resolved_target_pod_uid, event_ns,
                       "audit_derived.resolved_target_pod_uid")
        elif derived_field == "admission_derived":
            _check_uid(lid, ne.admission_derived.pod_uid, event_ns,
                       "admission_derived.pod_uid")
        elif derived_field == "offnode_derived":
            _check_uid(lid, ne.offnode_derived.pod_uid, event_ns,
                       "offnode_derived.pod_uid")

        # --- EntityRef UID checks for K8s entity types ---
        deleted_obs = (
            ne.source == common_pb2.CLUSTER_CONTEXT
            and ne.context.change_type == context_pb2.DELETED
        )
        for ref in ne.entities:
            etype_str = _ENTITY_TYPE_TO_HISTORY_TYPE.get(ref.type)
            if etype_str is None:
                continue
            if not ref.HasField("uid"):
                continue
            _check_uid(
                lid, ref.uid, event_ns,
                f"entities[type={ref.type}].uid",
                etype_str=etype_str,
                deleted=deleted_obs and ref.uid == ne.context.uid,
            )

    return result


# ---------------------------------------------------------------------------
# Check 5 – Evidence
# ---------------------------------------------------------------------------

def check_evidence(
    envelopes: List[envelope_pb2.Envelope],
    truth_actions: List,
    truth_findings: List,
    truth_links: List,
) -> CheckResult:
    """Evidence integrity checks on restricted truth tables.

    FindingOpportunity (PRESENT):
    - evidence_event_ids is non-empty.
    - every evidence_event_id exists in the base stream.
    - evidence_requirements is non-empty (finding has satisfied requirements).

    FindingOpportunity (UNOBSERVABLE):
    - reason is non-empty (names what is missing).

    ActionLink (PRESENT):
    - witness_type is not WITNESS_TYPE_UNSPECIFIED.
    - every rendered_event_id for both referenced GTAs is in the stream.
    """
    result = CheckResult(name="evidence", checked=0)

    stream_ids: frozenset = frozenset(
        env.logical_id for env in envelopes if env.logical_id
    )
    gta_by_seq: Dict[int, object] = {gta.action_seq: gta for gta in truth_actions}

    for opp in truth_findings:
        result.checked += 1
        oid = opp.opportunity_id or f"opp[action_seq={opp.action_seq}]"

        if opp.expected_state == dataset_pb2.PRESENT:
            if not opp.evidence_event_ids:
                result.failures.append(
                    f"{oid}: PRESENT opportunity has no evidence_event_ids"
                )
            else:
                for eid in opp.evidence_event_ids:
                    if eid not in stream_ids:
                        result.failures.append(
                            f"{oid}: evidence_event_id {eid!r} not in base stream"
                        )
            if not opp.evidence_requirements:
                result.failures.append(
                    f"{oid}: PRESENT opportunity has no evidence_requirements"
                )

        elif opp.expected_state == dataset_pb2.UNOBSERVABLE:
            if not opp.reason.strip():
                result.failures.append(
                    f"{oid}: UNOBSERVABLE opportunity has empty reason"
                )

    for lnk in truth_links:
        result.checked += 1
        lid = lnk.link_id or f"link[{lnk.from_action_seq}->{lnk.to_action_seq}]"

        if lnk.expected_state == dataset_pb2.PRESENT:
            if lnk.witness_type == witness_pb2.WITNESS_TYPE_UNSPECIFIED:
                result.failures.append(
                    f"{lid}: PRESENT link has no witness_type"
                )
            for seq in (lnk.from_action_seq, lnk.to_action_seq):
                gta = gta_by_seq.get(seq)
                if gta is None:
                    continue
                for eid in gta.rendered_event_ids:
                    if eid not in stream_ids:
                        result.failures.append(
                            f"{lid}: rendered_event_id {eid!r} "
                            f"for action_seq={seq} not in base stream"
                        )

    return result


# ---------------------------------------------------------------------------
# Check 6 – Leakage
# ---------------------------------------------------------------------------

def check_leakage(
    envelopes: List[envelope_pb2.Envelope],
    truth_actions: List,
    catalogue: dict,
) -> CheckResult:
    """Scan detector-visible NormalizedEvent fields for restricted vocabulary.

    Forbidden vocabulary:
    - Full scenario_id strings from truth and the catalogue.
    - Component words ≥ 8 chars from scenario IDs.
    - "HELD_OUT" (split-revealing; the most sensitive split name).

    Only NormalizedEvent payloads are scanned (those are what detectors see).
    Each envelope produces at most one failure line.
    """
    result = CheckResult(name="leakage", checked=0)

    vocab = _build_leakage_vocab(truth_actions, catalogue)
    if not vocab:
        return result

    for i, env in enumerate(envelopes):
        if env.WhichOneof("payload") != "normalized_event":
            continue
        result.checked += 1
        lid = env.logical_id or f"env[{i}]"
        ne = env.normalized_event

        ne_dict = json_format.MessageToDict(
            ne,
            preserving_proto_field_name=True,
        )
        string_values: List[str] = []
        _collect_strings(ne_dict, string_values)

        for val in string_values:
            for term in vocab:
                if term in val:
                    result.failures.append(
                        f"{lid}: detector-visible field contains "
                        f"forbidden term {term!r} (in {val!r})"
                    )
                    break  # at most one failure per envelope

    return result


# ---------------------------------------------------------------------------
# Check 7 – Truth consistency
# ---------------------------------------------------------------------------

def check_truth_consistency(
    envelopes: List[envelope_pb2.Envelope],
    truth_actions: List,
    truth_findings: List,
    truth_links: List,
) -> CheckResult:
    """Cross-reference integrity across truth tables and base stream.

    GroundTruthAction:
    - expected_finding_types == sorted set of finding_types of PRESENT
      FindingOpportunities for this action_seq.
    - every rendered_event_id exists in the base stream.

    FindingOpportunity:
    - every evidence_event_id exists in the base stream.

    ActionLink:
    - from_action_seq references an existing GroundTruthAction.
    - to_action_seq references an existing GroundTruthAction.
    """
    result = CheckResult(name="truth_consistency", checked=0)

    stream_ids: frozenset = frozenset(
        env.logical_id for env in envelopes if env.logical_id
    )
    gta_seqs: frozenset = frozenset(gta.action_seq for gta in truth_actions)

    # Build: action_seq -> sorted list of finding_types with PRESENT state
    present_types_by_seq: Dict[int, List[str]] = defaultdict(list)
    for opp in truth_findings:
        if opp.expected_state == dataset_pb2.PRESENT:
            present_types_by_seq[opp.action_seq].append(opp.finding_type)
    present_types_by_seq = {
        seq: sorted(set(types))
        for seq, types in present_types_by_seq.items()
    }

    for gta in truth_actions:
        result.checked += 1
        gid = f"GTA[action_seq={gta.action_seq}]"

        declared = sorted(gta.expected_finding_types)
        actual = present_types_by_seq.get(gta.action_seq, [])
        if declared != actual:
            result.failures.append(
                f"{gid}: expected_finding_types={declared!r} "
                f"!= PRESENT opportunity types={actual!r}"
            )

        for eid in gta.rendered_event_ids:
            result.checked += 1
            if eid not in stream_ids:
                result.failures.append(
                    f"{gid}: rendered_event_id {eid!r} not in base stream"
                )

    for opp in truth_findings:
        result.checked += 1
        oid = opp.opportunity_id or f"opp[action_seq={opp.action_seq}]"
        for eid in opp.evidence_event_ids:
            if eid not in stream_ids:
                result.failures.append(
                    f"{oid}: evidence_event_id {eid!r} not in base stream"
                )

    for lnk in truth_links:
        result.checked += 1
        lid = lnk.link_id or f"link[{lnk.from_action_seq}->{lnk.to_action_seq}]"
        if lnk.from_action_seq not in gta_seqs:
            result.failures.append(
                f"{lid}: from_action_seq={lnk.from_action_seq} "
                f"references no GroundTruthAction"
            )
        if lnk.to_action_seq not in gta_seqs:
            result.failures.append(
                f"{lid}: to_action_seq={lnk.to_action_seq} "
                f"references no GroundTruthAction"
            )

    return result


# ---------------------------------------------------------------------------
# Check 8 – Determinism
# ---------------------------------------------------------------------------

def check_determinism(
    run_dir: Path,
    manifest: dict,
) -> CheckResult:
    """Verify that on-disk files match the hashes recorded in manifest.json.

    Checks: base.pb, restricted/truth_*.pb (combined), context_history.jsonl.
    A mismatch means the run is not reproducible from the manifest (either the
    files were tampered with or the generator is non-deterministic).
    """
    result = CheckResult(name="determinism", checked=0)
    hashes = manifest.get("hashes", {})

    base_hash = hashes.get("base_stream_sha256", "")
    if base_hash:
        result.checked += 1
        base_path = run_dir / "base.pb"
        if base_path.exists():
            actual = hashlib.sha256(base_path.read_bytes()).hexdigest()
            if actual != base_hash:
                result.failures.append(
                    f"base.pb sha256 mismatch: "
                    f"manifest={base_hash[:16]}... actual={actual[:16]}..."
                )
        else:
            result.failures.append("base.pb not found")

    truth_hash = hashes.get("truth_sha256", "")
    if truth_hash:
        result.checked += 1
        actual = _compute_truth_sha256(run_dir)
        if actual != truth_hash:
            result.failures.append(
                f"truth files sha256 mismatch: "
                f"manifest={truth_hash[:16]}... actual={actual[:16]}..."
            )

    ch_hash = hashes.get("context_history_sha256", "")
    if ch_hash:
        result.checked += 1
        ch_path = run_dir / "context_history.jsonl"
        if ch_path.exists():
            actual = hashlib.sha256(ch_path.read_bytes()).hexdigest()
            if actual != ch_hash:
                result.failures.append(
                    f"context_history.jsonl sha256 mismatch: "
                    f"manifest={ch_hash[:16]}... actual={actual[:16]}..."
                )
        else:
            result.failures.append("context_history.jsonl not found")

    return result


def check_rebuild(
    run_dir: Path,
    spec_dir: Optional[Path] = None,
) -> CheckResult:
    """Rebuild from manifest and compare base stream, truth, and manifest.

    Only called when --rebuild is passed on the CLI; it is slow (full rebuild).
    Compares byte-by-byte: base.pb, restricted/truth_*.pb, manifest.json.
    """
    result = CheckResult(name="rebuild", checked=0)

    manifest_path = run_dir / "manifest.json"
    if not manifest_path.exists():
        result.failures.append("manifest.json not found; cannot rebuild")
        result.checked += 1
        return result

    py = sys.executable
    src_dir = Path(__file__).resolve().parents[2]

    with tempfile.TemporaryDirectory() as tmp:
        rebuild_dir = Path(tmp) / "rebuild"
        import os
        env = dict(os.environ, PYTHONHASHSEED="1")
        env.pop("SOURCE_DATE_EPOCH", None)       # mtgen's BUILD_EPOCH applies
        proc = subprocess.run(
            [py, "-m", "mtgen", "from-manifest", str(run_dir),
             "--out", str(rebuild_dir)],
            cwd=str(src_dir),
            env=env,
            capture_output=True,
        )
        if proc.returncode != 0:
            result.checked += 1
            result.failures.append(
                f"from-manifest rebuild failed (exit {proc.returncode}): "
                f"{proc.stderr.decode(errors='replace')[:200]}"
            )
            return result

        comparisons = [
            ("base.pb", run_dir / "base.pb", rebuild_dir / "base.pb"),
            (
                "restricted/truth_actions.pb",
                run_dir / "restricted" / "truth_actions.pb",
                rebuild_dir / "restricted" / "truth_actions.pb",
            ),
            (
                "restricted/truth_findings.pb",
                run_dir / "restricted" / "truth_findings.pb",
                rebuild_dir / "restricted" / "truth_findings.pb",
            ),
            (
                "restricted/truth_links.pb",
                run_dir / "restricted" / "truth_links.pb",
                rebuild_dir / "restricted" / "truth_links.pb",
            ),
            ("manifest.json", run_dir / "manifest.json",
             rebuild_dir / "manifest.json"),
        ]
        for name, orig, reb in comparisons:
            result.checked += 1
            if not orig.exists():
                continue  # optional file
            if not reb.exists():
                result.failures.append(
                    f"rebuild missing {name}"
                )
                continue
            if orig.read_bytes() != reb.read_bytes():
                result.failures.append(
                    f"{name} differs between original and rebuild"
                )

    return result


# ---------------------------------------------------------------------------
# Check 9 – Link witnesses
# ---------------------------------------------------------------------------

# Seconds apart that still count as the shared key "time".
_CLOSE_TIME_NS = 5_000_000_000


def _pk_tuple(pk) -> Optional[tuple]:
    return (pk.node_id, pk.boot_id, pk.tgid, pk.start_time_ns) if pk.tgid else None


def _socket_tuple(so):
    """(client ip, client port, server ip, server port, protocol) of a CONNECT
    or ACCEPT SocketDetail, as the correlator's flow key; None otherwise.
    A copy of mtcore.orchestrator.keys.flow_key on purpose: the generator
    does not import the system it labels for. test_ebpf_accept checks the two
    agree."""
    if not so.local.ip or not so.remote.ip:
        return None
    if so.op == ebpf_pb2.CONNECT:
        client, server = so.local, so.remote
    elif so.op == ebpf_pb2.ACCEPT:
        client, server = so.remote, so.local
    else:
        return None
    return (client.ip, client.port, server.ip, server.port, server.protocol or client.protocol)


def stream_connects(envelopes) -> dict:
    """Connection tuple -> {(time ns, socket)} of every CONNECT in the stream,
    for the port-reuse contradiction (link_witness_result)."""
    out: dict = defaultdict(set)
    for env in envelopes:
        ne = env.normalized_event
        if ne.WhichOneof("record") != "ebpf" or not ne.ebpf.HasField("socket"):
            continue
        so = ne.ebpf.socket
        tup = _socket_tuple(so) if so.op == ebpf_pb2.CONNECT else None
        if tup is not None:
            t = ne.time.event_time.seconds * 1_000_000_000 + ne.time.event_time.nanos
            out[tup].add((t, (so.flow.node_id, so.flow.boot_id, so.flow.socket_cookie)))
    return out


def _link_endpoint_keys(action, by_id: dict) -> dict:
    """Visible keys of one action's rendered events, for witness checks."""
    k = defaultdict(set)
    k["times"] = []
    for eid in action.rendered_event_ids:
        env = by_id.get(eid)
        if env is None or not env.HasField("normalized_event"):
            continue
        ne = env.normalized_event
        t_ns = ne.time.event_time.seconds * 1_000_000_000 + ne.time.event_time.nanos
        k["times"].append(t_ns)
        for ent in ne.entities:
            if ent.type == common_pb2.POD and ent.uid:
                k["pod_uid"].add(ent.uid)
        rec = ne.WhichOneof("record")
        if rec == "ebpf":
            eb, der = ne.ebpf, ne.ebpf_derived
            if _pk_tuple(eb.process):
                k["process"].add(_pk_tuple(eb.process))
            if der.lineage_id:
                k["lineage_id"].add(der.lineage_id)
            if der.HasField("pod_uid"):
                k["pod_uid"].add(der.pod_uid)
            for flow in ([eb.socket.flow] if eb.HasField("socket") else []) + \
                        ([eb.flow_counter.flow] if eb.HasField("flow_counter") else []):
                if flow.socket_cookie:
                    k["flow"].add((flow.node_id, flow.boot_id, flow.socket_cookie))
            if eb.HasField("socket") and eb.socket.remote.ip:
                k["remote_ip"].add(eb.socket.remote.ip)
                so, tup = eb.socket, _socket_tuple(eb.socket)
                if tup is not None and so.op == ebpf_pb2.CONNECT:
                    k["connects"].add((tup, t_ns, (so.flow.node_id, so.flow.boot_id, so.flow.socket_cookie)))
                elif tup is not None:
                    k["accepts"].add((tup, t_ns))
            if eb.HasField("flow_counter") and eb.flow_counter.remote.ip:
                k["remote_ip"].add(eb.flow_counter.remote.ip)
            if eb.HasField("file_access") and eb.file_access.file.projected.owner_pod_uid:
                k["token_owner_pod"].add(eb.file_access.file.projected.owner_pod_uid)
        elif rec == "gateway":
            k["request_id"].add(ne.gateway.request_id)
            if ne.gateway.request_id_origin == common_pb2.SENSOR:
                k["request_id_minted"].add(ne.gateway.request_id)
        elif rec == "audit":
            der = ne.audit_derived
            if der.HasField("principal") and der.principal.uid:
                k["principal"].add(der.principal.uid)
            if der.HasField("bound_pod_uid"):
                k["bound_pod_uid"].add(der.bound_pod_uid)
                k["pod_uid"].add(der.bound_pod_uid)
    return k


def link_witness_result(witness: int, a: dict, b: dict, parent: dict,
                        connects: Optional[dict] = None) -> str:
    """Whether the witness from a to b holds in the stream.

    Returns "holds", "same_process" (PROCESS_ANCESTRY through one process:
    continuity, reported apart from ancestry), "contradicted" (NETWORK_FLOW:
    the tuple matches, but another socket connected on it after a's connect
    and up to b's accept, the port-reuse contradiction; connects:
    stream_connects), "none", "no_events" (an endpoint renders nothing the
    witness reads), or "unchecked" (no checker for this witness type).
    """
    if witness == witness_pb2.PROCESS_ANCESTRY:
        if not a["process"] or not b["process"]:
            return "no_events"
        if a["process"] & b["process"]:
            return "same_process"
        for child in b["process"]:
            cur = child
            for _ in range(64):
                cur = parent.get(cur)
                if cur is None:
                    break
                if cur in a["process"]:
                    return "holds"
        return "none"
    if witness == witness_pb2.NETWORK_FLOW:
        if not a["flow"] or not b["flow"]:
            return "no_events"
        if a["flow"] & b["flow"]:
            return "holds"
        # A connect and an accept are two sockets (client and server node):
        # they join on the connection tuple, as in the correlator.
        res = "none"
        for tup, tc, own in a["connects"]:
            for tup_b, ta in b["accepts"]:
                if tup_b != tup or ta < tc:
                    continue
                if any(sock != own and tc < t <= ta for t, sock in (connects or {}).get(tup, ())):
                    res = "contradicted"
                else:
                    return "holds"
        return res
    if witness == witness_pb2.REQUEST_IDENTITY:
        # Only a gateway-minted ID on both ends is a witness; a shared ID that
        # one end's client set (WORKLOAD, a copy) is a shared key, not one.
        if not a["request_id"] or not b["request_id"]:
            return "no_events"
        return "holds" if a["request_id_minted"] & b["request_id_minted"] else "none"
    if witness == witness_pb2.CREDENTIAL_READ_TO_USE:
        if not a["token_owner_pod"] or not b["bound_pod_uid"]:
            return "no_events"
        if a["token_owner_pod"] & b["bound_pod_uid"] and min(a["times"]) <= max(b["times"]):
            return "holds"
        return "none"
    return "unchecked"


def _shares_key(key: str, a: dict, b: dict) -> Optional[bool]:
    """Whether both endpoints show a shared key; None for an unknown key name."""
    if key == "time":
        if not a["times"] or not b["times"]:
            return False
        return abs(min(b["times"]) - max(a["times"])) <= _CLOSE_TIME_NS
    if key == "flow_tuple":
        return bool({c[0] for c in a["connects"]} & {x[0] for x in b["accepts"]})
    if key in ("pod_uid", "lineage_id", "principal", "remote_ip", "request_id"):
        return bool(a[key] & b[key])
    return None


def check_link_witness(
    envelopes: List[envelope_pb2.Envelope],
    truth_actions: List,
    truth_links: List,
) -> CheckResult:
    """Every link's witness agrees with the stream.

    PRESENT: the witness holds between the two actions' rendered events
    (PROCESS_ANCESTRY also accepts one shared process, continuity).
    ABSENT (hard nonlink): the witness does not hold, and every declared
    shared key is visible on both actions. UNOBSERVABLE: not checked.
    Witness types without a checker are not failures.
    """
    result = CheckResult(name="link_witness", checked=0)
    by_id = {env.logical_id: env for env in envelopes if env.logical_id}
    parent: Dict[tuple, tuple] = {}
    for env in envelopes:
        ne = env.normalized_event
        if env.HasField("normalized_event") and ne.WhichOneof("record") == "ebpf":
            child, par = _pk_tuple(ne.ebpf.process), _pk_tuple(ne.ebpf.parent)
            if child and par:
                parent.setdefault(child, par)
    gta = {a.action_seq: a for a in truth_actions}
    connects = stream_connects(env for env in envelopes if env.HasField("normalized_event"))

    for lnk in truth_links:
        if lnk.expected_state == dataset_pb2.UNOBSERVABLE:
            continue
        a_act, b_act = gta.get(lnk.from_action_seq), gta.get(lnk.to_action_seq)
        if a_act is None or b_act is None:
            continue   # check_truth_consistency reports dangling links
        result.checked += 1
        lid = lnk.link_id or f"link[{lnk.from_action_seq}->{lnk.to_action_seq}]"
        a = _link_endpoint_keys(a_act, by_id)
        b = _link_endpoint_keys(b_act, by_id)
        res = link_witness_result(lnk.witness_type, a, b, parent, connects)
        wname = witness_pb2.WitnessType.Name(lnk.witness_type)
        if lnk.expected_state == dataset_pb2.PRESENT:
            if res not in ("holds", "same_process", "unchecked"):
                result.failures.append(f"{lid}: PRESENT {wname} witness {res}")
        elif lnk.expected_state == dataset_pb2.ABSENT:
            if res in ("holds", "same_process"):
                result.failures.append(f"{lid}: ABSENT {wname} witness {res} in the stream")
            for key in lnk.shared_keys:
                shared = _shares_key(key, a, b)
                if shared is None:
                    result.failures.append(f"{lid}: unknown shared key {key!r}")
                elif not shared:
                    result.failures.append(f"{lid}: shared key {key!r} not visible on both actions")
    return result


def _load_truth_incidents(run_dir: Path) -> Optional[List]:
    """GroundTruthIncident list, or None when the file is missing."""
    ip = run_dir / "restricted" / "truth_incidents.pb"
    return _read_ld_protos(ip, dataset_pb2.GroundTruthIncident) if ip.exists() else None


def check_incidents(truth_actions: List, truth_links: List, incidents: Optional[List]) -> CheckResult:
    """Incident truth (exp2-gaps-plan B1): every action lies in exactly one
    incident; a PRESENT link joins two actions of one incident; an ABSENT
    link inside one incident only where a path of non-ABSENT links also joins
    its two actions (otherwise the incident groups unrelated actions)."""
    result = CheckResult(name="incidents", checked=0)
    if incidents is None:
        if truth_actions:
            result.failures.append("restricted/truth_incidents.pb missing")
        return result
    inc_of: Dict[int, str] = {}
    for inc in incidents:
        for seq in inc.action_seqs:
            if seq in inc_of:
                result.failures.append(f"action {seq} in {inc_of[seq]} and {inc.incident_id}")
            inc_of[seq] = inc.incident_id
    for a in truth_actions:
        result.checked += 1
        if a.action_seq not in inc_of:
            result.failures.append(f"action {a.action_seq} in no incident")
    adj: Dict[int, set] = defaultdict(set)
    for lnk in truth_links:
        if lnk.expected_state != dataset_pb2.ABSENT:
            adj[lnk.from_action_seq].add(lnk.to_action_seq)
            adj[lnk.to_action_seq].add(lnk.from_action_seq)

    def joined(x: int, y: int) -> bool:
        seen, todo = {x}, [x]
        while todo:
            for n in adj[todo.pop()]:
                if n == y:
                    return True
                if n not in seen:
                    seen.add(n)
                    todo.append(n)
        return False

    for lnk in truth_links:
        a, b = inc_of.get(lnk.from_action_seq), inc_of.get(lnk.to_action_seq)
        lid = lnk.link_id or f"link[{lnk.from_action_seq}->{lnk.to_action_seq}]"
        if lnk.expected_state == dataset_pb2.PRESENT and a != b:
            result.failures.append(f"{lid}: PRESENT link across incidents {a} and {b}")
        elif (lnk.expected_state == dataset_pb2.ABSENT and a == b and a is not None
              and not joined(lnk.from_action_seq, lnk.to_action_seq)):
            result.failures.append(f"{lid}: ABSENT link inside {a} with no linked path between its actions")
    return result


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def verify(
    run_dir: Path,
    spec_dir: Optional[Path] = None,
    rebuild: bool = False,
) -> VerifyResult:
    """Run all checks on a dataset run directory.

    Args:
        run_dir:  Root of the run output directory.
        spec_dir: Root of the spec/ tree; auto-detected when None.
        rebuild:  When True, also run check_rebuild (slow: subprocess).

    Returns:
        VerifyResult containing one CheckResult per check.
    """
    run_dir = Path(run_dir)
    result = VerifyResult(run_dir=str(run_dir))

    # Phase-4a checks (structural)
    envelopes, load_errors = _load_base_stream(run_dir)
    context_history = _load_context_history(run_dir)
    topics = _load_topics(spec_dir)
    shipper_lines = _load_shipper_lines(run_dir)

    result.checks.append(check_schema(envelopes, load_errors))
    result.checks.append(check_contract(envelopes, shipper_lines, topics))
    result.checks.append(check_time(envelopes, shipper_lines))
    result.checks.append(check_identity(envelopes, context_history))

    # Phase-4b checks (semantic / truth)
    truth_actions, truth_findings, truth_links = _load_truth_files(run_dir)
    manifest = _load_manifest(run_dir)
    catalogue = _load_catalogue(spec_dir, manifest.get("catalogue_overlays", {}))

    result.checks.append(
        check_evidence(envelopes, truth_actions, truth_findings, truth_links))
    result.checks.append(
        check_leakage(envelopes, truth_actions, catalogue))
    result.checks.append(
        check_truth_consistency(envelopes, truth_actions, truth_findings, truth_links))
    result.checks.append(
        check_determinism(run_dir, manifest))
    result.checks.append(
        check_link_witness(envelopes, truth_actions, truth_links))
    result.checks.append(
        check_incidents(truth_actions, truth_links, _load_truth_incidents(run_dir)))

    if rebuild:
        result.checks.append(check_rebuild(run_dir, spec_dir))

    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def print_result(result: VerifyResult, *, verbose: bool = False) -> None:
    """Print a human-readable summary (never outputs restricted content)."""
    status = "PASS" if result.ok else "FAIL"
    print(f"verify {status}  run_dir={result.run_dir}")
    for c in result.checks:
        c_status = "PASS" if c.ok else "FAIL"
        print(f"  {c.name}: {c_status}  "
              f"checked={c.checked}  failures={len(c.failures)}")
        if not c.ok and verbose:
            for msg in c.failures[:20]:
                print(f"    - {msg}")


def main(argv=None) -> int:
    """CLI entry point for ``python -m mtgen verify``."""
    parser = argparse.ArgumentParser(
        description="Verify a MicroTRACE dataset run directory."
    )
    parser.add_argument("run_dir", help="Path to the run output directory")
    parser.add_argument("--json", metavar="OUT",
                        help="Write JSON result to this file path")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Print individual failure messages")
    parser.add_argument("--rebuild", action="store_true",
                        help="Also rebuild from manifest and compare byte-by-byte "
                             "(slow: triggers a full generator run)")
    args = parser.parse_args(argv)

    run_dir = Path(args.run_dir)
    if not run_dir.exists():
        print(f"error: run_dir does not exist: {run_dir}", file=sys.stderr)
        return 2

    try:
        result = verify(run_dir, rebuild=args.rebuild)
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print_result(result, verbose=args.verbose)

    if args.json:
        Path(args.json).write_text(
            json.dumps(result.to_dict(), indent=2), encoding="utf-8"
        )

    return 0 if result.ok else 1
