"""Build Finding and RuleEvaluation envelopes (findings.v0, rule.evaluations.v0).

IDs follow kafka-contract.md "Logical IDs" through spec/tools/mtcodec.py:
finding = (finding_type, sorted input_event_ids, detector_version);
evaluation = (rule_id, state_key_hex, window_end RFC 3339, detector_version).
"""
import time

from google.protobuf import timestamp_pb2

from mtcore.agents import DETECTOR_VERSION
from mtcore.agents import routing  # noqa: F401  (import path for mtcodec)
from mtcore.agents.params import BASELINES

import mtcodec  # noqa: E402
from microtrace.v0 import (common_pb2, dataset_pb2, envelope_pb2, finding_pb2,  # noqa: E402
                           keys_pb2)

SCHEMA_MAJOR, SCHEMA_MINOR = 0, 2   # minor 2: Finding ML provenance fields
PRODUCER_ID = "agents"
FINDINGS_TOPIC = "findings.v0"
EVALUATIONS_TOPIC = "rule.evaluations.v0"

OUT = dataset_pb2.EvaluationOutcome
FIRED, NOT_FIRED, ABSTAINED = OUT.Value("FIRED"), OUT.Value("NOT_FIRED"), OUT.Value("ABSTAINED")


def ts(ns):
    t = timestamp_pb2.Timestamp()
    if ns is not None:
        t.FromNanoseconds(int(ns))
    return t


def rfc3339(ns):
    return "" if ns is None else ts(ns).ToJsonString()


def finding_id(finding_type, input_event_ids):
    return mtcodec.logical_id("finding", {"finding_type": finding_type,
                                          "input_event_ids": list(input_event_ids),
                                          "detector_version": DETECTOR_VERSION})


def evaluation_id(rule_id, state_key_hex, window_end_ns):
    return mtcodec.logical_id("evaluation", {"rule_id": rule_id, "state_key_hex": state_key_hex,
                                             "window_end": rfc3339(window_end_ns),
                                             "detector_version": DETECTOR_VERSION})


def _key(type_name, comp_name, value):
    return mtcodec.encode_key(keys_pb2.KeyType.Value(type_name),
                              [(keys_pb2.KeyComponent.Value(comp_name), value)])


def _envelope(kind, logical_id, run_from, params):
    env = envelope_pb2.Envelope(schema_major=SCHEMA_MAJOR, schema_minor=SCHEMA_MINOR,
                                producer_id=PRODUCER_ID, producer_version=DETECTOR_VERSION,
                                kind=envelope_pb2.RecordKind.Value(kind), logical_id=logical_id)
    if run_from is not None and run_from.HasField("run"):
        env.run.CopyFrom(run_from.run)
    env.run.parameter_set_version = params.version
    return env


def build_finding(rule, spec, inputs, params, now_ns=None):
    """spec: rules.FindingSpec; inputs: [Ev] in evidence order."""
    ids = sorted({e.id for e in inputs})
    f = finding_pb2.Finding(finding_id=finding_id(rule.id, ids), finding_type=rule.id,
                            finding_name=rule.name, agent_id=rule.agent, input_event_ids=ids,
                            detector_version=DETECTOR_VERSION, parameter_set_version=params.version)
    times = [e.t for e in inputs if e.t is not None]
    f.event_start.CopyFrom(ts(spec.event_start if spec.event_start is not None else min(times)))
    f.event_end.CopyFrom(ts(spec.event_end if spec.event_end is not None else max(times)))
    f.publish_time.CopyFrom(ts(now_ns if now_ns is not None else time.time_ns()))
    if spec.action_id:
        f.action_id = spec.action_id
    if rule.tactic:
        f.primary_tactic = finding_pb2.Tactic.Value(rule.tactic)
    f.entities.extend(spec.entities)
    sev, conf = params.reporting(rule.id)
    f.severity = finding_pb2.Severity.Value(sev)
    f.detector_confidence = conf
    baselines = sorted(params.versions[a] for a in spec.artifacts if a in params.versions and a in BASELINES)
    if baselines:
        f.baseline_version = ";".join(baselines)
    f.artifact_versions.extend(sorted(params.versions[a] for a in spec.artifacts
                                      if a in params.versions and a not in BASELINES))
    seen = set()
    for e in inputs:
        ref = e.ne.evidence_ref
        k = (ref.archive_id, ref.object_key)
        if ref.object_key and k not in seen:
            seen.add(k)
            f.evidence_refs.add().CopyFrom(ref)
    # Known gaps travel with the finding: the rule's own, then each input
    # record's (an empty list means no known gap, not proven completeness).
    gaps = {}
    for g in list(spec.gaps) + [g for e in inputs for g in e.record_gaps()]:
        gaps.setdefault(g.SerializeToString(deterministic=True), g)
    f.completeness.gaps.extend(gaps[k] for k in sorted(gaps))
    for k, v in sorted(spec.attributes.items()):
        f.attributes[k] = "" if v is None else str(v)
    f.detection_path = finding_pb2.DetectionPath.Value(spec.detection_path)
    f.ml_status = finding_pb2.MlStatus.Value(spec.ml_status)
    if spec.anomaly_score is not None:
        f.anomaly_score = spec.anomaly_score
    if spec.model_version:
        f.model_version = spec.model_version
    env = _envelope("FINDING", f.finding_id, inputs[0].env if inputs else None, params)
    env.finding.CopyFrom(f)
    return FINDINGS_TOPIC, _key("KEY_FINDING_ID", "FINDING_ID", f.finding_id), env


def build_evaluation(rule, key_hex, lo, hi, outcome, reasons, inputs, features, fid, params):
    eid = evaluation_id(rule.id, key_hex, hi)
    r = dataset_pb2.RuleEvaluation(evaluation_id=eid, rule_id=rule.id, state_key_hex=key_hex,
                                   outcome=outcome, detector_version=DETECTOR_VERSION,
                                   parameter_set_version=params.version)
    if lo is not None:
        r.window_start.CopyFrom(ts(lo))
    if hi is not None:
        r.window_end.CopyFrom(ts(hi))
    r.abstain_reasons.extend(sorted(set(reasons)))
    r.input_event_ids.extend(sorted({e.id for e in inputs}))
    if fid:
        r.finding_id = fid
    for k, v in sorted(features.items()):
        r.features[k] = "" if v is None else str(v)
    env = _envelope("RULE_EVALUATION", eid, inputs[0].env if inputs else None, params)
    env.rule_evaluation.CopyFrom(r)
    return EVALUATIONS_TOPIC, _key("KEY_EVALUATION_ID", "EVALUATION_ID", eid), env


def gap(reason, scope, detail=""):
    return common_pb2.Gap(reason=common_pb2.GapReason.Value(reason), scope=scope, detail=detail)
