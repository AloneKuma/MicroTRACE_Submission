"""Witness proto from a PairDecision: the evidence part of a witness record.

Status, contradictions and contradiction coverage are set by link admission
(build step 5c); everything that follows from the evidence is set here.
"""
from microtrace.v0 import common_pb2, witness_pb2

from mtcore.orchestrator import DECISION_VERSION
from mtcore.orchestrator.emit import ts
from mtcore.orchestrator.keys import JOIN_KEY_TYPE

WT = witness_pb2.WitnessType
SENSOR = common_pb2.KeyOrigin.Value("SENSOR")


def limit_name(wtype):
    """Applied-limit name for a type's window, e.g. W_w[process-ancestry]."""
    if wtype == WT.Value("WITNESS_TYPE_UNSPECIFIED"):
        return "W_nw"                         # No-Witness (A2)
    return f"W_w[{WT.Name(wtype).lower().replace('_', '-')}]"


def to_witness(d, oparams, degraded=False):
    src, tgt = d.source_ev, d.target_ev
    w = witness_pb2.Witness(source_finding_id=d.source_fid, target_finding_id=d.target_fid,
                            relationship_type=d.wtype, strength_class=witness_pb2.WitnessClass.Value("DIRECT"),
                            join_key_type=JOIN_KEY_TYPE[d.wtype], join_key=d.join_key,
                            direction_basis=witness_pb2.DirectionBasis.Value("EVIDENCE_ORDER"),
                            clock_uncertainty_ns=d.eps_ns or 0, decision_version=DECISION_VERSION)
    if d.eps_ns is None:
        w.ClearField("clock_uncertainty_ns")
    if src.t is not None:
        w.source_event_time.CopyFrom(ts(src.t))
    if tgt.t is not None:
        w.target_event_time.CopyFrom(ts(tgt.t))
    for name, ns in ((limit_name(d.wtype), oparams.window_ns(d.wtype)), ("T", oparams.T_ns)):
        w.applied_limits.add(parameter=name, value_ms=ns // 1_000_000, parameter_set_version=oparams.version)
    w.evidence_event_ids.extend([src.id, tgt.id])
    w.key_origin.add(component=JOIN_KEY_TYPE[d.wtype], origin=d.origin or SENSOR, degraded=degraded,
                     evidence_event_ids=[src.id, tgt.id])
    return w



def to_enabling_witness(d, context_id):
    """Enabling witness (ENABLING_ONLY): evidence is the source event and the
    context observation that ties the target's container to the key. No
    window applies, so no applied limits."""
    src, tgt = d.source_ev, d.target_ev
    w = witness_pb2.Witness(source_finding_id=d.source_fid, target_finding_id=d.target_fid,
                            relationship_type=d.wtype, strength_class=witness_pb2.WitnessClass.Value("ENABLING"),
                            join_key_type=JOIN_KEY_TYPE[d.wtype], join_key=d.join_key,
                            direction_basis=witness_pb2.DirectionBasis.Value("EVIDENCE_ORDER"),
                            status=witness_pb2.WitnessStatus.Value("ENABLING_ONLY"),
                            decision_version=DECISION_VERSION)
    w.source_event_time.CopyFrom(ts(src.t))
    w.target_event_time.CopyFrom(ts(tgt.t))
    evidence = [src.id, context_id]
    w.evidence_event_ids.extend(evidence)
    w.key_origin.add(component=JOIN_KEY_TYPE[d.wtype], origin=SENSOR, degraded=False, evidence_event_ids=evidence)
    return w
