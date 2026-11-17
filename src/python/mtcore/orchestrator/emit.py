"""Build Witness and Incident envelopes (witness.decisions.v0, incidents.v0).

IDs follow kafka-contract.md "Logical IDs" through spec/tools/mtcodec.py:
witness  = (relationship_type name, source_finding_id, target_finding_id,
            sorted evidence_event_ids);
incident = (anchor_finding_id); the ID is recomputed on merge and the old
           one becomes an alias;
path     = (ordered finding_ids).
"""
from google.protobuf import timestamp_pb2

import mtcodec
from microtrace.v0 import envelope_pb2, keys_pb2, witness_pb2

from mtcore.orchestrator import PRODUCER_ID

SCHEMA_MAJOR, SCHEMA_MINOR = 0, 3
WITNESS_TOPIC = "witness.decisions.v0"
INCIDENT_TOPIC = "incidents.v0"
OUT_TOPICS = [WITNESS_TOPIC, INCIDENT_TOPIC]
WT = witness_pb2.WitnessType


def ts(ns):
    t = timestamp_pb2.Timestamp()
    if ns is not None:
        t.FromNanoseconds(int(ns))
    return t


def witness_id(relationship_type, source_finding_id, target_finding_id, evidence_event_ids):
    name = relationship_type if isinstance(relationship_type, str) else WT.Name(relationship_type)
    return mtcodec.logical_id("witness", {"relationship_type": name, "source_finding_id": source_finding_id,
                                          "target_finding_id": target_finding_id,
                                          "evidence_event_ids": list(evidence_event_ids)})


def incident_id(anchor_finding_id):
    return mtcodec.logical_id("incident", {"anchor_finding_id": anchor_finding_id})


def path_id(finding_ids):
    return mtcodec.logical_id("path", {"finding_ids": list(finding_ids)})


def _key(type_name, comp_name, value):
    return mtcodec.encode_key(keys_pb2.KeyType.Value(type_name), [(keys_pb2.KeyComponent.Value(comp_name), value)])


def instance_key(instance):
    return _key("KEY_PRODUCER_INSTANCE", "PRODUCER_INSTANCE", instance)


def _envelope(kind, logical_id, params_version):
    env = envelope_pb2.Envelope(schema_major=SCHEMA_MAJOR, schema_minor=SCHEMA_MINOR, producer_id=PRODUCER_ID,
                                kind=envelope_pb2.RecordKind.Value(kind), logical_id=logical_id)
    env.run.parameter_set_version = params_version
    return env


def witness_record(w, params_version):
    """w: a filled witness_pb2.Witness whose witness_id is unset or correct.
    Returns (topic, key bytes, Envelope); the ID is derived here."""
    w.witness_id = witness_id(w.relationship_type, w.source_finding_id, w.target_finding_id,
                              w.evidence_event_ids)
    env = _envelope("WITNESS", w.witness_id, params_version)
    env.witness.CopyFrom(w)
    return WITNESS_TOPIC, _key("KEY_WITNESS_ID", "WITNESS_ID", w.witness_id), env


def incident_record(inc, params_version):
    """inc: a filled incident_pb2.Incident with anchor_finding_id set; the ID
    and every path ID are derived here."""
    inc.incident_id = incident_id(inc.anchor_finding_id)
    for p in list(inc.ranked_paths) + list(inc.speculative_paths):
        p.path_id = path_id(p.finding_ids)
    env = _envelope("INCIDENT", inc.incident_id, params_version)
    env.incident.CopyFrom(inc)
    return INCIDENT_TOPIC, _key("KEY_INCIDENT_ID", "INCIDENT_ID", inc.incident_id), env


def heartbeat(topic, partition, instance, seq, low_ns, now_ns):
    """Heartbeat envelope for one output partition (sent by explicit partition)."""
    env = envelope_pb2.Envelope(schema_major=SCHEMA_MAJOR, schema_minor=SCHEMA_MINOR, producer_id=PRODUCER_ID,
                                kind=envelope_pb2.RecordKind.Value("HEARTBEAT"))
    hb = env.heartbeat
    hb.producer_id, hb.producer_instance, hb.topic, hb.partition = PRODUCER_ID, instance, topic, partition
    hb.low_watermark.CopyFrom(ts(low_ns))
    hb.emitted_at.CopyFrom(ts(now_ns))
    hb.producer_seq = seq
    return env
