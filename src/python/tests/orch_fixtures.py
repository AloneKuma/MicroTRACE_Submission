"""Fixture records for the orchestrator tests: heartbeats, findings, and the
example trace (spec/examples/trace-v0.json)."""
import json
import os

from google.protobuf import json_format

import agent_fixtures as F
from microtrace.v0 import envelope_pb2, finding_pb2

from mtcore import REPO
from mtcore.orchestrator.params import OrchParams

TRACE = os.path.join(REPO, "spec", "examples", "trace-v0.json")


def oparams(**overrides):
    p = OrchParams.load()
    return p.with_overrides(**overrides) if overrides else p


def hb(topic, partition, low, emitted, instance="agents-1", producer="agents"):
    """Heartbeat envelope; low and emitted in fixture seconds (F.ts)."""
    env = envelope_pb2.Envelope(schema_major=0, schema_minor=2, producer_id=producer,
                                kind=envelope_pb2.RecordKind.Value("HEARTBEAT"))
    h = env.heartbeat
    h.producer_id, h.producer_instance, h.topic, h.partition = producer, instance, topic, partition
    h.low_watermark.CopyFrom(F.ts(low))
    h.emitted_at.CopyFrom(F.ts(emitted))
    return env


def finding(fid, t, ftype="D1", inputs=(), publish=None, **attrs):
    f = finding_pb2.Finding(finding_id=fid, finding_type=ftype, agent_id=ftype[0], input_event_ids=list(inputs))
    f.event_start.CopyFrom(F.ts(t))
    f.event_end.CopyFrom(F.ts(t))
    f.publish_time.CopyFrom(F.ts(publish if publish is not None else t + 1))
    for k, v in attrs.items():
        f.attributes[k] = str(v)
    env = envelope_pb2.Envelope(schema_major=0, schema_minor=2, producer_id="agents",
                                kind=envelope_pb2.RecordKind.Value("FINDING"), logical_id=fid)
    env.finding.CopyFrom(f)
    return env


def trace_records():
    """[(label, topic, Envelope, key_hex)] of the example trace."""
    with open(TRACE, encoding="utf-8") as fh:
        recs = json.load(fh)["records"]
    return [(r["label"], r["topic"], json_format.ParseDict(r["envelope"], envelope_pb2.Envelope()), r["key_hex"])
            for r in recs]
