"""Shared runtime for the audit-to-incident slice (Python 3.12 slice image).

Envelopes, keys and logical IDs follow spec/kafka/kafka-contract.md exactly:
keys and IDs come from spec/tools/mtcodec.py and topic key specs from
spec/kafka/topics.yaml. Every downstream decision is a function of recorded
records and heartbeats (event and knowledge time), so a replay from the raw
topics reproduces it. Wall-clock time is used only by the two source
collectors and for live idle detection, which is marked where it applies.
"""

import json
import os
import signal
import sys
import time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.environ.get("MT_REPO", os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, os.path.join(REPO, "spec", "tools"))
sys.path.insert(0, os.environ.get("MT_PB_DIR", "/gen"))

import mtcodec  # noqa: E402
import yaml  # noqa: E402
from confluent_kafka import Consumer, KafkaError, Producer  # noqa: E402
from google.protobuf import json_format  # noqa: E402
from google.protobuf.timestamp_pb2 import Timestamp  # noqa: E402
from microtrace.v0 import (audit_pb2, common_pb2, context_pb2, dataset_pb2,  # noqa: E402,F401
                           envelope_pb2, finding_pb2, incident_pb2, keys_pb2,
                           normalized_pb2, stream_pb2)

VERSION = "slice-0.1.0"
PAYLOAD_VERSION = "raw.v0"
KT = keys_pb2.KeyType.Value
KC = keys_pb2.KeyComponent.Value
RK = envelope_pb2.RecordKind.Value
SRC = common_pb2.Source.Value

with open(os.path.join(REPO, "spec", "kafka", "topics.yaml"), encoding="utf-8") as _fh:
    TOPICS = {t["name"]: t for t in yaml.safe_load(_fh)["topics"]}


# ------------------------------------------------------------------ parameters

def load_params(path=None):
    path = path or os.path.join(HERE, "params.unfrozen-slice.yaml")
    with open(path, encoding="utf-8") as fh:
        p = yaml.safe_load(fh)
    assert p["parameter_set_version"] == "UNFROZEN-SLICE"
    return p


# ------------------------------------------------------------------ time

def now():
    return time.time()


def ts(epoch):
    t = Timestamp()
    t.FromNanoseconds(int(round(epoch * 1e9)))
    return t


def epoch(timestamp):
    return timestamp.seconds + timestamp.nanos / 1e9


def rfc3339(e):
    return datetime.fromtimestamp(e, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_rfc3339(value):
    if not value:
        return None
    v = value.rstrip("Z")
    if "." in v:
        head, frac = v.split(".", 1)
        v = head + "." + (frac + "000000")[:6]
        fmt = "%Y-%m-%dT%H:%M:%S.%f"
    else:
        fmt = "%Y-%m-%dT%H:%M:%S"
    return datetime.strptime(v, fmt).replace(tzinfo=timezone.utc).timestamp()


# ------------------------------------------------------------------ IDs and keys

def event_id(source, native, stage):
    return mtcodec.logical_id("event", {"source": source, "source_native_id": native,
                                        "source_stage": stage, "payload_version": PAYLOAD_VERSION})


def key_for(topic, values):
    """Encode the record key for `topic` from a dict of component values."""
    spec = TOPICS[topic.removeprefix("replay.")]
    comps = [(KC(c), values[c]) for c in spec["key_components"]]
    return mtcodec.encode_key(KT(spec["key_type"]), comps)


def heartbeat_key(instance):
    return mtcodec.encode_key(KT("KEY_PRODUCER_INSTANCE"), [(KC("PRODUCER_INSTANCE"), instance)])


# ------------------------------------------------------------------ envelopes

class Run:
    def __init__(self, run_id, descriptor_sha256, params):
        self.ctx = dataset_pb2.RunContext(run_id=run_id, split=dataset_pb2.FEASIBILITY,
                                          capture_profile="audit-slice-v0",
                                          parameter_set_version=params["parameter_set_version"],
                                          descriptor_set_sha256=descriptor_sha256)


def envelope(run, producer_id, kind, source, payload_field, msg, logical_id="", completeness=None):
    env = envelope_pb2.Envelope(schema_major=0, schema_minor=1, producer_id=producer_id,
                                producer_version=VERSION, kind=RK(kind), logical_id=logical_id,
                                source=SRC(source))
    env.run.CopyFrom(run.ctx)
    if completeness is not None:
        env.completeness.CopyFrom(completeness)
    getattr(env, payload_field).CopyFrom(msg)
    return env


def decode(value):
    env = envelope_pb2.Envelope()
    env.ParseFromString(value)
    if env.schema_major != 0:
        raise ValueError(f"unsupported schema_major {env.schema_major}")  # KAFKA-SCHEMA-REJECT
    return env


def to_dict(env):
    return json_format.MessageToDict(env, preserving_proto_field_name=True)


# ------------------------------------------------------------------ Kafka

class Bus:
    """Idempotent producer with the Java-compatible murmur2 partitioner."""

    def __init__(self, bootstrap, instance):
        self.instance = instance
        self.producer = Producer({"bootstrap.servers": bootstrap, "enable.idempotence": True,
                                  "partitioner": "murmur2_random", "linger.ms": 5,
                                  "client.id": instance})
        self.hb_seq = 0
        self._parts = {}

    def partitions(self, topic):
        if topic not in self._parts:
            md = self.producer.list_topics(topic, timeout=10)
            self._parts[topic] = sorted(md.topics[topic].partitions)
        return self._parts[topic]

    def send(self, topic, key, env):
        self.producer.produce(topic, value=env.SerializeToString(), key=key)
        self.producer.poll(0)

    def heartbeat(self, run, producer_id, topic, low_watermark, source):
        for p in self.partitions(topic):
            self.hb_seq += 1
            hb = stream_pb2.Heartbeat(producer_id=producer_id, producer_instance=self.instance, topic=topic,
                                      partition=p, producer_seq=self.hb_seq)
            hb.low_watermark.CopyFrom(ts(low_watermark))
            hb.emitted_at.CopyFrom(ts(now()))
            env = envelope(run, producer_id, "HEARTBEAT", source, "heartbeat", hb)
            self.producer.produce(topic, value=env.SerializeToString(), key=heartbeat_key(self.instance),
                                  partition=p)
        self.producer.poll(0)

    def broadcast(self, topic, env):
        """Send one record to every partition (used for WatchGap; see README)."""
        for p in self.partitions(topic):
            self.producer.produce(topic, value=env.SerializeToString(), key=heartbeat_key(self.instance),
                                  partition=p)
        self.producer.poll(0)

    def flush(self):
        self.producer.flush(30)


def consumer(bootstrap, group, topics):
    c = Consumer({"bootstrap.servers": bootstrap, "group.id": group, "auto.offset.reset": "earliest",
                  "enable.auto.commit": False, "enable.partition.eof": True})
    c.subscribe(topics)
    return c


class Watermarks:
    """Per-topic watermark: min over partitions of min over producer instances."""

    def __init__(self, partitions):
        self.partitions = partitions  # topic -> [partition ids]
        self.hb = {}

    def update(self, topic, part, instance, lw):
        slot = self.hb.setdefault((topic, part), {})
        slot[instance] = max(lw, slot.get(instance, lw))

    def topic(self, topic):
        vals = []
        for p in self.partitions[topic]:
            slot = self.hb.get((topic, p))
            if not slot:
                return None
            vals.append(min(slot.values()))
        return min(vals) if vals else None


class Loop:
    """Consume `topics`; call handler(topic, partition, offset, env). Stops on
    SIGTERM, on OUT/<name>.stop, or (replay) when every partition reached EOF
    and `idle()` reports nothing pending."""

    def __init__(self, bootstrap, group, topics, stop_path, replay=False):
        self.c = consumer(bootstrap, group, topics)
        self.topics = topics
        self.stop_path = stop_path
        self.replay = replay
        self.stop = False
        self.eof = set()
        self.assigned = set()
        signal.signal(signal.SIGTERM, self._term)
        signal.signal(signal.SIGINT, self._term)

    def _term(self, *_):
        self.stop = True

    def partitions(self):
        md = self.c.list_topics(timeout=10)
        return {t: sorted(md.topics[t].partitions) for t in self.topics}

    def run(self, handler, tick=None, tick_every=0.5, idle=lambda: True):
        last = 0.0
        total = sum(len(v) for v in self.partitions().values())
        while not self.stop and not os.path.exists(self.stop_path):
            msg = self.c.poll(0.2)
            if msg is not None:
                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        self.eof.add((msg.topic(), msg.partition()))
                    else:
                        raise RuntimeError(str(msg.error()))
                else:
                    self.eof.discard((msg.topic(), msg.partition()))
                    handler(msg.topic(), msg.partition(), msg.offset(), decode(msg.value()))
            if tick and (now() - last >= tick_every or msg is None):
                tick()
                last = now()
            if self.replay and len(self.eof) >= total and msg is None and idle():
                break
        self.c.close()


class JsonLog:
    def __init__(self, path):
        self.fh = open(path, "a", encoding="utf-8")

    def write(self, obj):
        obj.setdefault("wall_utc", rfc3339(now()))
        self.fh.write(json.dumps(obj, sort_keys=True) + "\n")
        self.fh.flush()


def completeness_msg(source, scope, start, end, status, gaps=(), counters=None):
    sc = stream_pb2.SourceCompleteness(source=SRC(source), scope=scope,
                                       status=stream_pb2.CompletenessStatus.Value(status))
    sc.interval_start.CopyFrom(ts(start))
    sc.interval_end.CopyFrom(ts(end))
    for g in gaps:
        sc.gaps.add().CopyFrom(g)
    for k, v in (counters or {}).items():
        sc.counters[k] = int(v)
    return sc


def gap(reason, scope, detail, start=None, end=None):
    g = common_pb2.Gap(reason=common_pb2.GapReason.Value(reason), scope=scope, detail=detail)
    if start is not None:
        g.__getattribute__("from").CopyFrom(ts(start))
    if end is not None:
        g.to.CopyFrom(ts(end))
    return g
