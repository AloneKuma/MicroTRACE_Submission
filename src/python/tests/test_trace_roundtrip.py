"""Send the spec's example trace through Kafka from Python and from Go.

Checks, for every record in spec/examples/trace-v0.json:
- Python writes it and Go reads it back as the same Envelope;
- Go writes it and Python reads back the same bytes;
- both clients put each key on the partition Kafka's Java client would
  (KAFKA-KEY-PARTITION).

Needs a running Kafka (src/scripts/kafka-up.sh) and the trace-check binary;
skipped when Kafka is not reachable.
"""
import base64
import json
import os
import socket
import subprocess

import pytest
from confluent_kafka import Consumer, Producer, TopicPartition
from google.protobuf import json_format

from mtcore import REPO
from mtcore.kafka_topics import DEV_CONFIG, ensure_topics
from mtcore.partition import partition_for
from microtrace.v0 import envelope_pb2

BOOTSTRAP = os.environ.get("MT_KAFKA", "127.0.0.1:9092")
TRACE_CHECK = os.environ.get(
    "MT_TRACE_CHECK", os.path.join(os.environ.get("MT_DEV", ""), "bin", "trace-check"))
TRACE = os.path.join(REPO, "spec", "examples", "trace-v0.json")


def _kafka_up():
    host, port = BOOTSTRAP.rsplit(":", 1)
    try:
        socket.create_connection((host, int(port)), timeout=2).close()
        return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not _kafka_up(), reason=f"no Kafka at {BOOTSTRAP}")


@pytest.fixture(scope="module")
def plan():
    plan, _, _, problems = ensure_topics(BOOTSTRAP, DEV_CONFIG)
    assert not problems, problems
    return plan


@pytest.fixture(scope="module")
def records():
    trace = json.load(open(TRACE, encoding="utf-8"))
    out = []
    for r in trace["records"]:
        env = json_format.ParseDict(r["envelope"], envelope_pb2.Envelope())
        out.append({"label": r["label"], "topic": r["topic"], "key": bytes.fromhex(r["key_hex"]),
                    "env": env, "value": env.SerializeToString(deterministic=True)})
    assert out
    return out


def _python_produce(records):
    p = Producer({"bootstrap.servers": BOOTSTRAP, "partitioner": "murmur2_random",
                  "enable.idempotence": True})
    placed = [None] * len(records)

    def done(i):
        def cb(err, msg):
            assert err is None, err
            placed[i] = (msg.topic(), msg.partition(), msg.offset())
        return cb

    for i, r in enumerate(records):
        p.produce(r["topic"], key=r["key"], value=r["value"], on_delivery=done(i))
    assert p.flush(30) == 0
    return placed


def _python_fetch(positions):
    c = Consumer({"bootstrap.servers": BOOTSTRAP, "group.id": "mt-roundtrip-test",
                  "enable.auto.commit": False})
    values = []
    try:
        for topic, part, off in positions:
            c.assign([TopicPartition(topic, part, off)])
            while True:
                msg = c.poll(15)
                assert msg is not None, f"no record at {topic}/{part}@{off}"
                assert msg.error() is None, msg.error()
                if msg.offset() == off:
                    values.append(msg.value())
                    break
    finally:
        c.close()
    return values


def _go(mode, lines):
    if not os.path.exists(TRACE_CHECK):
        pytest.fail(f"trace-check binary not found at {TRACE_CHECK}")
    res = subprocess.run([TRACE_CHECK, "-brokers", BOOTSTRAP, "-mode", mode],
                         input="".join(json.dumps(x) + "\n" for x in lines),
                         capture_output=True, text=True, timeout=300)
    assert res.returncode == 0, res.stderr
    return [json.loads(x) for x in res.stdout.splitlines()]


def test_python_write_go_read(plan, records):
    placed = _python_produce(records)
    for r, (topic, part, _) in zip(records, placed):
        assert part == partition_for(r["key"], plan[topic]["partitions"]), r["label"]
    got = _go("read", [{"topic": t, "partition": p, "offset": o} for t, p, o in placed])
    assert len(got) == len(records)
    for r, g in zip(records, got):
        back = json_format.Parse(g["envelope_json"], envelope_pb2.Envelope())
        assert back == r["env"], r["label"]


def test_go_write_python_read(plan, records):
    placed = _go("write", [{"topic": r["topic"], "key_hex": r["key"].hex(),
                            "value_b64": base64.b64encode(r["value"]).decode()} for r in records])
    for r, g in zip(records, placed):
        assert g["partition"] == partition_for(r["key"], plan[r["topic"]]["partitions"]), r["label"]
    values = _python_fetch([(g["topic"], g["partition"], g["offset"]) for g in placed])
    for r, v in zip(records, values):
        assert v == r["value"], r["label"]
