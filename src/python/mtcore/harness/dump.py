"""Dump a run's GO output from Kafka into the projection's JSONL format.

    python -m mtcore.harness.dump --bootstrap 127.0.0.1:9092 --out run.jsonl [--heartbeats]
    python -m mtcore.harness.dump --topics findings.v0,witness.decisions.v0 --out run.jsonl   # for score.py
    python -m mtcore.harness.dump --topics findings.v0,witness.decisions.v0,incidents.v0,norm.events.v0         --events --out run.jsonl                                                            # with latency

Reads witness.decisions.v0 and incidents.v0 (or --topics) from the beginning
up to the end offsets taken at start (assigned partitions, no group commit).
One line per record: {"topic", "record", "partition", "offset", "timestamp_ms"}, written
partition by partition in offset order (per-key order is kept). Heartbeats
are written as {"topic", "heartbeat", ...} only with --heartbeats (the
outage measure needs them). With --events, each norm.events.v0 record is
written as {"topic", "event": event ID, "timestamp_ms"} (its Kafka
LogAppendTime: when the receiver wrote it), for score.py's latency; the
projection skips these lines. Exit 2 without confluent_kafka or a broker.
"""
import argparse
import json
import sys
import time
import uuid

from google.protobuf import json_format

from microtrace.v0 import envelope_pb2

from mtcore.harness.project import INCIDENT_TOPIC, WITNESS_TOPIC

TOPICS = [WITNESS_TOPIC, INCIDENT_TOPIC]


def _line(topic, partition, offset, ts_ms, env, heartbeats, events=False):
    if events and env.HasField("normalized_event"):
        return {"topic": topic, "event": env.normalized_event.event_id or env.logical_id, "timestamp_ms": ts_ms}
    for name in ("witness", "incident", "finding", "rule_evaluation") + (("heartbeat",) if heartbeats else ()):
        if env.HasField(name):
            key = "heartbeat" if name == "heartbeat" else "record"
            return {"topic": topic, key: json_format.MessageToDict(getattr(env, name)),
                    "partition": partition, "offset": offset, "timestamp_ms": ts_ms}
    return None


def dump(consumer, out, topics=TOPICS, heartbeats=False, tp=None, timeout=10.0, idle_s=30.0, events=False):
    """Write every record below the start-time end offsets; returns the line count.
    `tp` builds a TopicPartition (default confluent_kafka's)."""
    if tp is None:
        from confluent_kafka import TopicPartition as tp
    md = consumer.list_topics(timeout=timeout).topics
    parts = [(t, p) for t in topics for p in sorted(md[t].partitions)]
    ends = {k: consumer.get_watermark_offsets(tp(*k), timeout=timeout, cached=False) for k in parts}
    want = {k: hi for k, (lo, hi) in ends.items() if hi > lo}
    consumer.assign([tp(t, p, lo) for (t, p), (lo, _) in ends.items()])
    got, pos, last = {k: [] for k in parts}, {}, time.time()
    while any(pos.get(k, -1) + 1 < hi for k, hi in want.items()):
        if time.time() - last > idle_s:
            raise TimeoutError(f"no progress for {idle_s}s; read {pos}, want {want}")
        for m in consumer.consume(500, timeout=0.5):
            if m.error():
                continue
            k = (m.topic(), m.partition())
            if m.offset() >= want.get(k, 0):
                continue
            env = envelope_pb2.Envelope()
            env.ParseFromString(m.value())
            got[k].append((m.offset(), m.timestamp()[1], env))
            pos[k] = max(pos.get(k, -1), m.offset())
            last = time.time()
    n = 0
    for (t, p) in parts:
        for off, ts_ms, env in sorted(got[(t, p)], key=lambda x: x[0]):
            line = _line(t, p, off, ts_ms, env, heartbeats, events)
            if line is not None:
                out.write(json.dumps(line, sort_keys=True) + "\n")
                n += 1
    return n


def main(argv=None):
    ap = argparse.ArgumentParser(description="Dump GO output topics to JSONL for the Exp. 5 projection.")
    ap.add_argument("--bootstrap", default="127.0.0.1:9092")
    ap.add_argument("--out", required=True)
    ap.add_argument("--heartbeats", action="store_true", help="also write heartbeat lines")
    ap.add_argument("--events", action="store_true", help="write normalized events as ID and timestamp lines")
    ap.add_argument("--topics", default=",".join(TOPICS), help="comma-separated topics (default the GO outputs)")
    ap.add_argument("--timeout", type=float, default=10.0)
    a = ap.parse_args(argv)
    try:
        from confluent_kafka import Consumer, KafkaException
    except ImportError:
        print("dump: confluent_kafka is not installed", file=sys.stderr)
        return 2
    c = Consumer({"bootstrap.servers": a.bootstrap, "group.id": f"mt-dump-{uuid.uuid4().hex[:8]}",
                  "enable.auto.commit": False, "socket.connection.setup.timeout.ms": int(a.timeout * 1000)})
    try:
        with open(a.out, "w", encoding="utf-8") as fh:
            n = dump(c, fh, topics=[t for t in a.topics.split(",") if t], heartbeats=a.heartbeats,
                     timeout=a.timeout, events=a.events)
    except (KafkaException, TimeoutError) as e:
        print(f"dump: {e}", file=sys.stderr)
        return 2
    finally:
        c.close()
    print(json.dumps({"lines": n}), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
