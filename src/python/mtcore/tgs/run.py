"""Run the TGS ingest against Kafka, or offline over a file.

    python -m mtcore.tgs.run [--bootstrap 127.0.0.1:9092] [--dsn postgresql://...]
    python -m mtcore.tgs.run --offline records.jsonl [--dsn ...]
    python -m mtcore.tgs.run --reset [...]      # rebuild: delete every row, replay from the start
    python -m mtcore.tgs.run --print-hash       # canonical graph hash (rebuild check)

Online: consumer group graph-view over the five input topics
(tgs-contract.md section 2). On assignment every partition starts at the
offset after the last one the store applied (from the beginning if none);
Kafka offsets are never committed, so the store's applied_offsets table is the
only progress record and a crash can never leave it disagreeing with the
data. Each consumed batch is one apply_batch transaction.

Offline: lines are {"topic", "envelope"} (Protobuf JSON) with optional
"partition" and "offset", the orchestrator's offline format; a missing
offset is the line's index within its topic and partition.

The DSN defaults to $MT_TGS_DSN.
"""
import argparse
import json
import os
import signal
import sys

from google.protobuf import json_format

from microtrace.v0 import envelope_pb2

from mtcore.tgs.apply import apply_batch

GROUP = "graph-view"
INPUTS = ["norm.events.v0", "findings.v0", "witness.decisions.v0", "incidents.v0", "source.completeness.v0"]


class TgsRunner:
    def __init__(self, store, bootstrap, group=GROUP, batch_size=500):
        from confluent_kafka import Consumer
        self.store = store
        self.batch_size = batch_size
        self.consumer = Consumer({"bootstrap.servers": bootstrap, "group.id": group,
                                  "enable.auto.commit": False, "auto.offset.reset": "earliest"})
        self.consumer.subscribe(INPUTS, on_assign=self._on_assign)

    def _on_assign(self, consumer, partitions):
        from confluent_kafka import OFFSET_BEGINNING
        done = self.store.offsets()
        for tp in partitions:
            last = done.get((tp.topic, tp.partition))
            tp.offset = last + 1 if last is not None else OFFSET_BEGINNING
        consumer.assign(partitions)
        print("ready", file=sys.stderr, flush=True)

    def step(self):
        msgs = [m for m in self.consumer.consume(self.batch_size, timeout=0.2) if not m.error()]
        if not msgs:
            return 0
        batch = []
        for m in msgs:
            env = envelope_pb2.Envelope()
            env.ParseFromString(m.value())
            batch.append((m.topic(), m.partition(), m.offset(), env))
        apply_batch(self.store, batch)
        return len(batch)

    def run(self, stop):
        while not stop():
            self.step()
        self.consumer.close()


def run_file(store, path, batch_size=500):
    """Apply a JSONL file in batches; returns the number of records."""
    batch, n, next_off = [], 0, {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            obj = json.loads(line)
            topic, part = obj["topic"], obj.get("partition", 0)
            off = obj.get("offset", next_off.get((topic, part), 0))
            next_off[(topic, part)] = off + 1
            batch.append((topic, part, off, json_format.ParseDict(obj["envelope"], envelope_pb2.Envelope())))
            n += 1
            if len(batch) >= batch_size:
                apply_batch(store, batch)
                batch = []
    if batch:
        apply_batch(store, batch)
    return n


def connect(dsn, rebuilding=False):
    import psycopg
    from mtcore.tgs.store import PgStore
    store = PgStore(psycopg.connect(dsn))
    store.apply_schema(rebuilding)
    return store


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run the MicroTRACE TGS ingest.")
    ap.add_argument("--dsn", default=os.environ.get("MT_TGS_DSN"), help="Postgres DSN (default $MT_TGS_DSN)")
    ap.add_argument("--offline", metavar="FILE", help="apply a file instead of Kafka")
    ap.add_argument("--bootstrap", default="127.0.0.1:9092")
    ap.add_argument("--group", default=GROUP)
    ap.add_argument("--batch-size", type=int, default=500, help="records per transaction at most")
    ap.add_argument("--reset", action="store_true", help="delete every row first (rebuild from the start)")
    ap.add_argument("--print-hash", action="store_true", help="print the canonical graph hash and exit")
    a = ap.parse_args(argv)
    if not a.dsn:
        ap.error("no DSN: pass --dsn or set MT_TGS_DSN")
    store = connect(a.dsn, rebuilding=a.reset)
    if a.print_hash:
        from mtcore.tgs.hashes import graph_hash
        print(graph_hash(store))
        return 0
    if a.reset:
        store.reset()
    if a.offline:
        print(json.dumps({"records": run_file(store, a.offline, a.batch_size)}), file=sys.stderr)
        return 0
    stopping = []
    signal.signal(signal.SIGTERM, lambda *_: stopping.append(1))
    TgsRunner(store, a.bootstrap, a.group, a.batch_size).run(lambda: bool(stopping))
    return 0


if __name__ == "__main__":
    sys.exit(main())
