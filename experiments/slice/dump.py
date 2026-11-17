#!/usr/bin/env python3
"""Dump topics from the beginning as JSONL (decoded envelopes plus transport provenance).

Usage: dump.py --bootstrap B --out DIR TOPIC [TOPIC...]
Writes DIR/<topic>.jsonl. Stops at the high watermark captured at start.
Output may contain identities (raw topics): write it only to a private directory.
"""

import argparse
import json
import os
import uuid

from confluent_kafka import Consumer, TopicPartition

import mtslice as M


def dump(bootstrap, topic, path):
    c = Consumer({"bootstrap.servers": bootstrap, "group.id": f"dump-{uuid.uuid4()}",
                  "enable.auto.commit": False, "auto.offset.reset": "earliest"})
    md = c.list_topics(topic, timeout=10)
    parts = sorted(md.topics[topic].partitions)
    ends = {p: c.get_watermark_offsets(TopicPartition(topic, p), timeout=10)[1] for p in parts}
    c.assign([TopicPartition(topic, p, 0) for p in parts])
    done = {p for p in parts if ends[p] == 0}
    n = 0
    with open(path, "w", encoding="utf-8") as fh:
        while len(done) < len(parts):
            msg = c.poll(1.0)
            if msg is None or msg.error():
                continue
            if msg.offset() >= ends[msg.partition()]:
                done.add(msg.partition())
                continue
            rec = M.to_dict(M.decode(msg.value()))
            rec["_transport"] = {"topic": topic, "partition": msg.partition(), "offset": msg.offset(),
                                 "key_hex": (msg.key() or b"").hex()}
            fh.write(json.dumps(rec, sort_keys=True) + "\n")
            n += 1
            if msg.offset() + 1 >= ends[msg.partition()]:
                done.add(msg.partition())
    c.close()
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bootstrap", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("topics", nargs="+")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    for t in a.topics:
        print(f"DUMP {t} {dump(a.bootstrap, t, os.path.join(a.out, t + '.jsonl'))}")


if __name__ == "__main__":
    main()
