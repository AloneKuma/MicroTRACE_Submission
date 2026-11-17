"""Integration tests T1-T8 for the shipping link (spec/kafka/ship-contract.md).

Real Go receiver and shipper processes on this host, over TLS 1.3, writing to
the dev Kafka. Skipped when Kafka is not reachable. The TLS 1.2 and
missing-certificate cases of T7 are in the Go tests
(internal/receiver TestIdentityAndTLSEnforced).
"""
import collections
import json
import os
import socket
import subprocess
import sys
import time
import uuid

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "spec", "tools"))
import mtcodec  # noqa: E402

from mtcore import REPO
from mtcore.kafka_topics import DEV_CONFIG, check_configs, ensure_topics
from mtcore.partition import partition_for
from microtrace.v0 import common_pb2, envelope_pb2, keys_pb2
from shipping_rig import (CuttingProxy, KafkaWindow, Receiver, Shipper, build_binaries, ebpf_line,
                          make_certs, stop_all, write_lines)
from google.protobuf import json_format

BOOTSTRAP = os.environ.get("MT_KAFKA", "127.0.0.1:9092")
TRACE = os.path.join(REPO, "spec", "examples", "trace-v0.json")
SHIPPED = ["raw.ebpf.v0", "raw.audit.v0", "raw.gateway.v0", "raw.kyverno.v0", "raw.dbaudit.v0",
           "raw.pathflow.v0", "context.cluster.v0", "norm.events.v0"]
WATCH = SHIPPED + ["source.completeness.v0"]
NODES = ["node-1", "node-2", "node-3", "node-4"]


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
    build_binaries()
    plan, _, _, problems = ensure_topics(BOOTSTRAP, DEV_CONFIG)
    assert not problems, problems
    return plan


@pytest.fixture(scope="module")
def certs(tmp_path_factory, plan):
    return make_certs(str(tmp_path_factory.mktemp("certs")), NODES)


@pytest.fixture(autouse=True)
def _stop_processes():
    yield
    stop_all()


@pytest.fixture
def window():
    w = KafkaWindow(BOOTSTRAP, WATCH)
    yield w
    w.close()


def data_records(recs, node=None, boot=None):
    """Shipped data records (not heartbeats or completeness), optionally for one stream."""
    out = []
    for r in recs:
        if r["topic"] not in SHIPPED or r["env"].kind == envelope_pb2.HEARTBEAT:
            continue
        if boot and not r["env"].logical_id.startswith(f"ev-{node}-{boot}-"):
            continue
        out.append(r)
    return out


def by_logical_id(recs):
    c = collections.Counter(r["env"].logical_id for r in recs)
    return c


def gen(node, boot, n, start=1):
    return [ebpf_line(node, boot, i) for i in range(start, start + n)]


# ---------------------------------------------------------------- T1

def trace_lines():
    trace = json.load(open(TRACE, encoding="utf-8"))
    lines = []
    for r in trace["records"]:
        # Heartbeats are written by the receiver itself, never shipped.
        if r["topic"] not in SHIPPED or r["envelope"].get("kind") == "HEARTBEAT":
            continue
        _, kt, comps = mtcodec.decode_key(bytes.fromhex(r["key_hex"]))
        lines.append({"lane": "NORMAL", "topic": r["topic"], "key_type": keys_pb2.KeyType.Name(kt),
                      "key_components": [v for _, v in comps], "envelope": r["envelope"]})
    return lines


def test_t1_everything_once_same_bytes_java_partition_receipt_time(plan, certs, tmp_path, window):
    rx = Receiver(str(tmp_path), certs, BOOTSTRAP).start()
    try:
        trace = trace_lines()
        assert trace, "no shippable trace records"
        sent = {}
        ships = []
        for node in ("node-1", "node-2"):
            boot = uuid.uuid4().hex
            lines = gen(node, boot, 2500)
            lines += [dict(ln, lane="PRIORITY") for ln in gen(node, boot, 20, start=100001)]
            if node == "node-1":
                lines = trace + lines
            for ln in lines:
                env = json_format.ParseDict(ln["envelope"], envelope_pb2.Envelope())
                sent[(node, ln["topic"], env.SerializeToString(deterministic=True))] = ln
            path = write_lines(str(tmp_path / f"in-{node}.jsonl"), lines)
            ships.append(Shipper(str(tmp_path), certs, rx.port, node, boot=boot).start(path))
        for s in ships:
            assert s.wait() == 0, s.log()
        recs = data_records(window.read())
        assert len(recs) == len(sent), f"Kafka has {len(recs)} shipped records, sent {len(sent)}"
        index = collections.defaultdict(list)
        for k in sent:
            index[(k[1], k[2])].append(k)
        seen = set()
        for r in recs:
            match = index.get((r["topic"], r["value"]), [])
            assert len(match) == 1, f"record at {r['topic']}/{r['partition']}@{r['offset']} matches {len(match)} sent items"
            assert match[0] not in seen, "delivered twice"
            seen.add(match[0])
            ln = sent[match[0]]
            want_key = mtcodec.encode_key(keys_pb2.KeyType.Value(ln["key_type"]),
                                          [(c, v) for c, v in zip(_codes(ln["topic"]), ln["key_components"])])
            assert r["key"] == want_key
            assert r["partition"] == partition_for(r["key"], plan[r["topic"]]["partitions"])
            assert r["log_append"], f"{r['topic']} record not stamped with LogAppendTime"
    finally:
        rx.stop()


_CODES = {}


def _codes(topic):
    if not _CODES:
        import yaml
        for t in yaml.safe_load(open(os.path.join(REPO, "spec", "kafka", "topics.yaml")))["topics"]:
            _CODES[t["name"]] = [keys_pb2.KeyComponent.Value(c) for c in t["key_components"]]
    return _CODES[topic]


# ---------------------------------------------------------------- T2

def test_t2_receiver_killed_and_restarted(plan, certs, tmp_path, window):
    rx = Receiver(str(tmp_path), certs, BOOTSTRAP).start()
    boot = uuid.uuid4().hex
    n = 20000
    path = write_lines(str(tmp_path / "in.jsonl"), gen("node-1", boot, n))
    sh = Shipper(str(tmp_path), certs, rx.port, "node-1", boot=boot, extra=["-window", "1000", "-batch-max", "200"]).start(path)
    time.sleep(1.0)
    rx.kill()
    time.sleep(2.0)
    rx.start()
    try:
        assert sh.wait() == 0, sh.log()
    finally:
        rx.stop()
    counts = by_logical_id(data_records(window.read(), "node-1", boot))
    assert set(counts) == {f"ev-node-1-{boot}-{i}" for i in range(1, n + 1)}, "records lost"
    dups = sum(c - 1 for c in counts.values())
    print(f"T2: {n} records, {dups} duplicates from the crash window (removable by logical_id)")
    assert dups <= 1000, "more duplicates than one window"


# ---------------------------------------------------------------- T3

def test_t3_shipper_killed_and_restarted(plan, certs, tmp_path, window):
    rx = Receiver(str(tmp_path), certs, BOOTSTRAP).start()
    boot = uuid.uuid4().hex
    n = 20000
    lines = gen("node-1", boot, n)
    path = write_lines(str(tmp_path / "in.jsonl"), lines)
    sh = Shipper(str(tmp_path), certs, rx.port, "node-1", boot=boot,
                 extra=["-window", "500", "-batch-max", "100"]).start(path)
    time.sleep(1.0)
    sh.kill()
    try:
        spooled = sh.spooled()["NORMAL"]
        print(f"T3: shipper killed with {spooled} of {n} items spooled")
        rest = write_lines(str(tmp_path / "rest.jsonl"), lines[spooled:])
        assert sh.start(rest).wait() == 0, sh.log()
    finally:
        rx.stop()
    counts = by_logical_id(data_records(window.read(), "node-1", boot))
    assert set(counts) == {f"ev-node-1-{boot}-{i}" for i in range(1, n + 1)}, "records lost"
    assert sum(c - 1 for c in counts.values()) == 0, "duplicates after a shipper restart"


# ---------------------------------------------------------------- T4

def test_t4_connection_cut_repeatedly(plan, certs, tmp_path, window):
    rx = Receiver(str(tmp_path), certs, BOOTSTRAP).start()
    proxy = CuttingProxy(rx.port, every=0.5)
    boot = uuid.uuid4().hex
    n = 20000
    path = write_lines(str(tmp_path / "in.jsonl"), gen("node-1", boot, n))
    sh = Shipper(str(tmp_path), certs, proxy.port, "node-1", boot=boot,
                 extra=["-window", "1000", "-batch-max", "200"]).start(path)
    try:
        time.sleep(4)
        proxy.stop_cutting()
        assert sh.wait() == 0, sh.log()
    finally:
        proxy.close()
        rx.stop()
    counts = by_logical_id(data_records(window.read(), "node-1", boot))
    assert set(counts) == {f"ev-node-1-{boot}-{i}" for i in range(1, n + 1)}, "records lost"
    assert proxy.accepted >= 3, f"only {proxy.accepted} connections; cuts did not happen"
    assert sum(c - 1 for c in counts.values()) == 0, "duplicates after connection cuts"


# ---------------------------------------------------------------- T5

def _kafka(script):
    subprocess.run(["bash", os.path.join(REPO, "src", "scripts", script)], check=True,
                   capture_output=True, text=True)


def test_t5_kafka_down_for_20s(plan, certs, tmp_path):
    rx = Receiver(str(tmp_path), certs, BOOTSTRAP, extra=["-produce-timeout", "5s"]).start()
    boot = uuid.uuid4().hex
    n = 10000
    path = write_lines(str(tmp_path / "in.jsonl"), gen("node-1", boot, n))
    window = KafkaWindow(BOOTSTRAP, WATCH)
    sh = Shipper(str(tmp_path), certs, rx.port, "node-1", boot=boot,
                 extra=["-window", "500", "-batch-max", "100", "-retransmit", "20s"]).start(path)
    try:
        time.sleep(0.5)
        _kafka("kafka-down.sh")
        down_at = time.time()
        time.sleep(20)
        _kafka("kafka-up.sh")
        print(f"T5: Kafka down for {time.time() - down_at:.0f}s")
        assert sh.wait(timeout=300) == 0, sh.log()
        counts = by_logical_id(data_records(window.read(timeout=120), "node-1", boot))
    finally:
        if not _kafka_up():
            _kafka("kafka-up.sh")
        rx.stop()
        window.close()
    assert set(counts) == {f"ev-node-1-{boot}-{i}" for i in range(1, n + 1)}, "records lost"
    dups = sum(c - 1 for c in counts.values())
    print(f"T5: {n} records, {dups} duplicates (removable by logical_id)")


# ---------------------------------------------------------------- T6

def test_t6_spool_overflow_reported_exactly(plan, certs, tmp_path, window):
    boot = uuid.uuid4().hex
    n = 500
    lines = gen("node-3", boot, n)
    path = write_lines(str(tmp_path / "in.jsonl"), lines)
    rx = Receiver(str(tmp_path), certs, BOOTSTRAP)  # not started yet: the shipper must spool
    sh = Shipper(str(tmp_path), certs, rx.port, "node-3", boot=boot,
                 extra=["-spool-max-bytes", "20000"]).start(path)
    time.sleep(2)
    rx.start()
    try:
        assert sh.wait() == 0, sh.log()
    finally:
        rx.stop()
    gaps = sh.stats()["NORMAL"]["gaps"]
    assert len(gaps) == 1 and gaps[0]["first"] == 1, gaps
    last = gaps[0]["last"]
    recs = window.read()
    counts = by_logical_id(data_records(recs, "node-3", boot))
    assert set(counts) == {f"ev-node-3-{boot}-{i}" for i in range(last + 1, n + 1)}
    loss = [r["env"].source_completeness for r in recs if r["topic"] == "source.completeness.v0"
            and r["env"].source_completeness.scope == f"node=node-3/boot={boot}/lane=NORMAL"]
    assert len(loss) == 1, loss
    g = loss[0].gaps[0]
    assert loss[0].status == 2 and g.reason == common_pb2.DROPPED_BEFORE
    assert f"seq 1-{last} " in g.detail, g.detail
    assert loss[0].source == common_pb2.EBPF
    print(f"T6: spool dropped seq 1-{last}; {n - last} delivered; one DROPPED_BEFORE record")


# ---------------------------------------------------------------- T7

def test_t7_impersonation_rejected(plan, certs, tmp_path, window):
    rx = Receiver(str(tmp_path), certs, BOOTSTRAP).start()
    boot = uuid.uuid4().hex
    path = write_lines(str(tmp_path / "in.jsonl"), gen("node-1", boot, 10))
    sh = Shipper(str(tmp_path), certs, rx.port, "node-1", boot=boot, cert_node="node-2").start(path)
    try:
        code = sh.wait(timeout=30)
    finally:
        rx.stop()
    assert code != 0 and "does not match certificate" in sh.log(), sh.log()
    assert not data_records(window.read(), "node-1", boot), "impersonated records were written"


# ---------------------------------------------------------------- T8

def test_t8_heartbeats_and_idle(plan, certs, tmp_path, window):
    rx = Receiver(str(tmp_path), certs, BOOTSTRAP, extra=["-heartbeat", "200ms", "-max-idle", "2s"]).start()
    boot = uuid.uuid4().hex
    wm = "2026-10-08T12:00:00Z"
    lines = gen("node-4", boot, 50) + [{"lane": "NORMAL", "watermark": wm}]
    path = write_lines(str(tmp_path / "in.jsonl"), lines)
    sh = Shipper(str(tmp_path), certs, rx.port, "node-4", boot=boot).start(path)
    try:
        assert sh.wait() == 0, sh.log()
        time.sleep(4)
    finally:
        rx.stop()
    recs = window.read()
    hbs = [r for r in recs if r["env"].kind == envelope_pb2.HEARTBEAT
           and r["env"].heartbeat.producer_instance == rx.instance]
    by_part = collections.defaultdict(list)
    for r in hbs:
        assert r["env"].heartbeat.partition == r["partition"] and r["env"].heartbeat.topic == r["topic"]
        by_part[(r["topic"], r["partition"])].append(r["env"].heartbeat)
    for t in SHIPPED:
        for p in range(plan[t]["partitions"]):
            assert by_part[(t, p)], f"no heartbeat on {t}/{p}"
    for tp, beats in by_part.items():
        beats.sort(key=lambda h: h.producer_seq)
        marks = [h.low_watermark.ToDatetime() for h in beats]
        assert marks == sorted(marks), f"watermark went backwards on {tp}"
    final = max(h.low_watermark.ToJsonString() for beats in by_part.values() for h in beats)
    assert final == wm, f"final watermark {final}, declared {wm}"
    idle = [r["env"].source_completeness for r in recs if r["topic"] == "source.completeness.v0"
            and r["env"].source_completeness.scope == f"node=node-4/boot={boot}"]
    assert len(idle) == 1 and idle[0].gaps[0].reason == common_pb2.SOURCE_IDLE, idle


# ---------------------------------------------------------------- topic config

def test_receiver_topics_use_log_append_time(plan):
    assert check_configs(BOOTSTRAP, DEV_CONFIG) == []
