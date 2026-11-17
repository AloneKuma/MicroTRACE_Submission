"""OrchRunner with Kafka stubbed out: the engine advances only to a snapshot
watermark whose side records were read, heartbeats go to every output
partition with the engine watermark, and nothing is published before it."""
import sys
import types
from collections import namedtuple

import pytest

import agent_fixtures as F
import orch_fixtures as O
import test_orch_witness as TW
from microtrace.v0 import envelope_pb2

from mtcore.orchestrator import emit
from mtcore.orchestrator.engine import Engine
from mtcore.orchestrator.run import SIDE_TOPICS, OrchRunner, input_topics

FND, NORM, COMP = "findings.v0", "norm.events.v0", "source.completeness.v0"
OUT_PARTS = {"witness.decisions.v0": 3, "incidents.v0": 2}


@pytest.fixture(autouse=True)
def fake_kafka(monkeypatch):
    """The runner imports confluent_kafka lazily; commit() needs TopicPartition."""
    mod = types.ModuleType("confluent_kafka")
    mod.TopicPartition = namedtuple("TopicPartition", "topic partition offset")
    monkeypatch.setitem(sys.modules, "confluent_kafka", mod)


class Msg:
    def __init__(self, topic, env, partition=0, offset=0):
        self._t, self._v, self._p, self._o = topic, env.SerializeToString(), partition, offset

    def topic(self):
        return self._t

    def partition(self):
        return self._p

    def offset(self):
        return self._o

    def key(self):
        return None

    def value(self):
        return self._v

    def error(self):
        return None


class Consumer:
    def __init__(self):
        self.queue, self.commits = [], []

    def consume(self, n, timeout):
        out, self.queue = self.queue, []
        return out

    def commit(self, offsets, asynchronous):
        self.commits.append(offsets)


class Producer:
    def __init__(self):
        self.sent = []

    def produce(self, topic, value, key=None, partition=None):
        env = envelope_pb2.Envelope()
        env.ParseFromString(value)
        self.sent.append((topic, partition, key, env))

    def flush(self, timeout):
        return 0


def runner(side_end=0, hook=False):
    r = object.__new__(OrchRunner)
    r.p = O.oparams()
    r.instance, r.heartbeat_s, r.last_hb, r.hb_seq = "orch-test", 0.0, 0.0, 0
    r.inputs = input_topics(r.p)
    r.partitions = {FND: 1, NORM: 1, COMP: 1, "context.cluster.v0": 1, **OUT_PARTS}
    r.engine = Engine(r.p, input_partitions={FND: 1, NORM: 1})
    r.consumer, r.producer = Consumer(), Producer()
    r.position, r.side_snapshot = {}, None
    r.mode, r.checkpoint, r.positions_log = "oldest-needed", None, None
    r.checkpoint_s, r.last_commit = 0.0, 0.0
    r.side_log, r.replay_until, r.held, r.committed, r.out_low, r.first_hb = [], {}, set(), {}, None, True
    r.ends = {(COMP, 0): (0, side_end)}
    r._side_ends = lambda: dict(r.ends)
    if hook:
        r.engine.hook_calls = []
        r.engine.incidents_hook = r.engine.hook_calls.append
    return r


def beats(r):
    return [(t, p, env.heartbeat.low_watermark.ToNanoseconds()) for t, p, _k, env in r.producer.sent
            if env.HasField("heartbeat")]


def decisions(r):
    return [env for _t, _p, _k, env in r.producer.sent if not env.HasField("heartbeat")]


def feed(r, topic, env, offset=0):
    r.consumer.queue.append(Msg(topic, env, offset=offset))


def linked_pair():
    e1, e2 = TW.proc(1, 10), TW.proc(5, 11)
    return [e1, e2, TW.fnd("f1", e1), TW.fnd("f2", e2)]


def test_inputs_follow_the_g1b_gate():
    assert input_topics(O.oparams()) == [FND, NORM]
    assert SIDE_TOPICS == [COMP, "context.cluster.v0"]


def test_nothing_is_published_or_promised_before_the_watermark():
    r = runner()
    for env in linked_pair():
        feed(r, NORM if env.HasField("normalized_event") else FND, env)
    r.step()
    assert r.engine.watermark is None and decisions(r) == [] and beats(r) == []
    assert r.engine.pending                                   # the findings wait


def test_snapshot_advance_waits_for_the_side_reads_then_publishes_and_heartbeats():
    r = runner(side_end=1, hook=True)
    for env in linked_pair():
        feed(r, NORM if env.HasField("normalized_event") else FND, env)
    feed(r, FND, O.hb(FND, 0, 1000, 1000))
    feed(r, NORM, O.hb(NORM, 0, 1000, 1000, instance="rs-1", producer="restreamer"))
    r.step()
    assert r.engine.watermark is None and decisions(r) == []   # completeness not read up to the snapshot
    assert r.engine.hook_calls == []
    feed(r, COMP, F.loss(900, 901, source="AUDIT")[1])        # the side record below the snapshot
    r.step()
    wm = r.engine.watermark
    assert wm == F.ns(1000) - r.p.lateness_ns
    assert r.engine.hook_calls == [F.ns(1000)]                # "now" = newest heartbeat emitted_at
    assert any(env.HasField("witness") for env in decisions(r))
    want = {(t, p, wm) for t, n in OUT_PARTS.items() for p in range(n)}
    assert set(beats(r)) == want                              # every output partition, explicit partition
    assert all(k == emit.instance_key("orch-test") for _t, _p, k, env in r.producer.sent if env.HasField("heartbeat"))
    [offs] = r.consumer.commits[-1:]
    assert {o.topic for o in offs} == {FND, NORM}              # side topics are never committed


def test_incidents_hook_runs_after_each_advance_with_heartbeat_time():
    r = runner()
    calls = []
    r.engine.incidents_hook = calls.append
    feed(r, FND, O.hb(FND, 0, 10, 10))
    feed(r, NORM, O.hb(NORM, 0, 10, 10))
    r.step()
    assert r.engine.watermark is not None and calls == [F.ns(10)]


def test_advances_under_steady_side_traffic():
    r = runner(side_end=1)
    feed(r, FND, O.hb(FND, 0, 100, 100))
    feed(r, NORM, O.hb(NORM, 0, 100, 100))
    r.step()
    assert r.engine.watermark is None
    r.position[(COMP, 0)] = 1                  # read up to the snapshot; the topic has grown meanwhile
    r.ends[(COMP, 0)] = (0, 2)
    feed(r, FND, O.hb(FND, 0, 200, 200))
    feed(r, NORM, O.hb(NORM, 0, 200, 200))
    r.step()
    assert r.engine.watermark == F.ns(100) - r.p.lateness_ns   # the snapshot's watermark, not the newer one
    r.position[(COMP, 0)] = 2
    r.step()                                   # the snapshot taken at 200 is now read
    r.step()
    assert r.engine.watermark == F.ns(200) - r.p.lateness_ns
