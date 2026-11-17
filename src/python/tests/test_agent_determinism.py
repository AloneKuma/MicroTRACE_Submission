"""Replay determinism: the same input gives the same findings and
evaluations (and IDs) whatever the arrival order within the lateness bound,
and whether windows are flushed by heartbeats or at end of input."""
import random

import agent_fixtures as F
import test_agent_c as C
import test_agent_e as E
import test_agent_g as G
import test_agent_h as H
from agent_testlib import params
from google.protobuf import timestamp_pb2

from mtcore.agents.engine import Engine
from mtcore.agents.rules import ALL, input_topics
from microtrace.v0 import envelope_pb2


def mixed_stream():
    items = [*E.CTX, *G.CTX[1:],
             F.gateway(1, matches=[("sqli-union", "QUERY")], indicators=["row-dump"]),
             *[F.audit(2 + i * 0.1, verb="list", resource=f"r{i}") for i in range(6)],
             C.ns_change(3, op="NS_SAMPLE", family="ns.sample", before=None, after=C.CONT), C.ns_change(4),
             E.write(5, seq=10), E.exec_(9, ino=777, seq=12), E.exec_(12, seq=13),
             G.exec_request(14), G.target_exec(14.5),
             H.data_read(16, seq=200), H.ext_connect(17, seq=201), H.flow_bytes(18, 5000, seq=202)]
    return F.stream(*items)


def key_of(eng):
    out = eng.drain()
    fs = sorted(env.finding.finding_id for _t, _k, env in out if env.HasField("finding"))
    evs = sorted((env.rule_evaluation.evaluation_id, env.rule_evaluation.outcome)
                 for _t, _k, env in out if env.HasField("rule_evaluation"))
    return fs, evs


def heartbeat(topic, low_ns):
    env = envelope_pb2.Envelope(schema_major=0, kind=envelope_pb2.RecordKind.Value("HEARTBEAT"))
    env.heartbeat.topic, env.heartbeat.partition = topic, 0
    t = timestamp_pb2.Timestamp()
    t.FromNanoseconds(low_ns)
    env.heartbeat.low_watermark.CopyFrom(t)
    return env


def event_time(env):
    if env.HasField("normalized_event"):
        t = env.normalized_event.time.event_time
        return t.seconds + t.nanos / 1e9 - F.T0
    return -1000.0   # context and completeness records first


def online(records, seed, p):
    """Arrival shuffled within 1 s (lateness is 2 s); heartbeats every 2 s."""
    rng = random.Random(seed)
    topics = input_topics(ALL)
    eng = Engine(ALL, p, input_partitions={t: 1 for t in topics})
    arrivals = sorted(records, key=lambda r: event_time(r[1]) + rng.uniform(0, 1.0))
    next_hb = 0.0
    for topic, env in arrivals:
        now = event_time(env)
        while now - 1.0 > next_hb:      # sender promises: nothing older than now - 1 s
            for t in topics:
                eng.feed(heartbeat(t, F.ns(next_hb)), t)
            next_hb += 2.0
        eng.feed(env, topic)
    eng.finish()
    return key_of(eng), eng.stats


def offline(records, p):
    eng = Engine(ALL, p)
    for topic, env in records:
        eng.feed(env, topic)
    eng.finish()
    return key_of(eng)


def test_same_ids_offline_twice_and_online_shuffled():
    p = params()
    recs = mixed_stream()
    ref = offline(recs, p)
    assert len(ref[0]) >= 7, ref[0]           # A1, A2, B1, C1a, C1b, E2, G2, H4 ...
    assert offline(list(reversed(recs)), p) == ref
    for seed in range(5):
        got, stats = online(recs, seed, p)
        assert not any(k.endswith(":late") for k in stats), stats
        assert got == ref, seed


def test_replayed_duplicates_are_ignored():
    p = params()
    recs = mixed_stream()
    assert offline(recs + recs, p) == offline(recs, p)
