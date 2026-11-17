"""Step 7g knowledge time in the agents: a completeness or context record is
known to a window only if received no later than the heartbeat update that
let the watermark pass the window's end, however far the side topics were
read; and the commit point keeps the heartbeats that set it."""
import agent_fixtures as F
import test_agent_c as C
from agent_testlib import ABSTAINED, FIRED, outcomes, params
from google.protobuf import timestamp_pb2

from mtcore.agents.engine import INF, Engine
from mtcore.agents.rules import ALL, input_topics
from microtrace.v0 import envelope_pb2

TOPICS = input_topics(ALL)


def hb(topic, low, emitted):
    env = envelope_pb2.Envelope(schema_major=0, kind=envelope_pb2.RecordKind.Value("HEARTBEAT"))
    env.heartbeat.topic, env.heartbeat.partition = topic, 0
    for field, sec in (("low_watermark", low), ("emitted_at", emitted)):
        t = timestamp_pb2.Timestamp()
        t.FromNanoseconds(F.ns(sec))
        getattr(env.heartbeat, field).CopyFrom(t)
    return env


def engine():
    return Engine(ALL, params(), input_partitions={t: 1 for t in TOPICS}, auto_advance=False)


def beat(eng, sec, offset=0):
    for t in TOPICS:
        eng.feed(hb(t, sec, sec), t, offset=offset)


def c1b_outcomes(eng):
    return outcomes([env.rule_evaluation for _t, _k, env in eng.drain() if env.HasField("rule_evaluation")], "C1b")


def events():
    return F.stream(C.ns_change(4))


def gap():
    return F.loss(3, 5, source="EBPF")[1]


def uninterrupted(receipt):
    """The gap is read before the first update whose heartbeats were emitted after it."""
    eng, out, pending = engine(), [], True
    for topic, env in events():
        eng.feed(env, topic)
    for sec in (10, 30):
        if pending and receipt <= F.ns(sec):
            eng.feed(gap(), "source.completeness.v0", receipt_ns=receipt)
            pending = False
        beat(eng, sec)
        eng.advance(eng.input_watermark())
        out += c1b_outcomes(eng)
    return out


def restarted(receipt):
    """Side topic read to its end first, then the inputs, then one advance."""
    eng = engine()
    eng.feed(gap(), "source.completeness.v0", receipt_ns=receipt)
    for topic, env in events():
        eng.feed(env, topic)
    for sec in (10, 30):
        beat(eng, sec)
    eng.advance(eng.input_watermark())
    return c1b_outcomes(eng)


def test_a_gap_received_after_the_window_was_evaluated_does_not_make_a_restarted_agent_abstain():
    assert uninterrupted(F.ns(20)) == restarted(F.ns(20)) == [FIRED]


def test_a_gap_received_before_the_update_is_known_with_or_without_a_restart():
    assert uninterrupted(F.ns(8)) == restarted(F.ns(8)) == [ABSTAINED]


def test_knowledge_time_is_the_newest_first_rise_over_partitions_and_inf_without_heartbeats():
    eng = engine()
    assert eng.knowledge_time(F.ns(5)) == INF
    beat(eng, 10)
    assert eng.knowledge_time(F.ns(5)) == F.ns(10)
    assert eng.knowledge_time(F.ns(50)) == INF


def test_the_commit_point_keeps_the_heartbeats_above_the_watermark():
    eng = engine()
    beat(eng, 10, offset=3)
    eng.advance(eng.input_watermark())
    beat(eng, 30, offset=7)                      # a rise above the watermark: a later window's update
    need = eng.needed_offsets()
    assert eng.topics and all(need[(t, 0)] == 7 for t in eng.topics)
