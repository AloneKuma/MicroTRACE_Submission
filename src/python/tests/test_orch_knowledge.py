"""Step 7g knowledge time in the orchestrator: a coverage or context record is
known at a decision only if its receipt time is not after the archived time
of the watermark update that makes it, however far the side topics were read."""
import json

import agent_fixtures as F
import orch_fixtures as O
import test_orch_admission as A
from google.protobuf import json_format
from microtrace.v0 import envelope_pb2, incident_pb2, witness_pb2

from mtcore.orchestrator.engine import Engine
from mtcore.orchestrator.run import run_file
from mtcore.orchestrator.watermark import INF, Watermarks

FND, NORM, COMP = "findings.v0", "norm.events.v0", "source.completeness.v0"
IS = incident_pb2.IncidentStatus
S = 1_000_000_000


def idle(source, start, end, name):
    """A SOURCE_IDLE record for source over [start, end] (fixture seconds)."""
    env = envelope_pb2.Envelope()
    json_format.ParseDict({"schemaMajor": 0, "kind": "SOURCE_COMPLETENESS", "logicalId": name,
                           "sourceCompleteness": {"source": source, "scope": "audit-collector=ac-1",
                                                  "intervalStart": F.ts(start).ToJsonString(),
                                                  "intervalEnd": F.ts(end).ToJsonString(), "status": "INCOMPLETE",
                                                  "gaps": [{"reason": "SOURCE_IDLE", "scope": "partition=raw.audit.v0/*"}]}},
                          env)
    return env


# --- knowledge_time ---------------------------------------------------------------
def _wm(order):
    w = Watermarks({FND: 2}, 2 * S, 10 * S)
    for topic, p, low, emitted in order:
        w.observe(topic, O.hb(topic, p, low, emitted, instance=f"a{p}").heartbeat)
    return w


def test_knowledge_time_is_the_newest_first_heartbeat_reaching_w_whatever_the_read_order():
    hbs = [(FND, 0, 10, 11), (FND, 0, 20, 21), (FND, 1, 15, 16), (FND, 1, 30, 31)]
    one, other = _wm(hbs), _wm([hbs[2], hbs[0], hbs[3], hbs[1]])
    for w in (F.ns(5), F.ns(13), F.ns(18), F.ns(25)):
        assert one.knowledge_time(w) == other.knowledge_time(w)
    # w = 13 s needs lows >= 15 s: partition 0 reached it at emitted 21, partition 1 at 16
    assert one.knowledge_time(F.ns(13)) == F.ns(21)
    assert one.knowledge_time(F.ns(40)) == INF           # no heartbeat reaches it: end of input


def test_an_instance_reaching_w_only_after_a_long_silence_does_not_set_the_knowledge_time():
    w = _wm([(FND, 0, 10, 11), (FND, 1, 10, 11), (FND, 1, 20, 21), (FND, 1, 30, 31), (FND, 0, 30, 60)])
    assert w.knowledge_time(F.ns(20)) == F.ns(31)          # p0 silent since 11 s when p1 got there at 31 s
    single = _wm([(FND, 0, 10, 11), (FND, 0, 30, 60)])
    assert single.knowledge_time(F.ns(20)) == F.ns(60)     # nothing else moved the watermark meanwhile


# --- a gap after seal stays an amendment ----------------------------------------------
def _pair():
    evs = [A.proc(1, 10), A.proc(5, 11)]
    return evs, [A.fnd("f1", evs[0]), A.fnd("f2", evs[1])]


def _records(eng):
    return [env.incident for _t, _k, env in eng.drain() if env.HasField("incident")]


def _latest(recs):
    out = {}
    for r in recs:
        out[r.incident_id] = r
    return out


def _sc(r):
    sc = r.source_completeness
    return list(sc.at_seal_excluded_sources), list(sc.current_excluded_sources)


def _uninterrupted(gap_receipt):
    """Inputs and the gap read as they arrive: the gap is read before the
    first update whose heartbeat was emitted after it (the runner reads side
    topics to their end before advancing)."""
    evs, fs = _pair()
    eng = Engine(O.oparams(), {FND: 1})
    for env in evs:
        eng.feed(env, NORM)
    for env in fs:
        eng.feed(env, FND)
    out, pending = [], True
    for t in (30, 200, 300):
        if pending and gap_receipt <= F.ns(t):
            eng.feed(idle("AUDIT", 2, 60, "sc-1"), COMP, receipt_ns=gap_receipt)
            pending = False
        eng.feed(O.hb(FND, 0, t, t), FND)
        eng.advance()
        eng.incidents_hook(F.ns(t))
        out += _records(eng)
    return out


def _reprocessed(gap_receipt):
    """A restart that reads the side topic to its end first, then every input, then advances once."""
    evs, fs = _pair()
    eng = Engine(O.oparams(), {FND: 1})
    eng.feed(idle("AUDIT", 2, 60, "sc-1"), COMP, receipt_ns=gap_receipt)
    for env in evs:
        eng.feed(env, NORM)
    for env in fs:
        eng.feed(env, FND)
    for t in (30, 200, 300):
        eng.feed(O.hb(FND, 0, t, t), FND)
    eng.advance()
    eng.incidents_hook(F.ns(300))
    return _records(eng)


def test_a_gap_received_after_the_seal_stays_an_amendment_with_or_without_a_restart():
    a = _uninterrupted(F.ns(250))
    assert [r.status for r in a] == [IS.Value("INCIDENT_OPEN"), IS.Value("INCIDENT_SEALED"),
                                     IS.Value("INCIDENT_AMENDED")]
    b = _reprocessed(F.ns(250))
    [la], [lb] = _latest(a).values(), _latest(b).values()
    assert _sc(la) == _sc(lb) == ([], ["AUDIT"])              # never frozen into the sealed result
    assert la.watermark_time == lb.watermark_time


def test_a_gap_received_before_the_seals_update_is_frozen_with_or_without_a_restart():
    a = _uninterrupted(F.ns(150))
    assert [r.status for r in a] == [IS.Value("INCIDENT_OPEN"), IS.Value("INCIDENT_SEALED")]
    [la], [lb] = _latest(a).values(), _latest(_reprocessed(F.ns(150))).values()
    assert _sc(la) == _sc(lb) == (["AUDIT"], ["AUDIT"])


# --- witness coverage ---------------------------------------------------------------
def _statuses(eng):
    return [env.witness.status for _t, _k, env in eng.drain() if env.HasField("witness")]


def _coverage_run(up_front, receipt):
    evs, fs = _pair()
    loss = F.loss(2, 4)[1]                                    # eBPF loss inside the pair's interval
    eng = Engine(O.oparams(), {FND: 1})
    if up_front:
        eng.feed(loss, COMP, receipt_ns=receipt)
    for env in evs:
        eng.feed(env, NORM)
    for env in fs:
        eng.feed(env, FND)
    eng.feed(O.hb(FND, 0, 200, 200), FND)
    eng.advance()
    if not up_front:
        eng.feed(loss, COMP, receipt_ns=receipt)
    eng.feed(O.hb(FND, 0, 300, 300), FND)
    eng.advance()
    return _statuses(eng)


def test_coverage_decisions_do_not_depend_on_how_far_the_side_topic_was_read():
    late = _coverage_run(False, F.ns(250))
    assert late == _coverage_run(True, F.ns(250))
    assert late[0] == witness_pb2.WitnessStatus.Value("CONFIRMED") and len(late) == 2   # then re-decided
    early = _coverage_run(True, F.ns(100))
    assert len(early) == 1 and early[0] == late[-1]


# --- offline -------------------------------------------------------------------------
def test_offline_replay_is_deterministic_and_knows_every_side_record_in_the_file(tmp_path):
    """Offline lines may carry receipt_ns or not: a file has no watermark
    updates, so end of input is the only one and knows the whole file."""
    import io
    evs, fs = _pair()
    lines = [{"topic": COMP, "envelope": json_format.MessageToDict(idle("AUDIT", 2, 60, "sc-1"))}]
    lines += [{"topic": NORM, "envelope": json_format.MessageToDict(e)} for e in evs]
    lines += [{"topic": FND, "envelope": json_format.MessageToDict(e)} for e in fs]
    outs = []
    for receipt in (None, F.ns(250), None):
        lines[0].pop("receipt_ns", None)
        if receipt is not None:
            lines[0]["receipt_ns"] = receipt
        path = tmp_path / "in.jsonl"
        path.write_text("\n".join(json.dumps(x) for x in lines) + "\n", encoding="utf-8")
        buf = io.StringIO()
        run_file(O.oparams(), str(path), out=buf)
        outs.append(buf.getvalue())
    assert outs[0] == outs[1] == outs[2]
    inc = [json.loads(x)["record"] for x in outs[0].splitlines() if json.loads(x)["topic"] == "incidents.v0"]
    assert inc[-1]["sourceCompleteness"]["atSealExcludedSources"] == ["AUDIT"]   # one update: end of input
