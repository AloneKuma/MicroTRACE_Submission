"""Orchestrator 5d + 5e integrated: the engine's groups go through the incident
book, so incidents are opened, sealed and amended from the stream itself."""
import agent_fixtures as F
import orch_fixtures as O
import test_orch_admission as A
from google.protobuf import json_format
from microtrace.v0 import envelope_pb2, incident_pb2

from mtcore.orchestrator.engine import Engine

FND, NORM, COMP = "findings.v0", "norm.events.v0", "source.completeness.v0"
IS = incident_pb2.IncidentStatus


def incidents(eng):
    return [env.incident for _t, _k, env in eng.drain() if env.HasField("incident")]


def _trace(skip_completeness=True):
    eng = Engine(O.oparams())
    for _label, topic, env, _key in O.trace_records():
        if topic == COMP and skip_completeness:
            continue
        eng.feed(env, NORM if env.HasField("normalized_event") else topic)
    eng.finish()
    return eng


def test_example_trace_seals_incident_i1():
    i1 = next(e.incident for label, _t, e, _k in O.trace_records() if label.startswith("I1"))
    eng = _trace()
    eng.drain()
    [inc] = incidents_after(eng, F.ns(0))
    for f in ("incident_id", "anchor_finding_id", "anchor_entity", "version", "finding_ids", "link_witness_ids",
              "event_start", "event_end", "status", "sealed_prediction_version", "source_completeness"):
        assert getattr(inc, f) == getattr(i1, f), f
    for got, want in ((inc.ranked_paths, i1.ranked_paths), (inc.speculative_paths, i1.speculative_paths)):
        assert [(p.path_id, list(p.finding_ids), list(p.witness_ids)) for p in got] == \
            [(p.path_id, list(p.finding_ids), list(p.witness_ids)) for p in want]
    # Sealed at the group's last extension: last event 10:00:11 + the largest enabled
    # direct window (60 s) + eps_bar (5 s),
    # not the trace's illustrative 11:00.
    assert inc.watermark_time.ToJsonString() == "2026-09-26T10:01:16Z"


def incidents_after(eng, now_ns):
    eng.incidents_hook(now_ns)
    return incidents(eng)


def _idle(source, start, end, name):
    env = envelope_pb2.Envelope()
    json_format.ParseDict({"schemaMajor": 0, "kind": "SOURCE_COMPLETENESS", "logicalId": name,
                           "sourceCompleteness": {"source": source, "scope": "audit-collector=ac-1",
                                                  "intervalStart": start, "intervalEnd": end, "status": "INCOMPLETE",
                                                  "gaps": [{"reason": "SOURCE_IDLE", "scope": "partition=raw.audit.v0/*"}]}},
                          env)
    return env


def test_an_idle_source_learned_after_seal_amends_an_incident_it_overlaps_and_only_that():
    eng = _trace()
    [i1] = incidents_after(eng, F.ns(0))
    # The trace's own audit idle (10:40-11:10) starts after I1 sealed (10:01:16): no amendment.
    eng.feed(_idle("AUDIT", "2026-09-26T10:40:00Z", "2026-09-26T11:10:00Z", "sc-late"), COMP)
    assert incidents_after(eng, F.ns(0)) == []
    # An audit idle overlapping I1's open period, learned after the seal: amendment, as I2.
    eng.feed(_idle("AUDIT", "2026-09-26T10:01:00Z", "2026-09-26T10:30:00Z", "sc-overlap"), COMP)
    amended_at = json_format.ParseDict("2026-09-26T11:20:00Z", i1.watermark_time.__class__())
    [i2] = incidents_after(eng, amended_at.seconds * 10**9)
    assert (i2.incident_id, i2.version, i2.status) == (i1.incident_id, 2, IS.Value("INCIDENT_AMENDED"))
    assert list(i2.source_completeness.current_excluded_sources) == ["AUDIT"]
    assert list(i2.source_completeness.at_seal_excluded_sources) == []
    assert i2.sealed_prediction_version == i1.sealed_prediction_version and i2.watermark_time == i1.watermark_time
    [am] = i2.amendments
    assert am.reason == "audit source excluded by max-idle after seal; analyst view only"
    assert am.amended_at.ToJsonString() == "2026-09-26T11:20:00Z"


def test_an_incident_is_published_open_before_it_seals_and_holds_the_output_watermark():
    evs, fs = [A.proc(1, 10), A.proc(5, 11)], None
    fs = [A.fnd("f1", evs[0]), A.fnd("f2", evs[1])]
    eng = Engine(O.oparams(), {FND: 1})
    for env in evs:
        eng.feed(env, NORM)
    for env in fs:
        eng.feed(env, FND)
    eng.feed(O.hb(FND, 0, 30, 30), FND)            # watermark 28: link decided, group not sealed
    eng.advance()
    [inc] = incidents_after(eng, F.ns(30))
    assert inc.status == IS.Value("INCIDENT_OPEN") and list(inc.finding_ids) == ["f1", "f2"]
    assert eng.output_low_watermark() == F.ns(1)   # the open incident can still be published at 1 s
    eng.feed(O.hb(FND, 0, 200, 200), FND)          # past 5 + 120 + 5
    eng.advance()
    [inc] = incidents_after(eng, F.ns(200))
    assert (inc.status, inc.version) == (IS.Value("INCIDENT_SEALED"), 1)
    assert eng.output_low_watermark() == eng.watermark


# --- input frontier and node-trust epochs (design-spec.md section 9) --------------
def _linked(recs):
    """Feed (topic, partition, offset, env) records, finish, return the incident."""
    eng = Engine(O.oparams())
    for topic, part, off, env in recs:
        eng.feed(env, topic, part, off)
    eng.finish()
    return eng, incidents_after(eng, F.ns(0))


def test_the_input_frontier_is_the_last_offset_the_incident_cites_per_partition():
    e1, e2 = A.proc(1, 10), A.proc(5, 11)
    other = A.proc(3, 50, lineage="ln-other", node="node-9")      # read, never cited
    _eng, [inc] = _linked([(NORM, 1, 7, e1), (NORM, 0, 3, e2), (NORM, 0, 9, other),
                           (FND, 0, 4, A.fnd("f1", e1)), (FND, 1, 2, A.fnd("f2", e2)),
                           (FND, 0, 8, A.fnd("f3", other))])
    assert list(inc.finding_ids) == ["f1", "f2"]
    assert dict(inc.input_frontier) == {"norm.events.v0/0": 3, "norm.events.v0/1": 7,
                                        "findings.v0/0": 4, "findings.v0/1": 2}


def test_a_node_trust_epoch_on_a_boot_that_supplied_member_evidence_is_on_the_incident():
    e1, e2 = A.proc(1, 10, ingest=1.2), A.proc(2, 11, ingest=2.2)
    ev, c1b = A.c1b(50)
    eng, [inc] = _linked([(NORM, 0, 0, e1), (NORM, 0, 1, e2), (NORM, 0, 2, ev),
                          (FND, 0, 0, A.fnd("f1", e1)), (FND, 0, 1, A.fnd("f2", e2)), (FND, 0, 2, c1b)])
    assert list(inc.finding_ids) == ["f1", "f2"]          # evidence received before the onset: still linked
    [ep] = inc.node_epochs
    assert (ep.node_id, ep.boot_id, ep.trigger_finding_id) == (F.NODE, F.BOOT, "c1b")
    assert ep.kind == incident_pb2.NodeEpochKind.Value("NODE_EPOCH_CONFIRMED")
    assert ep.tau_n.ToNanoseconds() == eng.epochs.onset(F.NODE, F.BOOT)


def test_an_incident_without_evidence_from_an_epoch_node_has_no_epoch():
    e1, e2 = A.proc(1, 10, ingest=1.2, node="node-2"), A.proc(2, 11, ingest=2.2, node="node-2")
    ev, c1b = A.c1b(50)                                   # epoch on node-1 only
    _eng, [inc] = _linked([(NORM, 0, 0, e1), (NORM, 0, 1, e2), (NORM, 0, 2, ev),
                           (FND, 0, 0, A.fnd("f1", e1)), (FND, 0, 1, A.fnd("f2", e2)), (FND, 0, 2, c1b)])
    assert list(inc.node_epochs) == []


def test_an_epoch_learned_after_seal_amends_the_incident():
    e1, e2 = A.proc(1, 10, ingest=1.2), A.proc(2, 11, ingest=2.2)
    eng = Engine(O.oparams(), {FND: 1})
    for env in (e1, e2):
        eng.feed(env, NORM)
    for env in (A.fnd("f1", e1), A.fnd("f2", e2)):
        eng.feed(env, FND)
    eng.feed(O.hb(FND, 0, 200, 200), FND)
    eng.advance()
    [i1] = incidents_after(eng, F.ns(200))
    assert i1.status == IS.Value("INCIDENT_SEALED") and list(i1.node_epochs) == []
    ev, c1b = A.c1b(50)                                   # a late trigger on the members' node
    eng.feed(ev, NORM)
    eng.feed(c1b, FND)
    eng.feed(O.hb(FND, 0, 210, 210), FND)
    eng.advance()
    [i2] = incidents_after(eng, F.ns(210))
    assert (i2.version, i2.status) == (2, IS.Value("INCIDENT_AMENDED"))
    assert [e.trigger_finding_id for e in i2.node_epochs] == ["c1b"]
    assert i2.amendments[-1].reason == "node-trust epoch recorded after seal; analyst view only"
    assert i2.sealed_prediction_version == i1.sealed_prediction_version
