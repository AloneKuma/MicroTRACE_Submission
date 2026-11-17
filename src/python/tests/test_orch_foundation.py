"""Orchestrator build step 5a: watermark, evidence index, IDs and keys, and
the processing order."""
import itertools

import pytest

import agent_fixtures as F
import orch_fixtures as O
from microtrace.v0 import incident_pb2, witness_pb2

from mtcore.orchestrator import emit
from mtcore.orchestrator.engine import Engine, PayloadConflict
from mtcore.orchestrator.evidence import EvidenceIndex
from mtcore.orchestrator.watermark import Watermarks

S = 10**9
FND, NORM = "findings.v0", "norm.events.v0"


# --- watermark ---------------------------------------------------------------
def wm(parts=None, lateness=2 * S, idle=10 * S):
    return Watermarks(parts or {FND: 2}, lateness, idle)


def test_watermark_waits_for_every_partition_then_takes_the_minimum_minus_lateness_once():
    w = wm()
    w.observe(FND, O.hb(FND, 0, 100, 100).heartbeat)
    assert w.watermark() is None                          # partition 1 has not reported
    w.observe(FND, O.hb(FND, 1, 90, 100).heartbeat)
    assert w.watermark() == F.ns(90) - 2 * S


def test_partition_watermark_is_the_minimum_over_active_instances():
    w = wm({FND: 1})
    w.observe(FND, O.hb(FND, 0, 100, 100, instance="agents-AB").heartbeat)
    w.observe(FND, O.hb(FND, 0, 60, 100, instance="agents-CD").heartbeat)
    assert w.watermark() == F.ns(60) - 2 * S              # not the max (the agents' per-partition rule)


def test_silent_instance_is_excluded_after_max_idle_and_recorded():
    w = wm({FND: 1})
    w.observe(FND, O.hb(FND, 0, 60, 100, instance="slow").heartbeat)
    w.observe(FND, O.hb(FND, 0, 100, 105, instance="live").heartbeat)
    assert w.watermark() == F.ns(60) - 2 * S and w.exclusions() == []
    w.observe(FND, O.hb(FND, 0, 120, 111, instance="live").heartbeat)   # 11 s after slow's last
    assert w.watermark() == F.ns(120) - 2 * S
    [x] = w.exclusions()
    assert (x.instance, x.since) == ("slow", F.ns(100))
    w.observe(FND, O.hb(FND, 0, 70, 112, instance="slow").heartbeat)    # back, but behind
    assert w.watermark() == F.ns(120) - 2 * S             # never moves back
    assert w.exclusions() == []


def test_partition_whose_instances_are_all_idle_does_not_hold_the_watermark():
    w = wm({FND: 1, NORM: 1})
    w.observe(FND, O.hb(FND, 0, 50, 100).heartbeat)
    w.observe(NORM, O.hb(NORM, 0, 200, 200, instance="normalizer-1", producer="normalizer").heartbeat)
    assert w.watermark() == F.ns(200) - 2 * S             # findings.v0's only instance is idle


def test_heartbeats_of_other_topics_are_ignored():
    w = wm({FND: 1})
    w.observe("raw.ebpf.v0", O.hb("raw.ebpf.v0", 0, 500, 500).heartbeat)
    assert w.watermark() is None


# --- evidence ----------------------------------------------------------------
def test_evidence_index_dedups_looks_up_and_evicts_by_event_time():
    ix = EvidenceIndex()
    a, b = F.done(F.ebpf(10, "file.read")), F.done(F.ebpf(50, "file.read"))
    assert ix.add(a) and ix.add(b) and not ix.add(a)
    fa = O.finding("fd_a", 10, inputs=[a.normalized_event.event_id, "ev_missing"]).finding
    have, missing = ix.for_finding(fa)
    assert [e.id for e in have] == [a.normalized_event.event_id] and missing == ["ev_missing"]
    assert ix.evict(F.ns(20)) == 1 and ix.get(a.normalized_event.event_id) is None
    assert ix.get(b.normalized_event.event_id) is not None


# --- IDs and keys against the example trace -----------------------------------
def test_witness_and_incident_ids_and_keys_match_the_example_trace():
    recs = {label.split()[0]: (env, key) for label, _t, env, key in O.trace_records()}
    for label in ("W1", "W2"):
        env, key = recs[label]
        w = witness_pb2.Witness()
        w.CopyFrom(env.witness)
        w.witness_id = ""
        topic, k, out = emit.witness_record(w, "UNFROZEN-EXAMPLE")
        assert (topic, out.witness.witness_id, k.hex()) == (emit.WITNESS_TOPIC, env.witness.witness_id, key)
    for label in ("I1", "I2"):
        env, key = recs[label]
        inc = incident_pb2.Incident()
        inc.CopyFrom(env.incident)
        inc.incident_id = ""
        for p in list(inc.ranked_paths) + list(inc.speculative_paths):
            p.path_id = ""
        topic, k, out = emit.incident_record(inc, "UNFROZEN-EXAMPLE")
        assert (out.incident.incident_id, k.hex()) == (env.incident.incident_id, key)
        assert [p.path_id for p in out.incident.ranked_paths] == [p.path_id for p in env.incident.ranked_paths]
        assert [p.path_id for p in out.incident.speculative_paths] == \
            [p.path_id for p in env.incident.speculative_paths]


# --- processing order --------------------------------------------------------
def _engine():
    return Engine(O.oparams(), {FND: 1})


def test_findings_are_processed_in_event_time_then_id_order_whatever_the_arrival_order():
    fs = [O.finding("fd_c", 20), O.finding("fd_b", 10), O.finding("fd_a", 20), O.finding("fd_d", 5)]
    for order in itertools.permutations(fs):
        eng = _engine()
        for env in order:
            eng.feed(env, FND)
        eng.finish()
        assert eng.processed == ["fd_d", "fd_b", "fd_a", "fd_c"]


def test_findings_wait_for_the_watermark():
    eng = _engine()
    eng.feed(O.finding("fd_a", 10), FND)
    eng.feed(O.finding("fd_b", 30), FND)
    eng.feed(O.hb(FND, 0, 21, 21), FND)                  # watermark 21 - 2 = 19
    eng.advance()
    assert eng.processed == ["fd_a"] and eng.frontier == F.ns(10)
    eng.feed(O.hb(FND, 0, 40, 40), FND)
    eng.advance()
    assert eng.processed == ["fd_a", "fd_b"]


def test_re_emitted_finding_is_a_duplicate_but_a_different_payload_is_an_error():
    eng = _engine()
    eng.feed(O.finding("fd_a", 10, publish=11), FND)
    eng.feed(O.finding("fd_a", 10, publish=99), FND)       # agent restart: only publish_time differs
    assert eng.stats["duplicate_findings"] == 1 and eng.stats["findings"] == 1
    with pytest.raises(PayloadConflict):
        eng.feed(O.finding("fd_a", 10, extra="changed"), FND)


def test_unknown_schema_major_is_rejected():
    eng = _engine()
    env = O.finding("fd_a", 10)
    env.schema_major = 1
    eng.feed(env, FND)
    assert eng.stats["schema_major_rejected"] == 1 and not eng.pending


def test_evidence_is_kept_while_a_link_could_still_cite_it():
    eng = _engine()
    old, recent = F.done(F.ebpf(0, "file.read")), F.done(F.ebpf(5000, "file.read"))
    for env in (old, recent):
        eng.feed(env, NORM)
    p = eng.p
    t = (p.max_horizon_ns() + p.A_ns) // S + 100            # frontier far past the old event
    eng.feed(O.finding("fd_a", t), FND)
    eng.finish()
    assert eng.evidence.get(old.normalized_event.event_id) is None
    assert eng.evidence.get(recent.normalized_event.event_id) is not None


def test_offline_runner_reads_shipper_format_lines(tmp_path, capsys):
    import json

    from google.protobuf import json_format

    from mtcore.orchestrator.run import main
    path = tmp_path / "in.jsonl"
    with open(path, "w", encoding="utf-8") as fh:
        for _label, topic, env, _key in O.trace_records():
            # The trace files normalized events under their agent topics;
            # the orchestrator reads them from norm.events.v0.
            if env.HasField("normalized_event"):
                topic = NORM
            if topic in (FND, NORM):
                fh.write(json.dumps({"topic": topic, "envelope": json_format.MessageToDict(env)}) + "\n")
    assert main(["--offline", str(path)]) == 0
    stats = json.loads(capsys.readouterr().err.strip().splitlines()[-1])
    assert stats["processed"] == 3 and stats["evidence"]["events"] == 5


def test_example_trace_is_read_without_touching_ground_truth():
    eng = Engine(O.oparams())
    for _label, topic, env, _key in O.trace_records():
        if topic in ("findings.v0", "norm.events.v0", "source.completeness.v0", "ground.truth.v0"):
            eng.feed(env, topic)
    eng.finish()
    assert len(eng.processed) == 3 and eng.stats.get("ignored_ground_truth_action") == 1
