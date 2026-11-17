"""Exp. 1 telemetry ablation (decided 2026-11-15): offline --drop-source removes one of
the four security sources, declares it not shipped (rules needing it abstain), keeps the
auxiliary sources, and writes the dropped IDs as a fault log the scorer reads."""
import io
import json

import pytest

from microtrace.v0 import common_pb2, envelope_pb2, normalized_pb2, stream_pb2

from mtcore.agents.completeness import GapIndex
from mtcore.harness import offline
from mtcore.harness.score import read_fault_log

S = common_pb2.Source
PX = common_pb2.GapReason.Value("POLICY_EXCLUDED")


def norm(event_id, source):
    ne = normalized_pb2.NormalizedEvent(event_id=event_id, source=S.Value(source))
    return "norm.events.v0", envelope_pb2.Envelope(logical_id="L-" + event_id, normalized_event=ne)


def completeness(source):
    sc = stream_pb2.SourceCompleteness(source=S.Value(source),
                                       status=stream_pb2.CompletenessStatus.Value("NO_KNOWN_GAP"))
    return "source.completeness.v0", envelope_pb2.Envelope(logical_id="C-" + source, source_completeness=sc)


STREAM = [norm("e1", "EBPF"), norm("a1", "AUDIT"), norm("g1", "GATEWAY"), norm("d1", "DB_AUDIT"),
          norm("x1", "CLUSTER_CONTEXT"), completeness("AUDIT"), completeness("EBPF"), norm("a2", "AUDIT")]


def run_filter(source):
    log = io.StringIO()
    kept = list(offline.drop_filter(iter(STREAM), source, log))
    return kept, log.getvalue()


def test_drops_only_that_source_and_declares_it_first():
    kept, _ = run_filter("AUDIT")
    topic, decl = kept[0]
    assert topic == "source.completeness.v0" and decl.source_completeness.source == S.Value("AUDIT")
    assert [g.reason for g in decl.source_completeness.gaps] == [common_pb2.GapReason.Value("POLICY_EXCLUDED")]
    ids = [e.normalized_event.event_id for _, e in kept[1:] if e.HasField("normalized_event")]
    assert ids == ["e1", "g1", "d1", "x1"]                        # auxiliary DB_AUDIT, CLUSTER_CONTEXT kept
    others = [e.source_completeness.source for _, e in kept[1:] if e.HasField("source_completeness")]
    assert others == [S.Value("EBPF")]                            # the source's own accounting goes too
    assert offline.drop_filter.dropped == 3


def test_fault_log_lists_every_dropped_event_id(tmp_path):
    _, text = run_filter("AUDIT")
    path = tmp_path / "dropped.jsonl"
    path.write_text(text)
    dropped, forged = read_fault_log(str(path))
    assert dropped == {"a1", "L-a1", "a2", "L-a2"} and not forged


def test_declared_gap_makes_rules_on_that_source_abstain():
    kept, _ = run_filter("GATEWAY")
    gaps = GapIndex()
    gaps.add_source_completeness(kept[0][1].source_completeness, kept[0][1].logical_id)
    t = 1_700_000_000 * 10**9
    assert gaps.query({S.Value("GATEWAY")}, None, t, t + 10**9) == [PX]
    assert gaps.query({S.Value("GATEWAY")}, None, 1, 2) == [PX]          # whole run
    assert gaps.query({S.Value("EBPF"), S.Value("AUDIT")}, None, t, t + 10**9) == []
    gaps.observe(S.Value("EBPF"), "n1", t)                       # other sources' events never close it
    assert gaps.query({S.Value("GATEWAY")}, None, t + 5 * 10**9, t + 6 * 10**9) == [PX]


@pytest.mark.parametrize("bad", ["CLUSTER_CONTEXT", "DB_AUDIT"])     # PATH_FLOW: Exp. 3 No-OffNode (2026-11-16)
def test_auxiliary_sources_cannot_be_dropped(bad):
    with pytest.raises(SystemExit):
        offline.run("unused", io.StringIO(), None, None, drop_source=bad, fault_log=io.StringIO())


def test_cli_needs_both_flags():
    with pytest.raises(SystemExit):
        offline.main(["run", "--out", "o.jsonl", "--drop-source", "AUDIT"])
