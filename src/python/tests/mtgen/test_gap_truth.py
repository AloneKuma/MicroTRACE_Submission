"""Truth and detector agree on what a declared gap hides (exp2-gaps-plan B0c).

  1. A link with an end within A + beta of a declared gap on its source and
     node, or with an eBPF gap between its ends, is UNOBSERVABLE: the
     correlator leaves it UNPROVEN (admit.distinct_action, admit.covered).
  2. A family-scoped gap (degraded_ebpf's probes not attached for some
     families) stops only rules and checks that read those families.
  3. The A and beta truth uses are the frozen orchestrator values (D-21).
"""
import pytest

import mtgen  # noqa: F401 — registers gen/ on sys.path
from mtgen import specs
from mtgen.scenarios import GroundTruthRecord
from mtgen.truth import RenderedEventInfo, TruthWriter, declared_gaps
from microtrace.v0 import common_pb2, dataset_pb2, stream_pb2

S = 10**9
TIMING = {"correlator_timing": {"A_s": 10, "beta_s": 8}}


def gap(lo_s, hi_s, node="n1", families=None):
    sc = stream_pb2.SourceCompleteness(source=common_pb2.EBPF, scope=f"node={node}")
    g = sc.gaps.add(reason=common_pb2.SOURCE_IDLE,
                    scope="family=" + ",".join(families) if families else "source=ebpf")
    getattr(g, "from").seconds, g.to.seconds = lo_s, hi_s
    return sc


def link_state(expected, *gaps, to_node="n1"):
    """exec (100 s, n1) -> connect (105 s) under PROCESS_ANCESTRY."""
    cat = {"scenarios": [{
        "id": "t_chain", "kind": "attack", "window_s": 60, "roles": [],
        "steps": [{"step": 1, "action": "shell_exec", "params": {"parent_process": "p"}},
                  {"step": 2, "action": "connect_external", "params": {"source_pod": "p"}}],
        "links": [{"from": 1, "to": 2, "witness": "PROCESS_ANCESTRY", "expected": expected}],
        "variants": [{"id": "v1"}]}]}
    writer = TruthWriter("r1", specs.load_evidence_rendering(), cat, gen_spec=TIMING)
    recs = [GroundTruthRecord(run_id="r1", action_seq=i, scenario_id="t_chain",
                              variant_id="v1", step_label=str(i), is_attack=True) for i in (1, 2)]
    infos = {1: [RenderedEventInfo("e1", "ebpf", "proc.exec", 100 * S, "n1")],
             2: [RenderedEventInfo("e2", "ebpf", "net.connect", 105 * S, to_node)]}
    return writer.write(recs, infos, list(gaps)).links[0].expected_state


@pytest.mark.parametrize("expected", ["PRESENT", "ABSENT"])
def test_a_gap_within_a_plus_beta_of_an_end_makes_the_link_unobservable(expected):
    want = getattr(dataset_pb2, expected)
    assert link_state(expected) == want
    assert link_state(expected, gap(120, 121)) == dataset_pb2.UNOBSERVABLE    # 105 + 10 + 8 >= 120
    assert link_state(expected, gap(124, 125)) == want                         # beyond A + beta
    assert link_state(expected, gap(120, 121, node="n2")) == want              # another node


def test_a_gap_between_the_ends_leaves_contradictions_uncovered():
    assert link_state("PRESENT", gap(80, 81)) == dataset_pb2.PRESENT          # 100 - 10 > 81
    assert link_state("PRESENT", gap(80, 81, node="n2"), to_node="n2") == dataset_pb2.PRESENT
    assert link_state("PRESENT", gap(102, 103, node="n2"), to_node="n2") == dataset_pb2.UNOBSERVABLE


def test_a_family_gap_counts_only_for_the_families_read():
    # Probes for forks and ptrace not attached for the whole run: an exec ->
    # connect link reads neither (its check reads exec), so it is decided.
    assert link_state("PRESENT", gap(0, 1000, families=["proc.fork", "proc.ptrace"])) == dataset_pb2.PRESENT
    assert link_state("PRESENT", gap(0, 1000, families=["proc.exec"])) == dataset_pb2.UNOBSERVABLE


def test_a_family_gap_blinds_only_rules_that_read_the_family():
    writer = TruthWriter("r1", specs.load_evidence_rendering(), {"scenarios": []})
    writer._gaps = declared_gaps([gap(0, 1000, families=["proc.fork", "proc.ptrace"])])
    ns = [RenderedEventInfo("e1", "ebpf", "ns.change", 100 * S, "n1")]
    conn = [RenderedEventInfo("e2", "ebpf", "net.connect", 100 * S, "n1")]
    assert writer._gap_blinds("C1b", ns)        # C1b reads proc.fork: the agent abstains
    assert not writer._gap_blinds("H2", conn)    # H2 reads net.connect only


def test_correlator_timing_matches_the_orchestrator():
    from mtcore.orchestrator.params import OrchParams
    t = specs.load_generator_spec()["correlator_timing"]
    p = OrchParams.load()
    assert (int(t["A_s"] * S), int(t["beta_s"] * S)) == (p.A_ns, p.beta_ns)


def test_a_link_ending_after_or_just_before_a_node_trust_epoch_is_unobservable():
    # D-23: a C1b on node n1 opens an epoch; the correlator distrusts evidence
    # received after the onset and leaves an interval ending within beta
    # before it uncovered.
    writer = TruthWriter("r1", specs.load_evidence_rendering(), {"scenarios": []}, gen_spec=TIMING)
    a = [RenderedEventInfo("e1", "ebpf", "proc.exec", 100 * S, "n1")]
    b = [RenderedEventInfo("e2", "ebpf", "net.connect", 105 * S, "n1")]
    for onset, hidden in ((120 * S, False), (112 * S, True), (104 * S, True)):
        writer._epochs = {"n1": onset}
        assert bool(writer._link_gap("PROCESS_ANCESTRY", a, b)) == hidden, onset
    writer._epochs = {"n2": 104 * S}                                       # another node
    assert not writer._link_gap("PROCESS_ANCESTRY", a, b)


def test_a_link_into_the_epoch_trigger_itself_stays_decidable():
    # D-23 narrowed (2026-10-24): the to-end holds the C1b event that opened
    # the epoch, so admit.covered does not count that epoch against the link.
    writer = TruthWriter("r1", specs.load_evidence_rendering(), {"scenarios": []}, gen_spec=TIMING)
    cap = [RenderedEventInfo("e1", "ebpf", "proc.exec", 100 * S, "n1")]
    esc = [RenderedEventInfo("e2", "ebpf", "ns.change", 110 * S, "n1")]
    shell = [RenderedEventInfo("e3", "ebpf", "proc.exec", 115 * S, "n1")]
    writer._epochs, writer._epoch_events = {"n1": 110 * S}, {"n1": {"e2"}}
    assert not writer._link_gap("PROCESS_ANCESTRY", cap, esc)           # into the escape: decidable
    assert writer._link_gap("PROCESS_ANCESTRY", esc, shell)             # after it: not trusted
    assert writer._link_gap("PROCESS_ANCESTRY", cap, shell)
    writer._epoch_events = {"n1": {"e9"}}                                # another trigger opened it
    assert writer._link_gap("PROCESS_ANCESTRY", cap, esc)


def test_the_epoch_opens_at_the_trigger_steps_own_events():
    # A C1b opportunity's evidence also cites an earlier step and standing
    # evidence from the run's start (pilot-multistep d5b31382: onset at 0 s,
    # escape at 230 s). The correlator opens the epoch at the C1b finding's
    # inputs, so truth must take the onset from the escape step alone.
    writer = TruthWriter("r1", specs.load_evidence_rendering(), {"scenarios": []}, gen_spec=TIMING)
    infos = {1: [RenderedEventInfo("e1", "ebpf", "proc.exec", 200 * S, "n1")],
             2: [RenderedEventInfo("e2", "ebpf", "ns.change", 230 * S, "n1")]}
    c1b = dataset_pb2.FindingOpportunity(action_seq=2, finding_type="C1b",
                                         expected_state=dataset_pb2.PRESENT,
                                         evidence_event_ids=["e0", "e1", "e2"])   # e0: standing, 0 s
    writer._open_epochs([c1b], infos)
    assert writer._epochs == {"n1": 230 * S} and writer._epoch_events == {"n1": {"e2"}}
    assert not writer._link_gap("PROCESS_ANCESTRY", infos[1], infos[2])        # into the escape
    c1b.expected_state = dataset_pb2.UNOBSERVABLE
    writer._open_epochs([c1b], infos)
    assert writer._epochs == {}


def test_only_a_gap_over_the_evidence_itself_blinds_a_finding():
    # Truth is what the data lost, not a detector's window: a gap 60 s after
    # the read leaves H4 and H1 observable, though the agents' windows meet it.
    writer = TruthWriter("r1", specs.load_evidence_rendering(), {"scenarios": []})
    writer._gaps = declared_gaps([gap(160, 160)])
    read = RenderedEventInfo("e1", "ebpf", "file.read", 100 * S, "n1")
    flow = RenderedEventInfo("e2", "ebpf", "net.flow_bytes", 101 * S, "n1")
    assert not writer._gap_blinds("H4", [read, flow])
    assert not writer._gap_blinds("H1", [flow])
    conn = RenderedEventInfo("e3", "ebpf", "net.connect", 159 * S, "n1")
    assert not writer._gap_blinds("H2", [conn])
    conn.time_ns = 160 * S
    assert writer._gap_blinds("H2", [conn])


def test_observer_loss_blinds_what_it_lost():
    # observer_loss loses the request body and the response, not the path
    # and query: A2 is blinded, A1 only when the payload was in the body.
    writer = TruthWriter("r1", specs.load_evidence_rendering(), {"scenarios": []})
    req = RenderedEventInfo("e1", "gateway", "", 100 * S, record_gap="SOURCE_IDLE")
    assert writer._gap_blinds("A2", [req], {"query_params": "id=1 OR 1=1"})
    assert not writer._gap_blinds("A1", [req], {"query_params": "id=1 OR 1=1"})
    assert writer._gap_blinds("A1", [req], {"body_prefix_b64": "ZXhwbG9pdA=="})
    req.record_gap = ""
    assert not writer._gap_blinds("A1", [req], {"body_prefix_b64": "ZXhwbG9pdA=="})
