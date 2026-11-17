"""Open-ended gaps (no end time): closed by the receiver's closing record or by
the next event of the same node and source, independently of arrival order."""
import agent_fixtures as F
import test_agent_c as C
from agent_testlib import ABSTAINED, FIRED, NOT_FIRED, outcomes, params, run
from microtrace.v0 import common_pb2, envelope_pb2, stream_pb2

from mtcore.agents.completeness import GapIndex

EBPF, AUDIT, UNSPEC, CTX = (common_pb2.Source.Value(n) for n in ("EBPF", "AUDIT", "SOURCE_UNSPECIFIED",
                                                                  "CLUSTER_CONTEXT"))


def idle(start, end=None, node=F.NODE):
    """The receiver's SOURCE_IDLE record (source-less, node-scoped)."""
    sc = stream_pb2.SourceCompleteness(source=UNSPEC, scope=f"node={node}/boot={F.BOOT}",
                                       status=stream_pb2.CompletenessStatus.Value("INCOMPLETE"))
    g = sc.gaps.add(reason=common_pb2.GapReason.Value("SOURCE_IDLE"), scope="transport")
    sc.interval_start.CopyFrom(F.ts(start))
    getattr(g, "from").CopyFrom(F.ts(start))
    if end is not None:
        sc.interval_end.CopyFrom(F.ts(end))
        g.to.CopyFrom(F.ts(end))
    env = envelope_pb2.Envelope(schema_major=0, kind=envelope_pb2.RecordKind.Value("SOURCE_COMPLETENESS"),
                                logical_id=f"idle-{start}-{end}")
    env.source_completeness.CopyFrom(sc)
    return ("source.completeness.v0", env)


def index(*items, shipped=None):
    """GapIndex fed with ('gap', record) and ('ev', source, node, t) items in order."""
    gi = GapIndex(shipped)
    for it in items:
        if it[0] == "gap":
            gi.add_source_completeness(it[1][1].source_completeness, it[1][1].logical_id)
        else:
            gi.observe(it[1], it[2], F.ns(it[3]))
    return gi


def hit(gi, sources, node, t, unc=1000):
    return bool(gi.query(set(sources), {node} if node else None, F.ns(t), F.ns(t), unc))


def test_open_gap_ends_at_the_next_event_of_its_node_exclusively():
    gi = index(("gap", F.loss(5, None, source="EBPF")), ("ev", EBPF, F.NODE, 3), ("ev", EBPF, F.NODE, 20))
    assert not hit(gi, [EBPF], F.NODE, 3)        # before the gap
    assert hit(gi, [EBPF], F.NODE, 10)           # inside [5, 20)
    assert not hit(gi, [EBPF], F.NODE, 20)       # the closing event itself arrived
    assert not hit(gi, [EBPF], F.NODE, 30)


def test_event_of_another_node_does_not_end_the_gap():
    gi = index(("gap", F.loss(5, None, source="EBPF")), ("ev", EBPF, "node-2", 20))
    assert hit(gi, [EBPF], F.NODE, 25)
    assert not hit(gi, [EBPF], "node-2", 25)     # node-2 was never in the gap


def test_audit_event_does_not_end_a_source_less_idle_gap_but_ebpf_of_the_node_does():
    gi = index(("gap", idle(5)), ("ev", AUDIT, None, 10))
    assert hit(gi, [EBPF], F.NODE, 15)
    gi.observe(EBPF, F.NODE, F.ns(18))
    assert hit(gi, [EBPF], F.NODE, 15) and not hit(gi, [EBPF], F.NODE, 18)


def test_idle_node_stops_only_what_it_ships():
    shipped = {"default": {EBPF}, "cp-1": {EBPF, AUDIT}}
    gi = index(("gap", idle(5, node="node-2")), shipped=shipped)
    assert not hit(gi, [EBPF, CTX], F.NODE, 10)        # eBPF+context rule on another node
    assert hit(gi, [EBPF, CTX], "node-2", 10)          # ... on the idle node
    assert not hit(gi, [AUDIT], None, 10)              # node-2 ships no audit
    assert hit(gi, [EBPF, AUDIT], None, 10)            # eBPF nodes unknown: conservative
    gi = index(("gap", idle(5, node="cp-1")), shipped=shipped)
    assert hit(gi, [AUDIT], None, 10)                  # the audit-shipping node is idle


def test_without_a_shipped_sources_declaration_an_idle_node_covers_every_source():
    gi = index(("gap", idle(5, node="node-2")))
    assert hit(gi, [EBPF, CTX], F.NODE, 10) and hit(gi, [AUDIT], None, 10)


def test_h1_on_one_node_is_evaluated_while_another_node_is_idle():
    import test_agent_h as H
    flows = [*H.CTX, H.flow_bytes(1, 700_000), H.flow_bytes(2, 600_000, cookie=2)]
    findings, evals, _ = run(F.stream(*flows, idle(0.5, node="node-2")), ["H1"])
    assert outcomes(evals, "H1") == [FIRED] and len(findings) == 1
    _, evals, _ = run(F.stream(*flows, idle(0.5)), ["H1"])          # the flows' own node
    assert outcomes(evals, "H1") == [ABSTAINED]


def test_audit_gap_is_ended_by_the_next_audit_event():
    gi = index(("gap", F.loss(5, None, source="AUDIT")), ("ev", EBPF, F.NODE, 7), ("ev", AUDIT, None, 12))
    assert hit(gi, [AUDIT], None, 9) and not hit(gi, [AUDIT], None, 12)


def test_receiver_closing_record_ends_the_idle_gap():
    gi = index(("gap", idle(5)), ("gap", idle(5, 15)))
    assert hit(gi, [EBPF], F.NODE, 15) and not hit(gi, [EBPF], F.NODE, 16)
    assert len(gi.gaps) == 1                     # closed in place, not added


def test_end_is_the_same_whichever_arrives_first():
    gap, evs = ("gap", F.loss(5, None, source="EBPF")), [("ev", EBPF, F.NODE, t) for t in (3, 20, 40)]
    for order in ([gap, *evs], [*evs, gap], [evs[0], gap, evs[2], evs[1]]):
        gi = index(*order)
        assert [hit(gi, [EBPF], F.NODE, t) for t in (4, 6, 19, 20, 30)] == [False, True, True, False, False]


def test_pruning_keeps_the_end_it_found():
    gi = index(("gap", F.loss(5, None, source="EBPF")), ("ev", EBPF, F.NODE, 20))
    gi.prune(F.ns(21))                           # forgets event times before 21
    assert gi.gaps == []                         # the gap ended at 20: nothing left to keep
    gi = index(("gap", F.loss(5, None, source="EBPF")), ("ev", EBPF, F.NODE, 20))
    gi.prune(F.ns(19))
    assert hit(gi, [EBPF], F.NODE, 10) and not hit(gi, [EBPF], F.NODE, 20)


def test_windowed_rule_spanning_a_closed_gap_abstains_and_later_windows_do_not():
    # B1 (300 s windows): the window holding the lost interval [5, 20) abstains;
    # the next window, after the gap closed, is evaluated.
    reads = [F.audit(1 + i * 0.1, verb="list", resource=f"r{i}") for i in range(6)]
    later = [F.audit(400 + i * 0.1, verb="list", resource=f"r{i}") for i in range(6)]
    _, evals, _ = run(F.stream(*reads, F.audit(20, resource="pods"), *later,
                               F.loss(5, None, source="AUDIT")), ["B1"])
    assert outcomes(evals, "B1") == [ABSTAINED, FIRED]


def test_engine_result_is_independent_of_record_order():
    recs = F.stream(*[F.audit(1 + i * 0.1, verb="list", resource=f"r{i}") for i in range(6)],
                    F.audit(20, resource="pods"), F.loss(5, None, source="AUDIT"),
                    C.ns_change(30, after=C.CONT), C.ns_change(650, after=C.CONT, lineage="ln-7"),
                    idle(600), idle(600, 640))
    p = params()
    ref = sorted((e.evaluation_id, e.outcome) for e in run(recs, None, p)[1])
    assert any(o == ABSTAINED for _i, o in ref) and any(o in (FIRED, NOT_FIRED) for _i, o in ref)
    for order in (list(reversed(recs)), recs[3:] + recs[:3]):
        assert sorted((e.evaluation_id, e.outcome) for e in run(order, None, p)[1]) == ref


def test_closing_records_are_found_by_key_so_a_backlog_applies_in_linear_time():
    """A restarted agent applies its whole side-topic backlog at once; a
    scan of every gap per closing record made that quadratic (step 8f)."""
    import time
    gi, n = GapIndex(), 20000
    for i in range(n):
        gi.add_source_completeness(F.loss(i, None, node=f"n{i % 50}")[1].source_completeness)
    t0 = time.perf_counter()
    for i in range(n):
        gi.add_source_completeness(F.loss(i, i + 0.5, node=f"n{i % 50}")[1].source_completeness)
    took = time.perf_counter() - t0
    assert len(gi.gaps) == n and all(g.hi is not None for g in gi.gaps)
    assert took < 5, f"{n} closing records took {took:.1f} s"
    gi.prune(F.ns(n))                                  # the index is rebuilt with the gaps that remain
    assert gi.gaps == [] and not gi.open


def family_gap(start, end, families):
    """Probes not attached for some eBPF families (degraded_ebpf's whole-run gap)."""
    rec = F.loss(start, end, source="EBPF", reason="SOURCE_IDLE")
    rec[1].source_completeness.gaps[0].scope = "family=" + ",".join(families)
    return rec


def test_family_gap_covers_only_queries_reading_its_families():
    gi = index(("gap", family_gap(0, 100, ["proc.fork", "proc.ptrace"])))
    q = lambda fams: bool(gi.query({EBPF}, {F.NODE}, F.ns(10), F.ns(10), 1000, fams))  # noqa: E731
    assert not q(frozenset({"net.connect"}))       # H2 reads connects: probes for them are attached
    assert q(frozenset({"proc.exec", "proc.fork"}))  # C1b reads forks
    assert q(None)                                 # families unknown: covered, as before


def test_rule_families_are_the_rulebook_input_families():
    from agent_testlib import RULEBOOK
    from mtcore.agents.rules import ALL
    declared = {fd["id"]: {inp["family"] for inp in fd.get("inputs") or [] if inp.get("family")}
                for fd in RULEBOOK["findings"]}
    for rule in ALL:
        want = declared.get(rule.id, set())
        assert (rule.families or set()) == want, (rule.id, rule.families, want)
