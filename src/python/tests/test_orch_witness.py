"""Orchestrator build step 5b: witness keys, the index, Supported and TimeValid."""
import random

import agent_fixtures as F
import orch_fixtures as O
from microtrace.v0 import witness_pb2

from mtcore.orchestrator import emit
from mtcore.orchestrator.engine import Engine
from mtcore.orchestrator.keys import HOST_TRANSITION, NETWORK_FLOW, PROCESS_ANCESTRY
from mtcore.orchestrator.witness import to_witness

FND, NORM = "findings.v0", "norm.events.v0"
PA, HT, NF = PROCESS_ANCESTRY, HOST_TRANSITION, NETWORK_FLOW


def proc(t, seq, lineage="ln-1", node=None, boot=F.BOOT, host=False, unc_ms=None):
    node = node or F.NODE
    ne = F.ebpf(t, "proc.exec", lineage=lineage, node=node, boot=boot, seq=seq, host_ns_after=host)
    if unc_ms is not None:
        ne.time.clock_uncertainty_ns = int(unc_ms * 1_000_000)
    return F.done(ne)


def sock(t, op, local, remote, node=None, seq=None):
    node = node or F.NODE
    ne = F.ebpf(t, "net.connect" if op == 1 else "net.accept", node=node, seq=seq, lineage=f"ln-{node}")
    s = ne.ebpf.socket
    s.op = op
    (s.local.ip, s.local.port), (s.remote.ip, s.remote.port) = local, remote
    s.local.protocol = s.remote.protocol = 6
    return F.done(ne)


def fnd(fid, *events, t=None):
    times = [e.normalized_event.time.event_time.seconds - F.ts(0).seconds for e in events]
    return O.finding(fid, t if t is not None else min(times), inputs=[e.normalized_event.event_id for e in events])


def run(*records, oparams=None):
    """Feed normalized events (norm.events.v0) and findings in the given order."""
    eng = Engine(oparams or O.oparams())
    for env in records:
        eng.feed(env, NORM if env.HasField("normalized_event") else FND)
    eng.finish()
    return eng


def why(eng, a, b, w):
    return [d for (x, y, ww, _k), d in eng.decisions.items() if (x, y, ww) == (a, b, w)]


# --- process ancestry ----------------------------------------------------------
def test_shared_lineage_in_node_seq_order_supports_process_ancestry_one_way():
    e1, e2 = proc(1, 10), proc(5, 11)
    eng = run(e1, e2, fnd("f1", e1), fnd("f2", e2))
    assert (("f1", "f2", PA) in eng.passing()) and (("f2", "f1", PA) not in eng.passing())


def test_reversed_node_seq_is_not_this_direction_and_the_other_is_too_far_back_in_time():
    e1, e2 = proc(1, 11), proc(5, 10)               # f1's event comes later in node_seq
    eng = run(e1, e2, fnd("f1", e1), fnd("f2", e2))
    assert not eng.passing()
    [d12] = why(eng, "f1", "f2", PA)
    [d21] = why(eng, "f2", "f1", PA)
    assert not d12.supported                         # direction comes from node_seq, not time
    assert d21.supported and not d21.time_valid      # f2 -> f1 is 4 s backwards in time


def test_same_lineage_name_on_another_boot_is_another_instance():
    e1, e2 = proc(1, 10), proc(5, 11, boot="boot-2")
    eng = run(e1, e2, fnd("f1", e1), fnd("f2", e2))
    assert not eng.decisions and not eng.passing()


def test_gap_beyond_the_window_is_time_invalid():
    e1, e2 = proc(1, 10), proc(1 + 61, 11)          # W_w[process-ancestry] = 60 s
    eng = run(e1, e2, fnd("f1", e1), fnd("f2", e2))
    [d] = why(eng, "f1", "f2", PA)
    assert d.supported and not d.time_valid


def test_uncertainty_above_the_cap_is_time_invalid_unless_the_cap_is_ablated():
    e1, e2 = proc(1, 10, unc_ms=3000), proc(5, 11, unc_ms=3000)     # eps 6 s > eps_bar 5 s
    eng = run(e1, e2, fnd("f1", e1), fnd("f2", e2))
    assert not eng.passing()
    eng = run(e1, e2, fnd("f1", e1), fnd("f2", e2), oparams=O.oparams(ablations=["no_eps_cap"]))
    assert ("f1", "f2", PA) in eng.passing()


def test_small_negative_time_gap_within_uncertainty_is_valid():
    e1, e2 = proc(1.0, 10, unc_ms=1), proc(0.999, 11, unc_ms=1)  # node_seq says e1 first
    eng = run(e1, e2, fnd("f1", e1), fnd("f2", e2))
    assert ("f1", "f2", PA) in eng.passing()


def test_tightest_ordered_pair_is_tested():
    # f1 has an early and a late event; only the early one precedes f2's event.
    a, b, c = proc(1, 10), proc(100, 30), proc(30, 20)
    eng = run(a, b, c, fnd("f1", a, b, t=1), fnd("f2", c))
    [d] = why(eng, "f1", "f2", PA)
    assert (d.source_ev.id, d.target_ev.id) == (a.normalized_event.event_id, c.normalized_event.event_id)
    assert d.time_valid                              # 29 s, within W_w = 60 s


def test_a_later_ordered_pair_counts_when_the_earliest_target_is_out_of_window():
    # f1: seq 10 @0 s, seq 30 @100 s.  f2: seq 20 @65 s, seq 40 @110 s.
    # 10 -> 20 is 65 s (outside W_w = 60 s); 30 -> 40 is 10 s.
    a, b = proc(0, 10), proc(100, 30)
    c, d = proc(65, 20), proc(110, 40)
    eng = run(a, b, c, d, fnd("f1", a, b, t=0), fnd("f2", c, d, t=65))
    assert ("f1", "f2", PA) in eng.passing()
    [dec] = why(eng, "f1", "f2", PA)
    assert (dec.source_ev.id, dec.target_ev.id) == (b.normalized_event.event_id, d.normalized_event.event_id)


# --- host transition -------------------------------------------------------------
def test_lineage_continuing_into_host_namespaces_is_a_host_transition():
    e1, e2 = proc(1, 10), proc(5, 11, host=True)
    eng = run(e1, e2, fnd("f1", e1), fnd("f2", e2))
    assert {("f1", "f2", PA), ("f1", "f2", HT)} <= eng.passing()
    e2 = proc(5, 11)
    eng = run(e1, e2, fnd("f1", e1), fnd("f2", e2))
    assert ("f1", "f2", HT) not in eng.passing() and ("f1", "f2", PA) in eng.passing()


# --- network flow -----------------------------------------------------------------
CLIENT, SERVER = ("10.244.1.5", 40000), ("10.244.2.7", 8080)


def test_connect_on_one_node_and_accept_on_another_share_the_flow():
    c = sock(1, 1, CLIENT, SERVER, node="node-1")
    a = sock(1.002, 2, SERVER, CLIENT, node="node-2")
    eng = run(c, a, fnd("f1", c), fnd("f2", a))
    assert ("f1", "f2", NF) in eng.passing() and ("f2", "f1", NF) not in eng.passing()
    [d] = why(eng, "f1", "f2", NF)
    assert d.join_key == "10.244.1.5:40000->10.244.2.7:8080/6"


def test_different_port_is_a_different_connection():
    c = sock(1, 1, CLIENT, SERVER, node="node-1")
    a = sock(1.002, 2, SERVER, ("10.244.1.5", 40001), node="node-2")
    assert not run(c, a, fnd("f1", c), fnd("f2", a)).decisions


def test_accept_never_opens_a_flow_witness():
    a = sock(1, 2, SERVER, CLIENT, node="node-2")      # accept first in time
    c = sock(2, 1, CLIENT, SERVER, node="node-1")
    eng = run(a, c, fnd("f1", a), fnd("f2", c))
    assert not eng.passing()
    [d] = why(eng, "f2", "f1", NF)                    # connect -> accept, but 1 s backwards
    assert d.supported and not d.time_valid
    assert not why(eng, "f1", "f2", NF)[0].supported


# --- index ------------------------------------------------------------------------
def test_posting_is_retrieved_within_the_horizon_and_not_after():
    h = O.oparams().horizon_ns(PA) // 10**9            # 60 + 5 + 2*10 = 85 s
    e1 = proc(0, 10)
    for gap, retrieved in ((h - 1, True), (h + 1, False)):
        e2 = proc(gap, 11)
        eng = run(e1, e2, fnd("f1", e1), fnd("f2", e2))
        assert bool(why(eng, "f1", "f2", PA)) is retrieved
        assert ("f1", "f2", PA) not in eng.passing()  # beyond W_w either way


def _random_set(seed):
    rnd = random.Random(seed)
    recs, seq = [], {}
    for i in range(30):
        t = rnd.uniform(0, 300)
        node = rnd.choice(["node-1", "node-2"])
        lineage = rnd.choice(["ln-a", "ln-b", "ln-c"])
        recs.append((t, node, lineage, f"f{i:02d}"))
    out = []
    for t, node, lineage, fid in sorted(recs):
        seq[node] = seq.get(node, 0) + 1
        e = proc(t, seq[node], lineage=lineage, node=node)
        out += [e, fnd(fid, e)]
    return out


def test_no_index_search_finds_the_same_pairs_and_order_does_not_matter():
    for seed in range(5):
        recs = _random_set(seed)
        ref = run(*recs).passing()
        assert ref                                      # the fixture does form links
        assert run(*recs, oparams=O.oparams(ablations=["no_index"])).passing() == ref
        rnd = random.Random(seed)
        for _ in range(3):
            shuffled = list(recs)
            rnd.shuffle(shuffled)
            assert run(*shuffled).passing() == ref


# --- the example trace -------------------------------------------------------------
def test_example_trace_gives_w1_and_nothing_else():
    recs = O.trace_records()
    eng = Engine(O.oparams())
    for _label, topic, env, _key in recs:
        if env.HasField("normalized_event"):
            eng.feed(env, NORM)
        elif topic == FND:
            eng.feed(env, FND)
    eng.finish()
    w1 = next(env.witness for label, _t, env, _k in recs if label.startswith("W1"))
    assert eng.passing() == {(w1.source_finding_id, w1.target_finding_id, PA)}
    [d] = [d for d in eng.decisions.values() if d.passes]
    w = to_witness(d, eng.p)
    _t, _k, env = emit.witness_record(w, eng.p.version)
    got = env.witness
    for f in ("witness_id", "source_finding_id", "target_finding_id", "relationship_type", "strength_class",
              "join_key_type", "join_key", "direction_basis", "source_event_time", "target_event_time",
              "evidence_event_ids"):
        assert getattr(got, f) == getattr(w1, f), f
    assert [(k.component, k.origin, list(k.evidence_event_ids)) for k in got.key_origin] == \
        [(k.component, k.origin, list(k.evidence_event_ids)) for k in w1.key_origin]
    assert [a.parameter for a in got.applied_limits] == [a.parameter for a in w1.applied_limits]
    assert got.strength_class == witness_pb2.WitnessClass.Value("DIRECT")
