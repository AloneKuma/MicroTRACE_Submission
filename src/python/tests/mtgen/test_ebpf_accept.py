"""Server accepts and fixed-source-port reconnects
(docs/plans/exp2-conflict-origin-cases-plan.md G1, G2).

  1. The accept delay and catalogue gaps (netmodel).
  2. Under the flag ebpf_accept every successful connect to a service gets
     an accept after it; without it nothing changes.
  3. The accept renders a handler fork and a net.accept with the server side
     of the connect's tuple; the correlator's flow key joins the two.
  4. A fixed source port: each socket on the tuple has its own cookie.
  5. A scenario chain c1 -> a1 -> c2 -> a2 timed with after; an accept step's
     handler is the process the renderer forks.
  6. Truth: a port-reuse nonlink whose reusing connect is lost is UNOBSERVABLE.
  7. verify: a connect -> accept holds on the tuple, and is contradicted when
     another socket connected on the tuple before the accept.
"""
import numpy as np
import pytest

import mtgen  # noqa: F401 — registers gen/ and spec/tools/ on sys.path
from mtgen import netmodel, specs
from mtgen.activity import Activity
from mtgen.evidence import EvidenceArchive
from mtgen.ids import pod_init_processes
from mtgen.render.ebpf import EbpfRenderer
from mtgen.scenarios import GroundTruthRecord, ScenarioEngine
from mtgen.truth import RenderedEventInfo, TruthWriter
from mtgen.verify import _shares_key, link_witness_result
from mtgen.workload import EBPF_ACCEPT, WorkloadEngine
from mtgen.world import World
from mtcore.orchestrator.keys import flow_key
from microtrace.v0 import dataset_pb2, ebpf_pb2, witness_pb2

S = 10**9
NF = witness_pb2.NETWORK_FLOW


@pytest.fixture(scope="module")
def gen_spec():
    return specs.load_generator_spec()


@pytest.fixture()
def world(gen_spec):
    return World("Small", gen_spec, "build:1", run_id="accept", run_duration_ns=600 * S)


def _two_pods(world):
    init = pod_init_processes(world.processes)
    pods = [p for p in world.pods if p.uid in init and p.pod_ips]
    a = pods[0]
    b = next(p for p in pods if p.service_name != a.service_name)
    return a, b, init


def _connect(pod, target, t, **params):
    return Activity(time_ns=t, kind="connect_internal", actor_uid=pod.uid, actor_type="Pod",
                    target_uid=target, target_type="Pod",
                    parameters=dict({"target_service_or_pod": target, "target_port": 8080,
                                     "protocol": "tcp"}, **params))


def _accept(of, t, **params):
    return Activity(time_ns=t, kind="accept_internal", actor_uid="svc", actor_type="Service",
                    target_uid="x", target_type="Pod", parameters=dict({"accept_of": of}, **params))


class _Ev:
    """The orchestrator event fields flow_key reads."""
    def __init__(self, ne):
        self.ebpf = ne.ebpf


# ---------------------------------------------------------------------------
# 1. Delays
# ---------------------------------------------------------------------------

def test_accept_delay_is_mostly_fast_and_sometimes_backlogged():
    rng = np.random.default_rng(1)
    d = np.array([netmodel.accept_delay_ns(rng) for _ in range(5000)]) / 1e9
    lo, hi = netmodel.ACCEPT_DELAY_FAST_S[0], netmodel.ACCEPT_DELAY_BACKLOG_S[1]
    assert d.min() >= lo * 0.99 and d.max() <= hi * 1.01
    slow = (d > netmodel.ACCEPT_DELAY_FAST_S[1]).mean()
    assert abs(slow - netmodel.BACKLOG_SHARE) < 0.03


def test_a_range_gap_draws_as_before():
    # PILOT's gap_s links keep their draws: one uniform per link.
    a, b = np.random.default_rng(7), np.random.default_rng(7)
    lo, hi = 3e9, 25e9
    assert netmodel.gap_ns([3, 25], a) == int(lo + (hi - lo) * float(b.random()))


# ---------------------------------------------------------------------------
# 2. Workload accepts
# ---------------------------------------------------------------------------

def test_accepts_only_under_the_flag_and_one_per_service_connect(world, gen_spec):
    off = WorkloadEngine(world, gen_spec)
    acts = off.generate()
    assert off.accepts(acts) == []
    assert not any("connection_id" in a.parameters for a in acts)

    on = WorkloadEngine(world, gen_spec, flags=(EBPF_ACCEPT,))
    acts_on = on.generate()
    assert [(a.time_ns, a.kind) for a in acts_on] == [(a.time_ns, a.kind) for a in acts]
    accepts = on.accepts(acts_on)
    by_id = {a.parameters["connection_id"]: a for a in acts_on if "connection_id" in a.parameters}
    assert accepts and len(by_id) == len(accepts)
    for acc in accepts:
        conn = by_id[acc.parameters["accept_of"]]
        assert conn.kind == "connect_internal" and conn.target_type != "InfraService"
        assert acc.time_ns > conn.time_ns and acc.action_seq is None
    infra = [a for a in acts_on if a.kind == "connect_internal" and a.target_type == "InfraService"]
    assert infra and not any("connection_id" in a.parameters for a in infra)


def test_a_scenario_connect_is_accepted_in_its_action_unless_a_step_accepts_it(world, gen_spec):
    a, b, _ = _two_pods(world)
    eng = WorkloadEngine(world, gen_spec, flags=(EBPF_ACCEPT,))
    c5, c6 = _connect(a, b.uid, world.run_start_ns + S), _connect(a, b.uid, world.run_start_ns + 2 * S)
    c5.action_seq, c6.action_seq = 5, 6
    c5.unobserved = ("ebpf",)
    own = _accept("6", world.run_start_ns + 3 * S)
    own.action_seq = 7
    accepts = eng.accepts([c5, c6, own])
    assert len(accepts) == 1
    # The connect's eBPF gap is at the client; the server's accept is seen
    # (review 2026-10-26: it copied the client's unobserved sources).
    assert accepts[0].action_seq == 5 and accepts[0].unobserved == ()


def test_no_accept_at_or_after_the_run_end(world, gen_spec):
    # Review 2026-10-26: a connect just before the end got its accept up to
    # 3 s after it. The delay is still drawn, so later accepts keep theirs.
    a, b, _ = _two_pods(world)
    end = world.run_start_ns + world.run_duration_ns
    early, late = _connect(a, b.uid, world.run_start_ns + S), _connect(a, b.uid, end - 1)
    accepts = WorkloadEngine(world, gen_spec, flags=(EBPF_ACCEPT,)).accepts([early, late])
    assert [x.parameters["accept_of"] for x in accepts] == [early.parameters["connection_id"]]
    assert "connection_id" not in late.parameters
    alone = WorkloadEngine(world, gen_spec, flags=(EBPF_ACCEPT,)).accepts(
        [_connect(a, b.uid, world.run_start_ns + S)])
    assert alone[0].time_ns == accepts[0].time_ns


# ---------------------------------------------------------------------------
# 3. Rendering
# ---------------------------------------------------------------------------

def test_accept_renders_a_handler_fork_and_the_server_side_of_the_tuple(world):
    a, b, init = _two_pods(world)
    r = EbpfRenderer(world, EvidenceArchive(archive_id="t"))
    t = world.run_start_ns + 10 * S
    conn = r.render(_connect(a, b.uid, t, connection_id="auto1"))[0]
    fork, acc = r.render(_accept("auto1", t + 5_000_000))
    assert fork.ebpf.event_family == "proc.fork" and acc.ebpf.event_family == "net.accept"
    assert acc.ebpf.socket.op == ebpf_pb2.ACCEPT
    assert acc.ebpf.process == fork.ebpf.process
    assert fork.ebpf.parent.tgid and acc.ebpf_derived.pod_uid == b.uid
    assert acc.ebpf_derived.remote_pod_uid == a.uid
    assert acc.ebpf_derived.remote_class == "cluster_pod"
    so, sc = acc.ebpf.socket, conn.ebpf.socket
    assert (so.local.ip, so.local.port) == (sc.remote.ip, sc.remote.port) == (b.pod_ips[0], 8080)
    assert (so.remote.ip, so.remote.port) == (sc.local.ip, sc.local.port)
    assert so.flow != sc.flow
    kc, rc = flow_key(_Ev(conn))
    ka, ra = flow_key(_Ev(acc))
    assert kc == ka and (rc, ra) == ("source", "target")


def test_no_accept_off_a_pod_or_for_an_unknown_connection(world):
    a, _, _ = _two_pods(world)
    r = EbpfRenderer(world, EvidenceArchive(archive_id="t"))
    t = world.run_start_ns + 10 * S
    infra = sorted(world.infra)[0]
    r.render(_connect(a, infra, t, connection_id="auto1"))
    assert r.render(_accept("auto1", t + S)) == []
    assert r.render(_accept("auto9", t + S)) == []


def test_accept_of_the_wrong_server_pod_fails(world):
    a, b, _ = _two_pods(world)
    r = EbpfRenderer(world, EvidenceArchive(archive_id="t"))
    t = world.run_start_ns + 10 * S
    r.render(_connect(a, b.uid, t, connection_id="auto1"))
    with pytest.raises(ValueError, match="server_pod"):
        r.render(_accept("auto1", t + S, server_pod=a.uid))


# ---------------------------------------------------------------------------
# 4. Fixed source port
# ---------------------------------------------------------------------------

def test_fixed_source_port_reuses_the_tuple_with_a_new_socket_each_time(world):
    a, b, _ = _two_pods(world)
    r = EbpfRenderer(world, EvidenceArchive(archive_id="t"))
    t = world.run_start_ns + 10 * S
    nes = [r.render(_connect(a, b.uid, t + i * S, source_port=40000))[0] for i in range(3)]
    assert {ne.ebpf.socket.local.port for ne in nes} == {40000}
    assert len({flow_key(_Ev(ne))[0] for ne in nes}) == 1
    assert len({ne.ebpf.socket.flow.socket_cookie for ne in nes}) == 3


# ---------------------------------------------------------------------------
# 5. Scenario chain
# ---------------------------------------------------------------------------

def _reuse_scenario(n=2, extra_links=()):
    steps = []
    for i in range(n):
        c, acc = 2 * i + 1, 2 * i + 2
        conn = {"step": c, "action": "connect_internal",
                "params": {"source_pod": "client", "target_service_or_pod": "server",
                           "target_port": 8080, "protocol": "tcp", "source_port": 40000}}
        if i:
            conn["after"] = {"step": c - 1, "gap_s": "accept_delay"}
        steps.append(conn)
        steps.append({"step": acc, "action": "accept_internal",
                      "after": {"step": c, "gap_s": "accept_delay"},
                      "params": {"server_pod": "server", "source_pod": "client",
                                 "accept_of": f"@step{c}.action_seq"}})
    links = [{"from": 2 * i + 1, "to": 2 * i + 2, "witness": "NETWORK_FLOW", "expected": "PRESENT"}
             for i in range(n)]
    return {"scenarios": [{
        "id": "t_reuse", "kind": "attack", "window_s": 60,
        "roles": [{"name": "client", "kind": "internal_pod"},
                  {"name": "server", "kind": "internal_pod"}],
        "steps": steps, "links": links + list(extra_links), "variants": [{"id": "v1"}],
    }]}


def test_reconnect_chain_is_timed_by_accept_delays_and_renders_its_handlers(world):
    cat = _reuse_scenario(n=3)
    acts, _ = ScenarioEngine(world, cat, {"scenarios": [{"scenario_id": "t_reuse"}]}, "s").execute()
    acts.sort(key=lambda a: a.time_ns)
    assert [a.kind for a in acts] == ["connect_internal", "accept_internal"] * 3
    gaps = np.diff([a.time_ns for a in acts]) / 1e9
    assert (gaps > 0).all() and gaps.max() <= netmodel.ACCEPT_DELAY_BACKLOG_S[1] + 0.01
    r = EbpfRenderer(world, EvidenceArchive(archive_id="t"))
    nes = [r.render(a) for a in acts]
    connects = [n[0] for n in nes[0::2]]
    accepts = [n[1] for n in nes[1::2]]
    assert len({c.ebpf.socket.flow.socket_cookie for c in connects}) == 3
    for act, (fork, acc) in zip(acts[1::2], nes[1::2]):
        assert act.parameters["process_key"].split(":")[2] == str(acc.ebpf.process.tgid)
    assert len({flow_key(_Ev(x))[0] for x in connects + accepts}) == 1


# ---------------------------------------------------------------------------
# 6. Truth
# ---------------------------------------------------------------------------

def _cross_link_truth(dropped):
    cat = _reuse_scenario(extra_links=[{
        "from": 1, "to": 4, "witness": "NETWORK_FLOW", "expected": "ABSENT",
        "reason": "port reuse: step 3's socket connected on the tuple before the accept",
        "shared_keys": ["flow_tuple"], "contradicted_by": [3]}])
    writer = TruthWriter("r1", specs.load_evidence_rendering(), cat)
    recs = [GroundTruthRecord(run_id="r1", action_seq=i, scenario_id="t_reuse",
                              variant_id="v1", step_label=str(i), is_attack=True)
            for i in (1, 2, 3, 4)]
    fam = {1: "net.connect", 2: "net.accept", 3: "net.connect", 4: "net.accept"}
    infos = {i: [RenderedEventInfo(f"e{i}", "ebpf", f)] for i, f in fam.items() if not (dropped and i == 3)}
    lost = {3: [RenderedEventInfo("e3", "ebpf", "net.connect")]} if dropped else {}
    links = writer.write(recs, infos, dropped_by_seq=lost).links
    return next(lk for lk in links if (lk.from_action_seq, lk.to_action_seq) == (1, 4))


def test_port_reuse_nonlink_is_unobservable_without_its_reusing_connect():
    assert _cross_link_truth(dropped=False).expected_state == dataset_pb2.ABSENT
    lk = _cross_link_truth(dropped=True)
    assert lk.expected_state == dataset_pb2.UNOBSERVABLE and "dropped" in lk.reason


# ---------------------------------------------------------------------------
# 7. verify
# ---------------------------------------------------------------------------

def _keys(connects=(), accepts=()):
    from collections import defaultdict
    k = defaultdict(set)
    k["connects"] = set(connects)
    k["accepts"] = set(accepts)
    k["flow"] = {sock for _, _, sock in connects} | {("srv", "b", i) for i, _ in enumerate(accepts)}
    return k


def test_verify_joins_connect_and_accept_on_the_tuple_up_to_a_reusing_socket():
    tup = ("10.0.0.1", 40000, "10.0.0.2", 8080, 6)
    s1, s2 = ("n", "b", 1), ("n", "b", 2)
    c1, c2 = (tup, 10, s1), (tup, 20, s2)
    stream = {tup: {(10, s1), (20, s2)}}
    a1, a2 = _keys(accepts=[(tup, 11)]), _keys(accepts=[(tup, 21)])
    assert link_witness_result(NF, _keys([c1]), a1, {}, stream) == "holds"
    assert link_witness_result(NF, _keys([c2]), a2, {}, stream) == "holds"
    assert link_witness_result(NF, _keys([c1]), a2, {}, stream) == "contradicted"
    assert link_witness_result(NF, _keys([c2]), a1, {}, stream) == "none"   # accept before the connect
    other = _keys(accepts=[(("10.0.0.9", 1, "10.0.0.2", 8080, 6), 11)])
    assert link_witness_result(NF, _keys([c1]), other, {}, stream) == "none"
    assert _shares_key("flow_tuple", _keys([c1]), a2) and not _shares_key("flow_tuple", _keys([c1]), other)


def test_a_reconnect_waits_the_probe_exchange_beyond_the_clock_uncertainty():
    rng = np.random.default_rng(3)
    d = np.array([netmodel.gap_ns("reconnect_delay", rng) for _ in range(2000)]) / 1e9
    assert d.min() >= netmodel.EXCHANGE_S[0]
    k = np.array([netmodel.gap_ns("accept_delay*3", rng) for _ in range(2000)]) / 1e9
    assert k.min() >= 3 * netmodel.ACCEPT_DELAY_FAST_S[0] * 0.99


def _two_contradictor_truth(lost):
    cat = _reuse_scenario(n=3, extra_links=[{
        "from": 1, "to": 6, "witness": "NETWORK_FLOW", "expected": "ABSENT",
        "reason": "port reuse", "shared_keys": ["flow_tuple"], "contradicted_by": [3, 5]}])
    writer = TruthWriter("r1", specs.load_evidence_rendering(), cat)
    recs = [GroundTruthRecord(run_id="r1", action_seq=i, scenario_id="t_reuse",
                              variant_id="v1", step_label=str(i), is_attack=True)
            for i in range(1, 7)]
    fam = {i: "net.connect" if i % 2 else "net.accept" for i in range(1, 7)}
    infos = {i: [RenderedEventInfo(f"e{i}", "ebpf", f)] for i, f in fam.items() if i not in lost}
    dropped = {i: [RenderedEventInfo(f"e{i}", "ebpf", "net.connect")] for i in lost}
    links = writer.write(recs, infos, dropped_by_seq=dropped).links
    return next(lk for lk in links if (lk.from_action_seq, lk.to_action_seq) == (1, 6)).expected_state


def test_a_nonlink_stays_decidable_while_one_reusing_connect_is_left():
    assert _two_contradictor_truth(lost={3}) == dataset_pb2.ABSENT
    assert _two_contradictor_truth(lost={3, 5}) == dataset_pb2.UNOBSERVABLE


def test_a_gap_expression_sums_its_terms():
    a, b = np.random.default_rng(9), np.random.default_rng(9)
    total = netmodel.gap_ns("reconnect_delay*2+accept_delay", a)
    assert total == sum((netmodel.reconnect_delay_ns(b), netmodel.reconnect_delay_ns(b),
                         netmodel.accept_delay_ns(b)))
    for bad in ("accept_delay*0", "accept_delay+bogus", "reconnect_delay*x"):
        with pytest.raises(ValueError):
            netmodel.gap_ns(bad, a)


def test_verify_socket_tuple_is_the_correlators_flow_key():
    # Review 2026-10-26: verify keeps its own copy (the generator does not
    # import mtcore), so the two must not drift apart.
    from microtrace.v0 import normalized_pb2
    from mtgen.verify import _socket_tuple
    for op in (ebpf_pb2.CONNECT, ebpf_pb2.ACCEPT, ebpf_pb2.SocketOp.Value("SOCKET_OP_UNSPECIFIED")):
        for local_ip, proto_l, proto_r in (("10.0.0.1", 6, 6), ("10.0.0.1", 0, 17), ("", 6, 6)):
            ne = normalized_pb2.NormalizedEvent()
            so = ne.ebpf.socket
            so.op = op
            so.local.ip, so.local.port, so.local.protocol = local_ip, 40000, proto_l
            so.remote.ip, so.remote.port, so.remote.protocol = "10.0.0.2", 8080, proto_r
            assert _socket_tuple(so) == flow_key(_Ev(ne))[0]
