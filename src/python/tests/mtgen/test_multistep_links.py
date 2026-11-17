"""Multi-step link tracking (docs/plans/multistep-chain-plan.md, phase 1).

The phase 0 audit of pilot-v2 found no PRESENT link with an instance witness
in the stream. Each test pins one cause or its fix:

  1. An exec forks a child: proc.fork/proc.exec name the child, with the
     forking process as parent (benign and scenario execs alike); a startup
     exec renders in place.
  2. A scenario step may act as the process an earlier exec step started
     ("@step<N>.process"), with the key the renderer derives.
  3. Every connect has its own local endpoint and socket cookie; a transfer
     counts bytes on its connect's flow and process, and the path record
     names the same 4-tuple.
  4. A link whose witness evidence a profile dropped is UNOBSERVABLE, for
     PRESENT and ABSENT links alike.
  5. verify's link_witness check: PRESENT witnesses hold, ABSENT ones do not,
     and declared shared keys are visible.
  6. A clean build of every linked scenario passes verify with every
     catalogue PRESENT link PRESENT.
"""
import os
import subprocess
import sys
from pathlib import Path

import numpy as np
import pytest

import mtgen  # noqa: F401 — registers gen/ and spec/tools/ on sys.path
from mtgen import specs
from mtgen.activity import Activity
from mtgen.evidence import EvidenceArchive
from mtgen.ids import child_process_key, pod_init_processes
from mtgen.render.ebpf import EbpfRenderer
from mtgen.render.offnode import OffNodeRenderer
from mtgen.scenarios import ScenarioEngine
from mtgen.truth import RenderedEventInfo, TruthWriter
from mtgen.scenarios import GroundTruthRecord
from mtgen.verify import _load_truth_files, verify
from mtgen.world import World
from microtrace.v0 import dataset_pb2, witness_pb2

REPO = Path(__file__).resolve().parents[4]

LINKED_SCENARIOS = (
    "chain_token_theft_exfil,chain_container_escape,chain_implant_scan_c2,"
    "h1_external_large_egress,h2_lidds_wget_external,h2_beth_external_connect,"
    "h4_external_sensitive_exfil,h4_benign_read_connect,h4_read_without_connect,"
    "nonlink_shared_pod_no_witness,nonlink_shared_ip_no_witness,"
    "nonlink_close_timestamp_no_witness"
)


@pytest.fixture(scope="module")
def gen_spec():
    return specs.load_generator_spec()


@pytest.fixture(scope="module")
def catalogue():
    return specs.load_scenario_catalogue()


@pytest.fixture()
def world(gen_spec):
    return World("Small", gen_spec, "build:1", run_id="multistep",
                 run_duration_ns=600 * 10**9)


def _act(kind, actor, t, **params):
    return Activity(time_ns=t, kind=kind, actor_uid=actor, actor_type="Process",
                    target_uid="x", target_type="File", parameters=params)


def _pod_and_init(world):
    pod = world.pods[0]
    return pod, pod_init_processes(world.processes)[pod.uid]


# ---------------------------------------------------------------------------
# 1. Exec forks a child
# ---------------------------------------------------------------------------

def test_exec_renders_a_child_with_its_parent(world):
    pod, init = _pod_and_init(world)
    t = world.run_start_ns + 10**9
    r = EbpfRenderer(world, EvidenceArchive(archive_id="t"))
    fork, exe = r.render(_act("process_exec", pod.uid, t, executable="/usr/bin/curl"))
    init_state = r._proc_info(init)
    child_key, tgid = child_process_key(init, init_state["node_id"], init_state["boot_id"], t)
    for ne in (fork, exe):
        assert ne.ebpf.process.tgid == tgid
        assert ne.ebpf.process.start_time_ns == t
        assert ne.ebpf.parent.tgid == init_state["tgid"]
    assert exe.ebpf.exec.filename == "/usr/bin/curl"
    # The parent's own image is unchanged; the child runs curl.
    assert r._process_executable(r._proc_info(child_key)) == "/usr/bin/curl"
    assert r._process_executable(init_state) != "/usr/bin/curl"


def test_startup_exec_renders_in_place(world):
    _, init = _pod_and_init(world)
    r = EbpfRenderer(world, EvidenceArchive(archive_id="t"))
    st = r._proc_info(init)
    fork, _ = r.render(_act("process_exec", init, world.run_start_ns + 5,
                            executable="/app/server", source="startup"))
    assert fork.ebpf.process.tgid == st["tgid"]
    assert not fork.ebpf.parent.tgid


def test_grandchild_keeps_the_pod_lineage(world):
    pod, _ = _pod_and_init(world)
    t = world.run_start_ns + 10**9
    r = EbpfRenderer(world, EvidenceArchive(archive_id="t"))
    shell = r.render(_act("shell_exec", pod.uid, t, shell_binary="/bin/sh"))[1]
    child = r._fork_child(r._real_key(pod.uid), t)
    cat = r.render(_act("process_exec", child, t + 10**9, executable="/bin/cat"))[1]
    assert cat.ebpf_derived.lineage_id == shell.ebpf_derived.lineage_id
    assert cat.ebpf.lineage_root.tgid == shell.ebpf.lineage_root.tgid


# ---------------------------------------------------------------------------
# 2. Steps act as an earlier step's process
# ---------------------------------------------------------------------------

def _scenario(steps, links=()):
    return {"scenarios": [{
        "id": "t_chain", "kind": "attack", "window_s": 60,
        "roles": [{"name": "p", "kind": "internal_pod"}],
        "steps": steps, "links": list(links), "variants": [{"id": "v1"}],
    }]}


def test_step_reference_names_the_rendered_child(world):
    cat = _scenario([
        {"step": 1, "action": "shell_exec",
         "params": {"parent_process": "p", "shell_binary": "/bin/sh"}},
        {"step": 2, "action": "connect_external",
         "params": {"source_pod": "p", "source_process": "@step1.process",
                    "remote_ip": "203.0.113.45"}},
    ])
    engine = ScenarioEngine(world, cat, {"scenarios": [{"scenario_id": "t_chain"}]}, "s")
    acts, _ = engine.execute()
    r = EbpfRenderer(world, EvidenceArchive(archive_id="t"))
    exec_ne = r.render(acts[0])[1]
    conn_ne = r.render(acts[1])[0]
    assert acts[1].parameters["source_process"] == acts[0].parameters["process_key"]
    assert conn_ne.ebpf.process == exec_ne.ebpf.process


def test_unresolved_step_reference_fails(world):
    cat = _scenario([
        {"step": 1, "action": "connect_external",
         "params": {"source_pod": "p", "source_process": "@step2.process"}},
    ])
    engine = ScenarioEngine(world, cat, {"scenarios": [{"scenario_id": "t_chain"}]}, "s")
    with pytest.raises(ValueError, match="earlier step"):
        engine.execute()


def test_follows_within_places_steps_close(world):
    cat = _scenario([
        {"step": 1, "action": "read_sensitive_file", "params": {"source_process": "p"}},
        {"step": 2, "action": "file_write", "follows_within_s": 2,
         "params": {"source_process": "p", "file_path": "/tmp/x"}},
    ])
    engine = ScenarioEngine(world, cat, {"scenarios": [{"scenario_id": "t_chain"}]}, "s")
    acts, _ = engine.execute()
    assert 0 < acts[1].time_ns - acts[0].time_ns <= 2 * 10**9


# ---------------------------------------------------------------------------
# 3. Flow identity
# ---------------------------------------------------------------------------

def test_connects_get_distinct_cookies_and_pod_ip(world):
    pod, _ = _pod_and_init(world)
    r = EbpfRenderer(world, EvidenceArchive(archive_id="t"))
    cookies = set()
    for i in range(50):
        ne = r.render(_act("connect_external", pod.uid, world.run_start_ns + i * 10**6,
                           remote_ip="203.0.113.10", remote_port=443))[0]
        cookies.add(ne.ebpf.socket.flow.socket_cookie)
        assert ne.ebpf.socket.local.ip == pod.pod_ips[0]
    assert len(cookies) == 50


def test_transfer_naming_its_process_keeps_that_process_flow(world):
    # A flow twin: another process of the Pod connects to the same remote
    # later; the transfer names its own process and stays on its flow.
    pod, _ = _pod_and_init(world)
    t = world.run_start_ns + 10**9
    r = EbpfRenderer(world, EvidenceArchive(archive_id="t"))
    child = r._fork_child(r._real_key(pod.uid), t)

    def connect(proc, dt):
        return r.render(Activity(time_ns=t + dt, kind="connect_external", actor_uid=pod.uid,
                                 actor_type="Pod", target_uid="203.0.113.10", target_type="Endpoint",
                                 parameters={"source_pod": pod.uid, "source_process": proc,
                                             "remote_ip": "203.0.113.10"}))[0]

    mine, other = connect(child, 1), connect(pod.uid, 2)
    fb = r.render(Activity(time_ns=t + 3, kind="egress_transfer", actor_uid=pod.uid,
                           actor_type="Pod", target_uid="203.0.113.10", target_type="Endpoint",
                           parameters={"source_pod": pod.uid, "source_process": child,
                                       "destination": "203.0.113.10", "bytes_out": 10}))[0]
    assert fb.ebpf.flow_counter.flow == mine.ebpf.socket.flow
    assert fb.ebpf.flow_counter.flow != other.ebpf.socket.flow


def test_peer_pod_is_another_replica_of_the_same_service(world):
    cat = {"scenarios": [{
        "id": "t_peer", "kind": "attack", "window_s": 60,
        "roles": [{"name": "p", "kind": "internal_pod"},
                  {"name": "q", "kind": "peer_pod", "of": "p"}],
        "steps": [], "links": [], "variants": [{"id": "v1"}],
    }]}
    engine = ScenarioEngine(world, cat, {"scenarios": []}, "s")
    pods = {p.uid: p for p in world.pods}
    rng = engine._streams.get("t")
    for _ in range(50):
        b = engine._bind_roles(cat["scenarios"][0], world.run_start_ns + 10**9, rng)
        p, q = pods[b["p"]["uid"]], pods[b["q"]["uid"]]
        assert p.uid != q.uid
        assert p.service_name == q.service_name and p.service_account == q.service_account


def test_role_namespace_reference_resolves(world):
    cat = _scenario([{"step": 1, "action": "api_request",
                      "params": {"principal": "p", "verb": "list", "resource": "pods",
                                 "namespace": "p.namespace"}}])
    acts, _ = ScenarioEngine(world, cat, {"scenarios": [{"scenario_id": "t_chain"}]}, "s").execute()
    pod = next(p for p in world.pods if p.uid == acts[0].parameters["principal"])
    assert acts[0].parameters["namespace"] == pod.namespace


def test_transfer_counts_bytes_on_its_connect(world):
    pod, _ = _pod_and_init(world)
    t = world.run_start_ns + 10**9
    r = EbpfRenderer(world, EvidenceArchive(archive_id="t"))
    child = r._fork_child(r._real_key(pod.uid), t)
    conn = r.render(Activity(time_ns=t + 1, kind="connect_external", actor_uid=pod.uid,
                             actor_type="Pod", target_uid="203.0.113.45", target_type="Endpoint",
                             parameters={"source_pod": pod.uid, "source_process": child,
                                         "remote_ip": "203.0.113.45"}))[0]
    xfer = Activity(time_ns=t + 2, kind="egress_transfer", actor_uid=pod.uid,
                    actor_type="Pod", target_uid="203.0.113.45", target_type="Endpoint",
                    parameters={"destination": "203.0.113.45", "bytes_out": 10})
    fb = r.render(xfer)[0]
    assert fb.ebpf.flow_counter.flow == conn.ebpf.socket.flow
    assert fb.ebpf.flow_counter.flow.socket_cookie != 0
    assert fb.ebpf.process == conn.ebpf.process
    path = OffNodeRenderer(world.history).render(xfer)[0]
    assert path.path_flow.src.port == conn.ebpf.socket.local.port
    assert path.path_flow.src.ip == conn.ebpf.socket.local.ip


def test_a_scenario_transfer_keeps_its_connect_when_background_traffic_intervenes(world):
    # B9 verify: a background connect of the same Pod to the same remote
    # between a scenario's connect and its transfer took the flow, and the
    # PRESENT same-socket continuity link lost its witness.
    pod, _ = _pod_and_init(world)
    t = world.run_start_ns + 10**9
    r = EbpfRenderer(world, EvidenceArchive(archive_id="t"))

    def connect(when, scenario):
        a = Activity(time_ns=when, kind="connect_external", actor_uid=pod.uid, actor_type="Pod",
                     target_uid="203.0.113.10", target_type="Endpoint",
                     parameters={"source_pod": pod.uid, "source_process": pod.uid, "remote_ip": "203.0.113.10"})
        a.action_seq = 7 if scenario else None
        return r.render(a)[0]
    mine = connect(t + 1, scenario=True)
    other = connect(t + 2, scenario=False)                          # background, same Pod and remote
    xfer = Activity(time_ns=t + 3, kind="egress_transfer", actor_uid=pod.uid, actor_type="Pod",
                    target_uid="203.0.113.10", target_type="Endpoint",
                    parameters={"source_pod": pod.uid, "source_process": pod.uid,
                                "destination": "203.0.113.10", "bytes_out": 10})
    xfer.action_seq = 8
    fb = r.render(xfer)[0]
    assert mine.ebpf.socket.flow != other.ebpf.socket.flow
    assert fb.ebpf.flow_counter.flow == mine.ebpf.socket.flow


# ---------------------------------------------------------------------------
# 4. Link labels under dropped evidence
# ---------------------------------------------------------------------------

def _link_truth(expected, dropped):
    cat = _scenario([
        {"step": 1, "action": "shell_exec", "params": {"parent_process": "p"}},
        {"step": 2, "action": "connect_external", "params": {"source_pod": "p"}},
    ], links=[{"from": 1, "to": 2, "witness": "PROCESS_ANCESTRY", "expected": expected}])
    writer = TruthWriter("r1", specs.load_evidence_rendering(), cat)
    recs = [GroundTruthRecord(run_id="r1", action_seq=i, scenario_id="t_chain",
                              variant_id="v1", step_label=str(i), is_attack=True)
            for i in (1, 2)]
    infos = {1: [RenderedEventInfo("e1", "ebpf", "proc.exec")],
             2: [RenderedEventInfo("e2", "ebpf", "net.connect")]}
    lost = {2: [RenderedEventInfo("e3", "ebpf", "proc.fork")]} if dropped else {}
    return writer.write(recs, infos, dropped_by_seq=lost).links[0]


@pytest.mark.parametrize("expected", ["PRESENT", "ABSENT"])
def test_link_with_dropped_witness_evidence_is_unobservable(expected):
    assert _link_truth(expected, dropped=False).expected_state == getattr(dataset_pb2, expected)
    assert _link_truth(expected, dropped=True).expected_state == dataset_pb2.UNOBSERVABLE


def test_declared_unobservable_link_is_kept():
    assert _link_truth("UNOBSERVABLE", dropped=False).expected_state == dataset_pb2.UNOBSERVABLE


# ---------------------------------------------------------------------------
# 5-6. Clean build of every linked scenario
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def linked_run(tmp_path_factory):
    out = tmp_path_factory.mktemp("multistep") / "run"
    env = dict(os.environ, PYTHONHASHSEED="1", SOURCE_DATE_EPOCH="0",
               PYTHONPATH=str(REPO / "src" / "python"))
    proc = subprocess.run(
        [sys.executable, "-m", "mtgen", "build", "--world", "Small",
         "--shape", "clean", "--scenarios", LINKED_SCENARIOS,
         "--seed", "11", "--duration-s", "1500", "--out", str(out)],
        env=env, capture_output=True, text=True, cwd=str(REPO),
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    for warning in ("truth consistency errors", "downgraded in a clean run",
                    "did not fit"):
        assert warning not in proc.stderr, proc.stderr[-2000:]
    return out


def test_linked_scenarios_pass_every_verify_check(linked_run):
    result = verify(linked_run)
    failed = {c.name: c.failures[:3] for c in result.checks if not c.ok}
    assert result.ok, f"verify failed: {failed}"
    assert any(c.name == "link_witness" and c.checked >= 20 for c in result.checks)


def test_clean_links_keep_their_catalogue_label(linked_run, catalogue):
    actions, _, links = _load_truth_files(linked_run)
    by_seq = {a.action_seq: a for a in actions}
    declared = {
        (s["id"], str(lk["from"]), str(lk["to"])): lk.get("expected", "PRESENT")
        for s in catalogue["scenarios"] for lk in s.get("links", [])
    }
    witnesses = set()
    for lk in links:
        a, b = by_seq[lk.from_action_seq], by_seq[lk.to_action_seq]
        want = declared[(a.scenario_id, a.step_label, b.step_label)]
        if any(k in lk.reason for k in ("declared gap", "node-trust epoch")):
            # an end near a degraded scenario's own lost step (B0c) or after
            # an escape's node-trust epoch (D-23)
            assert lk.expected_state == dataset_pb2.UNOBSERVABLE
            continue
        assert dataset_pb2.TruthExpectation.Name(lk.expected_state) == want
        if lk.expected_state == dataset_pb2.PRESENT:
            witnesses.add(witness_pb2.WitnessType.Name(lk.witness_type))
    # Credential links are UNOBSERVABLE until the read can be joined to its
    # token instance (link-work-remaining-plan.md D-9).
    assert {"PROCESS_ANCESTRY", "NETWORK_FLOW"} <= witnesses


def test_roles_bind_to_distinct_pods(world):
    # Two Pod roles are two Pods: in pilot-multistep a nonlink's two "different"
    # roles drew one Pod, and its absent link showed in the stream.
    cat = {"scenarios": [{
        "id": "t_pair", "kind": "nonlink", "window_s": 60,
        "roles": [{"name": f"p{i}", "kind": "internal_pod"} for i in range(6)],
        "steps": [], "links": [], "variants": [{"id": "v1"}],
    }]}
    engine = ScenarioEngine(world, cat, {"scenarios": []}, "s")
    rng = engine._streams.get("t")
    for _ in range(200):
        binding = engine._bind_roles(cat["scenarios"][0], world.run_start_ns + 10**9, rng)
        uids = [b["uid"] for b in binding.values()]
        assert len(set(uids)) == len(uids)


def _chain_truth(dropped):
    """shell (1) -> curl exec (2) -> token read (3) -> connect by curl (5),
    with a decoy exec (4) in the Pod between the endpoints."""
    cat = _scenario([
        {"step": 1, "action": "shell_exec", "params": {"parent_process": "p"}},
        {"step": 2, "action": "process_exec", "params": {"parent_process": "@step1.process"}},
        {"step": 3, "action": "read_token_file", "params": {"reader_process": "p"}},
        {"step": 4, "action": "process_exec", "params": {"parent_process": "p"}},
        {"step": 5, "action": "connect_external",
         "params": {"source_pod": "p", "source_process": "@step2.process"}},
    ], links=[{"from": 1, "to": 5, "witness": "PROCESS_ANCESTRY", "expected": "PRESENT"}])
    writer = TruthWriter("r1", specs.load_evidence_rendering(), cat)
    recs = [GroundTruthRecord(run_id="r1", action_seq=i, scenario_id="t_chain",
                              variant_id="v1", step_label=str(i), is_attack=True)
            for i in (1, 2, 3, 4, 5)]
    kept = {1: [RenderedEventInfo("e1", "ebpf", "proc.exec")],
            2: [RenderedEventInfo("e2", "ebpf", "proc.exec")],
            3: [RenderedEventInfo("e3", "ebpf", "file.read")],
            4: [RenderedEventInfo("e4", "ebpf", "proc.exec")],
            5: [RenderedEventInfo("e5", "ebpf", "net.connect")]}
    for seq, fam in dropped:
        kept[seq] = [k for k in kept[seq] if k.family != fam]
    lost = {seq: [RenderedEventInfo(f"d{seq}", "ebpf", fam)] for seq, fam in dropped}
    return writer.write(recs, kept, own_dropped_by_seq=lost).links[0].expected_state


def test_link_survives_a_lost_fork_whose_exec_was_kept():
    assert _chain_truth([(1, "proc.fork")]) == dataset_pb2.PRESENT


def test_link_survives_an_unrelated_lost_step_between_its_endpoints():
    assert _chain_truth([(3, "file.read")]) == dataset_pb2.PRESENT


def test_link_through_a_lost_exec_is_unobservable():
    assert _chain_truth([(2, "proc.exec")]) == dataset_pb2.UNOBSERVABLE


def test_link_survives_a_lost_decoy_exec_between_its_endpoints():
    # A floating decoy can sit between the endpoints; its exec is not on the
    # connect's ancestry path.
    assert _chain_truth([(4, "proc.exec")]) == dataset_pb2.PRESENT


# ---------------------------------------------------------------------------
# 7. Placement: random ordered times, floating decoy groups
#    (docs/plans/link-twin-decoys-plan.md, phase A)
# ---------------------------------------------------------------------------

def _engine(world, steps, links=()):
    return ScenarioEngine(world, _scenario(steps, links),
                          {"scenarios": [{"scenario_id": "t_chain"}]}, "s")


def test_placement_is_ordered_inside_the_window_and_two_seconds_apart(world):
    engine = _engine(world, [])
    steps = [{"step": i} for i in range(1, 9)] + [{"step": 9, "follows_within_s": 3}]
    start, end = 10**12, 10**12 + 60 * 10**9
    gaps_1_7 = set()
    for seed in range(50):
        rng = np.random.default_rng(seed)
        placed = engine._place_steps(steps, start, end, rng)
        times = [t for _, t in placed]
        assert [s["step"] for s, _ in placed] == list(range(1, 10))
        assert all(start <= t < end for t in times)
        assert all(b - a >= 2 * 10**9 for a, b in zip(times[:7], times[1:8]))
        assert 0 < times[8] - times[7] <= 3 * 10**9
        gaps_1_7.add(round((times[6] - times[0]) / 10**9))
    # The gap between two steps is not fixed by their step numbers.
    assert max(gaps_1_7) - min(gaps_1_7) >= 10


def _float_steps():
    return [
        {"step": 1, "action": "shell_exec", "params": {"parent_process": "p"}},
        {"step": 2, "action": "process_exec", "params": {"parent_process": "@step1.process"}},
        {"step": 3, "action": "connect_external",
         "params": {"source_pod": "p", "source_process": "@step2.process"}},
        {"step": 4, "action": "egress_transfer", "follows_within_s": 5,
         "params": {"source_pod": "p"}},
        {"step": 5, "action": "process_exec", "float": "decoy",
         "params": {"parent_process": "p"}},
        {"step": 6, "action": "connect_external", "float": "decoy",
         "params": {"source_pod": "p", "source_process": "@step5.process"}},
    ]


_FLOAT_LINKS = [{"from": 1, "to": 6, "witness": "PROCESS_ANCESTRY", "expected": "ABSENT"}]


def test_floating_group_keeps_its_order_and_its_constraints(world):
    engine = _engine(world, [])
    orders = set()
    for seed in range(200):
        order = [s["step"] for s in engine._float_groups(
            _float_steps(), _FLOAT_LINKS, np.random.default_rng(seed))]
        pos = {n: i for i, n in enumerate(order)}
        assert [n for n in order if n <= 4] == [1, 2, 3, 4]
        assert pos[5] < pos[6]            # group order
        assert pos[1] < pos[6]            # after the source of the link into it
        assert pos[4] == pos[3] + 1       # never between a step and its follower
        orders.add(tuple(order))
    # The decoy action lands before and after each real step after step 1
    # (real steps before it: 1, 2, or all 4, never between 3 and its follower).
    assert {sum(n <= 4 for n in o[:o.index(6)]) for o in orders} == {1, 2, 4}
    assert any(o.index(5) == 0 for o in orders)


def test_references_into_a_floating_group_resolve(world):
    acts, recs = _engine(world, _float_steps(), _FLOAT_LINKS).execute()
    by_label = {r.step_label: a for r, a in zip(recs, acts)}
    assert (by_label["6"].parameters["source_process"]
            == by_label["5"].parameters["process_key"])
    assert sorted(r.step_label for r in recs) == ["1", "2", "3", "4", "5", "6"]


def test_floating_step_with_no_room_fails(world):
    steps = _float_steps()
    steps[4]["params"]["parent_process"] = "@step6.process"
    with pytest.raises(ValueError):
        _engine(world, steps, _FLOAT_LINKS).execute()


# ---------------------------------------------------------------------------
# 8. Twins and variants (docs/plans/link-twin-decoys-plan.md, phases B-C)
# ---------------------------------------------------------------------------

_CHECKED = {"PROCESS_ANCESTRY", "NETWORK_FLOW", "REQUEST_IDENTITY", "CREDENTIAL_READ_TO_USE"}


def test_every_scored_link_pattern_has_both_labels(catalogue):
    # A (witness, from kind, to kind) pair with one label lets the endpoint
    # kinds stand in for the witness: pilot-multistep's link nuisance AUC 1.0.
    # Only links the GO is asked to decide count: a PRESENT finding at both
    # ends (D-20, exp2-gaps-plan B0a), as in link_nuisance.py.
    labels = {}
    for s in catalogue["scenarios"]:
        kinds = {st["step"]: st["action"] for st in s["steps"]}
        found = {st["step"] for st in s["steps"]
                 if any(e.get("state") == "PRESENT" for e in st.get("expects") or [])}
        for lk in s.get("links", []):
            if (lk["witness"] not in _CHECKED
                    or lk["from"] not in found or lk["to"] not in found
                    or lk.get("reason", "").startswith(("same-process continuity",
                                                        "same-socket continuity",
                                                        "benign continuity"))
                    or lk.get("expected", "PRESENT") == "UNOBSERVABLE"):
                continue
            key = (lk["witness"], kinds[lk["from"]], kinds[lk["to"]])
            labels.setdefault(key, set()).add(lk.get("expected", "PRESENT"))
    lpb = _pair_balance()
    one_label = {k: v for k, v in labels.items() if len(v) < 2 and k[1:] not in lpb.KNOWN_UNBALANCED}
    assert not one_label, one_label


def _pair_balance():
    import importlib.util
    path = REPO / "src" / "scripts" / "pilot" / "link_pair_balance.py"
    spec = importlib.util.spec_from_file_location("link_pair_balance", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_pair_balance_counts_scored_links_per_matrix_run():
    # Continuity, UNOBSERVABLE and links without a PRESENT finding at an end
    # are not scored; the rest count once per run of their scenario.
    lpb = _pair_balance()
    found = [{"finding": "H2", "state": "PRESENT"}]
    cat = {"scenarios": [{"id": "s", "steps": [
        {"step": 1, "action": "connect_external", "expects": found},
        {"step": 2, "action": "connect_external", "expects": found},
        {"step": 3, "action": "connect_external", "expects": found},
        {"step": 4, "action": "process_exec"}],
        "links": [
            {"from": 1, "to": 2, "witness": "PROCESS_ANCESTRY", "expected": "PRESENT"},
            {"from": 3, "to": 2, "witness": "PROCESS_ANCESTRY", "expected": "ABSENT"},
            {"from": 1, "to": 3, "witness": "PROCESS_ANCESTRY", "expected": "PRESENT",
             "reason": "same-process continuity: one process"},
            {"from": 3, "to": 1, "witness": "PROCESS_ANCESTRY", "expected": "UNOBSERVABLE"},
            {"from": 4, "to": 2, "witness": "PROCESS_ANCESTRY", "expected": "ABSENT"}]}]}
    matrix = {"runs": [{"scenario_id": "s,other"}, {"scenario_id": "s"}, {"scenario_id": "other"}]}
    pairs, _ = lpb.balance(cat, lpb.matrix_runs(matrix))
    assert dict(pairs) == {("connect_external", "connect_external"): [2.0, 2.0]}


def test_scored_kind_pairs_are_balanced_over_the_pilot_matrix(catalogue):
    # pilot-multistep link nuisance AUC 0.708 (B9): the endpoint kinds of a
    # scored link predicted its label (connect_external -> connect_external
    # 75 % PRESENT). Every pair with 10 links or more stays within 30-70 %
    # PRESENT over the matrix's runs (b9b-link-nuisance-plan.md step 3).
    import yaml
    lpb = _pair_balance()
    matrix = yaml.safe_load((REPO / "spec/generator/run-matrix.pilot-multistep.yaml")
                            .read_text(encoding="utf-8"))
    pairs, _ = lpb.balance(catalogue, lpb.matrix_runs(matrix))
    out = {k: (p, a) for k, (p, a) in pairs.items()
           if p + a >= 10 and not 0.3 <= p / (p + a) <= 0.7 and k not in lpb.KNOWN_UNBALANCED}
    assert not out, out


def test_every_decoy_group_carries_a_present_finding(catalogue):
    # A floating decoy in an attack is benign. Its decisive step fires a real
    # lookalike (PRESENT) whose link to the chain is ABSENT, so the GO is
    # asked about the decoy (B0b). An earlier step of the group may carry an
    # ABSENT negative control (a non-executable write before the chmod, review
    # fix A, 2026-10-28), but a group with no PRESENT finding never reaches the GO.
    for s in catalogue["scenarios"]:
        if s.get("kind") != "attack":
            continue
        groups = {}
        for st in s["steps"]:
            if st.get("float") and st.get("benign") and st.get("expects"):
                groups.setdefault(st["float"], set()).update(e.get("state") for e in st["expects"])
        for name, states in groups.items():
            assert "PRESENT" in states, (s["id"], name)


def _build(tmp, *extra):
    env = dict(os.environ, PYTHONHASHSEED="1", SOURCE_DATE_EPOCH="0",
               PYTHONPATH=str(REPO / "src" / "python"))
    proc = subprocess.run([sys.executable, "-m", "mtgen", *extra], env=env,
                          capture_output=True, text=True, cwd=str(REPO))
    assert proc.returncode == 0, proc.stderr[-2000:]
    return proc


def test_variants_option_runs_the_variant_and_rebuilds_from_manifest(tmp_path):
    import json
    args = ["--world", "Small", "--shape", "clean", "--scenarios", "h1_external_large_egress",
            "--seed", "3", "--duration-s", "120"]
    _build(tmp_path, "build", *args, "--out", str(tmp_path / "v1"))
    _build(tmp_path, "build", *args, "--variants", "h1_external_large_egress=v2",
           "--out", str(tmp_path / "v2"))
    m1 = json.loads((tmp_path / "v1" / "manifest.json").read_text(encoding="utf-8"))
    m2 = json.loads((tmp_path / "v2" / "manifest.json").read_text(encoding="utf-8"))
    assert m2["variant_per_scenario"] == {"h1_external_large_egress": "v2"}
    assert m1["run_id"] != m2["run_id"]
    actions, _, _ = _load_truth_files(tmp_path / "v2")
    assert {a.variant_id for a in actions} == {"v2"}
    _build(tmp_path, "from-manifest", str(tmp_path / "v2"), "--out", str(tmp_path / "re"))
    assert ((tmp_path / "re" / "base.pb").read_bytes()
            == (tmp_path / "v2" / "base.pb").read_bytes())


def test_unknown_variant_fails(tmp_path):
    env = dict(os.environ, PYTHONPATH=str(REPO / "src" / "python"))
    proc = subprocess.run(
        [sys.executable, "-m", "mtgen", "build", "--scenarios", "h1_external_large_egress",
         "--variants", "h1_external_large_egress=v9", "--duration-s", "60",
         "--out", str(tmp_path / "x")], env=env, capture_output=True, text=True, cwd=str(REPO))
    assert proc.returncode == 2 and "no variant" in proc.stderr


def test_matrix_alternates_variants_and_keeps_v3_for_held_out(tmp_path):
    import yaml
    script = REPO / "src" / "scripts" / "pilot" / "make_pilot_matrix.py"
    runs = {}
    for split in ("PILOT", "HELD_OUT"):
        out = tmp_path / f"{split}.yaml"
        subprocess.run([sys.executable, str(script), "--duration-s", "600", "--passes", "2",
                        "--split", split, "--out", str(out)], check=True, cwd=str(REPO))
        runs[split] = yaml.safe_load(out.read_text(encoding="utf-8"))["runs"]
    chosen = {split: [v for r in rs for v in filter(None, r.get("scenario_variants", "").split(","))]
              for split, rs in runs.items()}
    assert any(v.endswith("=v2") for v in chosen["PILOT"])
    assert not any(v.endswith("=v3") for v in chosen["PILOT"])
    assert "chain_token_theft_exfil=v3" in chosen["HELD_OUT"]
    # Splits never share a seed (a shared seed repeats the background).
    seeds = {split: {r["seed_generator"] for r in rs} for split, rs in runs.items()}
    assert not seeds["PILOT"] & seeds["HELD_OUT"]
    # The matrix names the run_id the build derives (variants included).
    sys.path.insert(0, str(script.parent))
    import make_pilot_matrix as mpm
    r = next(r for r in runs["PILOT"] if r.get("scenario_variants"))
    assert r["run_id"] == mpm.run_id(r["world_name"], r["observability_profile"],
                                     r["scenario_id"].split(","), "PILOT", r["seed_generator"],
                                     r["duration_s"], r["scenario_variants"])


def test_twin_link_matches_the_gap_of_its_real_link(world):
    # pilot-multistep pre-check: twins placed freely had other gaps than the
    # real links of their kinds (median 23 s vs 95 s), so the gap gave the
    # label away. gap_of re-times the twin's floating endpoint.
    steps = _float_steps()
    links = [{"from": 1, "to": 6, "witness": "PROCESS_ANCESTRY", "expected": "ABSENT",
              "gap_of": [1, 3]}]
    engine = _engine(world, [])
    ratios = []
    for seed in range(40):
        rng = np.random.default_rng(seed)
        ordered = engine._float_groups(steps, links, rng)
        placed = engine._match_gaps(engine._place_steps(ordered, 0, 120 * 10**9, rng),
                                    links, 0, 120 * 10**9, rng)
        t = {s["step"]: ts for s, ts in placed}
        assert [s["step"] for s, _ in placed] == sorted(t, key=t.get)   # time order
        assert t[5] < t[6] and t[1] < t[6]                              # constraints hold
        ratios.append((t[6] - t[1]) / (t[3] - t[1]))
    assert 0.7 <= min(ratios) and max(ratios) <= 1.3


def test_gap_matching_keeps_dependencies_when_clamped_to_the_window(world):
    # A twin pushed past the window end was clamped onto the same time as the
    # step it depends on and ran first ("names no 'process' of an earlier
    # step"). Dependencies now decide the order.
    steps = _float_steps() + [
        {"step": 7, "action": "file_write", "float": "decoy",
         "params": {"writer_process": "@step5.process", "file_path": "/tmp/x"}}]
    links = [{"from": 1, "to": 5, "witness": "PROCESS_ANCESTRY", "expected": "ABSENT",
              "gap_s": [500, 600]},
             {"from": 1, "to": 7, "witness": "PROCESS_ANCESTRY", "expected": "ABSENT",
              "gap_s": [1, 2]}]
    engine = _engine(world, [])
    for seed in range(20):
        rng = np.random.default_rng(seed)
        placed = engine._match_gaps(engine._place_steps(
            engine._float_groups(steps, links, rng), 0, 60 * 10**9, rng), links, 0, 60 * 10**9, rng)
        order = [s["step"] for s, _ in placed]
        times = [t for _, t in placed]
        assert order.index(5) < order.index(6) and order.index(5) < order.index(7)
        assert times == sorted(times) and max(times) < 60 * 10**9


def test_after_step_follows_a_predecessor_moved_by_a_gap_link(world):
    # Review 2026-10-26: the after: loop placed step 3 from step 2's first
    # time; the gap_s link then moved step 2 later, and the order pass pulled
    # step 2 back onto step 3, undoing the link's gap. The after step is now
    # placed last, from its predecessor's final time.
    steps = [{"step": 1, "action": "process_exec", "params": {}},
             {"step": 2, "action": "connect_internal", "float": "decoy", "params": {}},
             {"step": 3, "action": "accept_internal", "after": {"step": 2, "gap_s": [1, 2]},
              "params": {"accept_of": "@step2.action_seq"}}]
    links = [{"from": 1, "to": 2, "witness": "PROCESS_ANCESTRY", "expected": "ABSENT",
              "gap_s": [20, 25]}]
    engine = _engine(world, [])
    for seed in range(30):
        rng = np.random.default_rng(seed)
        placed = engine._match_gaps(engine._place_steps(steps, 0, 600 * 10**9, rng),
                                    links, 0, 600 * 10**9, rng)
        t = {s["step"]: ts for s, ts in placed}
        assert 20 * 10**9 <= t[2] - t[1] <= 25 * 10**9          # the link's gap holds
        assert 1 * 10**9 <= t[3] - t[2] <= 2 * 10**9            # and the after gap
        assert [s["step"] for s, _ in placed] == sorted(t, key=t.get)


def test_from_manifest_refuses_a_changed_catalogue_unless_allowed(tmp_path):
    # Review 2026-10-26: the run_id does not hash the catalogue, so a changed
    # catalogue was rebuilt under the same run_id without a word.
    import json
    _build(tmp_path, "build", "--world", "Small", "--shape", "clean", "--scenarios",
           "h1_external_large_egress", "--seed", "3", "--duration-s", "60", "--out", str(tmp_path / "r"))
    mp = tmp_path / "r" / "manifest.json"
    m = json.loads(mp.read_text(encoding="utf-8"))
    m["scenario_catalogue_version"] = "0" * 64
    mp.write_text(json.dumps(m), encoding="utf-8")
    env = dict(os.environ, PYTHONHASHSEED="1", PYTHONPATH=str(REPO / "src" / "python"))
    proc = subprocess.run([sys.executable, "-m", "mtgen", "from-manifest", str(tmp_path / "r"),
                           "--out", str(tmp_path / "re")], env=env, capture_output=True, text=True, cwd=str(REPO))
    assert proc.returncode == 1 and "catalogue changed since the build" in proc.stderr
    proc = _build(tmp_path, "from-manifest", str(tmp_path / "r"), "--out", str(tmp_path / "re"),
                  "--allow-spec-change")
    assert "rebuilding with a changed catalogue" in proc.stdout
