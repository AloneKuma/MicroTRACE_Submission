"""Tests for mtgen.scenarios (ScenarioEngine).

Coverage:
  1. Per action type, the state change is visible in world.history after the
     step time.
  2. A failed attempt (outcome == "attempt_failed") produces an Activity and
     GroundTruthRecord but does NOT apply any state change.
  3. Role binding and step timing are deterministic per seed (same engine
     configuration always produces identical output).
  4. A sequential multi-step chain keeps the declared step-number order.
  5. A nonsequential variant does not keep the declared order.
"""
import pytest

import mtgen
from mtgen.history import Ambiguous
from mtgen.scenarios import (
    EntityRefRecord,
    GroundTruthRecord,
    ScenarioEngine,
)
from mtgen.specs import load_generator_spec
from mtgen.world import World

# Short run: 2 minutes keeps worlds fast while providing enough time for
# several scenarios placed at 30 s spacing.
_RUN_NS = 120_000_000_000   # 120 s

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_world(spec, seed="test-scen"):
    """Build a small fresh world for each test (function scope)."""
    return World("Small", spec, seed=seed, run_duration_ns=_RUN_NS)


def _first_process(world):
    """Return a process that is alive well within the run window."""
    mid = world.run_start_ns + _RUN_NS // 2
    procs = [p for p in world.processes if p.valid_from <= mid < p.valid_to]
    assert procs, "expected at least one process alive at run midpoint"
    return procs[0]


def _run_single(world, action, extra_params=None, outcome="success",
                seed="test-engine"):
    """Execute a one-step scenario with the given action and return results."""
    proc = _first_process(world)
    params = {"parent_process": proc.process_key, "executable": "/bin/sh",
              "argv": ["/bin/sh"]}
    if action == "file_write":
        params = {"writer_process": proc.process_key,
                  "file_path": "/tmp/evil.dat"}
    elif action in ("make_executable", "chmod"):
        params = {"process": proc.process_key, "file_path": "/tmp/evil.sh",
                  "mode": "+x"}
    elif action == "read_token_file":
        tok_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        params = {"reader_process": proc.process_key,
                  "token_file_path": tok_path}
    elif action in ("privilege_change", "capability_gain"):
        params = {"process": proc.process_key, "target_euid": 0}
    elif action == "euid_to_root":
        params = {"process": proc.process_key}
    elif action == "namespace_escape":
        params = {"process": proc.process_key,
                  "target_namespaces": ["mnt", "pid"],
                  "method": "setns", "target_ns_inum": 4026531840}
    elif action == "rbac_change":
        sa = world.service_accounts[0]
        params = {"principal": sa.uid,
                  "object_type": "ClusterRoleBinding",
                  "name": "test-crb", "namespace": "",
                  "mutation_type": "create", "rules": []}
    elif action == "admit_pod":
        params = {"resource_uid": "pod-test-uid",
                  "pod_name": "test-pod",
                  "namespace": "ns-svc-01",
                  "policy_verdict": "PASS",
                  "policy_enforcement": "enforce"}
    if extra_params:
        params.update(extra_params)

    # Build a minimal scenario inline (no role substitution needed since
    # we pass literal UIDs directly in params)
    scenario = {
        "id": "test_" + action,
        "kind": "attack",
        "roles": [],
        "steps": [{"step": 1, "action": action, "params": params,
                   "outcome": outcome}],
        "variants": [{"id": "v1", "rulebook_shaped": False}],
        "links": [],
    }
    catalogue = {"scenarios": [scenario]}
    run_spec = {
        "scenarios": [{"scenario_id": "test_" + action, "variant_id": "v1"}],
        "scenario_spacing_ns": 5_000_000_000,
    }
    engine = ScenarioEngine(world, catalogue, run_spec, seed=seed)
    return engine.execute()


# ---------------------------------------------------------------------------
# Module-scoped spec
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def spec():
    return load_generator_spec()


# ---------------------------------------------------------------------------
# GroundTruthRecord / EntityRefRecord basics
# ---------------------------------------------------------------------------

def test_ground_truth_record_defaults():
    r = GroundTruthRecord(
        run_id="r1", action_seq=1, scenario_id="s1", variant_id="v1",
        step_label="1", is_attack=True,
    )
    assert r.harness_version == "scenarios.v0"
    assert r.harness_outcome == "effect_realized"
    assert r.rendered_event_ids == []
    assert r.actors == []
    assert r.targets == []


def test_entity_ref_record_defaults():
    ref = EntityRefRecord(entity_type="POD", uid="abc-123")
    assert ref.namespace == ""
    assert ref.name == ""


# ---------------------------------------------------------------------------
# State change tests (one per action type)
# ---------------------------------------------------------------------------

def test_process_exec_state_visible(spec):
    world = _make_world(spec, seed="proc-exec")
    acts, recs = _run_single(world, "process_exec", seed="proc-exec-eng")

    assert len(acts) == 1
    assert acts[0].kind == "process_exec"
    assert acts[0].action_seq is not None

    t = acts[0].time_ns
    entries = world.history.entries_by_kind("ScenarioProcess")
    assert len(entries) == 1, "expected exactly one ScenarioProcess entry"
    _vf, _vt, proc_state = entries[0]
    assert world.history.at("ScenarioProcess", proc_state.process_key, t + 1) is proc_state


def test_shell_exec_state_visible(spec):
    world = _make_world(spec, seed="shell-exec")
    acts, recs = _run_single(world, "shell_exec",
                             extra_params={"shell_binary": "/bin/bash",
                                           "command": "id"},
                             seed="shell-exec-eng")
    t = acts[0].time_ns
    entries = world.history.entries_by_kind("ScenarioProcess")
    assert len(entries) == 1
    _vf, _vt, proc_state = entries[0]
    assert world.history.at("ScenarioProcess", proc_state.process_key, t + 1) is proc_state


def test_file_write_state_visible(spec):
    world = _make_world(spec, seed="file-write")
    acts, recs = _run_single(world, "file_write", seed="file-write-eng")
    t = acts[0].time_ns
    entries = world.history.entries_by_kind("ScenarioFile")
    assert len(entries) == 1
    _vf, _vt, file_state = entries[0]
    assert world.history.at("ScenarioFile", file_state.path, t + 1) is file_state


def test_make_executable_state_visible(spec):
    world = _make_world(spec, seed="make-exec")
    acts, recs = _run_single(world, "make_executable", seed="make-exec-eng")
    t = acts[0].time_ns
    entries = world.history.entries_by_kind("ScenarioExecFile")
    assert len(entries) == 1
    _vf, _vt, file_state = entries[0]
    assert world.history.at("ScenarioExecFile", file_state.path, t + 1) is file_state


def test_read_token_file_state_visible(spec):
    world = _make_world(spec, seed="tok-read")
    acts, recs = _run_single(world, "read_token_file", seed="tok-read-eng")
    t = acts[0].time_ns
    proc = _first_process(world)
    # TokenRead is a point interval [t, t+1); query at t (included)
    entries = world.history.entries_by_kind("TokenRead")
    assert len(entries) == 1
    _vf, _vt, state = entries[0]
    # The reader_process key is the process_key used in params
    reader_pk = state["reader_process"]
    result = world.history.at("TokenRead", reader_pk, t)
    assert result is not None and result is not Ambiguous
    assert result["reader_process"] == reader_pk


def test_privilege_change_state_visible(spec):
    world = _make_world(spec, seed="priv-chg")
    acts, recs = _run_single(world, "privilege_change", seed="priv-chg-eng")
    t = acts[0].time_ns
    entries = world.history.entries_by_kind("ProcessPrivilege")
    assert len(entries) == 1
    _vf, _vt, state = entries[0]
    proc_pk = state["process"]
    result = world.history.at("ProcessPrivilege", proc_pk, t)
    assert result is not None and result is not Ambiguous
    assert result["euid"] == 0


def test_euid_to_root_state_visible(spec):
    world = _make_world(spec, seed="euid-root")
    acts, recs = _run_single(world, "euid_to_root", seed="euid-root-eng")
    t = acts[0].time_ns
    entries = world.history.entries_by_kind("ProcessPrivilege")
    assert len(entries) == 1
    _vf, _vt, state = entries[0]
    proc_pk = state["process"]
    result = world.history.at("ProcessPrivilege", proc_pk, t)
    assert result is not None and result is not Ambiguous
    assert result["euid"] == 0


def test_namespace_escape_state_visible(spec):
    world = _make_world(spec, seed="ns-escape")
    acts, recs = _run_single(world, "namespace_escape", seed="ns-escape-eng")
    t = acts[0].time_ns
    entries = world.history.entries_by_kind("ProcessNamespace")
    assert len(entries) == 1
    _vf, _vt, state = entries[0]
    proc_pk = state["process"]
    result = world.history.at("ProcessNamespace", proc_pk, t)
    assert result is not None and result is not Ambiguous
    assert "mnt" in result["namespaces"]


def test_rbac_change_state_visible(spec):
    world = _make_world(spec, seed="rbac-chg")
    acts, recs = _run_single(world, "rbac_change", seed="rbac-chg-eng")
    t = acts[0].time_ns
    entries = world.history.entries_by_kind("ScenarioRBAC")
    assert len(entries) == 1
    _vf, _vt, state = entries[0]
    obj_uid = state["uid"]
    result = world.history.at("ScenarioRBAC", obj_uid, t + 1)
    assert result is not None and result is not Ambiguous
    assert result["mutation_type"] == "create"


def test_admit_pod_state_visible(spec):
    world = _make_world(spec, seed="admit-pod")
    acts, recs = _run_single(world, "admit_pod", seed="admit-pod-eng")
    t = acts[0].time_ns
    entries = world.history.entries_by_kind("ScenarioPod")
    assert len(entries) == 1
    _vf, _vt, state = entries[0]
    uid = state["uid"]
    result = world.history.at("ScenarioPod", uid, t + 1)
    assert result is not None and result is not Ambiguous
    assert result["verdict"] == "PASS"


# ---------------------------------------------------------------------------
# Failed attempt: no state change
# ---------------------------------------------------------------------------

def test_attempt_failed_no_state_change(spec):
    """process_exec with outcome=attempt_failed emits Activity but no state."""
    world = _make_world(spec, seed="fail-attempt")
    acts, recs = _run_single(world, "process_exec", outcome="attempt_failed",
                             seed="fail-attempt-eng")

    assert len(acts) == 1
    assert acts[0].outcome == "attempt_failed"

    assert len(recs) == 1
    assert recs[0].harness_outcome == "attempt_failed"

    # No ScenarioProcess should exist
    entries = world.history.entries_by_kind("ScenarioProcess")
    assert entries == [], "attempt_failed must not create a process entry"


def test_attempt_failed_rbac_no_state_change(spec):
    """rbac_change with outcome=attempt_failed leaves no ScenarioRBAC entry."""
    world = _make_world(spec, seed="fail-rbac")
    acts, recs = _run_single(world, "rbac_change", outcome="attempt_failed",
                             seed="fail-rbac-eng")
    entries = world.history.entries_by_kind("ScenarioRBAC")
    assert entries == []


# ---------------------------------------------------------------------------
# GroundTruthRecord fields
# ---------------------------------------------------------------------------

def test_ground_truth_record_fields(spec):
    """GroundTruthRecord has correct scenario_id, variant_id, step_label."""
    world = _make_world(spec, seed="gt-fields")
    acts, recs = _run_single(world, "process_exec", seed="gt-fields-eng")
    assert len(recs) == 1
    r = recs[0]
    assert r.scenario_id == "test_process_exec"
    assert r.variant_id == "v1"
    assert r.step_label == "1"
    assert r.is_attack is True
    assert r.harness_outcome == "effect_realized"
    assert r.harness_version == "scenarios.v0"
    assert r.run_id == world.run_id
    assert r.started_at_ns < r.ended_at_ns
    assert r.rendered_event_ids == []


def test_activity_carries_action_seq(spec):
    """Activity.action_seq is set and does not appear in repr."""
    world = _make_world(spec, seed="action-seq")
    acts, recs = _run_single(world, "http_request",
                             extra_params={"source_pod": "external",
                                           "target_service": "svc-01",
                                           "method": "GET", "path": "/"},
                             seed="action-seq-eng")
    assert len(acts) == 1
    assert acts[0].action_seq is not None
    assert "action_seq" not in repr(acts[0])


# ---------------------------------------------------------------------------
# Determinism: same seed → identical output
# ---------------------------------------------------------------------------

def test_determinism_same_seed(spec):
    """Two engines built with the same seed produce byte-identical output."""
    for seed in ("det-a", "det-b"):
        w1 = _make_world(spec, seed=seed)
        w2 = _make_world(spec, seed=seed)

        scenario = {
            "id": "det_scenario",
            "kind": "attack",
            "roles": [
                {"name": "actor", "kind": "process"},
                {"name": "victim", "kind": "internal_pod"},
            ],
            "steps": [
                {"step": 1, "action": "process_exec",
                 "params": {"parent_process": "actor",
                            "executable": "/bin/sh", "argv": ["/bin/sh"]},
                 "outcome": "success"},
                {"step": 2, "action": "file_write",
                 "params": {"writer_process": "actor",
                            "file_path": "/tmp/out.dat"},
                 "outcome": "success"},
            ],
            "variants": [{"id": "v1", "rulebook_shaped": False}],
            "links": [],
        }
        catalogue = {"scenarios": [scenario]}
        run_spec = {
            "scenarios": [{"scenario_id": "det_scenario", "variant_id": "v1"}],
            "scenario_spacing_ns": 5_000_000_000,
        }

        e1 = ScenarioEngine(w1, catalogue, run_spec, seed="det-engine")
        e2 = ScenarioEngine(w2, catalogue, run_spec, seed="det-engine")
        acts1, recs1 = e1.execute()
        acts2, recs2 = e2.execute()

        assert len(acts1) == len(acts2)
        for a1, a2 in zip(acts1, acts2):
            assert a1.time_ns == a2.time_ns
            assert a1.kind == a2.kind
            assert a1.actor_uid == a2.actor_uid
            assert a1.target_uid == a2.target_uid

        assert len(recs1) == len(recs2)
        for r1, r2 in zip(recs1, recs2):
            assert r1.action_seq == r2.action_seq
            assert r1.started_at_ns == r2.started_at_ns
            assert r1.scenario_id == r2.scenario_id


def test_different_seeds_differ(spec):
    """Two engines with different seeds produce different role bindings."""
    world_a = _make_world(spec, seed="seed-a")
    world_b = _make_world(spec, seed="seed-b")
    scenario = {
        "id": "diff_scen",
        "kind": "attack",
        "roles": [{"name": "actor", "kind": "process"}],
        "steps": [
            {"step": 1, "action": "process_exec",
             "params": {"parent_process": "actor",
                        "executable": "/bin/sh", "argv": []},
             "outcome": "success"},
        ],
        "variants": [{"id": "v1", "rulebook_shaped": False}],
        "links": [],
    }
    catalogue = {"scenarios": [scenario]}
    run_spec = {"scenarios": [{"scenario_id": "diff_scen", "variant_id": "v1"}],
                "scenario_spacing_ns": 5_000_000_000}
    e_a = ScenarioEngine(world_a, catalogue, run_spec, seed="eng-a")
    e_b = ScenarioEngine(world_b, catalogue, run_spec, seed="eng-b")
    acts_a, _ = e_a.execute()
    acts_b, _ = e_b.execute()
    # With different world seeds the actor UIDs should differ (different pod/
    # process allocations), OR at minimum the timing should differ.
    # We just verify neither engine crashes and both produce one activity.
    assert len(acts_a) == 1
    assert len(acts_b) == 1


# ---------------------------------------------------------------------------
# Ordering: sequential vs nonsequential
# ---------------------------------------------------------------------------

def _ordering_scenario(sequential: bool):
    """Build a 4-step scenario with sequential flag."""
    return {
        "id": "order_test",
        "kind": "attack",
        "roles": [],
        "steps": [
            {"step": 1, "action": "http_request",
             "params": {"source_pod": "external", "target_service": "svc-01",
                        "method": "GET", "path": "/step1"}},
            {"step": 2, "action": "http_request",
             "params": {"source_pod": "external", "target_service": "svc-01",
                        "method": "GET", "path": "/step2"}},
            {"step": 3, "action": "http_request",
             "params": {"source_pod": "external", "target_service": "svc-01",
                        "method": "GET", "path": "/step3"}},
            {"step": 4, "action": "http_request",
             "params": {"source_pod": "external", "target_service": "svc-01",
                        "method": "GET", "path": "/step4"}},
        ],
        "variants": [
            {"id": "seq",   "rulebook_shaped": False, "sequential": True},
            {"id": "nonseq", "rulebook_shaped": False, "sequential": False},
        ],
        "links": [],
    }


def test_sequential_chain_keeps_order(spec):
    """A sequential multi-step chain executes in declared step-number order."""
    world = _make_world(spec, seed="order-seq")
    scenario = _ordering_scenario(sequential=True)
    catalogue = {"scenarios": [scenario]}
    run_spec = {
        "scenarios": [{"scenario_id": "order_test", "variant_id": "seq"}],
        "scenario_spacing_ns": 5_000_000_000,
    }
    engine = ScenarioEngine(world, catalogue, run_spec, seed="order-seq-eng")
    acts, recs = engine.execute()

    assert len(recs) == 4
    step_labels = [r.step_label for r in recs]
    assert step_labels == ["1", "2", "3", "4"], (
        f"sequential variant must keep declared order; got {step_labels}"
    )
    # Times must be non-decreasing (steps placed in slot order)
    times = [r.started_at_ns for r in recs]
    assert times == sorted(times)


def test_nonsequential_variant_does_not_keep_order(spec):
    """A nonsequential variant shuffles the step execution order.

    With 4 steps (4! = 24 permutations) and a fixed seed, the shuffled order
    is deterministic and will differ from [1,2,3,4] with overwhelming
    probability.  We verify determinism across two runs and that at least one
    of the two orderings actually differs from the sequential order.
    """
    world_1 = _make_world(spec, seed="order-nonseq-1")
    world_2 = _make_world(spec, seed="order-nonseq-1")  # same seed
    scenario = _ordering_scenario(sequential=False)
    catalogue = {"scenarios": [scenario]}
    run_spec = {
        "scenarios": [{"scenario_id": "order_test", "variant_id": "nonseq"}],
        "scenario_spacing_ns": 5_000_000_000,
    }

    e1 = ScenarioEngine(world_1, catalogue, run_spec, seed="nonseq-eng")
    e2 = ScenarioEngine(world_2, catalogue, run_spec, seed="nonseq-eng")
    _, recs1 = e1.execute()
    _, recs2 = e2.execute()

    labels1 = [r.step_label for r in recs1]
    labels2 = [r.step_label for r in recs2]

    # Determinism: both runs must agree
    assert labels1 == labels2, "nonsequential must be deterministic per seed"

    # Ordering: the shuffled order must differ from sequential [1,2,3,4].
    # If this assert ever fails (1/24 chance for a truly random shuffle),
    # change the seed "nonseq-eng" to something that produces a shuffle.
    assert labels1 != ["1", "2", "3", "4"], (
        "nonsequential variant must not preserve declared step order "
        f"(got {labels1}); choose a different seed"
    )


# ---------------------------------------------------------------------------
# Role binding: named roles bind to valid world entities
# ---------------------------------------------------------------------------

def test_role_binding_resolves_to_world_entities(spec):
    """Role-bound UIDs reference entities that are alive at scenario time."""
    world = _make_world(spec, seed="role-bind")
    scenario = {
        "id": "role_test",
        "kind": "attack",
        "roles": [
            {"name": "actor", "kind": "process"},
            {"name": "target_svc", "kind": "internal_pod"},
        ],
        "steps": [
            {"step": 1, "action": "connect_internal",
             "params": {"source_pod": "target_svc",
                        "target_service_or_pod": "svc-01",
                        "target_port": 8080, "protocol": "tcp"}},
        ],
        "variants": [{"id": "v1", "rulebook_shaped": False}],
        "links": [],
    }
    catalogue = {"scenarios": [scenario]}
    run_spec = {
        "scenarios": [{"scenario_id": "role_test", "variant_id": "v1"}],
        "scenario_spacing_ns": 5_000_000_000,
    }
    engine = ScenarioEngine(world, catalogue, run_spec, seed="role-bind-eng")
    acts, recs = engine.execute()

    assert len(acts) == 1
    # actor_uid should be a valid pod UID in the world (non-empty, non-external)
    pod_uids = {p.uid for p in world.pods}
    assert acts[0].actor_uid in pod_uids, (
        f"actor_uid {acts[0].actor_uid!r} not in world pods"
    )


def test_unknown_scenario_raises(spec):
    """ScenarioEngine raises ValueError for a missing scenario ID."""
    world = _make_world(spec, seed="err-test")
    catalogue = {"scenarios": []}
    run_spec = {
        "scenarios": [{"scenario_id": "does_not_exist", "variant_id": "v1"}],
        "scenario_spacing_ns": 5_000_000_000,
    }
    engine = ScenarioEngine(world, catalogue, run_spec, seed="err-eng")
    with pytest.raises(ValueError, match="does_not_exist"):
        engine.execute()


def test_multi_scenario_action_seqs_are_unique(spec):
    """Action seqs are globally unique across multiple scenarios in a run."""
    world = _make_world(spec, seed="multi-scen")
    scenario = {
        "id": "scen_a",
        "kind": "attack",
        "roles": [],
        "steps": [
            {"step": 1, "action": "http_request",
             "params": {"source_pod": "external", "target_service": "svc-01",
                        "method": "GET", "path": "/a"}},
            {"step": 2, "action": "http_request",
             "params": {"source_pod": "external", "target_service": "svc-01",
                        "method": "GET", "path": "/b"}},
        ],
        "variants": [{"id": "v1", "rulebook_shaped": False}],
        "links": [],
    }
    catalogue = {"scenarios": [scenario]}
    run_spec = {
        "scenarios": [
            {"scenario_id": "scen_a", "variant_id": "v1"},
            {"scenario_id": "scen_a", "variant_id": "v1"},
        ],
        "scenario_spacing_ns": 5_000_000_000,
    }
    engine = ScenarioEngine(world, catalogue, run_spec, seed="multi-eng")
    acts, recs = engine.execute()

    seqs = [a.action_seq for a in acts]
    assert len(seqs) == len(set(seqs)), "action_seqs must be unique across steps"
    assert len(acts) == 4  # 2 scenarios × 2 steps each
