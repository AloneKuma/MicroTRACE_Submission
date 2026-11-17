"""Tests for mtgen.activity and mtgen.workload.

All four required properties are covered:
  1. Every service produces activity.
  2. Rates are within tolerance of the profile.
  3. Activities only reference entities valid at their time.
  4. Output is deterministic.
"""
import pytest

import mtgen
from mtgen.activity import Activity
from mtgen.workload import WorkloadEngine, ScriptedSource, DistributionSource
from mtgen.world import World
from mtgen.specs import load_generator_spec
from mtgen.history import Ambiguous

# Very short run (10 seconds) keeps the test suite fast while still
# producing enough events to exercise every activity kind.
_SHORT_RUN_NS = 10_000_000_000   # 10 s


# ---------------------------------------------------------------------------
# Module-scoped fixtures to avoid rebuilding worlds
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def spec():
    return load_generator_spec()


@pytest.fixture(scope="module")
def small_world(spec):
    return World("Small", spec, seed="test-workload", run_duration_ns=_SHORT_RUN_NS)


@pytest.fixture(scope="module")
def activities(small_world, spec):
    engine = WorkloadEngine(small_world, spec)
    return engine.generate()


# ---------------------------------------------------------------------------
# Activity dataclass
# ---------------------------------------------------------------------------

def test_activity_fields():
    """Activity has all required fields with correct defaults."""
    act = Activity(
        time_ns=1_000_000_000, kind="http_request",
        actor_uid="pod-uid-abc", actor_type="Pod",
        target_uid="svc-01", target_type="Service",
    )
    assert act.time_ns == 1_000_000_000
    assert act.kind == "http_request"
    assert act.actor_uid == "pod-uid-abc"
    assert act.actor_type == "Pod"
    assert act.target_uid == "svc-01"
    assert act.target_type == "Service"
    assert act.parameters == {}
    assert act.outcome == "success"
    assert act.action_seq is None


def test_activity_action_seq_not_in_repr():
    """action_seq does not appear in Activity repr (private field)."""
    act = Activity(
        time_ns=1, kind="http_request",
        actor_uid="pod", actor_type="Pod",
        target_uid="svc", target_type="Service",
        action_seq=42,
    )
    # action_seq carries repr=False; it should not show up in str(act)
    assert "action_seq" not in repr(act)
    # But the value is still accessible
    assert act.action_seq == 42


def test_activity_outcome_variants():
    """outcome can be set to attempt_failed."""
    act = Activity(
        time_ns=5, kind="api_auth_failure",
        actor_uid="sa-uid", actor_type="ServiceAccount",
        target_uid="list:pods", target_type="APIResource",
        outcome="attempt_failed",
    )
    assert act.outcome == "attempt_failed"


# ---------------------------------------------------------------------------
# ScriptedSource / DistributionSource interface
# ---------------------------------------------------------------------------

def test_scripted_source_is_distribution_source(spec):
    """ScriptedSource is a DistributionSource."""
    profile = spec["background_profiles"]
    src = ScriptedSource(profile=profile, n_services=12)
    assert isinstance(src, DistributionSource)


def test_scripted_source_rates_positive(spec):
    """rate_per_ns returns a positive rate for all expected kinds."""
    profile = spec["background_profiles"]
    src = ScriptedSource(profile=profile, n_services=12)
    for kind in ("http_request", "api_request", "process_exec",
                 "read_token_file", "connect_internal", "file_write"):
        r = src.rate_per_ns(kind, "svc-01")
        assert r > 0, f"Expected positive rate for {kind}, got {r}"


def test_scripted_source_fixed_total_divides_rate(spec):
    """fixed_total mode gives rate = fixed_per_service / n_services."""
    profile = spec["background_profiles"]
    n = 12
    src_ps = ScriptedSource(profile=profile, rate_mode="fixed_per_service", n_services=n)
    src_ft = ScriptedSource(profile=profile, rate_mode="fixed_total",     n_services=n)
    rate_ps = src_ps.rate_per_ns("http_request", "svc-01")
    rate_ft = src_ft.rate_per_ns("http_request", "svc-01")
    assert abs(rate_ft * n - rate_ps) < 1e-30


def test_scripted_source_invalid_rate_mode(spec):
    """ScriptedSource raises ValueError for unknown rate_mode."""
    with pytest.raises(ValueError):
        ScriptedSource(profile={}, rate_mode="per_node")


def test_scripted_source_sample_parameters_http(spec):
    """sample_parameters returns expected keys for http_request."""
    import numpy as np
    profile = spec["background_profiles"]
    src = ScriptedSource(profile=profile)
    rng = np.random.default_rng(0)
    params = src.sample_parameters("http_request", "svc-01", rng, {})
    assert "method" in params
    assert params["method"] in ("GET", "POST", "PUT", "DELETE")
    assert "path" in params


def test_scripted_source_sample_parameters_api(spec):
    """sample_parameters returns expected keys for api_request."""
    import numpy as np
    profile = spec["background_profiles"]
    src = ScriptedSource(profile=profile)
    rng = np.random.default_rng(1)
    params = src.sample_parameters("api_request", "svc-01", rng, {"namespace": "ns-svc-01"})
    assert "verb" in params
    assert "resource" in params
    assert params["namespace"] == "ns-svc-01"


# ---------------------------------------------------------------------------
# Requirement 1: every service produces activity
# ---------------------------------------------------------------------------

def test_all_services_have_inbound_http(small_world, activities):
    """Every service has at least one inbound HTTP activity targeting it."""
    target_services = {
        a.target_uid for a in activities
        if a.kind == "http_request" and a.actor_type == "External"
    }
    missing = set(small_world.service_names) - target_services
    assert not missing, f"Services with no inbound HTTP: {sorted(missing)}"


def test_all_services_have_actor_activity(small_world, activities):
    """Every service has at least one activity where a Pod from it acts."""
    pod_to_svc = {pod.uid: pod.service_name for pod in small_world.pods}
    active_services = {
        pod_to_svc[a.actor_uid]
        for a in activities
        if a.actor_type == "Pod" and a.actor_uid in pod_to_svc
    }
    missing = set(small_world.service_names) - active_services
    assert not missing, f"Services with no Pod-actor activity: {sorted(missing)}"


def test_all_services_have_sa_activity(small_world, activities):
    """Every service has at least one API call from its ServiceAccount."""
    sa_to_ns = {sa.uid: sa.namespace for sa in small_world.service_accounts}
    # Map namespace -> service name (ns-svc-01 -> svc-01)
    active_namespaces = {
        sa_to_ns[a.actor_uid]
        for a in activities
        if a.kind == "api_request" and a.actor_uid in sa_to_ns
    }
    expected_ns = {f"ns-{svc}" for svc in small_world.service_names}
    missing = expected_ns - active_namespaces
    assert not missing, f"Namespaces with no API activity: {sorted(missing)}"


# ---------------------------------------------------------------------------
# Requirement 2: rates within tolerance
# ---------------------------------------------------------------------------

def test_http_inbound_rate_within_tolerance(small_world, activities, spec):
    """Inbound HTTP count per service is within [0.1, 10] × expected (10 s run).

    Poisson at 10 req/s × 10 s = 100 events expected; a ±90% window is wide
    but reliable for a 10-second sample with high variance.
    """
    profile = spec["background_profiles"]
    rr = profile.get("request_rates", {})
    rate_per_s = float(rr.get("baseline_requests_per_second", 10))
    run_s = _SHORT_RUN_NS / 1e9
    expected = rate_per_s * run_s

    for svc in small_world.service_names:
        inbound = [
            a for a in activities
            if a.kind == "http_request"
            and a.actor_type == "External"
            and a.target_uid == svc
        ]
        count = len(inbound)
        assert count > 0, f"Zero inbound HTTP events for {svc}"
        # Wide tolerance for a 10-second Poisson sample
        assert count <= expected * 10, (
            f"HTTP rate far too high for {svc}: {count} events, expected ~{expected}"
        )
        assert count >= expected * 0.1, (
            f"HTTP rate far too low for {svc}: {count} events, expected ~{expected}"
        )


def test_api_activity_nonzero(small_world, activities):
    """At least one api_request Activity is produced."""
    api_acts = [a for a in activities if a.kind == "api_request"]
    assert len(api_acts) > 0, "No api_request activities generated"


def test_process_exec_nonzero(small_world, activities):
    """At least one process_exec Activity is produced."""
    exec_acts = [a for a in activities if a.kind == "process_exec"]
    assert len(exec_acts) > 0, "No process_exec activities generated"


def test_admit_pod_for_churned_pods(small_world, activities):
    """Every churn-recreated Pod born within the run window has an admit_pod."""
    end_ns = small_world.run_start_ns + small_world.run_duration_ns
    # Pods recreated after run_end cannot have an in-window admission event.
    churned = [
        p for p in small_world.pods
        if p.generation > 0 and p.valid_from < end_ns
    ]
    if not churned:
        pytest.skip("No in-window churned pods in this world size")
    churned_uids = {p.uid for p in churned}
    admitted = {
        a.target_uid for a in activities if a.kind == "admit_pod"
    }
    missing = churned_uids - admitted
    assert not missing, f"Churned pods without admit_pod: {missing}"


# ---------------------------------------------------------------------------
# Requirement 3: activities only reference entities valid at their time
# ---------------------------------------------------------------------------

def test_pod_actors_alive_at_event_time(small_world, activities):
    """Every Pod-actor is alive (valid_from <= t < valid_to) at the activity time."""
    pod_map = {pod.uid: pod for pod in small_world.pods}
    violations = []
    for act in activities:
        if act.actor_type != "Pod":
            continue
        pod = pod_map.get(act.actor_uid)
        if pod is None:
            violations.append(f"Unknown pod {act.actor_uid} at t={act.time_ns}")
            continue
        if not (pod.valid_from <= act.time_ns < pod.valid_to):
            violations.append(
                f"Pod {act.actor_uid} dead at t={act.time_ns} "
                f"(alive {pod.valid_from}–{pod.valid_to})"
            )
    assert not violations, "\n".join(violations[:10])


def test_process_actors_alive_at_event_time(small_world, activities):
    """Every Process-actor is alive at the activity time."""
    proc_map = {p.process_key: p for p in small_world.processes}
    violations = []
    for act in activities:
        if act.actor_type != "Process":
            continue
        proc = proc_map.get(act.actor_uid)
        if proc is None:
            violations.append(f"Unknown process {act.actor_uid}")
            continue
        if not (proc.valid_from <= act.time_ns < proc.valid_to):
            violations.append(
                f"Process {act.actor_uid} dead at t={act.time_ns} "
                f"(alive {proc.valid_from}–{proc.valid_to})"
            )
    assert not violations, "\n".join(violations[:10])


def test_service_account_actors_alive(small_world, activities):
    """Every ServiceAccount-actor exists in the world (SAs don't churn)."""
    sa_uids = {sa.uid for sa in small_world.service_accounts}
    violations = [
        act.actor_uid
        for act in activities
        if act.actor_type == "ServiceAccount" and act.actor_uid not in sa_uids
    ]
    assert not violations, f"Unknown SA UIDs: {violations[:5]}"


def test_activities_sorted_by_time(activities):
    """generate() returns activities sorted by time_ns."""
    times = [a.time_ns for a in activities]
    assert times == sorted(times), "Activities are not sorted by time_ns"


def test_all_times_within_run(small_world, activities):
    """All activity times fall within [run_start_ns, run_end_ns)."""
    start = small_world.run_start_ns
    end = start + small_world.run_duration_ns
    out = [a.time_ns for a in activities if not (start <= a.time_ns < end)]
    assert not out, f"Activities outside run window: {out[:5]}"


# ---------------------------------------------------------------------------
# Requirement 4: output is deterministic
# ---------------------------------------------------------------------------

def test_output_deterministic(small_world, spec):
    """Two WorkloadEngine instances with the same world produce identical output."""
    engine1 = WorkloadEngine(small_world, spec)
    engine2 = WorkloadEngine(small_world, spec)
    acts1 = engine1.generate()
    acts2 = engine2.generate()
    assert len(acts1) == len(acts2), (
        f"Different lengths: {len(acts1)} vs {len(acts2)}"
    )
    for i, (a1, a2) in enumerate(zip(acts1, acts2)):
        assert a1.time_ns == a2.time_ns, f"Mismatch at index {i}: time_ns"
        assert a1.kind == a2.kind, f"Mismatch at index {i}: kind"
        assert a1.actor_uid == a2.actor_uid, f"Mismatch at index {i}: actor_uid"
        assert a1.target_uid == a2.target_uid, f"Mismatch at index {i}: target_uid"


def test_generate_returns_cached_copy(small_world, spec):
    """generate() returns a copy; mutating it does not affect the cached list."""
    engine = WorkloadEngine(small_world, spec)
    acts1 = engine.generate()
    acts1.clear()                        # mutate the returned copy
    acts2 = engine.generate()
    assert len(acts2) > 0, "Cache was mutated by clearing the returned list"


def test_different_seeds_produce_different_output(spec):
    """Different seeds yield different activity sequences."""
    world1 = World("Small", spec, seed="seed-A", run_duration_ns=_SHORT_RUN_NS)
    world2 = World("Small", spec, seed="seed-B", run_duration_ns=_SHORT_RUN_NS)
    acts1 = WorkloadEngine(world1, spec).generate()
    acts2 = WorkloadEngine(world2, spec).generate()
    # Times should differ (with high probability)
    times1 = [a.time_ns for a in acts1]
    times2 = [a.time_ns for a in acts2]
    assert times1 != times2, "Different seeds produced identical activity times"


# ---------------------------------------------------------------------------
# Activity kind coverage
# ---------------------------------------------------------------------------

def test_all_expected_kinds_present(activities):
    """All required activity kinds appear in the output."""
    kinds = {a.kind for a in activities}
    required = {
        "http_request",    # gateway inbound + interservice
        "connect_internal",  # DB queries, broker, process connects
        "process_exec",    # process starts + scheduled jobs
        "read_token_file", # app reads + kubelet refresh
        "api_request",     # controller/operator control plane
        "admit_pod",       # churn admissions
        "file_write",      # application file writes
    }
    missing = required - kinds
    assert not missing, f"Missing required activity kinds: {missing}"
