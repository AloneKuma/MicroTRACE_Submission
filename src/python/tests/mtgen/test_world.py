"""Tests for mtgen.world: entity counts, reuse ambiguity, and determinism."""
import pytest

import mtgen
from mtgen.world import World
from mtgen.specs import load_generator_spec
from mtgen.history import Ambiguous


# ---------------------------------------------------------------------------
# Shared fixtures (module-scoped to avoid rebuilding worlds per test)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def spec():
    return load_generator_spec()


@pytest.fixture(scope="module")
def ref_world(spec):
    return World("Reference", spec, seed="test-ref")


@pytest.fixture(scope="module")
def small_world(spec):
    return World("Small", spec, seed="test-small")


@pytest.fixture(scope="module")
def large_world(spec):
    return World("Large", spec, seed="test-large")


# ---------------------------------------------------------------------------
# Reference world: design-table numbers
# ---------------------------------------------------------------------------

def test_reference_node_count(ref_world):
    assert len(ref_world.nodes) == 4


def test_reference_service_count(ref_world):
    assert len(ref_world.service_names) == 24


def test_reference_initial_pod_count(ref_world):
    initial = [p for p in ref_world.pods if p.generation == 0]
    assert len(initial) == 48


def test_reference_initial_container_count(ref_world):
    initial_pod_uids = {p.uid for p in ref_world.pods if p.generation == 0}
    initial_ctrs = [c for c in ref_world.containers
                    if c.pod_uid in initial_pod_uids]
    assert len(initial_ctrs) == 56


def test_reference_sidecar_count(ref_world):
    sidecars = [c for c in ref_world.containers if c.is_sidecar]
    assert len(sidecars) == 8


def test_reference_total_pod_lifetimes(ref_world):
    """All pod lifetimes (initial + replacement) must be at least 54."""
    assert len(ref_world.pods) >= 54


def test_reference_total_container_lifetimes(ref_world):
    """All container lifetimes must be at least 62."""
    assert len(ref_world.containers) >= 62


# ---------------------------------------------------------------------------
# Small world: design-table numbers
# ---------------------------------------------------------------------------

def test_small_node_count(small_world):
    assert len(small_world.nodes) == 3


def test_small_service_count(small_world):
    assert len(small_world.service_names) == 12


def test_small_initial_pod_count(small_world):
    initial = [p for p in small_world.pods if p.generation == 0]
    assert len(initial) == 24


def test_small_initial_container_count(small_world):
    initial_pod_uids = {p.uid for p in small_world.pods if p.generation == 0}
    initial_ctrs = [c for c in small_world.containers
                    if c.pod_uid in initial_pod_uids]
    assert len(initial_ctrs) == 28


# ---------------------------------------------------------------------------
# Large world: design-table numbers
# ---------------------------------------------------------------------------

def test_large_node_count(large_world):
    assert len(large_world.nodes) == 8


def test_large_service_count(large_world):
    assert len(large_world.service_names) == 50


def test_large_initial_pod_count(large_world):
    initial = [p for p in large_world.pods if p.generation == 0]
    assert len(initial) == 100


def test_large_initial_container_count(large_world):
    initial_pod_uids = {p.uid for p in large_world.pods if p.generation == 0}
    initial_ctrs = [c for c in large_world.containers
                    if c.pod_uid in initial_pod_uids]
    assert len(initial_ctrs) == 110


# ---------------------------------------------------------------------------
# Reuse: IP reuse → Ambiguous lookup
# ---------------------------------------------------------------------------

def _first_churn_pair(world):
    """Return (old_pod, new_pod) for the first churn event (churn_idx==0).

    The first replacement pod (generation=1, earliest valid_from) and the
    old pod sharing its IP.
    """
    replacements = [p for p in world.pods if p.generation == 1]
    assert replacements, "No replacement pods — world has no churn"
    new_pod = min(replacements, key=lambda p: p.valid_from)
    ip = new_pod.pod_ips[0]
    old_pods = [p for p in world.pods
                if ip in p.pod_ips and p.uid != new_pod.uid]
    assert old_pods, "Old pod with the reused IP not found"
    return old_pods[0], new_pod


def test_ip_reuse_ambiguity(ref_world):
    """At the IP reuse boundary the history lookup returns Ambiguous."""
    history = ref_world.history
    old_pod, new_pod = _first_churn_pair(ref_world)
    ip = new_pod.pod_ips[0]

    # Ambiguity window: new pod observed (obs_from) before old pod deleted
    # from the watcher's perspective (obs_to = valid_to + 60s large lag).
    t_obs_new_from = new_pod.valid_from + 50_000_000        # 50 ms create lag
    t_obs_old_to   = old_pod.valid_to   + 60_000_000_000    # 60 s deletion lag

    t_mid = (t_obs_new_from + t_obs_old_to) // 2
    assert history.at("PodIP", ip, t_mid) is Ambiguous


def test_ip_reuse_no_ambiguity_before_window(ref_world):
    """Before the new pod appears the IP resolves unambiguously to the old pod."""
    history = ref_world.history
    old_pod, new_pod = _first_churn_pair(ref_world)
    ip = new_pod.pod_ips[0]

    t_early = old_pod.valid_from + 1_000_000_000  # 1 s into old pod's life
    result = history.at("PodIP", ip, t_early)
    assert result is not Ambiguous
    assert result is not None
    assert result.uid == old_pod.uid


# ---------------------------------------------------------------------------
# Reuse: PID reuse → Ambiguous ProcessPID lookup
# ---------------------------------------------------------------------------

def test_pid_reuse_ambiguity(ref_world):
    """First churn forces TGID reuse; ProcessPID lookup is Ambiguous at overlap."""
    history = ref_world.history
    old_pod, new_pod = _first_churn_pair(ref_world)

    # Locate init process of old pod's main container
    old_main = next(
        c for c in ref_world.containers
        if c.pod_uid == old_pod.uid and not c.is_sidecar
    )
    old_init = next(
        p for p in ref_world.processes
        if p.container_uid == old_main.uid and p.parent_process_key == ""
    )
    pid_key = f"{old_init.node_uid}:{old_init.tgid}"

    # Same timing window as IP reuse
    t_obs_new_from = new_pod.valid_from + 50_000_000
    t_obs_old_to   = old_pod.valid_to   + 60_000_000_000
    t_mid = (t_obs_new_from + t_obs_old_to) // 2

    assert history.at("ProcessPID", pid_key, t_mid) is Ambiguous


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

def test_determinism_same_seed(spec):
    """Two worlds with the same seed produce identical pod UIDs."""
    w1 = World("Reference", spec, seed="det-42")
    w2 = World("Reference", spec, seed="det-42")
    assert sorted(p.uid for p in w1.pods) == sorted(p.uid for p in w2.pods)


def test_determinism_different_seeds(spec):
    """Two worlds with different seeds produce different pod UIDs."""
    w1 = World("Reference", spec, seed="det-A")
    w2 = World("Reference", spec, seed="det-B")
    assert sorted(p.uid for p in w1.pods) != sorted(p.uid for p in w2.pods)
