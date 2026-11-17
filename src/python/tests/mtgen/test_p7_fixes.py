"""Regression tests for the generator defects found by the 3600 s pilot.

At 60 s only one scenario fits in a run, so the p7-01 checks passed while
these defects hid. Each test pins one defect class:

  1. Every catalogue action that declares records renders at least one event
     (secret_list, secret_get and rbac_change rendered nothing).
  2. Audit requests from a Pod or ServiceAccount actor are authenticated
     (every audit event had an empty user, so no rule saw a principal).
  3. any_of inputs are alternatives in the truth evidence check (C1a, an OR
     of escape primitives, could never be PRESENT).
  4. Findings the rendering table excludes get no opportunity (G2).
  5. A clean build of the previously broken scenarios passes every verify
     check, labels every catalogue PRESENT expectation PRESENT, and carries
     a cluster-context stream with Pod summaries.
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

import mtgen  # noqa: F401 — registers gen/ and spec/tools/ on sys.path
from mtgen import specs
from mtgen.__main__ import _render_activity
from mtgen.activity import Activity
from mtgen.evidence import EvidenceArchive
from mtgen.render.audit import AuditRenderer
from mtgen.render.ebpf import EbpfRenderer
from mtgen.render.gateway import GatewayRenderer
from mtgen.render.kyverno import KyvernoRenderer
from mtgen.render.offnode import OffNodeRenderer
from mtgen.scenarios import GroundTruthRecord, ScenarioEngine, scenario_window_ns
from mtgen.truth import RenderedEventInfo, TruthWriter
from mtgen.verify import _load_base_stream, _load_truth_files, verify
from mtgen.world import World
from microtrace.v0 import common_pb2, dataset_pb2

REPO = Path(__file__).resolve().parents[4]

BROKEN_SCENARIOS = (
    "c1b_namespace_escape,e2_cadets_implant_write,"
    "g2_external_stolen_credentials,h3_external_bulk_enumeration,"
    "h4_external_sensitive_exfil,e1_external_unsigned_image"
)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def gen_spec():
    return specs.load_generator_spec()


@pytest.fixture(scope="module")
def catalogue():
    return specs.load_scenario_catalogue()


@pytest.fixture(scope="module")
def world(gen_spec):
    return World("Small", gen_spec, "build:1", run_id="p7-fixes",
                 run_duration_ns=600 * 10**9)


# ---------------------------------------------------------------------------
# 1. Every record-producing action renders
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def whole_catalogue(gen_spec, catalogue):
    """Every catalogue scenario executed and rendered, without workload."""
    ids = [s["id"] for s in catalogue["scenarios"]]
    # Each scenario takes its window plus 30 s spacing; chains run longer.
    duration_s = sum(scenario_window_ns(s) // 10**9 + 30
                     for s in catalogue["scenarios"]) + 180
    w = World("Small", gen_spec, "build:1", run_id="p7-cov",
              run_duration_ns=duration_s * 10**9)
    run_spec = {"scenarios": [{"scenario_id": i, "variant_id": "v1"} for i in ids]}
    engine = ScenarioEngine(w, catalogue, run_spec, "build:1")
    activities, _ = engine.execute()
    assert not engine.dropped_scenarios

    archive = EvidenceArchive(archive_id="p7-cov")
    renderers = (
        GatewayRenderer(specs.load_pattern_artifacts(),
                        specs.load_indicator_artifacts(), archive),
        AuditRenderer(w.history, world=w),
        EbpfRenderer(w, archive),
        KyvernoRenderer(w),
        OffNodeRenderer(w.history),
    )
    rendered = [(a, _render_activity(a, *renderers)) for a in activities]
    return w, rendered


def test_every_record_producing_action_renders(whole_catalogue):
    actions = yaml.safe_load(
        (REPO / "spec/scenarios/actions.v0.yaml").read_text(encoding="utf-8"))
    produces = {
        a["id"]: [r for r in a.get("produces_records", []) if r != "none"]
        for a in actions["actions"]
    }
    _, rendered = whole_catalogue
    silent = sorted({a.kind for a, nes in rendered if produces.get(a.kind) and not nes})
    assert not silent, f"actions declaring records rendered nothing: {silent}"


def test_scenario_events_name_only_world_entities(whole_catalogue):
    """No placeholder ("unknown", a process nickname, a pod name) as a UID."""
    from mtgen.emit import _set_entities
    w, rendered = whole_catalogue
    known = {row.entity_uid for row in w.context_history_rows}
    k8s = {common_pb2.POD, common_pb2.CONTAINER, common_pb2.NODE,
           common_pb2.SERVICE_ACCOUNT, common_pb2.NAMESPACE}
    bad = set()
    for act, nes in rendered:
        for ne in nes:
            _set_entities(ne)
            for ref in ne.entities:
                if ref.type in k8s and ref.HasField("uid") and ref.uid not in known:
                    bad.add((act.kind, common_pb2.EntityType.Name(ref.type), ref.uid))
    assert not bad, f"events name entities outside the world: {sorted(bad)[:10]}"


# ---------------------------------------------------------------------------
# 2. Audit identity
# ---------------------------------------------------------------------------

def _audit(world, kind, actor_uid, **params):
    act = Activity(time_ns=world.run_start_ns + 10**9, kind=kind,
                   actor_uid=actor_uid, actor_type="Pod",
                   target_uid="", target_type="APIResource",
                   parameters=params)
    return AuditRenderer(world.history, world=world).render(act)


def test_secret_list_from_pod_is_authenticated_as_its_service_account(world):
    pod = world.pods[0]
    ne = _audit(world, "secret_list", pod.uid, namespace=pod.namespace)
    assert ne.audit.verb == "list"
    assert ne.audit.object_ref.resource == "secrets"
    assert ne.audit.user.username == (
        f"system:serviceaccount:{pod.namespace}:{pod.service_account}")
    assert ne.audit_derived.HasField("principal")
    assert not ne.audit_derived.authentication_failed
    assert ne.audit_derived.bound_pod_uid == pod.uid


def test_rbac_change_maps_to_rbac_resource(world):
    pod = world.pods[0]
    ne = _audit(world, "rbac_change", pod.uid, object_type="ClusterRoleBinding",
                mutation_type="create", name="rb")
    assert ne.audit.verb == "create"
    assert ne.audit.object_ref.api_group == "rbac.authorization.k8s.io"
    assert ne.audit.object_ref.resource == "clusterrolebindings"


def test_auth_failure_stays_unauthenticated(world):
    ne = _audit(world, "api_auth_failure", world.pods[0].uid,
                response_code=401, verb="get", resource="pods")
    assert ne.audit.user.username == ""
    assert ne.audit_derived.authentication_failed
    assert not ne.audit_derived.HasField("principal")


# ---------------------------------------------------------------------------
# 3. any_of evidence groups
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def truth_writer(catalogue, gen_spec):
    return TruthWriter("p7-fixes", specs.load_evidence_rendering(), catalogue,
                       gen_spec=gen_spec)


def _info(record, family=""):
    return RenderedEventInfo(event_id=f"ev-{record}-{family}",
                             record_type=record, family=family, time_ns=1)


@pytest.mark.parametrize("family", [
    "ns.change", "priv.creds", "ipc.runtime_socket", "bpf.call"])
def test_c1a_any_single_escape_primitive_suffices(truth_writer, family):
    assert truth_writer._check_evidence("C1a", [_info("ebpf", family)]) == []


def test_c1a_without_any_primitive_is_missing(truth_writer):
    missing = truth_writer._check_evidence("C1a", [_info("ebpf", "file.read")])
    assert "microtrace.v0.BpfDetail.cmd" in missing
    assert "microtrace.v0.NamespaceDetail.op" in missing


def test_ungrouped_inputs_stay_required(truth_writer):
    # H4 has no any_of group: the read alone leaves connect and flow missing.
    missing = truth_writer._check_evidence(
        "H4", [_info("ebpf", "file.open"), _info("ebpf", "file.read")])
    assert "microtrace.v0.SocketDetail.remote" in missing
    assert "microtrace.v0.FlowCounter.bytes_out" in missing


# ---------------------------------------------------------------------------
# 4. Excluded findings
# ---------------------------------------------------------------------------

def test_excluded_finding_gets_no_opportunity(truth_writer):
    rec = GroundTruthRecord(
        run_id="p7-fixes", action_seq=1,
        scenario_id="g2_external_stolen_credentials", variant_id="v1",
        step_label="1", is_attack=True, expected_finding_types=["G2"],
        started_at_ns=1, ended_at_ns=2,
    )
    result = truth_writer.write([rec], {1: [_info("audit")]})
    assert not [o for o in result.opportunities if o.finding_type == "G2"]
    assert list(result.actions[0].expected_finding_types) == []
    assert result.consistency_errors == []


# ---------------------------------------------------------------------------
# 5. Clean build of the previously broken scenarios
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def broken_scenarios_run(tmp_path_factory):
    out = tmp_path_factory.mktemp("p7_fixes") / "run"
    env = dict(os.environ, PYTHONHASHSEED="1", SOURCE_DATE_EPOCH="0",
               PYTHONPATH=str(REPO / "src" / "python"))
    proc = subprocess.run(
        [sys.executable, "-m", "mtgen", "build", "--world", "Small",
         "--shape", "clean", "--scenarios", BROKEN_SCENARIOS,
         "--seed", "7", "--duration-s", "600", "--out", str(out)],
        env=env, capture_output=True, text=True, cwd=str(REPO),
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert "truth consistency errors" not in proc.stderr, proc.stderr[-2000:]
    assert "downgraded in a clean run" not in proc.stderr, proc.stderr[-2000:]
    return out


def test_broken_scenarios_pass_every_verify_check(broken_scenarios_run):
    result = verify(broken_scenarios_run)
    failed = {c.name: c.failures[:3] for c in result.checks if not c.ok}
    assert result.ok, f"verify failed: {failed}"


def test_every_catalogue_present_expectation_is_present(
        broken_scenarios_run, catalogue):
    actions, opps, _ = _load_truth_files(broken_scenarios_run)
    present = {(o.action_seq, o.finding_type) for o in opps
               if o.expected_state == dataset_pb2.PRESENT}
    excluded = {f["id"] for f in specs.load_evidence_rendering()["findings"]
                if f.get("included") is False}
    steps = {(s["id"], str(st["step"])): st
             for s in catalogue["scenarios"] for st in s["steps"]}
    expected = {
        (a.action_seq, e["finding"]) for a in actions
        for e in steps[(a.scenario_id, a.step_label)].get("expects", [])
        if e.get("state") == "PRESENT" and e["finding"] not in excluded
    }
    assert expected, "no PRESENT expectations in the build"
    assert expected <= present, f"not PRESENT: {sorted(expected - present)}"
    found = {ft for _, ft in present}
    for ft in ("C1a", "C1b", "E2", "H3", "H4"):
        assert ft in found, f"{ft} never PRESENT"


def test_context_stream_carries_pod_summaries(broken_scenarios_run):
    envs, _ = _load_base_stream(broken_scenarios_run)
    pods = [
        e.normalized_event.context for e in envs
        if e.WhichOneof("payload") == "normalized_event"
        and e.normalized_event.source == common_pb2.CLUSTER_CONTEXT
        and e.normalized_event.context.kind == "Pod"
        and e.normalized_event.context.HasField("pod")
    ]
    assert pods, "no Pod watch events in the base stream"
    assert all(c.started_at.seconds > 0
               for obs in pods for c in obs.pod.containers)


# ---------------------------------------------------------------------------
# 6. Degraded profiles drop events in declared gap windows
# ---------------------------------------------------------------------------

from mtgen.degrade import Degrader, _param  # noqa: E402


@pytest.mark.parametrize("profile_name,key", [
    ("degraded_gateway", "observer_loss_percentage"),
    ("degraded_audit", "event_loss_percentage"),
    ("degraded_ebpf", "probe_loss_percentage"),
])
def test_gap_windows_cover_declared_share(world, gen_spec, profile_name, key):
    profile = gen_spec["observability_profiles"][profile_name]
    deg = Degrader(world, profile_name, profile, "build:1")
    assert deg.windows
    by_scope = {}
    for w in deg.windows:
        by_scope.setdefault(w.scope, []).append(w)
    span = world.run_duration_ns
    pct = float(_param(profile, key, 0))
    for scope, ws in by_scope.items():
        ws.sort(key=lambda w: w.start_ns)
        assert all(a.end_ns <= b.start_ns for a, b in zip(ws, ws[1:])), scope
        covered = sum(w.end_ns - w.start_ns for w in ws) / span * 100
        assert abs(covered - pct) <= pct * 0.25 + 1, (scope, covered, pct)


def test_context_gaps_cover_watch_events(world, gen_spec):
    profile = gen_spec["observability_profiles"]["degraded_context"]
    deg = Degrader(world, "degraded_context", profile, "build:1")
    times = [o.observed_time.seconds * 10**9 + o.observed_time.nanos
             for o in world.context_observations]
    assert deg.windows
    for w in deg.windows:
        assert any(w.start_ns <= t < w.end_ns for t in times)


def test_clean_profile_drops_nothing(world, gen_spec):
    deg = Degrader(world, "clean", gen_spec["observability_profiles"]["clean"],
                   "build:1")
    assert not deg.windows and not deg.lost_families


@pytest.fixture(scope="module")
def degraded_ebpf_run(tmp_path_factory):
    out = tmp_path_factory.mktemp("p7_fixes_ebpf") / "run"
    env = dict(os.environ, PYTHONHASHSEED="1", SOURCE_DATE_EPOCH="0",
               PYTHONPATH=str(REPO / "src" / "python"))
    proc = subprocess.run(
        [sys.executable, "-m", "mtgen", "build", "--world", "Small",
         "--shape", "degraded_ebpf", "--scenarios",
         "c1b_namespace_escape,h4_external_sensitive_exfil",
         "--seed", "7", "--duration-s", "600", "--out", str(out)],
        env=env, capture_output=True, text=True, cwd=str(REPO),
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    return out


def test_degraded_ebpf_run_verifies_and_loses_lineage(degraded_ebpf_run):
    result = verify(degraded_ebpf_run)
    failed = {c.name: c.failures[:3] for c in result.checks if not c.ok}
    assert result.ok, f"verify failed: {failed}"
    _, opps, _ = _load_truth_files(degraded_ebpf_run)
    c1b = [o for o in opps if o.finding_type == "C1b"]
    assert c1b and all(o.expected_state == dataset_pb2.UNOBSERVABLE for o in c1b)
    assert any("RawEbpfRecord.lineage_root" in r
               for o in c1b for r in o.evidence_requirements)

    envs, _ = _load_base_stream(degraded_ebpf_run)
    ebpf_sc = [e.source_completeness for e in envs
               if e.WhichOneof("payload") == "source_completeness"
               and e.source_completeness.source == common_pb2.EBPF]
    assert ebpf_sc
    for sc in ebpf_sc:
        timed = [g for g in sc.gaps if g.HasField("to")]
        assert timed and all(g.to.seconds >= getattr(g, "from").seconds for g in timed)
    families = {e.normalized_event.ebpf.event_family for e in envs
                if e.WhichOneof("payload") == "normalized_event"
                and e.normalized_event.source == common_pb2.EBPF}
    assert "proc.fork" not in families


# ---------------------------------------------------------------------------
# 7. Background traffic uses every source a scenario can add
# ---------------------------------------------------------------------------

def test_background_has_egress_and_admission_volume(world, gen_spec):
    """Flow counters, path-flow records and admissions must not be
    scenario-only: their presence or a +1 in their count would mark a run."""
    from collections import Counter
    from mtgen.workload import WorkloadEngine
    kinds = Counter(a.kind for a in WorkloadEngine(world, gen_spec).generate())
    assert kinds["egress_transfer"] >= 20, kinds
    assert kinds["connect_external"] >= kinds["egress_transfer"]
    assert kinds["admit_pod"] >= 10, kinds


# ---------------------------------------------------------------------------
# 8. Scenario actors stay alive for the whole scenario
# ---------------------------------------------------------------------------

def test_pod_actors_alive_at_every_step(gen_spec, catalogue):
    """A role bound at scenario start must not act after its Pod is deleted
    (a Pod-bound token of a deleted Pod is not a valid identity). Short
    Reference runs pack Pod churn densely enough to hit scenario windows."""
    ids = [s["id"] for s in catalogue["scenarios"]]
    dead = []
    for k in range(1, 31):
        seed = f"build:{k}"
        w = World("Reference", gen_spec, seed, run_id=f"p7-alive-{k}",
                  run_duration_ns=600 * 10**9)
        pods = {p.uid: p for p in w.pods}
        _, records = ScenarioEngine(
            w, catalogue,
            {"scenarios": [{"scenario_id": i, "variant_id": "v1"} for i in ids]},
            seed).execute()
        dead += [
            (seed, r.scenario_id, r.step_label)
            for r in records for ref in r.actors
            if ref.uid in pods and not (
                pods[ref.uid].valid_from <= r.started_at_ns < pods[ref.uid].valid_to)
        ]
    assert not dead, f"actors act after their Pod is gone: {dead[:5]}"
