"""Regression tests for the generator defects behind the PILOT zero-recall
findings (step 9, diagnosed 2026-10-14). Each test pins one defect:

  1. B2: an auth failure is a 401 from the step's source_ip (rendered 200
     with no source address, so it had no observed_source key).
  2. G1a: connect_internal resolves its target to an in-cluster address
     (every one rendered as 1.2.3.4:443, external).
  3. H4: an egress_transfer counts bytes on the actor's preceding connect
     (cookie 0 and port 443 never joined the connect).
  4. E1: a scenario-admitted Pod is observed on the context stream (it was
     only in the reference history, so the agents never saw it).
  5. D1: read_token_file can name the reading executable.
  6. Scenario steps with repeat render a burst as one action.
  7. Privilege changes: only euid_to_root escalates; privilege_change
     without a target drops privilege; capability_gain adds its caps.
  8. Catalogue scans and egress reach their target Pod; a WAF-blocked
     injection is refused (403).
  9. A degraded scenario's `unobserved` step loses its records in a declared
     SOURCE_IDLE gap, and the truth writer flags any source-degraded
     UNOBSERVABLE expectation whose evidence was all rendered.
"""
import pytest

import mtgen  # noqa: F401 — registers gen/ and spec/tools/ on sys.path
from mtgen import specs
from mtgen.activity import Activity
from mtgen.evidence import EvidenceArchive
from mtgen.render.audit import AuditRenderer
from mtgen.render.ebpf import EbpfRenderer
from mtgen.scenarios import ScenarioEngine
from mtgen.world import World
from microtrace.v0 import common_pb2


@pytest.fixture(scope="module")
def gen_spec():
    return specs.load_generator_spec()


@pytest.fixture(scope="module")
def catalogue():
    return specs.load_scenario_catalogue()


@pytest.fixture(scope="module")
def world(gen_spec):
    return World("Small", gen_spec, "build:1", run_id="step9-fixes",
                 run_duration_ns=600 * 10**9)


def _act(world, kind, actor_uid, target_uid="", dt_s=10, **params):
    return Activity(time_ns=world.run_start_ns + dt_s * 10**9, kind=kind,
                    actor_uid=actor_uid, actor_type="Pod",
                    target_uid=target_uid, target_type="",
                    parameters=params)


def _two_live_pods(world):
    t = world.run_start_ns + 10 * 10**9
    live = [p for p in world.pods if p.valid_from <= t < p.valid_to and p.pod_ips]
    return live[0], live[1]


# 1. B2 ---------------------------------------------------------------------

def test_auth_failure_is_401_from_its_source_ip(world):
    ne = AuditRenderer(world.history, world=world).render(
        _act(world, "api_auth_failure", "external",
             source_ip="172.16.0.50", verb="get", resource="pods"))
    assert ne.audit.response_code == 401
    assert ne.audit_derived.authentication_failed
    assert ne.audit_derived.observed_source == "172.16.0.50"


# 2. G1a --------------------------------------------------------------------

def test_connect_internal_to_pod_is_cluster_pod(world):
    src, dst = _two_live_pods(world)
    (ne,) = EbpfRenderer(world, EvidenceArchive(archive_id="t")).render(
        _act(world, "connect_internal", src.uid, dst.uid,
             target_service_or_pod=dst.uid, target_port=22))
    assert ne.ebpf.socket.remote.ip == dst.pod_ips[0]
    assert ne.ebpf.socket.remote.port == 22
    assert ne.ebpf_derived.remote_class == "cluster_pod"
    assert ne.ebpf_derived.remote_pod_uid == dst.uid


def test_connect_internal_to_service_lands_on_its_pod(world):
    src, dst = _two_live_pods(world)
    (ne,) = EbpfRenderer(world, EvidenceArchive(archive_id="t")).render(
        _act(world, "connect_internal", src.uid, dst.service_name, target_port=8080))
    assert ne.ebpf_derived.remote_class == "cluster_pod"
    resolved = next(p for p in world.pods if p.uid == ne.ebpf_derived.remote_pod_uid)
    assert resolved.service_name == dst.service_name


def test_connect_internal_to_infra_is_cluster_service(world):
    src, _ = _two_live_pods(world)
    db = world.infra["database"]
    (ne,) = EbpfRenderer(world, EvidenceArchive(archive_id="t")).render(
        _act(world, "connect_internal", src.uid, db.uid, target_port=5432))
    assert ne.ebpf_derived.remote_class == "cluster_service"
    assert not ne.ebpf_derived.HasField("remote_pod_uid")
    assert ne.ebpf.socket.remote.port == 5432


# 3. H4 ---------------------------------------------------------------------

def test_egress_counts_bytes_on_the_preceding_connect(world):
    src, _ = _two_live_pods(world)
    r = EbpfRenderer(world, EvidenceArchive(archive_id="t"))
    (conn,) = r.render(_act(world, "connect_external", src.uid,
                            remote_ip="198.51.100.7", remote_port=4444))
    (flow,) = r.render(_act(world, "egress_transfer", src.uid, dt_s=12,
                            destination="198.51.100.7", bytes_out=2048))
    assert flow.ebpf.flow_counter.flow.socket_cookie == conn.ebpf.socket.flow.socket_cookie != 0
    assert flow.ebpf.flow_counter.remote.port == 4444


# 4. E1 ---------------------------------------------------------------------

def test_admitted_pod_is_observed_on_the_context_stream(gen_spec, catalogue):
    w = World("Small", gen_spec, "build:2", run_id="step9-e1",
              run_duration_ns=600 * 10**9)
    before = {o.uid for o in w.context_observations}
    ScenarioEngine(w, catalogue, {"scenarios": [
        {"scenario_id": "e1_external_unsigned_image", "variant_id": "v1"}]}, "build:2").execute()
    added = [o for o in w.context_observations if o.uid not in before]
    assert [(o.kind, o.name) for o in added] == [("Pod", "malicious-app")]
    seqs = [o.watch_stream_seq for o in w.context_observations if o.watch_stream_id == "watch-pods"]
    assert len(seqs) == len(set(seqs))


# 5. D1 ---------------------------------------------------------------------

def test_token_read_names_the_reader_executable(world):
    src, _ = _two_live_pods(world)
    nes = EbpfRenderer(world, EvidenceArchive(archive_id="t")).render(
        _act(world, "read_token_file", src.uid, reader_executable="/usr/bin/cat",
             token_file_path="/var/run/secrets/kubernetes.io/serviceaccount/token"))
    read = next(ne for ne in nes if ne.ebpf.event_family == "file.read")
    procs = [e.name for e in read.entities if e.type == common_pb2.PROCESS]
    assert procs == ["/usr/bin/cat"]


# 6. repeat -----------------------------------------------------------------

def test_repeat_renders_a_burst_as_one_action(gen_spec, catalogue):
    w = World("Small", gen_spec, "build:3", run_id="step9-repeat",
              run_duration_ns=600 * 10**9)
    acts, records = ScenarioEngine(w, catalogue, {"scenarios": [
        {"scenario_id": "h3_external_bulk_enumeration", "variant_id": "v1"}]}, "build:3").execute()
    gets = [a for a in acts if a.kind == "secret_get"]
    burst = [a for a in gets if a.parameters["name"].startswith("secret-enum-")]
    assert len(burst) == 60 and len({a.parameters["name"] for a in burst}) == 60
    assert len({a.action_seq for a in burst}) == 1
    assert len(records) == 5                    # one truth action per step
    span = max(a.time_ns for a in burst) - min(a.time_ns for a in burst)
    assert span < 5 * 10**9                     # within the step duration


def test_repeat_burst_stays_inside_a_short_window(gen_spec, catalogue):
    """A burst placed near the window end is compressed, never spilling past
    it (pilot-v3: copies after the run end named Pods no longer alive)."""
    w = World("Small", gen_spec, "build:4", run_id="step9-edge",
              run_duration_ns=600 * 10**9)
    eng = ScenarioEngine(w, catalogue, {"scenarios": []}, "build:4")
    scenario = next(s for s in catalogue["scenarios"] if s["id"] == "b3_kube_ids0_rate_spike")
    start = w.run_start_ns + 597 * 10**9
    end = w.run_start_ns + 600 * 10**9
    acts, _ = eng._execute_scenario(scenario, "v1", start, end)
    assert len(acts) == 302
    assert all(start <= a.time_ns < end for a in acts)


# 7. Privilege credentials (pre-pilot review, 2026-10-14) ---------------------

def _creds(world, kind, **params):
    src, _ = _two_live_pods(world)
    (ne,) = EbpfRenderer(world, EvidenceArchive(archive_id="t")).render(
        _act(world, kind, src.uid, **params))
    return ne.ebpf.privilege


def test_euid_to_root_escalates(world):
    pr = _creds(world, "euid_to_root")
    assert (pr.before.euid, pr.after.euid) == (1000, 0)


def test_privilege_change_without_target_is_a_drop(world):
    """f1_benign_privilege_drop rendered 1000 -> 0, an escalation."""
    pr = _creds(world, "privilege_change")
    assert (pr.before.euid, pr.after.euid) == (0, 1000)
    assert _creds(world, "privilege_change", target_euid=0).after.euid == 0


def test_capability_gain_adds_the_named_caps(world):
    """capability_gain ignored caps and set euid to 0 instead."""
    from microtrace.v0 import ebpf_pb2
    pr = _creds(world, "capability_gain", caps=["CAP_SYS_PTRACE", "CAP_SYS_ADMIN"])
    assert pr.op == ebpf_pb2.CAPSET
    assert pr.before.euid == pr.after.euid == 1000
    assert pr.after.cap_effective & ~pr.before.cap_effective == (1 << 19) | (1 << 21)
    assert _creds(world, "capability_gain").after.cap_effective == 1 << 21   # default CAP_SYS_ADMIN


# 8. Catalogue targets (pre-pilot review) -------------------------------------

@pytest.mark.parametrize("sid", ["g1a_benign_network_scan", "g1a_port_scan_unobserved"])
def test_g1a_scans_reach_a_cluster_pod(gen_spec, catalogue, sid):
    """These scanned 'target_pod: 10.0.0.1', which resolved to 1.2.3.4 external."""
    w = World("Small", gen_spec, "build:5", run_id=f"step9-{sid}", run_duration_ns=600 * 10**9)
    acts, _ = ScenarioEngine(w, catalogue, {"scenarios": [{"scenario_id": sid, "variant_id": "v1"}]},
                             "build:5").execute()
    r = EbpfRenderer(w, EvidenceArchive(archive_id="t"))
    nes = [ne for a in acts for ne in r.render(a) if ne.ebpf.event_family == "net.connect"]
    assert nes and all(ne.ebpf_derived.remote_class == "cluster_pod" for ne in nes)


def test_egress_to_a_target_pod_is_internal(world):
    """h1_benign_large_response sent its bytes to 1.2.3.4 (external)."""
    src, dst = _two_live_pods(world)
    (ne,) = EbpfRenderer(world, EvidenceArchive(archive_id="t")).render(
        _act(world, "egress_transfer", src.uid, target_pod=dst.uid, bytes_out=10**9))
    assert ne.ebpf.flow_counter.remote.ip == dst.pod_ips[0]
    assert ne.ebpf_derived.remote_class == "cluster_pod"
    from mtgen.render.offnode import OffNodeRenderer
    (off,) = OffNodeRenderer(world.history).render(
        _act(world, "egress_transfer", src.uid, target_pod=dst.uid, bytes_out=10**9))
    assert off.offnode_derived.remote_class == "cluster_pod"


def test_waf_blocked_injection_is_refused(catalogue):
    """a1_blocked_by_waf had no status, so it rendered 200 (an A2 success indicator)."""
    s = next(s for s in catalogue["scenarios"] if s["id"] == "a1_blocked_by_waf")
    assert s["steps"][0]["params"]["response_status"] == 403


def test_catalogue_step_params_are_declared(catalogue):
    """A step parameter the action does not declare is silently ignored by the
    renderers (target_pod, destination_ip, kind all fell back to defaults)."""
    import os
    import yaml
    from mtgen.scenarios import _ACTOR_SYNONYMS
    path = os.path.join(specs.REPO_ROOT, "spec", "scenarios", "actions.v0.yaml")
    actions = yaml.safe_load(open(path, encoding="utf-8"))["actions"]
    declared = {a["id"]: {p["name"] for p in a.get("parameters", [])} for a in actions}
    # Known leftovers: observe_state is never rendered; admit_pod's image is
    # informational (the digest comes from the container or image_digest).
    allowed = {("observe_state", k) for k in ("ip_address", "pod", "clock_offset_ms")} | {("admit_pod", "image")}
    stray = sorted(
        (s["id"], st["action"], k)
        for s in catalogue["scenarios"] for st in s.get("steps", [])
        for k in st.get("params", {})
        if k not in declared.get(st["action"], set()) and k not in _ACTOR_SYNONYMS
        and (st["action"], k) not in allowed
    )
    assert not stray, stray


# 9. Degraded scenarios lose what they declare (step `unobserved`) -----------

DEGRADED_BY_SOURCE = [
    "a1_missing_gateway_observer", "b1_offline_audit", "b3_rate_spike_unobserved",
    "c1a_no_capability_change", "e1_policy_not_enforced", "e2_write_no_execute_observed",
    "f1_privilege_change_not_recorded", "g1a_port_scan_unobserved",
    "h2_external_connect_no_witness", "h3_secret_enumeration_audit_gap", "h4_read_without_connect",
]


def test_unobserved_step_is_dropped_in_a_declared_gap(gen_spec, catalogue):
    from mtgen.degrade import Degrader
    w = World("Small", gen_spec, "build:6", run_id="step9-unobs", run_duration_ns=600 * 10**9)
    acts, _ = ScenarioEngine(w, catalogue, {"scenarios": [
        {"scenario_id": "c1a_no_capability_change", "variant_id": "v1"}]}, "build:6").execute()
    (act,) = acts
    assert act.unobserved == ("ebpf",)
    (ne,) = EbpfRenderer(w, EvidenceArchive(archive_id="t")).render(act)   # still rendered
    deg = Degrader(w, "clean", None, "build:6")
    assert deg.add_step_window(ne, act.unobserved) and not deg.keep(ne)
    gaps = deg.gaps("ebpf", f"node={ne.ebpf.node_id}")
    assert [(g.reason, g.detail) for g in gaps] == [(common_pb2.SOURCE_IDLE, "scenario step unobserved")]
    # A source the step does not list is untouched.
    assert not Degrader(w, "clean", None, "x").add_step_window(ne, ("audit",))


def _truth(gen_spec, cat, sid, drop):
    """In-process build of one scenario; returns the TruthResult."""
    from mtgen.__main__ import _make_rendered_event_info, _render_activity
    from mtgen.degrade import Degrader
    from mtgen.render.audit import AuditRenderer
    from mtgen.render.gateway import GatewayRenderer
    from mtgen.render.kyverno import KyvernoRenderer
    from mtgen.render.offnode import OffNodeRenderer
    from mtgen.truth import TruthWriter
    w = World("Small", gen_spec, "build:7", run_id="step9-hollow", run_duration_ns=600 * 10**9)
    acts, records = ScenarioEngine(w, cat, {"scenarios": [{"scenario_id": sid, "variant_id": "v1"}]},
                                   "build:7").execute()
    archive = EvidenceArchive(archive_id="t")
    rs = (GatewayRenderer(specs.load_pattern_artifacts(), specs.load_indicator_artifacts(), archive),
          AuditRenderer(w.history, world=w), EbpfRenderer(w, archive), KyvernoRenderer(w),
          OffNodeRenderer(w.history))
    deg = Degrader(w, "clean", None, "build:7")
    by_seq = {}
    for a in acts:
        nes = _render_activity(a, *rs)
        if drop and a.unobserved:
            for ne in nes:
                deg.add_step_window(ne, a.unobserved)
        by_seq.setdefault(a.action_seq, []).extend(
            _make_rendered_event_info(ne) for ne in nes if deg.keep(ne))
    return TruthWriter("t", specs.load_evidence_rendering(), cat, gen_spec=gen_spec).write(records, by_seq)


@pytest.mark.parametrize("sid", ["c1a_no_capability_change", "h4_read_without_connect"])
def test_guard_flags_a_hollow_degraded_scenario(gen_spec, catalogue, sid):
    import copy
    hollow_cat = copy.deepcopy(catalogue)
    for s in hollow_cat["scenarios"]:
        for st in s.get("steps", []):
            st.pop("unobserved", None)
    assert _truth(gen_spec, hollow_cat, sid, drop=False).hollow_unobservable
    assert not _truth(gen_spec, catalogue, sid, drop=True).hollow_unobservable


@pytest.fixture(scope="module")
def degraded_run(tmp_path_factory):
    import os
    import subprocess
    import sys
    from pathlib import Path
    repo = Path(specs.REPO_ROOT)
    out = tmp_path_factory.mktemp("step9_degraded") / "run"
    env = dict(os.environ, PYTHONHASHSEED="1", SOURCE_DATE_EPOCH="0",
               PYTHONPATH=str(repo / "src" / "python"))
    proc = subprocess.run(
        [sys.executable, "-m", "mtgen", "build", "--world", "Small", "--shape", "clean",
         "--scenarios", ",".join(DEGRADED_BY_SOURCE), "--seed", "9",
         "--duration-s", str((len(DEGRADED_BY_SOURCE) + 2) * 90), "--out", str(out)],
        env=env, capture_output=True, text=True, cwd=str(repo))
    assert proc.returncode == 0, proc.stderr[-2000:]
    return out, proc.stderr


def test_degraded_scenarios_build_without_hollow_labels(degraded_run):
    out, stderr = degraded_run
    assert "all evidence rendered" not in stderr, stderr[-2000:]
    assert "downgraded in a clean run" not in stderr, stderr[-2000:]
    from mtgen.verify import verify
    result = verify(out)
    assert result.ok, {c.name: c.failures[:3] for c in result.checks if not c.ok}


def test_clean_run_with_step_gaps_declares_them(degraded_run):
    import json
    out, _ = degraded_run
    cg = json.load(open(out / "manifest.json", encoding="utf-8"))["completeness_guarantees"]
    for src in ("ebpf", "audit", "gateway", "kyverno"):
        assert cg[src]["expected_complete"] is False and cg[src]["scenario_gap_windows"] >= 1, (src, cg)
    assert cg["context"]["expected_complete"] is True
