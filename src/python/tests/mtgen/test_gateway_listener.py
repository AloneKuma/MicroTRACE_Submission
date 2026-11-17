"""Gateway listeners and copied request IDs (exp2-conflict-origin-cases-plan G3),
the catalogue overlay (D-31), and the origin-aware request-identity check."""
from collections import defaultdict

import pytest

import mtgen  # noqa: F401  sets up sys.path for gen/ and spec/tools/
from mtgen import specs
from mtgen.activity import Activity
from mtgen.evidence import EvidenceArchive
from mtgen.render.gateway import PROPAGATE_WINDOW_NS, GatewayRenderer
from mtgen.specs import load_generator_spec
from mtgen.verify import _shares_key, link_witness_result
from mtgen.workload import GATEWAY_INTERNAL_LISTENER, WorkloadEngine
from mtgen.world import World
from microtrace.v0 import common_pb2, witness_pb2

S = 1_000_000_000
T0 = 1_791_460_800 * S


def _renderer():
    return GatewayRenderer({"version": "p_a.test", "patterns": []}, {"version": "i_a2.test", "indicators": []},
                           EvidenceArchive(archive_id="test"))


def _req(t_s, target="svc-b", actor="external", **params):
    return Activity(time_ns=T0 + int(t_s * S), kind="http_request", actor_uid=actor,
                    actor_type="External" if actor == "external" else "Pod", target_uid=target,
                    target_type="Service", parameters={"method": "GET", "path": "/api/v1/items", **params})


def test_edge_listener_mints_the_id_and_ignores_a_client_id():
    ne = _renderer().render(_req(1, client_request_id="forged"))
    g = ne.gateway
    assert g.request_id != "forged" and g.request_id_origin == common_pb2.SENSOR
    assert ne.action_id == ne.source_native_id == g.request_id


def test_internal_listener_keeps_the_client_id_as_workload_and_keeps_actions_apart():
    r = _renderer()
    edge = r.render(_req(1))
    inner = r.render(_req(2, target="svc-c", actor="pod-x", listener="internal",
                          client_request_id=edge.gateway.request_id))
    assert inner.gateway.request_id == edge.gateway.request_id
    assert inner.gateway.request_id_origin == common_pb2.WORKLOAD
    assert inner.action_id != edge.action_id and inner.event_id != edge.event_id


def test_internal_listener_without_a_client_id_is_still_workload():
    ne = _renderer().render(_req(1, target="svc-c", actor="pod-x", listener="internal"))
    assert ne.gateway.request_id and ne.gateway.request_id_origin == common_pb2.WORKLOAD
    assert ne.gateway.request_id != ne.action_id


def test_a_call_propagates_the_callers_current_edge_request_only():
    r = _renderer()
    edge = r.render(_req(1, target="svc-b"))
    near = r.render(_req(2, target="svc-c", actor="pod-b", listener="internal", propagate_from="svc-b"))
    other = r.render(_req(2, target="svc-c", actor="pod-d", listener="internal", propagate_from="svc-d"))
    late = r.render(_req(1 + PROPAGATE_WINDOW_NS / S + 1, target="svc-c", actor="pod-b",
                         listener="internal", propagate_from="svc-b"))
    assert near.gateway.request_id == edge.gateway.request_id
    assert other.gateway.request_id != edge.gateway.request_id
    assert late.gateway.request_id != edge.gateway.request_id


def test_unknown_listener_is_an_error():
    with pytest.raises(ValueError):
        _renderer().render(_req(1, listener="sidecar"))


def test_copying_a_request_id_needs_the_internal_listener():
    # Review 2026-10-26: on the edge listener the copy was silently replaced
    # by a minted ID.
    from mtgen.__main__ import _bind_request_id
    with pytest.raises(ValueError, match="listener: internal"):
        _bind_request_id(_req(2, copy_request_id_of="1"), {1: "r-1"})
    bound = _bind_request_id(_req(2, copy_request_id_of="1", listener="internal"), {1: "r-1"})
    assert bound.parameters["client_request_id"] == "r-1"


def _keys(rid, minted):
    k = defaultdict(set)
    k["request_id"].add(rid)
    if minted:
        k["request_id_minted"].add(rid)
    return k


def test_request_identity_holds_only_on_a_minted_id_at_both_ends():
    RI = witness_pb2.REQUEST_IDENTITY
    edge, copy = _keys("r1", True), _keys("r1", False)
    assert link_witness_result(RI, edge, copy, {}) == "none"
    assert _shares_key("request_id", edge, copy)
    assert link_witness_result(RI, edge, _keys("r1", True), {}) == "holds"


def test_overlay_adds_scenarios_and_never_replaces_one(tmp_path):
    base = specs.load_scenario_catalogue()
    rel = "spec/scenarios/catalogue.pilot-cases.v0.yaml"
    ids = [s["id"] for s in specs.load_scenario_catalogue([rel])["scenarios"]]
    assert ids[:len(base["scenarios"])] == [s["id"] for s in base["scenarios"]]
    assert {"origin_request_id_graft", "origin_request_id_propagate"} <= set(ids)
    dup = tmp_path / "dup.yaml"
    dup.write_text("version: catalogue.dup.v0\nstatus: draft\nscenarios:\n  - id: %s\n" % base["scenarios"][0]["id"])
    with pytest.raises(ValueError):
        specs.load_scenario_catalogue([str(dup)])        # absolute: os.path.join keeps it


@pytest.fixture(scope="module")
def world_and_spec():
    spec = load_generator_spec()
    return World("Small", spec, seed="test-listener", run_duration_ns=60 * S), spec


def test_internal_listener_flag_is_off_by_default_and_marks_only_service_calls(world_and_spec):
    world, spec = world_and_spec
    off = WorkloadEngine(world, spec).generate()
    on = WorkloadEngine(world, spec, flags=(GATEWAY_INTERNAL_LISTENER,)).generate()
    http_off = [a for a in off if a.kind == "http_request"]
    http_on = [a for a in on if a.kind == "http_request"]
    assert not any("listener" in a.parameters for a in http_off)
    assert [(a.time_ns, a.actor_uid, a.target_uid) for a in http_off] == \
        [(a.time_ns, a.actor_uid, a.target_uid) for a in http_on]
    internal = [a for a in http_on if a.parameters.get("listener") == "internal"]
    assert internal and all(a.actor_type == "Pod" for a in internal)
    assert all(a.parameters.get("listener") is None for a in http_on if a.actor_type == "External")
    assert any("propagate_from" in a.parameters for a in internal)
