"""Tests for Phase 2.4c: kyverno, context, off-node renderers, and completeness.

Required tests (task spec):
  1. An unsigned image gives an audit-mode FAIL; a signed one gives PASS.
  2. There is one AdmissionDerived per container.
  3. A degraded profile produces matching completeness gaps.
  4. All records round-trip through Envelope.
  5. Every topic/kind pair is allowed by topics.yaml.
"""
import types

import pytest
import yaml

import mtgen  # registers gen/ and spec/tools/ on sys.path
from mtgen.activity import Activity
from mtgen.completeness import CompletenessRenderer
from mtgen.envelopes import (
    build_envelope,
    build_run_context,
    deserialize_length_delimited,
    serialize_length_delimited,
)
from mtgen.history import WorldHistory, FOREVER
from mtgen.render.context import ContextRenderer
from mtgen.render.kyverno import KyvernoRenderer
from mtgen.render.offnode import OffNodeRenderer
from microtrace.v0 import (
    common_pb2,
    context_pb2,
    envelope_pb2,
    kyverno_pb2,
    normalized_pb2,
    offnode_pb2,
    stream_pb2,
)

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

RUN_START_NS = 1_704_067_200_000_000_000  # 2024-01-01 00:00:00 UTC
RUN_DURATION_NS = 3_600_000_000_000_000   # 1 hour
T0 = RUN_START_NS + 5_000_000_000         # 5 s into the run

POD_UID_SIGNED = "pod-signed-0001"
POD_UID_UNSIGNED = "pod-unsigned-001"
CTR_NAME_APP = "app"
CTR_NAME_SIDECAR = "sidecar"
NODE_UID = "node-uid-0001"
POD_IP = "10.0.1.100"


# ---------------------------------------------------------------------------
# Minimal fake world for kyverno renderer tests
# ---------------------------------------------------------------------------

def _make_container(pod_uid, name, image_signed, valid_from=RUN_START_NS):
    """Return a simple namespace-like object mimicking ContainerState."""
    return types.SimpleNamespace(
        uid=f"ctr-{pod_uid[:8]}-{name}",
        name=name,
        pod_uid=pod_uid,
        image_digest=f"sha256:{'a' * 64}",
        image_signed=image_signed,
        is_sidecar=(name == "sidecar"),
        valid_from=valid_from,
    )


def _make_kyverno_world(containers):
    """Minimal fake world: only .containers matters for KyvernoRenderer."""
    return types.SimpleNamespace(containers=containers)


def _make_admit_activity(pod_uid, pod_name="test-pod", namespace="default"):
    return Activity(
        time_ns=T0,
        kind="admit_pod",
        actor_uid="infra-admission",
        actor_type="InfraService",
        target_uid=pod_uid,
        target_type="Pod",
        parameters={"pod_name": pod_name, "namespace": namespace},
    )


# ---------------------------------------------------------------------------
# Test 1a: Unsigned image → audit-mode FAIL
# ---------------------------------------------------------------------------

def test_kyverno_unsigned_image_gives_fail():
    """An unsigned container image produces verdict=FAIL with enforcement_audit_mode=True."""
    ctr = _make_container(POD_UID_UNSIGNED, CTR_NAME_APP, image_signed=False)
    world = _make_kyverno_world([ctr])
    renderer = KyvernoRenderer(world)
    activity = _make_admit_activity(POD_UID_UNSIGNED)

    events = renderer.render(activity)

    assert len(events) == 1
    ne = events[0]
    assert ne.HasField("kyverno")
    decision = ne.kyverno
    assert decision.verdict == kyverno_pb2.FAIL
    assert decision.enforcement_audit_mode is True
    assert decision.dry_run is False
    assert decision.resource_uid == POD_UID_UNSIGNED


# ---------------------------------------------------------------------------
# Test 1b: Signed image → PASS
# ---------------------------------------------------------------------------

def test_kyverno_signed_image_gives_pass():
    """A signed container image produces verdict=PASS."""
    ctr = _make_container(POD_UID_SIGNED, CTR_NAME_APP, image_signed=True)
    world = _make_kyverno_world([ctr])
    renderer = KyvernoRenderer(world)
    activity = _make_admit_activity(POD_UID_SIGNED)

    events = renderer.render(activity)

    assert len(events) == 1
    ne = events[0]
    assert ne.kyverno.verdict == kyverno_pb2.PASS
    assert ne.kyverno.enforcement_audit_mode is True
    assert ne.kyverno.dry_run is False


# ---------------------------------------------------------------------------
# Test 2: One AdmissionDerived per container
# ---------------------------------------------------------------------------

def test_kyverno_one_derived_per_container():
    """Renderer emits one NormalizedEvent (with AdmissionDerived) per container."""
    containers = [
        _make_container(POD_UID_SIGNED, CTR_NAME_APP, image_signed=True),
        _make_container(POD_UID_SIGNED, CTR_NAME_SIDECAR, image_signed=True),
    ]
    world = _make_kyverno_world(containers)
    renderer = KyvernoRenderer(world)
    activity = _make_admit_activity(POD_UID_SIGNED)

    events = renderer.render(activity)

    assert len(events) == 2
    container_names = set()
    for ne in events:
        assert ne.HasField("admission_derived")
        derived = ne.admission_derived
        assert derived.pod_uid == POD_UID_SIGNED
        container_names.add(derived.container_name)
    assert container_names == {CTR_NAME_APP, CTR_NAME_SIDECAR}


# ---------------------------------------------------------------------------
# Mixed: Two containers, one unsigned → one FAIL, one PASS
# ---------------------------------------------------------------------------

def test_kyverno_mixed_signed_unsigned():
    """Mixed containers: unsigned gets FAIL, signed gets PASS."""
    containers = [
        _make_container(POD_UID_UNSIGNED, "app", image_signed=False),
        _make_container(POD_UID_UNSIGNED, "sidecar", image_signed=True),
    ]
    world = _make_kyverno_world(containers)
    renderer = KyvernoRenderer(world)
    activity = _make_admit_activity(POD_UID_UNSIGNED)

    events = renderer.render(activity)
    assert len(events) == 2

    by_name = {ne.admission_derived.container_name: ne for ne in events}
    assert by_name["app"].kyverno.verdict == kyverno_pb2.FAIL
    assert by_name["sidecar"].kyverno.verdict == kyverno_pb2.PASS


# ---------------------------------------------------------------------------
# Context renderer tests
# ---------------------------------------------------------------------------

def _make_object_observation(uid, rv="1000", kind="Pod", ns="default", name="p1"):
    obs = context_pb2.ObjectObservation()
    obs.uid = uid
    obs.resource_version = rv
    obs.kind = kind
    obs.namespace = ns
    obs.name = name
    obs.api_group = ""
    obs.change_type = context_pb2.ADDED
    obs.observed_time.CopyFrom(_ns_to_ts(T0))
    obs.watch_stream_id = "ws-1"
    obs.watch_stream_seq = 1
    return obs


def _ns_to_ts(ns: int):
    from google.protobuf.timestamp_pb2 import Timestamp
    ts = Timestamp()
    ts.seconds = ns // 1_000_000_000
    ts.nanos = ns % 1_000_000_000
    return ts


def _make_context_world(observations):
    return types.SimpleNamespace(context_observations=observations)


def test_context_render_all_produces_normalized_events():
    """ContextRenderer.render_all() wraps every observation into a NormalizedEvent."""
    obs1 = _make_object_observation("pod-uid-0001", rv="100")
    obs2 = _make_object_observation("pod-uid-0002", rv="200")
    world = _make_context_world([obs1, obs2])
    renderer = ContextRenderer(world)

    events = renderer.render_all()

    assert len(events) == 2
    for ne in events:
        assert ne.HasField("context")
        assert ne.source == common_pb2.CLUSTER_CONTEXT


def test_context_render_one_event_id_stable():
    """Two calls to render_one with the same observation produce the same event_id."""
    obs = _make_object_observation("pod-uid-0001", rv="100")
    world = _make_context_world([obs])
    renderer = ContextRenderer(world)

    ne1 = renderer.render_one(obs)
    ne2 = renderer.render_one(obs)
    assert ne1.event_id == ne2.event_id


def test_context_time_basis_watch_observation():
    """Context events carry WATCH_OBSERVATION time basis."""
    obs = _make_object_observation("pod-uid-abc", rv="50")
    world = _make_context_world([obs])
    renderer = ContextRenderer(world)

    events = renderer.render_all()
    assert len(events) == 1
    assert events[0].time.event_time_basis == common_pb2.WATCH_OBSERVATION


# ---------------------------------------------------------------------------
# Off-node renderer tests
# ---------------------------------------------------------------------------

def _make_history_with_pod_ip():
    """WorldHistory with one Pod IP entry."""
    h = WorldHistory()

    class _FakePod:
        uid = POD_UID_SIGNED

    h.add("PodIP", POD_IP, RUN_START_NS, FOREVER, _FakePod())
    return h


def test_offnode_db_query_pod_address():
    """A db_query from a known Pod IP is classified as POD_ADDRESS."""
    history = _make_history_with_pod_ip()
    renderer = OffNodeRenderer(history)

    activity = Activity(
        time_ns=T0,
        kind="db_query",
        actor_uid="pod-uid-0001",
        actor_type="Pod",
        target_uid="infra-db",
        target_type="InfraService",
        parameters={"client_ip": POD_IP, "statement_class": "SELECT"},
    )
    events = renderer.render(activity)

    assert len(events) == 1
    ne = events[0]
    assert ne.HasField("db_audit")
    assert ne.HasField("offnode_derived")
    assert ne.offnode_derived.source_address_class == offnode_pb2.POD_ADDRESS
    assert ne.offnode_derived.pod_uid == POD_UID_SIGNED
    assert ne.source == common_pb2.DB_AUDIT


def test_offnode_db_query_unknown_ip_node_host():
    """A db_query from an unknown IP is classified as NODE_HOST_CONTEXT."""
    history = WorldHistory()
    renderer = OffNodeRenderer(history)

    activity = Activity(
        time_ns=T0,
        kind="db_query",
        actor_uid="node-uid",
        actor_type="Node",
        target_uid="infra-db",
        target_type="InfraService",
        parameters={"client_ip": "192.168.0.5"},
    )
    events = renderer.render(activity)

    assert len(events) == 1
    assert events[0].offnode_derived.source_address_class == offnode_pb2.NODE_HOST_CONTEXT


def test_offnode_path_flow_external_dst():
    """An egress_transfer to an external IP produces a PathFlowRecord."""
    history = WorldHistory()
    renderer = OffNodeRenderer(history)

    activity = Activity(
        time_ns=T0,
        kind="egress_transfer",
        actor_uid=POD_UID_SIGNED,
        actor_type="Pod",
        target_uid="1.2.3.4",
        target_type="Endpoint",
        parameters={
            "src_ip": POD_IP,
            "dst_ip": "1.2.3.4",
            "dst_port": 443,
            "octets": 500_000,
            "packets": 350,
        },
    )
    events = renderer.render(activity)

    assert len(events) == 1
    ne = events[0]
    assert ne.HasField("path_flow")
    assert ne.path_flow.octets == 500_000
    assert ne.offnode_derived.remote_class == "external"
    assert ne.source == common_pb2.PATH_FLOW


def test_offnode_unsupported_kind_returns_empty():
    """An unsupported activity kind returns an empty list."""
    history = WorldHistory()
    renderer = OffNodeRenderer(history)
    activity = Activity(
        time_ns=T0, kind="shell_exec",
        actor_uid="x", actor_type="Process",
        target_uid="y", target_type="File",
    )
    assert renderer.render(activity) == []


# ---------------------------------------------------------------------------
# Test 3: Degraded profile produces matching completeness gaps
# ---------------------------------------------------------------------------

def _make_completeness_world(n_nodes=2):
    nodes = [
        types.SimpleNamespace(uid=f"node-{i:04d}")
        for i in range(n_nodes)
    ]
    return types.SimpleNamespace(
        nodes=nodes,
        run_start_ns=RUN_START_NS,
        run_duration_ns=RUN_DURATION_NS,
    )


def test_completeness_clean_profile_no_gaps():
    """Clean profile produces NO_KNOWN_GAP status with no gaps."""
    world = _make_completeness_world(n_nodes=1)
    renderer = CompletenessRenderer(world, profile_name="clean", profile={})

    records = renderer.render_completeness()
    # ebpf(1 node) + 6 other sources = 7 records
    assert len(records) == 7
    for sc in records:
        assert sc.status == stream_pb2.NO_KNOWN_GAP
        assert len(sc.gaps) == 0


def test_completeness_degraded_gateway_has_gap():
    """degraded_gateway profile sets INCOMPLETE status for gateway source."""
    world = _make_completeness_world(n_nodes=1)
    profile = {"observer_loss_percentage": {"pilot_default": 15, "frozen": None}}
    renderer = CompletenessRenderer(
        world, profile_name="degraded_gateway", profile=profile
    )

    records = renderer.render_completeness()
    gw_records = [sc for sc in records if sc.source == common_pb2.GATEWAY]
    assert len(gw_records) == 1
    gw = gw_records[0]
    assert gw.status == stream_pb2.INCOMPLETE
    assert len(gw.gaps) == 1
    assert gw.gaps[0].reason == common_pb2.SOURCE_IDLE

    # Other sources are unaffected (clean)
    ebpf_records = [sc for sc in records if sc.source == common_pb2.EBPF]
    assert all(sc.status == stream_pb2.NO_KNOWN_GAP for sc in ebpf_records)


def test_completeness_degraded_audit_has_gap():
    """degraded_audit profile sets INCOMPLETE for audit source."""
    world = _make_completeness_world(n_nodes=1)
    profile = {"event_loss_percentage": 10}
    renderer = CompletenessRenderer(
        world, profile_name="degraded_audit", profile=profile
    )

    records = renderer.render_completeness()
    audit_records = [sc for sc in records if sc.source == common_pb2.AUDIT]
    assert len(audit_records) == 1
    assert audit_records[0].status == stream_pb2.INCOMPLETE
    assert audit_records[0].gaps[0].reason == common_pb2.DROPPED_BEFORE


def test_completeness_degraded_ebpf_has_gap():
    """degraded_ebpf profile sets INCOMPLETE for eBPF source on every node."""
    world = _make_completeness_world(n_nodes=2)
    profile = {"syscall_families_lost": ["ptrace", "clone"]}
    renderer = CompletenessRenderer(
        world, profile_name="degraded_ebpf", profile=profile
    )

    records = renderer.render_completeness()
    ebpf_records = [sc for sc in records if sc.source == common_pb2.EBPF]
    assert len(ebpf_records) == 2  # one per node
    for sc in ebpf_records:
        assert sc.status == stream_pb2.INCOMPLETE
        assert sc.gaps[0].reason == common_pb2.SOURCE_IDLE


def test_completeness_heartbeats_one_per_producer():
    """render_heartbeats() produces one heartbeat per node (eBPF) + one per other source."""
    world = _make_completeness_world(n_nodes=3)
    renderer = CompletenessRenderer(world, profile_name="clean")

    hbs = renderer.render_heartbeats()
    # 3 node-sensor heartbeats + 6 other producer heartbeats = 9 total
    assert len(hbs) == 9
    node_sensor_hbs = [h for h in hbs if h.producer_id == "node-sensor"]
    assert len(node_sensor_hbs) == 3


# ---------------------------------------------------------------------------
# Test 4: Round-trip through Envelope
# ---------------------------------------------------------------------------

_RUN_CTX = build_run_context("run-test-01", 2, "clean", "params.v0")


def _make_normalized_envelope(ne):
    import mtcodec
    ev_id = ne.event_id or mtcodec.logical_id("event", {"x": "1"})
    return build_envelope(
        kind=envelope_pb2.NORMALIZED_EVENT,
        logical_id=ev_id,
        source=ne.source,
        run_context=_RUN_CTX,
        payload=ne,
    )


def test_kyverno_ne_round_trips_envelope():
    """A kyverno NormalizedEvent serializes and deserializes through Envelope."""
    ctr = _make_container(POD_UID_UNSIGNED, CTR_NAME_APP, image_signed=False)
    world = _make_kyverno_world([ctr])
    renderer = KyvernoRenderer(world)
    activity = _make_admit_activity(POD_UID_UNSIGNED)

    ne = renderer.render(activity)[0]
    env = _make_normalized_envelope(ne)
    data = serialize_length_delimited(env)
    env2, _ = deserialize_length_delimited(data)

    assert env2.kind == envelope_pb2.NORMALIZED_EVENT
    assert env2.normalized_event.kyverno.verdict == kyverno_pb2.FAIL
    assert env2.normalized_event.admission_derived.container_name == CTR_NAME_APP


def test_context_ne_round_trips_envelope():
    """A context NormalizedEvent round-trips through Envelope."""
    obs = _make_object_observation("pod-uid-0001", rv="100")
    world = _make_context_world([obs])
    renderer = ContextRenderer(world)

    ne = renderer.render_all()[0]
    env = _make_normalized_envelope(ne)
    data = serialize_length_delimited(env)
    env2, _ = deserialize_length_delimited(data)

    assert env2.kind == envelope_pb2.NORMALIZED_EVENT
    assert env2.normalized_event.context.uid == "pod-uid-0001"


def test_offnode_db_ne_round_trips_envelope():
    """A db_audit NormalizedEvent round-trips through Envelope."""
    history = WorldHistory()
    renderer = OffNodeRenderer(history)
    activity = Activity(
        time_ns=T0,
        kind="db_query",
        actor_uid="x",
        actor_type="Pod",
        target_uid="db",
        target_type="InfraService",
        parameters={"client_ip": "10.0.0.5", "statement_class": "SELECT"},
    )

    ne = renderer.render(activity)[0]
    env = _make_normalized_envelope(ne)
    data = serialize_length_delimited(env)
    env2, _ = deserialize_length_delimited(data)

    assert env2.kind == envelope_pb2.NORMALIZED_EVENT
    assert env2.normalized_event.db_audit.statement_class == "SELECT"


def test_source_completeness_round_trips_envelope():
    """A SourceCompleteness record round-trips through Envelope."""
    import uuid
    world = _make_completeness_world(n_nodes=1)
    renderer = CompletenessRenderer(world, profile_name="clean")

    sc = renderer.render_completeness()[0]
    logical_id = f"sc_{uuid.uuid4().hex[:32]}"
    env = build_envelope(
        kind=envelope_pb2.SOURCE_COMPLETENESS,
        logical_id=logical_id,
        source=sc.source,
        run_context=_RUN_CTX,
        payload=sc,
    )
    data = serialize_length_delimited(env)
    env2, _ = deserialize_length_delimited(data)

    assert env2.kind == envelope_pb2.SOURCE_COMPLETENESS
    assert env2.source_completeness.status == stream_pb2.NO_KNOWN_GAP


def test_heartbeat_round_trips_envelope():
    """A Heartbeat record round-trips through Envelope."""
    world = _make_completeness_world(n_nodes=1)
    renderer = CompletenessRenderer(world)

    hbs = renderer.render_heartbeats()
    assert hbs
    hb = hbs[0]

    import uuid
    logical_id = f"hb_{uuid.uuid4().hex[:32]}"
    env = build_envelope(
        kind=envelope_pb2.HEARTBEAT,
        logical_id=logical_id,
        source=common_pb2.EBPF,
        run_context=_RUN_CTX,
        payload=hb,
    )
    data = serialize_length_delimited(env)
    env2, _ = deserialize_length_delimited(data)

    assert env2.kind == envelope_pb2.HEARTBEAT
    assert env2.heartbeat.producer_id == hb.producer_id


# ---------------------------------------------------------------------------
# Test 5: Every topic/kind pair is allowed by topics.yaml
# ---------------------------------------------------------------------------

def _load_topics_yaml():
    """Load the topics contract from spec/kafka/topics.yaml."""
    import os
    repo_root = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")
    )
    path = os.path.join(repo_root, "spec", "kafka", "topics.yaml")
    with open(path) as f:
        return yaml.safe_load(f)


def _build_allowed_pairs(topics_data: dict) -> dict:
    """Return {topic_name: {kind_name, ...}} from the YAML."""
    allowed = {}
    for entry in topics_data.get("topics", []):
        name = entry["name"]
        allowed[name] = set(entry.get("kinds", []))
    return allowed


def test_topic_kind_pairs_allowed_by_contract():
    """All topic/kind pairs produced by the renderers and completeness module are valid."""
    topics_data = _load_topics_yaml()
    allowed = _build_allowed_pairs(topics_data)

    # Pairs this task's code produces
    expected_pairs = [
        # Kyverno/context/offnode NormalizedEvents -> norm.events.v0
        ("norm.events.v0", "NORMALIZED_EVENT"),
        # SourceCompleteness records
        ("source.completeness.v0", "SOURCE_COMPLETENESS"),
        # Raw kyverno (before normalizer, for envelope kind check)
        ("raw.kyverno.v0", "RAW_KYVERNO"),
        ("raw.kyverno.v0", "HEARTBEAT"),
        # context.cluster.v0 raw records
        ("context.cluster.v0", "CONTEXT_OBSERVATION"),
        ("context.cluster.v0", "CONTEXT_WATCH_GAP"),
        ("context.cluster.v0", "HEARTBEAT"),
        # Off-node raw records
        ("raw.dbaudit.v0", "RAW_DB_AUDIT"),
        ("raw.dbaudit.v0", "HEARTBEAT"),
        ("raw.pathflow.v0", "RAW_PATH_FLOW"),
        ("raw.pathflow.v0", "HEARTBEAT"),
        # norm.events.v0 also carries HEARTBEAT
        ("norm.events.v0", "HEARTBEAT"),
    ]

    for topic, kind in expected_pairs:
        assert topic in allowed, f"Topic {topic!r} missing from topics.yaml"
        assert kind in allowed[topic], (
            f"Kind {kind!r} not allowed on topic {topic!r} (allowed: {allowed[topic]})"
        )
