"""Tests for phase 2.4a: evidence archive, common helpers, gateway and audit renderers.

Required tests (task spec):
  1. A1 negative control: tokens inside a JSON string field give no match.
  2. A truncated body sets body_truncated and body-class patterns abstain.
  3. An audit event round-trips through Envelope.
  4. An ambiguous Pod IP leaves peer_caller_pod_uid unset with a JOIN_UNCERTAIN gap.
  5. Evidence references resolve, and the hash matches.
"""
import pytest

import mtgen  # sets up sys.path for gen/ and spec/tools/
from mtgen.activity import Activity
from mtgen.evidence import EvidenceArchive
from mtgen.history import WorldHistory, FOREVER
from mtgen.render.common import (
    CAPTURE_MANIFEST_VERSION,
    CONTEXT_VERSION,
    NORMALIZER_VERSION,
    completeness_gap,
    event_id,
    make_entity_ref,
    make_time_info,
)
from mtgen.render.gateway import (
    BODY_CAP_BYTES,
    BODY_CONTEXT_JSON_STRING,
    GatewayRenderer,
)
from mtgen.render.audit import AuditRenderer
from mtgen.envelopes import (
    build_envelope,
    build_run_context,
    deserialize_length_delimited,
    serialize_length_delimited,
)
from microtrace.v0 import (
    audit_pb2,
    common_pb2,
    envelope_pb2,
    gateway_pb2,
    normalized_pb2,
)


# ---------------------------------------------------------------------------
# Minimal P_A / I_A2 test fixtures
# ---------------------------------------------------------------------------

_PA_MINIMAL = {
    "version": "p_a.test",
    "patterns": [
        {
            "pattern_id": "sqli_union",
            "class": "sql-injection",
            "locations": ["PATH", "QUERY", "REQUEST_BODY"],
            "regex": r"(?i)union\s+(all\s+)?select",
        },
        {
            "pattern_id": "sqli_or",
            "class": "sql-injection",
            "locations": ["QUERY", "REQUEST_BODY"],
            "regex": r"(?i)or\s+[0-9]\s*=\s*[0-9]",
        },
    ],
}

_IA2_MINIMAL = {
    "version": "i_a2.test",
    "indicators": [
        {
            "indicator_id": "sqli_2xx_success",
            "class": "sql-injection",
            "pattern_type": "status",
            "status_codes": [200, 201, 202, 204],
        },
        {
            "indicator_id": "sqli_error_mysql",
            "class": "sql-injection",
            "pattern_type": "body_marker",
            "body_regexes": [r"(?i)(SQL\s+syntax|mysql_error)"],
        },
    ],
}


# ---------------------------------------------------------------------------
# Activity helpers
# ---------------------------------------------------------------------------

def _gw_activity(time_ns: int = 1_000_000_000, **params) -> Activity:
    return Activity(
        time_ns=time_ns,
        kind="http_request",
        actor_uid="10.0.0.1",
        actor_type="External",
        target_uid="svc-web",
        target_type="Service",
        parameters=params,
    )


def _audit_activity(time_ns: int = 1_000_000_000, **params) -> Activity:
    return Activity(
        time_ns=time_ns,
        kind="api_request",
        actor_uid="sa-default",
        actor_type="ServiceAccount",
        target_uid="default/pods",
        target_type="APIResource",
        parameters=params,
    )


def _make_gw_renderer(archive=None) -> GatewayRenderer:
    if archive is None:
        archive = EvidenceArchive("test-archive-01")
    return GatewayRenderer(_PA_MINIMAL, _IA2_MINIMAL, archive)


# ---------------------------------------------------------------------------
# Evidence archive tests
# ---------------------------------------------------------------------------

def test_evidence_put_and_hash_match():
    """Evidence references resolve, and the hash matches (required test 5)."""
    arch = EvidenceArchive("arch-01")
    data = b"hello evidence bytes"
    ref = arch.put(data, common_pb2.PROTECTED_HTTP_BODY)

    assert ref.archive_id == "arch-01"
    assert len(ref.sha256_hex) == 64
    assert ref.object_key == ref.sha256_hex
    assert arch.verify(ref)
    assert arch.get(ref.object_key) == data


def test_evidence_verify_absent_key():
    """verify() returns False for an unknown object key."""
    arch = EvidenceArchive("arch-02")
    fake_key = "a" * 64
    ref = common_pb2.EvidenceRef(
        archive_id="arch-02",
        object_key=fake_key,
        sha256_hex=fake_key,
        protection=common_pb2.ORDINARY,
    )
    assert not arch.verify(ref)


def test_evidence_deduplication():
    """Identical bytes map to the same object key (content-addressed)."""
    arch = EvidenceArchive("arch-03")
    data = b"same content"
    ref1 = arch.put(data, common_pb2.PROTECTED_HTTP_BODY)
    ref2 = arch.put(data, common_pb2.PROTECTED_HTTP_BODY)
    assert ref1.object_key == ref2.object_key
    assert len(arch) == 1


# ---------------------------------------------------------------------------
# Common helper tests
# ---------------------------------------------------------------------------

def test_event_id_stable():
    """event_id produces stable ev_ prefix IDs."""
    eid = event_id("gateway", "req-001", "ResponseComplete")
    assert eid.startswith("ev_")
    assert eid == event_id("gateway", "req-001", "ResponseComplete")


def test_event_id_differs_by_stage():
    """Different stages produce different event IDs."""
    e1 = event_id("audit", "a-001", "ResponseStarted")
    e2 = event_id("audit", "a-001", "ResponseComplete")
    assert e1 != e2


def test_make_time_info_fields():
    """make_time_info populates all fields correctly."""
    ns = 1_704_067_200_000_000_000
    ti = make_time_info(ns, common_pb2.GATEWAY_OBSERVATION, uncertainty_ns=5_000_000)
    assert ti.event_time_basis == common_pb2.GATEWAY_OBSERVATION
    assert ti.source_time.seconds == ti.event_time.seconds
    assert ti.clock_uncertainty_ns == 5_000_000
    assert not ti.event_time_uncertain


def test_completeness_gap_fields():
    """completeness_gap fills reason and scope."""
    g = completeness_gap(common_pb2.JOIN_UNCERTAIN, "field=x", "detail here")
    assert g.reason == common_pb2.JOIN_UNCERTAIN
    assert g.scope == "field=x"
    assert g.detail == "detail here"


# ---------------------------------------------------------------------------
# Required test 1: A1 negative control – JSON string field gives no match
# ---------------------------------------------------------------------------

def test_a1_negative_control_json_string_field():
    """A1 negative control: tokens inside a JSON string field give no match."""
    rend = _make_gw_renderer()
    # Body contains UNION SELECT but only inside a JSON string value
    body = '{"data": "UNION SELECT * FROM users", "cmd": "cat /etc/passwd"}'
    act = _gw_activity(
        path="/api/query",
        query="",
        body=body,
        body_context=BODY_CONTEXT_JSON_STRING,
        response_status=200,
    )
    ne = rend.render(act)
    obs = ne.gateway
    assert len(obs.matches) == 0, (
        f"Expected no matches but got: {[m.pattern_id for m in obs.matches]}"
    )


def test_a1_negative_control_path_and_query_still_match():
    """Even with json_string_field context, path/query patterns still match."""
    rend = _make_gw_renderer()
    act = _gw_activity(
        path="/api/UNION SELECT 1",
        query="id=1 OR 1=1",
        body='{"x": "UNION SELECT 1"}',
        body_context=BODY_CONTEXT_JSON_STRING,
        response_status=200,
    )
    ne = rend.render(act)
    locations = {m.location for m in ne.gateway.matches}
    assert gateway_pb2.PATH in locations
    assert gateway_pb2.QUERY in locations
    assert gateway_pb2.REQUEST_BODY not in locations


# ---------------------------------------------------------------------------
# Required test 2: Truncated body sets flag; body-class patterns abstain
# ---------------------------------------------------------------------------

def test_body_truncated_flag_and_no_body_matches():
    """Truncated body sets body_truncated; body-class patterns abstain."""
    rend = _make_gw_renderer()
    # Body is just over 64 KiB with an injection pattern at the end
    large_body = "A" * (BODY_CAP_BYTES + 10) + " UNION SELECT 1 "
    act = _gw_activity(
        path="/api/data",
        query="",
        body=large_body,
        response_status=200,
    )
    ne = rend.render(act)
    obs = ne.gateway
    assert obs.body_truncated, "body_truncated should be True"
    body_matches = [m for m in obs.matches if m.location == gateway_pb2.REQUEST_BODY]
    assert len(body_matches) == 0, "body-class patterns must abstain when truncated"


def test_body_not_truncated_below_cap():
    """Body within 64 KiB does not set body_truncated."""
    rend = _make_gw_renderer()
    body = "A" * (BODY_CAP_BYTES - 1)
    act = _gw_activity(path="/api/safe", query="", body=body, response_status=200)
    ne = rend.render(act)
    assert not ne.gateway.body_truncated


# ---------------------------------------------------------------------------
# Required test 3: Audit event round-trips through Envelope
# ---------------------------------------------------------------------------

def test_audit_round_trip_envelope():
    """An audit event round-trips through Envelope (required test 3)."""
    history = WorldHistory()
    rend = AuditRenderer(history)
    act = _audit_activity(
        username="user1",
        uid="uid-001",
        groups=["system:authenticated"],
        source_ips=["10.0.0.5"],
        user_agent="kubectl/v1.28",
        verb="list",
        resource="pods",
        namespace="default",
        response_code=200,
        stage="ResponseComplete",
        level="Metadata",
    )
    ne = rend.render(act, audit_id="audit-rt-001")

    ctx = build_run_context("run-01", 2, "clean", "v0")
    env = build_envelope(
        kind=envelope_pb2.NORMALIZED_EVENT,
        logical_id=ne.event_id,
        source=common_pb2.AUDIT,
        run_context=ctx,
        payload=ne,
    )

    data = serialize_length_delimited(env)
    env2, consumed = deserialize_length_delimited(data)

    assert consumed == len(data)
    assert env2.normalized_event.source == common_pb2.AUDIT
    assert env2.normalized_event.audit.audit_id == "audit-rt-001"
    assert env2.normalized_event.audit.user.username == "user1"
    assert not env2.normalized_event.audit_derived.authentication_failed
    assert env2.normalized_event.audit_derived.observed_source == "10.0.0.5"
    assert env2.normalized_event.audit_derived.HasField("principal")


# ---------------------------------------------------------------------------
# Required test 4: Ambiguous Pod IP – peer_caller_pod_uid unset + JOIN_UNCERTAIN
# ---------------------------------------------------------------------------

def test_ambiguous_pod_ip_peer_caller_unset():
    """Ambiguous Pod IP leaves peer_caller_pod_uid unset and records JOIN_UNCERTAIN."""
    from dataclasses import dataclass

    @dataclass
    class _FakePod:
        uid: str
        namespace: str = "default"
        name: str = "pod"

    history = WorldHistory()
    # Two Pods share the same IP (overlapping valid intervals -> Ambiguous)
    history.add("PodIP", "10.0.1.50", 0, FOREVER, _FakePod(uid="pod-a"))
    history.add("PodIP", "10.0.1.50", 0, FOREVER, _FakePod(uid="pod-b"))

    rend = AuditRenderer(history)
    act = _audit_activity(
        username="user2",
        uid="uid-002",
        source_ips=["192.168.1.1", "10.0.1.50"],  # last entry is the ambiguous IP
        verb="get",
        resource="secrets",
        namespace="default",
        response_code=200,
    )
    ne = rend.render(act, audit_id="audit-ambig")

    # peer_caller_pod_uid must be absent
    assert not ne.audit_derived.HasField("peer_caller_pod_uid"), (
        f"Expected peer_caller_pod_uid unset, got {ne.audit_derived.peer_caller_pod_uid!r}"
    )
    # A JOIN_UNCERTAIN gap must be present
    gap_reasons = [g.reason for g in ne.completeness.gaps]
    assert common_pb2.JOIN_UNCERTAIN in gap_reasons, (
        f"Expected JOIN_UNCERTAIN gap, got {gap_reasons}"
    )


# ---------------------------------------------------------------------------
# Additional gateway tests
# ---------------------------------------------------------------------------

def test_pattern_match_in_path():
    """Injection pattern in the path produces PatternMatch with location=PATH."""
    rend = _make_gw_renderer()
    act = _gw_activity(
        path="/api/UNION SELECT * FROM users",
        query="",
        body="",
        response_status=200,
    )
    ne = rend.render(act)
    path_matches = [m for m in ne.gateway.matches if m.location == gateway_pb2.PATH]
    assert len(path_matches) > 0
    assert path_matches[0].pattern_id == "sqli_union"
    assert path_matches[0].pattern_set_version == "p_a.test"


def test_pattern_match_in_query():
    """Injection pattern in the query produces PatternMatch with location=QUERY."""
    rend = _make_gw_renderer()
    act = _gw_activity(
        path="/search",
        query="id=1 OR 1=1",
        body="",
        response_status=200,
    )
    ne = rend.render(act)
    q_matches = [m for m in ne.gateway.matches if m.location == gateway_pb2.QUERY]
    assert len(q_matches) > 0


def test_pattern_match_in_body():
    """Injection in the body (raw context) produces a body PatternMatch."""
    rend = _make_gw_renderer()
    act = _gw_activity(
        path="/api/submit",
        query="",
        body="data=1 UNION SELECT username, password FROM users",
        body_context="raw",
        response_status=200,
    )
    ne = rend.render(act)
    body_matches = [m for m in ne.gateway.matches if m.location == gateway_pb2.REQUEST_BODY]
    assert len(body_matches) > 0


def test_scripted_payload_pa_miss_stays_unmatched():
    """A payload with no P_A match produces no PatternMatch entries."""
    rend = _make_gw_renderer()
    act = _gw_activity(
        path="/api/safe",
        query="name=Alice&age=30",
        body="normal benign request body",
        response_status=200,
    )
    ne = rend.render(act)
    assert len(ne.gateway.matches) == 0


def test_response_indicator_status_fires_with_match():
    """I_A2 status indicator fires when there is a request match and a 2xx response."""
    rend = _make_gw_renderer()
    act = _gw_activity(
        path="/api/UNION SELECT 1",
        query="",
        body="",
        response_status=200,
        response_body="result data returned",
    )
    ne = rend.render(act)
    assert len(ne.gateway.matches) > 0
    ri_ids = [ri.indicator_id for ri in ne.gateway.response_indicators]
    assert "sqli_2xx_success" in ri_ids


def test_response_indicator_body_marker():
    """I_A2 body_marker indicator fires on MySQL error in response body."""
    rend = _make_gw_renderer()
    act = _gw_activity(
        path="/api/query",
        query="",
        body="",
        response_status=500,
        response_body="SQL syntax error near '1' at line 1",
    )
    ne = rend.render(act)
    ri_ids = [ri.indicator_id for ri in ne.gateway.response_indicators]
    assert "sqli_error_mysql" in ri_ids


def test_observer_loss_suppresses_indicators():
    """When observer_loss is set, response indicators are not computed."""
    rend = _make_gw_renderer()
    act = _gw_activity(
        path="/api/UNION SELECT 1",
        query="",
        body="",
        response_status=200,
        observer_loss=True,
    )
    ne = rend.render(act)
    assert len(ne.gateway.response_indicators) == 0


def test_gateway_event_id_prefix():
    """Gateway NormalizedEvent has an ev_ prefixed event_id."""
    rend = _make_gw_renderer()
    act = _gw_activity(path="/api/test", query="", response_status=200)
    ne = rend.render(act)
    assert ne.event_id.startswith("ev_")
    assert ne.source == common_pb2.GATEWAY


def test_body_chunk_archived():
    """Non-empty body bytes produce a body_chunk EvidenceRef in the observation."""
    arch = EvidenceArchive("arch-body")
    rend = _make_gw_renderer(archive=arch)
    act = _gw_activity(
        path="/api/test",
        query="",
        body="some body content",
        response_status=200,
    )
    ne = rend.render(act)
    obs = ne.gateway
    assert len(obs.body_chunks) == 1
    ref = obs.body_chunks[0]
    assert arch.verify(ref)
    assert ref.protection == common_pb2.PROTECTED_HTTP_BODY


# ---------------------------------------------------------------------------
# Additional audit tests
# ---------------------------------------------------------------------------

def test_audit_failed_auth_no_principal():
    """Failed authentication (401) carries no principal."""
    history = WorldHistory()
    rend = AuditRenderer(history)
    act = _audit_activity(
        username="",
        uid="",
        source_ips=["10.0.0.2"],
        verb="get",
        resource="pods",
        namespace="default",
        response_code=401,
    )
    ne = rend.render(act, audit_id="audit-fail")
    assert ne.audit_derived.authentication_failed
    assert not ne.audit_derived.HasField("principal")


def test_audit_principal_uid_preferred():
    """Principal uses user.uid (STRENGTH_HIGH) when present."""
    history = WorldHistory()
    rend = AuditRenderer(history)
    act = _audit_activity(
        username="alice",
        uid="uid-alice",
        source_ips=["10.0.0.3"],
        verb="list",
        resource="pods",
        namespace="default",
        response_code=200,
    )
    ne = rend.render(act, audit_id="audit-uid")
    assert ne.audit_derived.HasField("principal")
    p = ne.audit_derived.principal
    assert p.uid == "uid-alice"
    assert p.strength_class == common_pb2.STRENGTH_HIGH


def test_audit_principal_username_fallback():
    """Principal falls back to username (STRENGTH_MEDIUM) when uid is absent."""
    history = WorldHistory()
    rend = AuditRenderer(history)
    act = _audit_activity(
        username="bob",
        uid="",
        source_ips=["10.0.0.4"],
        verb="get",
        resource="pods",
        namespace="default",
        response_code=200,
    )
    ne = rend.render(act, audit_id="audit-name")
    assert ne.audit_derived.HasField("principal")
    p = ne.audit_derived.principal
    assert p.name == "bob"
    assert not p.HasField("uid")
    assert p.strength_class == common_pb2.STRENGTH_MEDIUM


def test_audit_bound_pod_uid_from_token_binding():
    """bound_pod_uid is populated from token binding extra keys."""
    history = WorldHistory()
    rend = AuditRenderer(history)
    act = _audit_activity(
        username="svc",
        uid="uid-svc",
        source_ips=["10.0.0.5"],
        extra={
            "authentication.kubernetes.io/pod-uid": "pod-uid-abc",
            "authentication.kubernetes.io/pod-name": "my-pod",
        },
        verb="get",
        resource="secrets",
        namespace="default",
        response_code=200,
    )
    ne = rend.render(act, audit_id="audit-binding")
    assert ne.audit_derived.HasField("bound_pod_uid")
    assert ne.audit_derived.bound_pod_uid == "pod-uid-abc"
    assert ne.audit_derived.HasField("bound_pod_name")
    assert ne.audit_derived.bound_pod_name == "my-pod"


def test_audit_used_credential_id_jti_stripped():
    """used_credential_id strips the JTI= prefix."""
    history = WorldHistory()
    rend = AuditRenderer(history)
    act = _audit_activity(
        username="svc",
        uid="uid-svc",
        source_ips=["10.0.0.6"],
        extra={
            "authentication.kubernetes.io/credential-id": "JTI=some-uuid-here",
        },
        verb="list",
        resource="pods",
        namespace="default",
        response_code=200,
    )
    ne = rend.render(act, audit_id="audit-jti")
    assert ne.audit_derived.HasField("used_credential_id")
    assert ne.audit_derived.used_credential_id == "some-uuid-here"


def test_audit_unambiguous_pod_ip_sets_peer_caller():
    """Unambiguous Pod IP -> PodIP history sets peer_caller_pod_uid."""
    from dataclasses import dataclass

    @dataclass
    class _FakePod:
        uid: str
        namespace: str = "default"
        name: str = "pod-c"

    history = WorldHistory()
    history.add("PodIP", "10.0.2.10", 0, FOREVER, _FakePod(uid="pod-c"))

    rend = AuditRenderer(history)
    act = _audit_activity(
        username="svc",
        uid="uid-svc",
        source_ips=["10.0.2.10"],
        verb="get",
        resource="pods",
        namespace="default",
        response_code=200,
    )
    ne = rend.render(act, audit_id="audit-peer")
    assert ne.audit_derived.HasField("peer_caller_pod_uid")
    assert ne.audit_derived.peer_caller_pod_uid == "pod-c"
    # No JOIN_UNCERTAIN gap
    gap_reasons = [g.reason for g in ne.completeness.gaps]
    assert common_pb2.JOIN_UNCERTAIN not in gap_reasons


def test_audit_versions_in_event():
    """NormalizedEvent carries normalizer, context, and capture manifest versions."""
    history = WorldHistory()
    rend = AuditRenderer(history)
    act = _audit_activity(
        username="u", uid="x", source_ips=[], verb="get",
        resource="pods", namespace="default", response_code=200,
    )
    ne = rend.render(act)
    assert ne.normalizer_version == NORMALIZER_VERSION
    assert ne.context_version == CONTEXT_VERSION
    assert ne.capture_manifest_version == CAPTURE_MANIFEST_VERSION


def test_gateway_versions_in_event():
    """NormalizedEvent from gateway carries version strings."""
    rend = _make_gw_renderer()
    act = _gw_activity(path="/", query="", response_status=200)
    ne = rend.render(act)
    assert ne.normalizer_version == NORMALIZER_VERSION
    assert ne.context_version == CONTEXT_VERSION
    assert ne.capture_manifest_version == CAPTURE_MANIFEST_VERSION
