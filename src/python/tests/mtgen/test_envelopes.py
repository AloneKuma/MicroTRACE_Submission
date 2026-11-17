"""Tests for mtgen.envelopes: RunContext, Envelope building, serialization."""
import pytest

import mtgen
from mtgen.envelopes import (
    build_run_context,
    build_envelope,
    serialize_length_delimited,
    deserialize_length_delimited,
)
from microtrace.v0 import envelope_pb2, common_pb2


def test_run_context_fields():
    """build_run_context populates all fields."""
    ctx = build_run_context("run-001", 2, "clean", "v0.1")
    assert ctx.run_id == "run-001"
    assert ctx.split == 2
    assert ctx.capture_profile == "clean"
    assert ctx.parameter_set_version == "v0.1"
    assert len(ctx.descriptor_set_sha256) == 64


def test_descriptor_set_sha256_deterministic():
    """descriptor_set_sha256 is the same across two calls."""
    ctx1 = build_run_context("r1", 2, "clean", "v0")
    ctx2 = build_run_context("r2", 2, "clean", "v0")
    assert ctx1.descriptor_set_sha256 == ctx2.descriptor_set_sha256


def test_build_envelope_fields():
    """build_envelope sets kind, logical_id, source, run, producer."""
    ctx = build_run_context("run-e", 2, "clean", "v0")
    env = build_envelope(
        kind=envelope_pb2.HEARTBEAT,
        logical_id="hb_0001",
        source=common_pb2.CLUSTER_CONTEXT,
        run_context=ctx,
        producer_id="test-producer",
    )
    assert env.kind == envelope_pb2.HEARTBEAT
    assert env.logical_id == "hb_0001"
    assert env.source == common_pb2.CLUSTER_CONTEXT
    assert env.run.run_id == "run-e"
    assert env.producer_id == "test-producer"


def test_round_trip():
    """Serializing and deserializing an Envelope returns an equal message."""
    ctx = build_run_context("run-rt", 2, "clean", "v0")
    env = build_envelope(
        kind=envelope_pb2.HEARTBEAT,
        logical_id="hb_rt",
        source=common_pb2.CLUSTER_CONTEXT,
        run_context=ctx,
    )
    data = serialize_length_delimited(env)
    env2, consumed = deserialize_length_delimited(data)
    assert consumed == len(data)
    assert env2.logical_id == "hb_rt"
    assert env2.kind == envelope_pb2.HEARTBEAT


def test_serialization_deterministic():
    """Two identical Envelopes serialize to identical bytes."""
    ctx = build_run_context("run-det", 2, "clean", "v0")
    env1 = build_envelope(envelope_pb2.HEARTBEAT, "hb_det",
                          common_pb2.CLUSTER_CONTEXT, ctx)
    env2 = build_envelope(envelope_pb2.HEARTBEAT, "hb_det",
                          common_pb2.CLUSTER_CONTEXT, ctx)
    assert serialize_length_delimited(env1) == serialize_length_delimited(env2)


def test_truncated_data_error():
    """deserialize_length_delimited raises on truncated data."""
    with pytest.raises(ValueError, match="insufficient"):
        deserialize_length_delimited(b"\x00\x00\x00\x10TRUNCATED")


def test_completeness_gaps():
    """build_envelope accepts Completeness with a Gap."""
    ctx = build_run_context("run-cg", 2, "clean", "v0")
    gap = common_pb2.Gap(reason=common_pb2.SOURCE_IDLE, scope="family=ebpf")
    completeness = common_pb2.Completeness(gaps=[gap])
    env = build_envelope(
        kind=envelope_pb2.HEARTBEAT,
        logical_id="hb_cg",
        source=common_pb2.CLUSTER_CONTEXT,
        run_context=ctx,
        completeness=completeness,
    )
    assert len(env.completeness.gaps) == 1
    assert env.completeness.gaps[0].reason == common_pb2.SOURCE_IDLE
