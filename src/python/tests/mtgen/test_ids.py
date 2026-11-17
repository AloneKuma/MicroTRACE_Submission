"""Tests for mtgen.ids: deterministic UID allocation and logical IDs."""
import re
import pytest

import mtgen
from mtgen.rng import Streams
from mtgen.ids import UIDAllocator, event_logical_id

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


def test_uid_determinism():
    """Same seed and stream name produce the same UID sequence."""
    s1 = Streams("seed-uid")
    s2 = Streams("seed-uid")
    a1 = UIDAllocator(s1, "world.pods")
    a2 = UIDAllocator(s2, "world.pods")
    uids1 = [a1.next() for _ in range(10)]
    uids2 = [a2.next() for _ in range(10)]
    assert uids1 == uids2


def test_uid_stream_independence():
    """UIDs from different stream names do not coincide."""
    s = Streams("seed-uid")
    a1 = UIDAllocator(s, "world.pods")
    a2 = UIDAllocator(s, "world.containers")
    uid1 = a1.next()
    uid2 = a2.next()
    assert uid1 != uid2


def test_uid_uuid_format():
    """Allocated UIDs are valid UUID strings."""
    s = Streams("seed-uid")
    a = UIDAllocator(s, "world.nodes")
    for _ in range(5):
        uid = a.next()
        assert _UUID_RE.match(uid), f"not a UUID: {uid}"


def test_logical_id_determinism():
    """event_logical_id is deterministic for the same fields."""
    fields = {
        "source": "GATEWAY",
        "source_native_id": "req-001",
        "source_stage": "REQUEST",
        "payload_version": "v0",
    }
    id1 = event_logical_id(fields)
    id2 = event_logical_id(fields)
    assert id1 == id2
    assert id1.startswith("ev_")
    assert len(id1) == 3 + 32  # "ev_" + 32 hex chars


def test_logical_id_different_fields():
    """Different fields produce different logical IDs."""
    f1 = {"source": "GATEWAY", "source_native_id": "req-001",
          "source_stage": "REQUEST", "payload_version": "v0"}
    f2 = {"source": "GATEWAY", "source_native_id": "req-002",
          "source_stage": "REQUEST", "payload_version": "v0"}
    assert event_logical_id(f1) != event_logical_id(f2)
