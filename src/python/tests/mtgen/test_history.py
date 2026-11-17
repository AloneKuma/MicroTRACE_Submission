"""Tests for mtgen.history: WorldHistory interval store and Ambiguous sentinel."""
import pytest

import mtgen
from mtgen.history import WorldHistory, Ambiguous, FOREVER, ContextHistoryRow


# ---------------------------------------------------------------------------
# Sentinel
# ---------------------------------------------------------------------------

def test_ambiguous_is_singleton():
    from mtgen.history import _Ambiguous
    a1 = _Ambiguous()
    a2 = _Ambiguous()
    assert a1 is a2
    assert a1 is Ambiguous


def test_ambiguous_repr():
    assert repr(Ambiguous) == "Ambiguous"


# ---------------------------------------------------------------------------
# Basic add / at lookups
# ---------------------------------------------------------------------------

def test_at_returns_none_when_empty():
    h = WorldHistory()
    assert h.at("Pod", "uid-1", 1000) is None


def test_at_returns_none_before_valid_from():
    h = WorldHistory()
    h.add("Pod", "uid-1", 100, 200, "state-a")
    assert h.at("Pod", "uid-1", 99) is None


def test_at_returns_state_within_interval():
    h = WorldHistory()
    h.add("Pod", "uid-1", 100, 200, "state-a")
    assert h.at("Pod", "uid-1", 100) == "state-a"
    assert h.at("Pod", "uid-1", 150) == "state-a"
    assert h.at("Pod", "uid-1", 199) == "state-a"


def test_at_returns_none_at_valid_to_boundary():
    """valid_to is exclusive: at(t=valid_to) returns None."""
    h = WorldHistory()
    h.add("Pod", "uid-1", 100, 200, "state-a")
    assert h.at("Pod", "uid-1", 200) is None


def test_at_returns_none_after_valid_to():
    h = WorldHistory()
    h.add("Pod", "uid-1", 100, 200, "state-a")
    assert h.at("Pod", "uid-1", 201) is None


def test_at_different_kinds_do_not_interfere():
    h = WorldHistory()
    h.add("Pod", "key-1", 0, 100, "pod-state")
    h.add("Container", "key-1", 0, 100, "ctr-state")
    assert h.at("Pod", "key-1", 50) == "pod-state"
    assert h.at("Container", "key-1", 50) == "ctr-state"


def test_at_different_keys_do_not_interfere():
    h = WorldHistory()
    h.add("PodIP", "10.0.0.1", 0, 100, "pod-a")
    h.add("PodIP", "10.0.0.2", 0, 100, "pod-b")
    assert h.at("PodIP", "10.0.0.1", 50) == "pod-a"
    assert h.at("PodIP", "10.0.0.2", 50) == "pod-b"


# ---------------------------------------------------------------------------
# Ambiguous lookup
# ---------------------------------------------------------------------------

def test_at_ambiguous_when_two_overlap():
    """Two states with overlapping intervals return Ambiguous."""
    h = WorldHistory()
    h.add("PodIP", "10.0.0.1", 0, 200, "pod-a")   # valid [0, 200)
    h.add("PodIP", "10.0.0.1", 150, 300, "pod-b")  # valid [150, 300)
    # Ambiguity window: [150, 200)
    assert h.at("PodIP", "10.0.0.1", 175) is Ambiguous


def test_at_not_ambiguous_outside_overlap():
    h = WorldHistory()
    h.add("PodIP", "10.0.0.1", 0, 200, "pod-a")
    h.add("PodIP", "10.0.0.1", 150, 300, "pod-b")
    assert h.at("PodIP", "10.0.0.1", 50) == "pod-a"    # only pod-a
    assert h.at("PodIP", "10.0.0.1", 250) == "pod-b"   # only pod-b
    assert h.at("PodIP", "10.0.0.1", 200) == "pod-b"   # pod-a ended at 200


def test_at_pid_reuse_ambiguous():
    h = WorldHistory()
    h.add("ProcessPID", "node1:1234", 0, 300, "proc-old")
    h.add("ProcessPID", "node1:1234", 200, 500, "proc-new")
    assert h.at("ProcessPID", "node1:1234", 250) is Ambiguous
    assert h.at("ProcessPID", "node1:1234", 100) == "proc-old"
    assert h.at("ProcessPID", "node1:1234", 350) == "proc-new"


def test_at_no_ambiguity_when_gaps():
    """Sequential states with no overlap return the correct one or None."""
    h = WorldHistory()
    h.add("PodIP", "10.0.0.5", 0, 100, "pod-a")
    h.add("PodIP", "10.0.0.5", 150, 300, "pod-b")
    assert h.at("PodIP", "10.0.0.5", 125) is None
    assert h.at("PodIP", "10.0.0.5", 50) == "pod-a"
    assert h.at("PodIP", "10.0.0.5", 200) == "pod-b"


# ---------------------------------------------------------------------------
# ContextHistoryRow
# ---------------------------------------------------------------------------

def test_history_row_roundtrip():
    h = WorldHistory()
    row = ContextHistoryRow(
        run_id="run-001", entity_type="Pod", entity_uid="uid-x",
        valid_from=0, valid_to=1000, observed_from=50,
        parent_uid="node-uid", attributes={"name": "test-pod"},
        history_version="context.v0", ambiguity_reason="",
    )
    h.add_history_row(row)
    rows = h.history_rows
    assert len(rows) == 1
    assert rows[0].entity_uid == "uid-x"
    assert rows[0].entity_type == "Pod"


def test_history_rows_are_copy():
    """history_rows returns a copy, not the live list."""
    h = WorldHistory()
    rows1 = h.history_rows
    h.add_history_row(ContextHistoryRow(
        run_id="r", entity_type="Node", entity_uid="n",
        valid_from=0, valid_to=1, observed_from=0,
        parent_uid="", attributes={},
        history_version="v0", ambiguity_reason="",
    ))
    rows2 = h.history_rows
    assert len(rows1) == 0
    assert len(rows2) == 1
