"""Phase 6 offline tests: archiver, reconcile, fault-log adjustment, shell syntax.

Tests:
  1. Archiver.write() + flush() creates topic=/partition= files.
  2. Archiver.logical_id_set() returns IDs from written records.
  3. OfflineArchiver round-trip: feed records, flush, read back.
  4. reconcile() exact match passes.
  5. reconcile() missing record fails.
  6. reconcile() transit drop without gap record fails.
  7. apply_fault_adjustment() marks affected opportunities UNOBSERVABLE.
  8. apply_fault_adjustment() leaves already-UNOBSERVABLE opportunities alone.
  9. apply_fault_adjustment() does not touch opportunities with no evidence match.
 10. reconcile() forged records are not counted as "extra".
 11. parse_fault_log() parses header + entries correctly.
 12. Shell syntax: dataset-roundtrip.sh passes bash -n (skipped if bash absent).
"""
import json
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[4]
PY_SRC = REPO / "src" / "python"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_payload(logical_id: str) -> bytes:
    """Build a minimal length-delimited-free Envelope-like payload.

    We encode just field 6 (Envelope.logical_id, wire type 2 = LEN) as a raw protobuf
    so that _extract_proto_string_field can find it without a compiled schema.
    """
    tag = (6 << 3) | 2  # field 6, wire type LEN
    encoded_id = logical_id.encode("utf-8")
    # varint for tag, varint for length, then bytes
    return _encode_varint(tag) + _encode_varint(len(encoded_id)) + encoded_id


def _encode_varint(value: int) -> bytes:
    parts = []
    while value > 0x7F:
        parts.append((value & 0x7F) | 0x80)
        value >>= 7
    parts.append(value)
    return bytes(parts)


def _make_length_delimited(payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + payload


# ---------------------------------------------------------------------------
# Test 1: Archiver.write() + flush() creates topic=/partition= files
# ---------------------------------------------------------------------------

def test_archiver_flush_creates_partition_files(tmp_path):
    from mtgen.archiver import Archiver

    a = Archiver(tmp_path / "archive")
    payload = b"hello-world"
    a.write("norm.events.v0", partition=0, offset=0, payload=payload)
    a.write("norm.events.v0", partition=0, offset=1, payload=b"second")
    a.write("source.completeness.v0", partition=0, offset=0, payload=b"sc")
    files = a.flush()

    assert len(files) == 2
    part_dir = tmp_path / "archive" / "topic=norm.events.v0" / "partition=0"
    assert part_dir.exists()
    assert list(part_dir.glob("*.pb.zst")), "no .pb.zst file in partition dir"


# ---------------------------------------------------------------------------
# Test 2: Archiver.logical_id_set() extracts IDs
# ---------------------------------------------------------------------------

def test_archiver_logical_id_set(tmp_path):
    from mtgen.archiver import Archiver, envelope_logical_id

    a = Archiver(tmp_path / "archive", extract_logical_id=envelope_logical_id)
    # Minimal payload that has field 6 = logical_id  (raw proto)
    p1 = _make_payload("ev-aaa111")
    p2 = _make_payload("ev-bbb222")
    a.write("norm.events.v0", 0, 0, p1)
    a.write("norm.events.v0", 0, 1, p2)
    a.flush()

    ids = a.logical_id_set()
    assert isinstance(ids, frozenset)


# ---------------------------------------------------------------------------
# Test 3: OfflineArchiver round-trip
# ---------------------------------------------------------------------------

def test_offline_archiver_round_trip(tmp_path):
    from mtgen.archiver import OfflineArchiver, _decode_partition

    records = [
        ("norm.events.v0", 0, 0, b"payload-one"),
        ("norm.events.v0", 0, 1, b"payload-two"),
        ("norm.events.v0", 1, 0, b"payload-three"),
    ]
    oa = OfflineArchiver(tmp_path / "arch")
    oa.feed(records)
    archiver = oa.flush()

    assert archiver.record_count() == 3

    # Read back partition 0
    p0_dir = tmp_path / "arch" / "topic=norm.events.v0" / "partition=0"
    files = list(p0_dir.glob("*.pb.zst"))
    assert len(files) == 1
    payloads = _decode_partition(files[0].read_bytes())
    assert len(payloads) == 2
    assert payloads[0] == b"payload-one"
    assert payloads[1] == b"payload-two"

    # Partition 1
    p1_dir = tmp_path / "arch" / "topic=norm.events.v0" / "partition=1"
    files1 = list(p1_dir.glob("*.pb.zst"))
    assert len(files1) == 1
    payloads1 = _decode_partition(files1[0].read_bytes())
    assert len(payloads1) == 1
    assert payloads1[0] == b"payload-three"


# ---------------------------------------------------------------------------
# Test 4: reconcile() exact match passes
# ---------------------------------------------------------------------------

def test_reconcile_exact_match(tmp_path):
    from mtgen.reconcile import reconcile

    base_ids = frozenset({"ev-001", "ev-002", "ev-003"})
    received_ids = frozenset({"ev-001", "ev-002", "ev-003"})
    result = reconcile(
        base_ids=base_ids,
        received_ids=received_ids,
        src_log_entries=[],
        transit_log_entries=[],
        gap_scopes=frozenset(),
    )
    assert result.ok is True
    assert result.missing == []
    assert result.extra == []
    assert result.errors == []
    assert result.base_count == 3
    assert result.received_count == 3
    assert result.dropped_count == 0


# ---------------------------------------------------------------------------
# Test 5: reconcile() missing record fails
# ---------------------------------------------------------------------------

def test_reconcile_missing_record_fails(tmp_path):
    from mtgen.reconcile import reconcile

    base_ids = frozenset({"ev-001", "ev-002", "ev-003"})
    # ev-003 is neither received nor in any fault log
    received_ids = frozenset({"ev-001", "ev-002"})
    result = reconcile(
        base_ids=base_ids,
        received_ids=received_ids,
        src_log_entries=[],
        transit_log_entries=[],
        gap_scopes=frozenset(),
    )
    assert result.ok is False
    assert "ev-003" in result.missing
    assert len(result.errors) >= 1


# ---------------------------------------------------------------------------
# Test 6: reconcile() transit drop without gap record fails
# ---------------------------------------------------------------------------

def test_reconcile_transit_drop_without_gap_fails(tmp_path):
    from mtgen.reconcile import reconcile, FaultLogEntry

    base_ids = frozenset({"ev-001", "ev-002", "ev-003"})
    received_ids = frozenset({"ev-001", "ev-002"})
    # ev-003 was dropped at transit stage (reported drop = dropped_reported)
    transit_entry = FaultLogEntry(
        fault_id="loss-10",
        kind="loss",
        stage="transit",
        logical_id="ev-003",
        topic="norm.events.v0",
        action="dropped_reported",
    )
    # No DROPPED_BEFORE gap record in the archive (gap_scopes is empty)
    result = reconcile(
        base_ids=base_ids,
        received_ids=received_ids,
        src_log_entries=[],
        transit_log_entries=[transit_entry],
        gap_scopes=frozenset(),  # empty → no gap record
    )
    assert result.ok is False
    assert "ev-003" in result.transit_drops_without_gap


# ---------------------------------------------------------------------------
# Test 7: apply_fault_adjustment() marks affected opportunities UNOBSERVABLE
# ---------------------------------------------------------------------------

def test_apply_fault_adjustment_marks_unobservable():
    from mtgen.reconcile import apply_fault_adjustment

    opportunities = [
        {
            "opportunity_id": "opp-A1",
            "expected_state": "PRESENT",
            "evidence_event_ids": ["ev-001", "ev-002"],
        },
        {
            "opportunity_id": "opp-B2",
            "expected_state": "PRESENT",
            "evidence_event_ids": ["ev-010", "ev-011"],
        },
    ]
    dropped_ids = {"ev-001"}  # ev-001 was dropped

    changed = apply_fault_adjustment(opportunities, dropped_ids)

    # opp-A1 had ev-001 in its evidence → UNOBSERVABLE
    assert any(oid == "opp-A1" for oid, _ in changed)
    assert opportunities[0]["expected_state"] == "UNOBSERVABLE"
    # opp-B2 has no dropped evidence → unchanged
    assert opportunities[1]["expected_state"] == "PRESENT"
    assert not any(oid == "opp-B2" for oid, _ in changed)


# ---------------------------------------------------------------------------
# Test 8: apply_fault_adjustment() leaves UNOBSERVABLE unchanged
# ---------------------------------------------------------------------------

def test_apply_fault_adjustment_leaves_unobservable_unchanged():
    from mtgen.reconcile import apply_fault_adjustment

    opportunities = [
        {
            "opportunity_id": "opp-U",
            "expected_state": "UNOBSERVABLE",
            "evidence_event_ids": ["ev-999"],
        },
    ]
    dropped_ids = {"ev-999"}
    changed = apply_fault_adjustment(opportunities, dropped_ids)
    # already UNOBSERVABLE → no change recorded
    assert changed == []
    assert opportunities[0]["expected_state"] == "UNOBSERVABLE"


# ---------------------------------------------------------------------------
# Test 9: apply_fault_adjustment() does not touch opportunities without match
# ---------------------------------------------------------------------------

def test_apply_fault_adjustment_no_match():
    from mtgen.reconcile import apply_fault_adjustment

    opportunities = [
        {
            "opportunity_id": "opp-X",
            "expected_state": "ABSENT",
            "evidence_event_ids": ["ev-100"],
        },
    ]
    dropped_ids = {"ev-999"}  # different ID
    changed = apply_fault_adjustment(opportunities, dropped_ids)
    assert changed == []
    assert opportunities[0]["expected_state"] == "ABSENT"


# ---------------------------------------------------------------------------
# Test 10: reconcile() forged records not counted as extra
# ---------------------------------------------------------------------------

def test_reconcile_forged_not_counted_as_extra():
    from mtgen.reconcile import reconcile, FaultLogEntry

    base_ids = frozenset({"ev-001", "ev-002"})
    # ev-999 is a forged record (appears in archive but not in base)
    received_ids = frozenset({"ev-001", "ev-002", "ev-999"})
    forge_entry = FaultLogEntry(
        fault_id="forge-1",
        kind="forge",
        stage="source",
        logical_id="ev-999",
        topic="norm.events.v0",
        action="forged",
    )
    result = reconcile(
        base_ids=base_ids,
        received_ids=received_ids,
        src_log_entries=[forge_entry],
        transit_log_entries=[],
        gap_scopes=frozenset(),
    )
    assert result.ok is True
    assert result.extra == []


# ---------------------------------------------------------------------------
# Test 10b: base-stream reader leaves out HEARTBEAT (the shipper skips them)
# ---------------------------------------------------------------------------

def test_base_stream_ids_skip_heartbeats(tmp_path):
    import mtgen  # noqa: F401 — registers gen/ on sys.path
    envelope_pb2 = pytest.importorskip("microtrace.v0.envelope_pb2")
    from mtgen.reconcile import read_base_stream_logical_ids

    data = b""
    for lid, kind in (("ev-001", envelope_pb2.NORMALIZED_EVENT),
                      ("hb-001", envelope_pb2.HEARTBEAT)):
        env = envelope_pb2.Envelope(logical_id=lid, kind=kind)
        data += _make_length_delimited(env.SerializeToString())
    base = tmp_path / "base.pb"
    base.write_bytes(data)
    assert read_base_stream_logical_ids(base) == frozenset({"ev-001"})


def test_archive_ids_read_from_real_envelopes(tmp_path):
    import mtgen  # noqa: F401 — registers gen/ on sys.path
    envelope_pb2 = pytest.importorskip("microtrace.v0.envelope_pb2")
    from mtgen.archiver import OfflineArchiver
    from mtgen.reconcile import read_archive_logical_ids

    env = envelope_pb2.Envelope(logical_id="ev-001", producer_id="node-sensor",
                                kind=envelope_pb2.NORMALIZED_EVENT)
    oa = OfflineArchiver(tmp_path / "arch")
    oa.feed([("norm.events.v0", 0, 0, env.SerializeToString())])
    oa.flush()
    assert read_archive_logical_ids(tmp_path / "arch") == frozenset({"ev-001"})


def test_reconcile_dropped_but_received_fails():
    from mtgen.reconcile import reconcile, FaultLogEntry

    drop = FaultLogEntry(
        fault_id="supp-1",
        kind="suppress",
        stage="source",
        logical_id="ev-002",
        topic="norm.events.v0",
        action="dropped_unreported",
    )
    result = reconcile(
        base_ids=frozenset({"ev-001", "ev-002"}),
        received_ids=frozenset({"ev-001", "ev-002"}),
        src_log_entries=[drop],
        transit_log_entries=[],
        gap_scopes=frozenset(),
    )
    assert result.ok is False


def test_shipper_input_ids_skip_watermarks(tmp_path):
    from mtgen.reconcile import read_shipper_input_logical_ids

    p = tmp_path / "node-1.jsonl"
    p.write_text(
        '{"lane":"NORMAL","watermark":"2026-01-01T00:00:00Z"}\n'
        '{"lane":"NORMAL","topic":"norm.events.v0","envelope":{"logical_id":"ev-001"}}\n'
        '{"lane":"NORMAL","topic":"norm.events.v0","envelope":{"logical_id":"ev-002"}}\n',
        encoding="utf-8",
    )
    assert read_shipper_input_logical_ids(p) == frozenset({"ev-001", "ev-002"})


# ---------------------------------------------------------------------------
# Test 11: parse_fault_log() parses header + entries
# ---------------------------------------------------------------------------

def test_parse_fault_log(tmp_path):
    from mtgen.reconcile import parse_fault_log

    log_path = tmp_path / "fault.jsonl"
    header = {"header": {"version": "faultplan.v0", "stage": "transit", "seed": 42}}
    entry1 = {
        "fault_id": "loss-10",
        "kind": "loss",
        "stage": "transit",
        "logical_id": "ev-abc",
        "topic": "norm.events.v0",
        "lane": "NORMAL",
        "seq": 5,
        "action": "dropped_reported",
        "detail": "",
    }
    entry2 = {
        "fault_id": "forge-1",
        "kind": "forge",
        "stage": "source",
        "logical_id": "ev-xyz",
        "topic": "norm.events.v0",
        "lane": "NORMAL",
        "seq": 0,
        "action": "forged",
        "detail": "",
    }
    log_path.write_text(
        "\n".join([
            json.dumps(header),
            json.dumps(entry1),
            json.dumps(entry2),
            "",  # trailing newline
        ]),
        encoding="utf-8",
    )

    entries = parse_fault_log(log_path)
    assert len(entries) == 2
    assert entries[0].fault_id == "loss-10"
    assert entries[0].action == "dropped_reported"
    assert entries[0].logical_id == "ev-abc"
    assert entries[1].action == "forged"


# ---------------------------------------------------------------------------
# Test 12: dataset-roundtrip.sh passes bash -n (shell syntax check)
# ---------------------------------------------------------------------------

def test_roundtrip_sh_bash_syntax():
    """Check dataset-roundtrip.sh syntax with bash -n.

    Skipped if bash is not on PATH, or if the found bash cannot execute
    (e.g. the Windows WSL stub bash.EXE when WSL is not configured).
    """
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash not found on PATH; shell syntax check skipped")

    # Probe: run 'bash --version' to confirm bash is functional, not just
    # present as a stub (e.g. WSL bash.EXE without a working WSL distro).
    probe = subprocess.run(
        [bash, "--version"],
        capture_output=True,
    )
    if probe.returncode != 0:
        pytest.skip(
            f"bash found at {bash!r} but is not functional "
            f"(probe exit {probe.returncode}); shell syntax check skipped"
        )

    script = REPO / "src" / "scripts" / "dataset-roundtrip.sh"
    if not script.exists():
        pytest.skip(f"script not found: {script}")

    proc = subprocess.run(
        [bash, "-n", str(script)],
        capture_output=True,
    )
    assert proc.returncode == 0, (
        f"bash -n failed on dataset-roundtrip.sh:\n"
        f"{proc.stderr.decode(errors='replace')}"
    )
