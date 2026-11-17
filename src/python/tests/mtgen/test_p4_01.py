"""Phase 4.1 exit gate tests: Schema, Contract, Time, Identity checks.

Exit gates:
  1. Clean dev run passes all four checks.
  2a. Schema check: truncated base.pb frame fails.
  2b. Schema check: kind/payload mismatch fails.
  2c. Schema check: Envelope with unknown fields fails.
  2d. Schema check: NE with no record fails.
  3a. Contract check: shipper line with bad key_type fails.
  3b. Contract check: NE with wrong logical_id fails.
  3c. Contract check: NE with wrong event_id (recomputed) fails.
  4a. Time check: NE with ingest_time < event_time fails.
  4b. Time check: shipper watermark violation fails.
  5.  Identity check: pod_uid not alive in context_history fails.
  6.  from-manifest rebuild is byte-identical to original build.
"""
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

import pytest

import mtgen  # noqa: F401 — registers gen/ and spec/tools/ on sys.path
from mtgen.verify import (
    check_contract,
    check_identity,
    check_schema,
    check_time,
    verify,
    _load_base_stream,
    _load_context_history,
    _load_shipper_lines,
    _load_topics,
)
from microtrace.v0 import envelope_pb2, normalized_pb2

REPO = Path(__file__).resolve().parents[4]
PY_SRC = REPO / "src" / "python"

DEV_SCENARIOS = "a1_lidds_php_cwe434_upload,a1_kube_ids0_sqli,a1_csic_xss"
DEV_SEED = 42
DEV_DURATION_S = 60


# ---------------------------------------------------------------------------
# Build fixture (session-scoped, built once)
# ---------------------------------------------------------------------------

def _cli_build(out: Path) -> None:
    env = dict(os.environ, PYTHONHASHSEED="1", SOURCE_DATE_EPOCH="0")
    subprocess.run(
        [sys.executable, "-m", "mtgen", "build",
         "--world", "Small",
         "--scenarios", DEV_SCENARIOS,
         "--seed", str(DEV_SEED),
         "--duration-s", str(DEV_DURATION_S),
         "--out", str(out)],
        cwd=PY_SRC, env=env, check=True, capture_output=True,
    )


@pytest.fixture(scope="session")
def dev_run(tmp_path_factory):
    """Build the 3-scenario dev run once for the whole test session."""
    base = tmp_path_factory.mktemp("p4_01")
    out = base / "run"
    _cli_build(out)
    return out


# ---------------------------------------------------------------------------
# Exit gate 1: clean run passes all four checks
# ---------------------------------------------------------------------------

def test_clean_run_passes_all_checks(dev_run):
    result = verify(dev_run)
    bad = [(c.name, c.failures[:3]) for c in result.checks if not c.ok]
    assert result.ok, f"clean run failed checks: {bad}"


# ---------------------------------------------------------------------------
# Exit gate 2a: Schema – truncated frame in base.pb
# ---------------------------------------------------------------------------

def test_schema_clean_passes(dev_run):
    envelopes, load_errors = _load_base_stream(dev_run)
    r = check_schema(envelopes, load_errors)
    assert r.ok, f"schema failures on clean run: {r.failures[:5]}"
    assert r.checked > 0


def test_schema_fails_truncated_frame(tmp_path):
    """Write a base.pb whose last frame is truncated; check_schema must fail."""
    # Build a minimal valid Envelope to write first.
    env = envelope_pb2.Envelope()
    env.kind = envelope_pb2.HEARTBEAT
    env.logical_id = "hb_test"
    env.heartbeat.SetInParent()
    payload = env.SerializeToString()
    frame = struct.pack(">I", len(payload)) + payload

    # Write one complete frame + one truncated frame (header says 100 bytes, only 2 follow).
    bogus_header = struct.pack(">I", 100)
    truncated_pb = tmp_path / "base.pb"
    truncated_pb.write_bytes(frame + bogus_header + b"\x00\x01")

    run_dir = tmp_path
    envelopes, load_errors = _load_base_stream(run_dir)
    r = check_schema(envelopes, load_errors)
    assert not r.ok, "schema check must fail with truncated frame"
    assert any("truncated" in f.lower() for f in r.failures)


# ---------------------------------------------------------------------------
# Exit gate 2b: Schema – kind/payload mismatch
# ---------------------------------------------------------------------------

def test_schema_fails_kind_mismatch(dev_run):
    """Set kind=HEARTBEAT on an envelope whose payload is normalized_event."""
    envelopes, _ = _load_base_stream(dev_run)
    ne_idx = next(
        (i for i, e in enumerate(envelopes)
         if e.WhichOneof("payload") == "normalized_event"),
        None,
    )
    assert ne_idx is not None, "no NE found in dev run"

    corrupt_env = envelope_pb2.Envelope()
    corrupt_env.CopyFrom(envelopes[ne_idx])
    corrupt_env.kind = envelope_pb2.HEARTBEAT  # wrong kind for NE payload

    corrupt_envs = list(envelopes)
    corrupt_envs[ne_idx] = corrupt_env

    r = check_schema(corrupt_envs)
    assert not r.ok, "schema check must fail with kind/payload mismatch"
    assert any("kind" in f.lower() for f in r.failures)


# ---------------------------------------------------------------------------
# Exit gate 2c: Schema – unknown fields
# ---------------------------------------------------------------------------

def test_schema_fails_unknown_fields(dev_run):
    """Binary-inject an unknown proto field into the first envelope."""
    raw = (dev_run / "base.pb").read_bytes()
    first_len = struct.unpack(">I", raw[:4])[0]
    # Field 255, wire_type 0 (varint): tag = (255 << 3) | 0 = 2040 → \xf8\x0f
    # Value 1 → \x01.  Three bytes appended to the first envelope's proto bytes.
    unknown = b"\xf8\x0f\x01"
    corrupt_bytes = raw[4:4 + first_len] + unknown

    corrupt_env = envelope_pb2.Envelope()
    corrupt_env.ParseFromString(corrupt_bytes)

    clean_envs, _ = _load_base_stream(dev_run)
    corrupt_envs = [corrupt_env] + clean_envs[1:]

    r = check_schema(corrupt_envs)
    assert not r.ok, "schema check must fail with unknown fields present"
    assert any("unknown" in f.lower() for f in r.failures)


# ---------------------------------------------------------------------------
# Exit gate 2d: Schema – NE missing record field
# ---------------------------------------------------------------------------

def test_schema_fails_ne_missing_record(dev_run):
    """Replace NE payload with an empty NormalizedEvent (no record set)."""
    clean_envs, _ = _load_base_stream(dev_run)
    ne_idx = next(
        (i for i, e in enumerate(clean_envs)
         if e.WhichOneof("payload") == "normalized_event"
         and e.normalized_event.WhichOneof("record") is not None),
        None,
    )
    assert ne_idx is not None, "no NE with record found in dev run"

    corrupt_env = envelope_pb2.Envelope()
    corrupt_env.CopyFrom(clean_envs[ne_idx])
    # Replace the NE with an empty one (no record, no derived)
    corrupt_env.ClearField("normalized_event")
    corrupt_env.normalized_event.CopyFrom(normalized_pb2.NormalizedEvent(
        event_id=clean_envs[ne_idx].normalized_event.event_id,
    ))

    corrupt_envs = list(clean_envs)
    corrupt_envs[ne_idx] = corrupt_env

    r = check_schema(corrupt_envs)
    assert not r.ok, "schema check must fail with NE missing record field"
    assert any("record" in f.lower() for f in r.failures)


# ---------------------------------------------------------------------------
# Exit gate 3a: Contract – bad key_type in shipper line
# ---------------------------------------------------------------------------

def test_contract_clean_passes(dev_run):
    envelopes, _ = _load_base_stream(dev_run)
    shipper_lines = _load_shipper_lines(dev_run)
    topics = _load_topics()
    r = check_contract(envelopes, shipper_lines, topics)
    assert r.ok, f"contract failures on clean run: {r.failures[:5]}"
    assert r.checked > 0


def test_contract_fails_bad_key_type(dev_run):
    """Replace key_type in the first record line with an invalid value."""
    clean_shipper = _load_shipper_lines(dev_run)

    # Find first JSONL file with at least one record line
    target_fname = None
    target_idx = None
    for fname, lines in sorted(clean_shipper.items()):
        for i, line in enumerate(lines):
            if "topic" in line:
                target_fname = fname
                target_idx = i
                break
        if target_fname:
            break
    assert target_fname is not None, "no record line found in any shipper JSONL"

    corrupt_shipper = {k: list(v) for k, v in clean_shipper.items()}
    corrupt_line = dict(corrupt_shipper[target_fname][target_idx])
    corrupt_line["key_type"] = "KEY_BOGUS_INVALID"
    corrupt_shipper[target_fname][target_idx] = corrupt_line

    envelopes, _ = _load_base_stream(dev_run)
    topics = _load_topics()
    r = check_contract(envelopes, corrupt_shipper, topics)
    assert not r.ok, "contract check must fail with invalid key_type"
    assert any("key_type" in f or "KEY_BOGUS" in f for f in r.failures)


# ---------------------------------------------------------------------------
# Exit gate 3b: Contract – NE logical_id / event_id mismatch
# ---------------------------------------------------------------------------

def test_contract_fails_logical_id_mismatch(dev_run):
    """Set logical_id on a NE envelope to a wrong value."""
    clean_envs, _ = _load_base_stream(dev_run)
    ne_idx = next(
        (i for i, e in enumerate(clean_envs)
         if e.WhichOneof("payload") == "normalized_event"),
        None,
    )
    assert ne_idx is not None

    corrupt_env = envelope_pb2.Envelope()
    corrupt_env.CopyFrom(clean_envs[ne_idx])
    corrupt_env.logical_id = "ev_" + "0" * 32  # wrong value

    corrupt_envs = list(clean_envs)
    corrupt_envs[ne_idx] = corrupt_env

    shipper_lines = _load_shipper_lines(dev_run)
    topics = _load_topics()
    r = check_contract(corrupt_envs, shipper_lines, topics)
    assert not r.ok, "contract check must fail with mismatched logical_id"
    assert any("logical_id" in f or "event_id" in f for f in r.failures)


# ---------------------------------------------------------------------------
# Exit gate 3c: Contract – event_id recomputation mismatch
# ---------------------------------------------------------------------------

def test_contract_fails_event_id_recompute(dev_run):
    """Mutate ne.source_native_id so the recomputed event_id differs."""
    clean_envs, _ = _load_base_stream(dev_run)
    ne_idx = next(
        (i for i, e in enumerate(clean_envs)
         if e.WhichOneof("payload") == "normalized_event"
         and e.normalized_event.source_native_id),
        None,
    )
    assert ne_idx is not None, "no NE with source_native_id found"

    corrupt_env = envelope_pb2.Envelope()
    corrupt_env.CopyFrom(clean_envs[ne_idx])
    # Flip one character in source_native_id; event_id stays unchanged
    orig = corrupt_env.normalized_event.source_native_id
    corrupt_env.normalized_event.source_native_id = orig[:-1] + ("X" if orig[-1] != "X" else "Y")

    corrupt_envs = list(clean_envs)
    corrupt_envs[ne_idx] = corrupt_env

    shipper_lines = _load_shipper_lines(dev_run)
    topics = _load_topics()
    r = check_contract(corrupt_envs, shipper_lines, topics)
    assert not r.ok, "contract check must fail when recomputed event_id differs"
    assert any("recomputed" in f for f in r.failures)


# ---------------------------------------------------------------------------
# Exit gate 4a: Time – ingest_time < event_time
# ---------------------------------------------------------------------------

def test_time_clean_passes(dev_run):
    envelopes, _ = _load_base_stream(dev_run)
    shipper_lines = _load_shipper_lines(dev_run)
    r = check_time(envelopes, shipper_lines)
    assert r.ok, f"time failures on clean run: {r.failures[:5]}"
    assert r.checked > 0


def test_time_fails_ingest_before_event(dev_run):
    """Set ingest_time to 1 second before event_time on the first NE."""
    clean_envs, _ = _load_base_stream(dev_run)
    ne_idx = next(
        (i for i, e in enumerate(clean_envs)
         if e.WhichOneof("payload") == "normalized_event"
         and e.normalized_event.time.event_time.seconds > 0),
        None,
    )
    assert ne_idx is not None

    corrupt_env = envelope_pb2.Envelope()
    corrupt_env.CopyFrom(clean_envs[ne_idx])
    ne = corrupt_env.normalized_event
    ne.time.ingest_time.seconds = ne.time.event_time.seconds - 1
    ne.time.ingest_time.nanos = ne.time.event_time.nanos

    corrupt_envs = list(clean_envs)
    corrupt_envs[ne_idx] = corrupt_env

    shipper_lines = _load_shipper_lines(dev_run)
    r = check_time(corrupt_envs, shipper_lines)
    assert not r.ok, "time check must fail when ingest_time < event_time"
    assert any("ingest_time" in f for f in r.failures)


# ---------------------------------------------------------------------------
# Exit gate 4b: Time – watermark violation in shipper lane
# ---------------------------------------------------------------------------

def test_time_fails_watermark_violation(dev_run):
    """Inject a far-future watermark before an existing record line."""
    clean_shipper = _load_shipper_lines(dev_run)

    # Find first file and first record line
    target_fname = None
    target_idx = None
    for fname, lines in sorted(clean_shipper.items()):
        for i, line in enumerate(lines):
            if "topic" in line:
                target_fname = fname
                target_idx = i
                break
        if target_fname:
            break
    assert target_fname is not None, "no record line found in any shipper JSONL"

    lane = clean_shipper[target_fname][target_idx].get("lane", "NORMAL")
    future_watermark = {
        "lane": lane,
        "watermark": "2099-01-01T00:00:00.000000000Z",
    }

    corrupt_shipper = {k: list(v) for k, v in clean_shipper.items()}
    orig_lines = list(corrupt_shipper[target_fname])
    # Insert future watermark immediately before the record
    corrupt_shipper[target_fname] = (
        orig_lines[:target_idx] + [future_watermark] + orig_lines[target_idx:]
    )

    envelopes, _ = _load_base_stream(dev_run)
    r = check_time(envelopes, corrupt_shipper)
    assert not r.ok, "time check must fail with watermark violation"
    assert any("watermark" in f for f in r.failures)


# ---------------------------------------------------------------------------
# Exit gate 5a: Identity – pod UID not alive in context_history
# ---------------------------------------------------------------------------

def test_identity_clean_passes(dev_run):
    envelopes, _ = _load_base_stream(dev_run)
    context_history = _load_context_history(dev_run)
    r = check_identity(envelopes, context_history)
    assert r.ok, f"identity failures on clean run: {r.failures[:5]}"


def test_identity_fails_pod_removed_from_history(dev_run):
    """Remove a Pod row so a pod_uid reference in derived fails lookup."""
    envelopes, _ = _load_base_stream(dev_run)
    context_history = _load_context_history(dev_run)

    # Find any NE that has a non-empty Pod UID in any checked field.
    target_uid = None
    for env in envelopes:
        if env.WhichOneof("payload") != "normalized_event":
            continue
        ne = env.normalized_event
        derived = ne.WhichOneof("derived")
        if derived == "ebpf_derived":
            for cand in (
                ne.ebpf_derived.pod_uid,
                ne.ebpf_derived.remote_pod_uid,
            ):
                if cand:
                    target_uid = cand
                    break
            if target_uid:
                break
            if ne.ebpf_derived.HasField("token_file"):
                cand = ne.ebpf_derived.token_file.owner_pod_uid
                if cand:
                    target_uid = cand
                    break
        elif derived == "admission_derived" and ne.admission_derived.pod_uid:
            target_uid = ne.admission_derived.pod_uid
            break
        elif derived == "audit_derived":
            for cand in (
                ne.audit_derived.peer_caller_pod_uid,
                ne.audit_derived.resolved_target_pod_uid,
                ne.audit_derived.bound_pod_uid,
                ne.audit_derived.attributed_caller_pod_uid,
            ):
                if cand:
                    target_uid = cand
                    break
            if target_uid:
                break
        elif derived == "offnode_derived" and ne.offnode_derived.pod_uid:
            target_uid = ne.offnode_derived.pod_uid
            break

    assert target_uid is not None, (
        "no NE with non-empty pod_uid in any derived field; "
        "generator must produce pod-uid references for this test to run"
    )

    # Remove the Pod row for target_uid so the lookup fails
    corrupt_history = [
        row for row in context_history
        if not (row.get("entity_type") == "Pod"
                and row.get("entity_uid") == target_uid)
    ]
    assert len(corrupt_history) < len(context_history), (
        f"pod_uid {target_uid!r} not found in context_history rows"
    )

    r = check_identity(envelopes, corrupt_history)
    assert not r.ok, "identity check must fail when Pod row removed from history"
    assert any(target_uid in f for f in r.failures)


# ---------------------------------------------------------------------------
# Exit gate 6: from-manifest rebuild is byte-identical
# ---------------------------------------------------------------------------

def test_from_manifest_rebuild_byte_identical(tmp_path_factory):
    """Build a run, then rebuild from its manifest; base.pb must match."""
    base = tmp_path_factory.mktemp("p4_01_manifest")
    orig_dir = base / "orig"
    rebuild_dir = base / "rebuild"

    # Initial build.
    _cli_build(orig_dir)
    orig_pb = (orig_dir / "base.pb").read_bytes()

    # Rebuild from manifest.
    env = dict(os.environ, PYTHONHASHSEED="1", SOURCE_DATE_EPOCH="0")
    subprocess.run(
        [sys.executable, "-m", "mtgen", "from-manifest",
         str(orig_dir), "--out", str(rebuild_dir)],
        cwd=PY_SRC, env=env, check=True, capture_output=True,
    )
    rebuild_pb = (rebuild_dir / "base.pb").read_bytes()

    assert orig_pb == rebuild_pb, (
        f"from-manifest rebuild produced different base.pb "
        f"(orig={len(orig_pb)} bytes, rebuild={len(rebuild_pb)} bytes)"
    )


def test_identity_accepts_references_within_the_watch_deletion_lag():
    """The generator's watch deletion lag (up to 60 s) lets the normalizer resolve to a pod
    after its actual deletion; the identity check accepts that window and no more
    (declared verifier fix 2026-11-12)."""
    from microtrace.v0 import envelope_pb2
    from mtgen.world import _WATCH_DELAY_DELETE_LARGE_NS as LAG
    deleted = 1_704_067_285_714_285_714
    ctx = [{"entity_type": "Pod", "entity_uid": "pod-old", "valid_from": deleted - 85_000_000_000,
            "valid_to": deleted, "ambiguity_reason": ""}]

    def env_at(t):
        e = envelope_pb2.Envelope(logical_id=f"ev_{t}")
        e.normalized_event.time.event_time.FromNanoseconds(t)
        e.normalized_event.ebpf_derived.remote_pod_uid = "pod-old"
        return e
    inside = check_identity([env_at(deleted + 5_032_623_251)], ctx)
    assert inside.ok and inside.checked == 1, inside.failures
    edge = check_identity([env_at(deleted + LAG - 1)], ctx)
    assert edge.ok, edge.failures
    after = check_identity([env_at(deleted + LAG + 1_000_000_000)], ctx)
    assert not after.ok and "not alive" in after.failures[0]
    before = check_identity([env_at(deleted - 86_000_000_000)], ctx)
    assert not before.ok
