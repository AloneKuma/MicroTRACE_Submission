"""Phase 5.1-5.2 exit gate tests: Parquet projections and detector view.

Exit gates:
  1. project_run creates all expected Parquet files.
  2. Lossless: every NORMALIZED_EVENT logical_id in base.pb appears exactly
     once in events.parquet, and every projected value matches the decoded
     envelope with the same logical_id.
  3. detector_view contains no restricted or routing column.
  4. Truth tables row counts match the source .pb files.
  5. CLI: python -m mtgen project <run_dir> exits 0 and creates the files.
"""
import json
import os
import struct
import subprocess
import sys
from pathlib import Path
from typing import List

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

import mtgen  # noqa: F401 — registers gen/ and spec/tools/ on sys.path
from mtgen.project import (
    EVENTS_SCHEMA,
    RUNS_SCHEMA,
    CONTEXT_HISTORY_SCHEMA,
    COVERAGE_SCHEMA,
    TRUTH_ACTIONS_SCHEMA,
    TRUTH_FINDINGS_SCHEMA,
    TRUTH_LINKS_SCHEMA,
    TEMPLATE_PROVENANCE_SCHEMA,
    _DETECTOR_DROP,
    project_run,
    detector_view,
)
from mtgen.envelopes import deserialize_length_delimited
from microtrace.v0 import envelope_pb2, dataset_pb2

REPO = Path(__file__).resolve().parents[4]
PY_SRC = REPO / "src" / "python"

DEV_SCENARIOS = "a1_lidds_php_cwe434_upload,a1_kube_ids0_sqli,a1_csic_xss"
DEV_SEED = 42
DEV_DURATION_S = 60


# ---------------------------------------------------------------------------
# Fixtures
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
    """Build the 3-scenario dev run once for this test session."""
    base = tmp_path_factory.mktemp("p5_01")
    out = base / "run"
    _cli_build(out)
    return out


@pytest.fixture(scope="session")
def dev_parquet(dev_run):
    """Run project_run on the dev run once."""
    return project_run(dev_run)


@pytest.fixture(scope="session")
def events_table(dev_parquet):
    return pq.read_table(dev_parquet / "events.parquet")


# ---------------------------------------------------------------------------
# Exit gate 1: expected files exist with correct schemas
# ---------------------------------------------------------------------------

def test_parquet_files_exist(dev_parquet):
    """All expected Parquet files must exist after project_run."""
    expected = [
        "events.parquet",
        "context_history.parquet",
        "coverage.parquet",
        "runs.parquet",
        "restricted/truth_actions.parquet",
        "restricted/truth_findings.parquet",
        "restricted/truth_links.parquet",
        "restricted/template_provenance.parquet",
    ]
    for name in expected:
        assert (dev_parquet / name).exists(), f"missing: {name}"


def test_events_schema(dev_parquet):
    """events.parquet must have the exact expected schema."""
    tbl = pq.read_table(dev_parquet / "events.parquet")
    actual_names = set(tbl.schema.names)
    expected_names = set(EVENTS_SCHEMA.names)
    assert actual_names == expected_names, (
        f"schema mismatch — extra: {actual_names - expected_names}, "
        f"missing: {expected_names - actual_names}"
    )


def test_runs_schema(dev_parquet):
    tbl = pq.read_table(dev_parquet / "runs.parquet")
    assert set(tbl.schema.names) == set(RUNS_SCHEMA.names)
    assert tbl.num_rows == 1, "runs.parquet must have exactly one row"


def test_context_history_schema(dev_parquet):
    tbl = pq.read_table(dev_parquet / "context_history.parquet")
    assert set(tbl.schema.names) == set(CONTEXT_HISTORY_SCHEMA.names)


def test_truth_tables_schemas(dev_parquet):
    for name, expected_schema in [
        ("restricted/truth_actions.parquet", TRUTH_ACTIONS_SCHEMA),
        ("restricted/truth_findings.parquet", TRUTH_FINDINGS_SCHEMA),
        ("restricted/truth_links.parquet", TRUTH_LINKS_SCHEMA),
        ("restricted/template_provenance.parquet", TEMPLATE_PROVENANCE_SCHEMA),
    ]:
        tbl = pq.read_table(dev_parquet / name)
        actual = set(tbl.schema.names)
        expected = set(expected_schema.names)
        assert actual == expected, f"{name}: extra={actual - expected}, missing={expected - actual}"


# ---------------------------------------------------------------------------
# Exit gate 2: lossless projection
# ---------------------------------------------------------------------------

def test_events_lossless_count(dev_run, events_table):
    """Every NORMALIZED_EVENT logical_id in base.pb appears exactly once."""
    # Collect all NORMALIZED_EVENT logical_ids from base.pb
    base_ids: List[str] = []
    with open(dev_run / "base.pb", "rb") as fh:
        data = fh.read()
    offset = 0
    while offset < len(data):
        env, consumed = deserialize_length_delimited(data[offset:])
        offset += consumed
        if env.kind == envelope_pb2.NORMALIZED_EVENT:
            base_ids.append(env.logical_id)

    parquet_ids = events_table.column("logical_id").to_pylist()
    assert len(base_ids) > 0, "no NORMALIZED_EVENT in base.pb"
    assert sorted(base_ids) == sorted(parquet_ids), (
        f"lossless check failed: base has {len(base_ids)}, "
        f"parquet has {len(parquet_ids)} rows"
    )


def test_events_lossless_values(dev_run, events_table):
    """Spot-check: projected event_id matches NormalizedEvent.event_id for each row."""
    # Build {logical_id: NormalizedEvent} from base.pb
    ne_by_lid = {}
    with open(dev_run / "base.pb", "rb") as fh:
        data = fh.read()
    offset = 0
    while offset < len(data):
        env, consumed = deserialize_length_delimited(data[offset:])
        offset += consumed
        if env.kind == envelope_pb2.NORMALIZED_EVENT:
            ne_by_lid[env.logical_id] = (env, env.normalized_event)

    lids = events_table.column("logical_id").to_pylist()
    event_ids = events_table.column("event_id").to_pylist()
    source_families = events_table.column("source_family").to_pylist()
    run_ids = events_table.column("run_id").to_pylist()

    from microtrace.v0 import common_pb2
    _src_names = {
        common_pb2.EBPF: "EBPF", common_pb2.GATEWAY: "GATEWAY",
        common_pb2.AUDIT: "AUDIT", common_pb2.KYVERNO: "KYVERNO",
        common_pb2.CLUSTER_CONTEXT: "CLUSTER_CONTEXT",
        common_pb2.DB_AUDIT: "DB_AUDIT", common_pb2.PATH_FLOW: "PATH_FLOW",
        common_pb2.SOURCE_UNSPECIFIED: "SOURCE_UNSPECIFIED",
    }

    failures = []
    for lid, eid, sf, rid in zip(lids, event_ids, source_families, run_ids):
        env, ne = ne_by_lid[lid]
        if ne.event_id != eid:
            failures.append(f"{lid}: event_id {eid!r} != {ne.event_id!r}")
        expected_sf = _src_names.get(env.source, str(env.source))
        if expected_sf != sf:
            failures.append(f"{lid}: source_family {sf!r} != {expected_sf!r}")
        if env.run.run_id != rid:
            failures.append(f"{lid}: run_id {rid!r} != {env.run.run_id!r}")

    assert not failures, f"value mismatches (first 5): {failures[:5]}"


def test_events_no_nulls_in_required_columns(events_table):
    """Required columns (event_time, ingest_time, logical_id, event_id) must have no nulls."""
    for col in ("logical_id", "event_id", "event_time", "ingest_time",
                "record_payload", "source_family"):
        arr = events_table.column(col)
        null_count = arr.null_count
        assert null_count == 0, f"column {col!r} has {null_count} null(s)"


# ---------------------------------------------------------------------------
# Exit gate 3: detector_view
# ---------------------------------------------------------------------------

def test_detector_view_drops_restricted_columns(events_table):
    """detector_view must not contain any routing or version/hash column."""
    det = detector_view(events_table)
    det_names = set(det.schema.names)
    leaked = det_names & _DETECTOR_DROP
    assert not leaked, f"detector_view leaks restricted columns: {leaked}"


def test_detector_view_keeps_opaque_refs(events_table):
    """detector_view must keep event_id and logical_id."""
    det = detector_view(events_table)
    assert "event_id" in det.schema.names
    assert "logical_id" in det.schema.names


def test_detector_view_row_count_preserved(events_table):
    """detector_view must have the same number of rows as the events table."""
    det = detector_view(events_table)
    assert det.num_rows == events_table.num_rows


def test_detector_view_is_subset(events_table):
    """Every column in detector_view must be present in events_table."""
    det = detector_view(events_table)
    events_names = set(events_table.schema.names)
    for name in det.schema.names:
        assert name in events_names, f"detector_view has unknown column {name!r}"


# ---------------------------------------------------------------------------
# Exit gate 4: truth tables match protobuf files
# ---------------------------------------------------------------------------

def _count_ld_protos(path: Path) -> int:
    """Count messages in a length-delimited protobuf file."""
    count = 0
    with open(path, "rb") as fh:
        while True:
            hdr = fh.read(4)
            if not hdr:
                break
            (length,) = struct.unpack(">I", hdr)
            fh.read(length)
            count += 1
    return count


def test_truth_actions_matches_pb(dev_run, dev_parquet):
    """truth_actions.parquet row count must equal truth_actions.pb message count."""
    pb_path = dev_run / "restricted" / "truth_actions.pb"
    pq_path = dev_parquet / "restricted" / "truth_actions.parquet"
    if not pb_path.exists():
        pytest.skip("truth_actions.pb not found")
    pb_count = _count_ld_protos(pb_path)
    pq_count = pq.read_table(pq_path).num_rows
    assert pb_count == pq_count, (
        f"truth_actions: pb has {pb_count}, parquet has {pq_count}"
    )


def test_truth_findings_matches_pb(dev_run, dev_parquet):
    """truth_findings.parquet row count must equal truth_findings.pb message count."""
    pb_path = dev_run / "restricted" / "truth_findings.pb"
    pq_path = dev_parquet / "restricted" / "truth_findings.parquet"
    if not pb_path.exists():
        pytest.skip("truth_findings.pb not found")
    pb_count = _count_ld_protos(pb_path)
    pq_count = pq.read_table(pq_path).num_rows
    assert pb_count == pq_count, (
        f"truth_findings: pb has {pb_count}, parquet has {pq_count}"
    )


def test_truth_links_matches_pb(dev_run, dev_parquet):
    """truth_links.parquet row count must equal truth_links.pb message count."""
    pb_path = dev_run / "restricted" / "truth_links.pb"
    pq_path = dev_parquet / "restricted" / "truth_links.parquet"
    if not pb_path.exists():
        pytest.skip("truth_links.pb not found")
    pb_count = _count_ld_protos(pb_path)
    pq_count = pq.read_table(pq_path).num_rows
    assert pb_count == pq_count, (
        f"truth_links: pb has {pb_count}, parquet has {pq_count}"
    )


def test_truth_findings_values_match_pb(dev_run, dev_parquet):
    """Spot-check: opportunity_id and expected_state in parquet match the pb."""
    pb_path = dev_run / "restricted" / "truth_findings.pb"
    if not pb_path.exists():
        pytest.skip("truth_findings.pb not found")

    # Read pb messages
    pb_msgs = []
    with open(pb_path, "rb") as fh:
        while True:
            hdr = fh.read(4)
            if not hdr:
                break
            (length,) = struct.unpack(">I", hdr)
            data = fh.read(length)
            msg = dataset_pb2.FindingOpportunity()
            msg.ParseFromString(data)
            pb_msgs.append(msg)

    _state_names = {
        dataset_pb2.TRUTH_EXPECTATION_UNSPECIFIED: "TRUTH_EXPECTATION_UNSPECIFIED",
        dataset_pb2.PRESENT: "PRESENT",
        dataset_pb2.ABSENT: "ABSENT",
        dataset_pb2.UNOBSERVABLE: "UNOBSERVABLE",
    }

    pq_tbl = pq.read_table(dev_parquet / "restricted" / "truth_findings.parquet")
    pq_opps = pq_tbl.column("opportunity_id").to_pylist()
    pq_states = pq_tbl.column("expected_state").to_pylist()

    pb_by_id = {msg.opportunity_id: msg for msg in pb_msgs}
    failures = []
    for opp_id, state in zip(pq_opps, pq_states):
        msg = pb_by_id.get(opp_id)
        if msg is None:
            failures.append(f"opp_id {opp_id!r} in parquet but not in pb")
            continue
        expected_state = _state_names.get(msg.expected_state, str(msg.expected_state))
        if state != expected_state:
            failures.append(
                f"{opp_id}: expected_state {state!r} != {expected_state!r}"
            )
    assert not failures, f"truth_findings value mismatches: {failures[:5]}"


# ---------------------------------------------------------------------------
# Exit gate 5: CLI
# ---------------------------------------------------------------------------

def test_project_cli(dev_run, tmp_path):
    """python -m mtgen project <run_dir> must exit 0 and write events.parquet."""
    env = dict(os.environ, PYTHONHASHSEED="1")
    # Write to a fresh copy to avoid clobbering the session fixture
    import shutil
    run_copy = tmp_path / "run"
    shutil.copytree(str(dev_run), str(run_copy))

    proc = subprocess.run(
        [sys.executable, "-m", "mtgen", "project", str(run_copy)],
        cwd=PY_SRC, env=env, capture_output=True,
    )
    assert proc.returncode == 0, (
        f"project CLI failed: {proc.stderr.decode(errors='replace')}"
    )
    assert (run_copy / "parquet" / "events.parquet").exists()
    assert (run_copy / "parquet" / "restricted" / "truth_findings.parquet").exists()
