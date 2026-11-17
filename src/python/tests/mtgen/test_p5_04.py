"""Phase 5.4 exit gate tests: layout and sealing.

Exit gates:
  1. assemble_dataset creates all expected Parquet files.
  2. Row counts match (one run).
  3. Row counts sum correctly across two runs.
  4. manifests/dataset_manifest.json has sha256 for every output table.
  5. sha256 values in manifest match the actual files.
  6. External partitions are copied and appear in the manifest.
  7. seal_dataset writes manifests/SEALED with the correct manifest_sha256.
  8. Re-sealing raises RuntimeError.
  9. CLI: python -m mtgen assemble exits 0 and creates events.parquet.
  10. CLI: python -m mtgen seal exits 0 and creates SEALED.
  11. verify_seal detects a modified file (ok=False, file listed in modified).
  12. public_package excludes local_only external partitions; writes datasheet.
"""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

import mtgen  # noqa: F401 — registers gen/ and spec/tools/ on sys.path
from mtgen.layout import (
    PACKAGE_VERSION,
    _ALL_TABLES,
    _TABLE_SCHEMAS,
    assemble_dataset,
    public_package,
    seal_dataset,
    verify_seal,
)

REPO = Path(__file__).resolve().parents[4]
PY_SRC = REPO / "src" / "python"


# ---------------------------------------------------------------------------
# Helpers: build synthetic run parquet dirs
# ---------------------------------------------------------------------------

def _make_synthetic_parquet(run_dir: Path, run_id: str, n_events: int) -> Path:
    """Create a minimal parquet/ directory matching project_run output.

    events.parquet has n_events rows; runs.parquet has one row; all other
    tables are empty.  Returns run_dir.
    """
    pdir = run_dir / "parquet"
    (pdir / "restricted").mkdir(parents=True)

    for rel_path, schema in _TABLE_SCHEMAS.items():
        path = pdir / rel_path
        if rel_path == "events.parquet":
            tbl = _make_events_table(schema, run_id, n_events)
        elif rel_path == "runs.parquet":
            tbl = _make_runs_table(schema, run_id)
        else:
            tbl = schema.empty_table()
        pq.write_table(tbl, path)

    return run_dir


def _make_events_table(schema: pa.Schema, run_id: str, n: int) -> pa.Table:
    """Build an events table with n rows of minimal valid values."""
    cols: Dict[str, list] = {f.name: [] for f in schema}
    for i in range(n):
        for f in schema:
            if f.name == "logical_id":
                cols[f.name].append(f"ev_{run_id}_{i:04d}")
            elif f.name == "event_id":
                cols[f.name].append(f"eid_{run_id}_{i:04d}")
            elif f.name == "run_id":
                cols[f.name].append(run_id)
            elif f.name == "record_payload":
                cols[f.name].append("{}")
            elif f.name == "source_family":
                cols[f.name].append("GATEWAY")
            else:
                cols[f.name].append(None)
    arrays = [pa.array(cols[f.name], type=f.type) for f in schema]
    return pa.table(dict(zip(schema.names, arrays)), schema=schema)


def _make_runs_table(schema: pa.Schema, run_id: str) -> pa.Table:
    """Build a runs table with one row."""
    cols: Dict[str, list] = {f.name: [] for f in schema}
    for f in schema:
        cols[f.name].append(run_id if f.name == "run_id" else None)
    arrays = [pa.array(cols[f.name], type=f.type) for f in schema]
    return pa.table(dict(zip(schema.names, arrays)), schema=schema)


def _make_synthetic_external_dir(base: Path) -> Path:
    """Create a minimal external partitions directory with one dataset."""
    from mtgen.external import EXTERNAL_LABELS_SCHEMA, EXTERNAL_RECORDS_SCHEMA

    ext_dir = base / "external"
    ds_dir = ext_dir / "test-ds"
    ds_dir.mkdir(parents=True)

    rec_path = ds_dir / "records.parquet"
    lbl_path = ds_dir / "labels.parquet"
    pq.write_table(EXTERNAL_RECORDS_SCHEMA.empty_table(), rec_path)
    pq.write_table(EXTERNAL_LABELS_SCHEMA.empty_table(), lbl_path)

    def _sha(p: Path) -> str:
        return hashlib.sha256(p.read_bytes()).hexdigest()

    pm = {
        "dataset_id": "test-ds",
        "local_only": False,
        "record_count": 0,
        "label_count": 0,
        "records_sha256": _sha(rec_path),
        "labels_sha256": _sha(lbl_path),
        "written_at": "2026-10-11T00:00:00Z",
    }
    (ds_dir / "partition_manifest.json").write_text(
        json.dumps(pm), encoding="utf-8"
    )
    return ext_dir


# ---------------------------------------------------------------------------
# Session fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def syn_run_a(tmp_path_factory):
    """Synthetic run with 3 events."""
    base = tmp_path_factory.mktemp("p5_04_a")
    return _make_synthetic_parquet(base / "run_a", "run-aaa-0001", n_events=3)


@pytest.fixture(scope="session")
def syn_run_b(tmp_path_factory):
    """Synthetic run with 5 events (different run_id)."""
    base = tmp_path_factory.mktemp("p5_04_b")
    return _make_synthetic_parquet(base / "run_b", "run-bbb-0002", n_events=5)


@pytest.fixture(scope="session")
def syn_ext(tmp_path_factory):
    """Synthetic external partitions directory."""
    base = tmp_path_factory.mktemp("p5_04_ext")
    return _make_synthetic_external_dir(base)


# ---------------------------------------------------------------------------
# Exit gate 1: all expected files exist after assembly
# ---------------------------------------------------------------------------

def test_assemble_creates_all_table_files(syn_run_a, tmp_path):
    out = tmp_path / "pkg"
    assemble_dataset([syn_run_a], out)
    for rel in _ALL_TABLES:
        assert (out / rel).exists(), f"missing: {rel}"
    assert (out / "manifests" / "dataset_manifest.json").exists()


# ---------------------------------------------------------------------------
# Exit gate 2: row counts match for one run
# ---------------------------------------------------------------------------

def test_assemble_row_counts_one_run(syn_run_a, tmp_path):
    out = tmp_path / "pkg"
    manifest = assemble_dataset([syn_run_a], out)
    assert manifest["tables"]["events.parquet"]["row_count"] == 3
    assert manifest["tables"]["runs.parquet"]["row_count"] == 1
    assert manifest["run_count"] == 1
    assert manifest["run_ids"] == ["run-aaa-0001"]
    assert manifest["package_version"] == PACKAGE_VERSION


# ---------------------------------------------------------------------------
# Exit gate 3: row counts sum correctly across two runs
# ---------------------------------------------------------------------------

def test_assemble_row_counts_two_runs(syn_run_a, syn_run_b, tmp_path):
    out = tmp_path / "pkg"
    manifest = assemble_dataset([syn_run_a, syn_run_b], out)
    assert manifest["tables"]["events.parquet"]["row_count"] == 8  # 3 + 5
    assert manifest["tables"]["runs.parquet"]["row_count"] == 2
    assert manifest["run_count"] == 2
    assert sorted(manifest["run_ids"]) == ["run-aaa-0001", "run-bbb-0002"]
    # Verify the merged events table is readable and has correct count.
    tbl = pq.read_table(out / "events.parquet")
    assert tbl.num_rows == 8


# ---------------------------------------------------------------------------
# Exit gate 4: manifest has sha256 for every table
# ---------------------------------------------------------------------------

def test_manifest_has_sha256_for_all_tables(syn_run_a, tmp_path):
    out = tmp_path / "pkg"
    manifest = assemble_dataset([syn_run_a], out)
    for rel in _ALL_TABLES:
        assert rel in manifest["tables"], f"table missing in manifest: {rel}"
        sha = manifest["tables"][rel].get("sha256", "")
        assert len(sha) == 64, f"bad sha256 for {rel!r}: {sha!r}"


# ---------------------------------------------------------------------------
# Exit gate 5: sha256 values match the actual files
# ---------------------------------------------------------------------------

def test_manifest_sha256_matches_files(syn_run_a, tmp_path):
    out = tmp_path / "pkg"
    manifest = assemble_dataset([syn_run_a], out)
    for rel, info in manifest["tables"].items():
        actual = hashlib.sha256((out / rel).read_bytes()).hexdigest()
        assert actual == info["sha256"], f"sha256 mismatch for {rel!r}"


# ---------------------------------------------------------------------------
# Exit gate 6: external partitions copied and listed in manifest
# ---------------------------------------------------------------------------

def test_assemble_external_partitions(syn_run_a, syn_ext, tmp_path):
    out = tmp_path / "pkg"
    manifest = assemble_dataset([syn_run_a], out, external_dir=syn_ext)
    # Files copied.
    assert (out / "external" / "test-ds" / "records.parquet").exists()
    assert (out / "external" / "test-ds" / "labels.parquet").exists()
    assert (out / "external" / "test-ds" / "partition_manifest.json").exists()
    # Manifest entry correct.
    assert "test-ds" in manifest["external"]
    ext = manifest["external"]["test-ds"]
    assert ext["local_only"] is False
    assert len(ext.get("records_sha256") or "") == 64


# ---------------------------------------------------------------------------
# Exit gate 7: seal writes SEALED with the correct manifest_sha256
# ---------------------------------------------------------------------------

def test_seal_writes_sealed_file(syn_run_a, tmp_path):
    out = tmp_path / "pkg"
    assemble_dataset([syn_run_a], out)
    seal_record = seal_dataset(out)
    sealed_path = out / "manifests" / "SEALED"
    assert sealed_path.exists()
    data = json.loads(sealed_path.read_text(encoding="utf-8"))
    assert "sealed_at" in data
    assert data["manifest_sha256"] == seal_record["manifest_sha256"]
    # manifest_sha256 must match the file on disk.
    mp = out / "manifests" / "dataset_manifest.json"
    expected = hashlib.sha256(mp.read_bytes()).hexdigest()
    assert data["manifest_sha256"] == expected


# ---------------------------------------------------------------------------
# Exit gate 8: re-sealing raises RuntimeError
# ---------------------------------------------------------------------------

def test_seal_raises_if_already_sealed(syn_run_a, tmp_path):
    out = tmp_path / "pkg"
    assemble_dataset([syn_run_a], out)
    seal_dataset(out)
    with pytest.raises(RuntimeError, match="already sealed"):
        seal_dataset(out)


# ---------------------------------------------------------------------------
# Exit gate 9: CLI assemble
# ---------------------------------------------------------------------------

def test_assemble_cli(syn_run_a, tmp_path):
    out = tmp_path / "pkg"
    env = dict(os.environ, PYTHONHASHSEED="1")
    proc = subprocess.run(
        [sys.executable, "-m", "mtgen", "assemble",
         "--runs", str(syn_run_a),
         "--out", str(out)],
        cwd=PY_SRC, env=env, capture_output=True,
    )
    assert proc.returncode == 0, (
        f"assemble CLI failed:\n{proc.stderr.decode(errors='replace')}"
    )
    assert (out / "events.parquet").exists()
    assert (out / "manifests" / "dataset_manifest.json").exists()
    m = json.loads(
        (out / "manifests" / "dataset_manifest.json").read_text(encoding="utf-8")
    )
    assert m["package_version"] == PACKAGE_VERSION


# ---------------------------------------------------------------------------
# Exit gate 10: CLI seal
# ---------------------------------------------------------------------------

def test_seal_cli(syn_run_a, tmp_path):
    out = tmp_path / "pkg"
    assemble_dataset([syn_run_a], out)
    env = dict(os.environ, PYTHONHASHSEED="1")
    proc = subprocess.run(
        [sys.executable, "-m", "mtgen", "seal", str(out)],
        cwd=PY_SRC, env=env, capture_output=True,
    )
    assert proc.returncode == 0, (
        f"seal CLI failed:\n{proc.stderr.decode(errors='replace')}"
    )
    assert (out / "manifests" / "SEALED").exists()


# ---------------------------------------------------------------------------
# Exit gate 11: verify_seal detects a modified file
# ---------------------------------------------------------------------------

def test_verify_seal_detects_modification(syn_run_a, tmp_path):
    """verify_seal returns ok=False when a table file is modified after sealing."""
    import stat

    out = tmp_path / "pkg"
    assemble_dataset([syn_run_a], out)
    seal_dataset(out)

    # Re-enable write permission on the target file (seal makes files read-only
    # on a best-effort basis, and the test must be able to corrupt the file).
    events_path = out / "events.parquet"
    try:
        mode = events_path.stat().st_mode
        events_path.chmod(mode | stat.S_IWRITE)
    except OSError:
        pass

    # Append one null byte to corrupt the file.
    with open(events_path, "ab") as fh:
        fh.write(b"\x00")

    result = verify_seal(out)
    assert result["ok"] is False, "verify_seal should detect the corruption"
    assert "events.parquet" in result["modified"]
    assert result["checked"] >= 1


# ---------------------------------------------------------------------------
# Exit gate 12: public_package excludes local_only external partitions
# ---------------------------------------------------------------------------

def _write_ext_pm(ds_dir: Path, dataset_id: str, local_only: bool) -> None:
    """Write a minimal partition_manifest.json for an external dataset."""
    pm = {
        "dataset_id": dataset_id,
        "local_only": local_only,
        "record_count": 0,
        "label_count": 0,
        "records_sha256": "a" * 64,
        "labels_sha256": "b" * 64,
        "written_at": "2026-10-11T00:00:00Z",
    }
    (ds_dir / "partition_manifest.json").write_text(
        json.dumps(pm), encoding="utf-8"
    )


def test_public_package_excludes_local_only(syn_run_a, tmp_path):
    """public_package copies public partitions and skips local_only ones."""
    from mtgen.external import EXTERNAL_LABELS_SCHEMA, EXTERNAL_RECORDS_SCHEMA

    # Build assembled dataset with two external partitions.
    ext_dir = tmp_path / "ext"
    pub_ds_dir = ext_dir / "pub-ds"
    loc_ds_dir = ext_dir / "local-ds"
    pub_ds_dir.mkdir(parents=True)
    loc_ds_dir.mkdir(parents=True)

    pq.write_table(EXTERNAL_RECORDS_SCHEMA.empty_table(), pub_ds_dir / "records.parquet")
    pq.write_table(EXTERNAL_LABELS_SCHEMA.empty_table(), pub_ds_dir / "labels.parquet")
    _write_ext_pm(pub_ds_dir, "pub-ds", local_only=False)

    pq.write_table(EXTERNAL_RECORDS_SCHEMA.empty_table(), loc_ds_dir / "records.parquet")
    pq.write_table(EXTERNAL_LABELS_SCHEMA.empty_table(), loc_ds_dir / "labels.parquet")
    _write_ext_pm(loc_ds_dir, "local-ds", local_only=True)

    assembled = tmp_path / "assembled"
    assemble_dataset([syn_run_a], assembled, external_dir=ext_dir)

    pub_out = tmp_path / "public"
    result = public_package(assembled, pub_out)

    # Public partition is present; local-only is absent.
    assert "pub-ds" in result["included_external"]
    assert "local-ds" in result["excluded_external"]
    assert (pub_out / "external" / "pub-ds" / "records.parquet").exists()
    assert not (pub_out / "external" / "local-ds").exists()

    # Datasheet stub is written.
    datasheet = pub_out / "manifests" / "datasheet.md"
    assert datasheet.exists()
    text = datasheet.read_text(encoding="utf-8")
    assert "semi-synthetic" in text.lower()
    assert "local_only" not in text  # datasheet describes limitations, not internals

    # Generated tables are present.
    assert (pub_out / "events.parquet").exists()
    assert (pub_out / "runs.parquet").exists()
