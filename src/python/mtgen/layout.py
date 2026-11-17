"""Layout and sealing for the assembled dataset package.

Assembles per-run Parquet projections and external partition files into
the unified dataset structure described in unified-dataset-schema.md:

    <out>/
        runs.parquet
        events.parquet
        context_history.parquet
        coverage.parquet
        restricted/
            truth_actions.parquet
            truth_findings.parquet
            truth_links.parquet
            template_provenance.parquet
        external/<dataset_id>/
            records.parquet
            labels.parquet
            partition_manifest.json
            [cadets_report_truth.json]
        manifests/
            dataset_manifest.json
            [SEALED]

Usage (CLI)::

    python -m mtgen package run1/ run2/ --root datasets/generated/package/
    python -m mtgen assemble --runs run1/ --runs run2/ --out datasets/generated/package/

    python -m mtgen seal datasets/generated/package/
    python -m mtgen verify-seal datasets/generated/package/

    python -m mtgen public-package datasets/generated/package/ --out datasets/generated/public/
"""
from __future__ import annotations

import datetime
import hashlib
import json
import shutil
import stat
from pathlib import Path
from typing import Dict, List, Optional

import pyarrow as pa
import pyarrow.parquet as pq

from .project import (
    CONTEXT_HISTORY_SCHEMA,
    COVERAGE_SCHEMA,
    EVENTS_SCHEMA,
    RUNS_SCHEMA,
    TEMPLATE_PROVENANCE_SCHEMA,
    TRUTH_ACTIONS_SCHEMA,
    TRUTH_FINDINGS_SCHEMA,
    TRUTH_LINKS_SCHEMA,
)

PACKAGE_VERSION = "v0"

_GENERATED_TABLES = [
    "events.parquet",
    "context_history.parquet",
    "coverage.parquet",
    "runs.parquet",
]

_RESTRICTED_TABLES = [
    "restricted/truth_actions.parquet",
    "restricted/truth_findings.parquet",
    "restricted/truth_links.parquet",
    "restricted/template_provenance.parquet",
]

_ALL_TABLES = _GENERATED_TABLES + _RESTRICTED_TABLES

_TABLE_SCHEMAS: Dict[str, pa.Schema] = {
    "events.parquet": EVENTS_SCHEMA,
    "context_history.parquet": CONTEXT_HISTORY_SCHEMA,
    "coverage.parquet": COVERAGE_SCHEMA,
    "runs.parquet": RUNS_SCHEMA,
    "restricted/truth_actions.parquet": TRUTH_ACTIONS_SCHEMA,
    "restricted/truth_findings.parquet": TRUTH_FINDINGS_SCHEMA,
    "restricted/truth_links.parquet": TRUTH_LINKS_SCHEMA,
    "restricted/template_provenance.parquet": TEMPLATE_PROVENANCE_SCHEMA,
}

# Files inside an external partition directory to copy verbatim.
_EXTERNAL_COPY_FILES = (
    "records.parquet",
    "labels.parquet",
    "partition_manifest.json",
    "cadets_report_truth.json",
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def assemble_dataset(
    run_dirs: List[Path],
    out_dir: Path,
    external_dir: Optional[Path] = None,
) -> dict:
    """Assemble one dataset package from one or more run directories.

    Parameters
    ----------
    run_dirs:
        Paths to run directories each containing a ``parquet/`` subdirectory
        written by ``project_run``.  Must be non-empty.
    out_dir:
        Output directory.  Created if absent.  Existing files are overwritten.
    external_dir:
        Optional directory of external partitions written by
        ``write_external_partition`` (one subdirectory per dataset_id, each
        containing ``records.parquet``, ``labels.parquet``,
        ``partition_manifest.json``).  Each partition is copied to
        ``out_dir/external/<dataset_id>/``.

    Returns
    -------
    dict
        The written ``dataset_manifest`` dict.

    Raises
    ------
    FileNotFoundError
        If any run_dir has no ``parquet/`` subdirectory.
    ValueError
        If run_dirs is empty.
    """
    if not run_dirs:
        raise ValueError("run_dirs must be non-empty")

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "restricted").mkdir(exist_ok=True)
    manifests_dir = out_dir / "manifests"
    manifests_dir.mkdir(exist_ok=True)

    # Validate and collect per-run parquet dirs.
    parquet_dirs: List[Path] = []
    for rdir in run_dirs:
        pdir = rdir / "parquet"
        if not pdir.exists():
            raise FileNotFoundError(f"parquet/ not found under {rdir}")
        parquet_dirs.append(pdir)

    # Collect run_ids from runs.parquet across all runs.
    run_ids: List[str] = []
    for pdir in parquet_dirs:
        runs_path = pdir / "runs.parquet"
        if runs_path.exists():
            tbl = pq.read_table(runs_path, columns=["run_id"])
            run_ids.extend(
                rid for rid in tbl.column("run_id").to_pylist() if rid
            )

    # Concatenate each table.
    table_info: Dict[str, dict] = {}
    for rel_path in _ALL_TABLES:
        src_paths = [pdir / rel_path for pdir in parquet_dirs]
        dst_path = out_dir / rel_path
        dst_path.parent.mkdir(parents=True, exist_ok=True)
        row_count = _concat_parquet(src_paths, dst_path, _TABLE_SCHEMAS[rel_path])
        table_info[rel_path] = {
            "sha256": _file_sha256(dst_path),
            "row_count": row_count,
        }

    # Copy external partitions.
    external_info: Dict[str, dict] = {}
    if external_dir and external_dir.exists():
        ext_out = out_dir / "external"
        ext_out.mkdir(exist_ok=True)
        for dataset_dir in sorted(external_dir.iterdir()):
            if not dataset_dir.is_dir():
                continue
            pm_path = dataset_dir / "partition_manifest.json"
            if not pm_path.exists():
                continue
            pm = json.loads(pm_path.read_text(encoding="utf-8"))
            dataset_id = pm["dataset_id"]
            dst_dataset = ext_out / dataset_id
            dst_dataset.mkdir(exist_ok=True)
            for fname in _EXTERNAL_COPY_FILES:
                src = dataset_dir / fname
                if src.exists():
                    shutil.copy2(src, dst_dataset / fname)
            external_info[dataset_id] = {
                "local_only": pm.get("local_only", False),
                "record_count": pm.get("record_count", 0),
                "label_count": pm.get("label_count", 0),
                "records_sha256": pm.get("records_sha256"),
                "labels_sha256": pm.get("labels_sha256"),
            }

    manifest = {
        "package_version": PACKAGE_VERSION,
        "assembled_at": datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "run_count": len(run_ids),
        "run_ids": sorted(set(run_ids)),
        "tables": table_info,
        "external": external_info,
    }
    (manifests_dir / "dataset_manifest.json").write_text(
        json.dumps(manifest, indent=1), encoding="utf-8", newline="\n"
    )
    return manifest


def seal_dataset(dataset_dir: Path) -> dict:
    """Write a SEALED marker for an assembled dataset.

    Records the SHA-256 of ``manifests/dataset_manifest.json`` so that any
    post-seal modification is detectable.  Makes all files read-only on a
    best-effort basis (may be skipped on some platforms).

    Parameters
    ----------
    dataset_dir:
        Path to an assembled dataset directory containing
        ``manifests/dataset_manifest.json``.

    Returns
    -------
    dict
        The seal record written to ``manifests/SEALED``.

    Raises
    ------
    FileNotFoundError
        If ``manifests/dataset_manifest.json`` does not exist.
    RuntimeError
        If the dataset is already sealed.
    """
    manifests_dir = dataset_dir / "manifests"
    manifest_path = manifests_dir / "dataset_manifest.json"
    sealed_path = manifests_dir / "SEALED"

    if not manifest_path.exists():
        raise FileNotFoundError(
            f"dataset_manifest.json not found in {manifests_dir}"
        )
    if sealed_path.exists():
        raise RuntimeError(f"dataset already sealed: {sealed_path}")

    seal_record = {
        "sealed_at": datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "manifest_sha256": _file_sha256(manifest_path),
    }
    sealed_path.write_text(json.dumps(seal_record, indent=1), encoding="utf-8", newline="\n")
    _make_readonly_best_effort(dataset_dir)
    return seal_record


# Semi-synthetic limitations text for the public datasheet stub.
# Source: docs/plans/evaluation-plan.md section 8.
_DATASHEET_LIMITATIONS = """\
# MicroTRACE Dataset — Semi-Synthetic Limitations

This dataset is semi-synthetic. The following limitations apply:

- Phase 1 enrichment (normalisation, identity resolution) and node sensing
  (Tetragon, onset sealing, coverage measured at the sensor) are described
  in the paper but not evaluated.
- Conditional findings (D2, E3, F2, G1b, G2, H5) are not included.
- Correlation links are planted by the generator; results measure how well
  Phases 2-4 recover them under controlled conditions, not whether links
  are detectable in live traffic.
- Every attack is scripted (re-enacted from public recordings where an
  anchor exists); public data shapes only the benign background. Scenario
  independence from the rulebook is limited by the safeguards in the
  generator design, not guaranteed.
- Host compromise is simulated at the sender node, not on a real exploited
  host.
- Experiment 5 (automated investigation) shows reduced retrieval effort and
  preserved correctness; human usability is not assessed.

See docs/plans/evaluation-plan.md section 8 for full details.
"""


def verify_seal(dataset_dir: Path) -> dict:
    """Verify an assembled dataset against its seal and manifest hashes.

    Reads ``manifests/SEALED`` and ``manifests/dataset_manifest.json``, then
    recomputes the SHA-256 of every table listed in the manifest and compares
    against the stored hashes.  Reports pass/fail and counts only; never
    opens restricted content.

    Parameters
    ----------
    dataset_dir:
        Path to a sealed dataset directory.

    Returns
    -------
    dict
        ``{"ok": bool, "checked": int, "modified": list[str]}``

    Raises
    ------
    FileNotFoundError
        If ``manifests/SEALED`` or ``manifests/dataset_manifest.json`` is absent.
    """
    manifests_dir = dataset_dir / "manifests"
    manifest_path = manifests_dir / "dataset_manifest.json"
    sealed_path = manifests_dir / "SEALED"

    if not sealed_path.exists():
        raise FileNotFoundError(f"SEALED not found: {sealed_path}")
    if not manifest_path.exists():
        raise FileNotFoundError(f"dataset_manifest.json not found: {manifest_path}")

    # Check that the manifest itself has not been tampered with.
    seal_record = json.loads(sealed_path.read_text(encoding="utf-8"))
    actual_manifest_sha = _file_sha256(manifest_path)
    if actual_manifest_sha != seal_record.get("manifest_sha256", ""):
        return {
            "ok": False,
            "checked": 1,
            "modified": ["manifests/dataset_manifest.json"],
        }

    # Check every table recorded in the manifest.
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    tables = manifest.get("tables", {})
    modified: List[str] = []
    checked = 0
    for rel_path, info in tables.items():
        path = dataset_dir / rel_path
        if not path.exists():
            modified.append(rel_path)
            checked += 1
            continue
        actual = _file_sha256(path)
        if actual != info.get("sha256", ""):
            modified.append(rel_path)
        checked += 1

    return {"ok": len(modified) == 0, "checked": checked, "modified": modified}


def public_package(dataset_dir: Path, out_dir: Path) -> dict:
    """Copy only the publicly distributable parts of an assembled dataset.

    Excludes external partitions whose ``partition_manifest.json`` has
    ``local_only=True`` and any run whose template provenance includes
    local-only or unverified sources (currently identified via the manifest's
    ``external`` table; per-run template filtering is deferred to pilot).

    Writes a datasheet stub at ``out_dir/manifests/datasheet.md``.

    Parameters
    ----------
    dataset_dir:
        Source assembled dataset directory (may or may not be sealed).
    out_dir:
        Output directory for the public package.  Created if absent.

    Returns
    -------
    dict
        ``{"included_external": [...], "excluded_external": [...]}``
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "restricted").mkdir(exist_ok=True)
    manifests_out = out_dir / "manifests"
    manifests_out.mkdir(exist_ok=True)

    # Copy generated tables verbatim.
    for rel_path in _GENERATED_TABLES:
        src = dataset_dir / rel_path
        if src.exists():
            shutil.copy2(src, out_dir / rel_path)

    # Copy restricted tables (truth tables are part of the public package;
    # HELD_OUT truth is governed by a separate seal, not this function).
    for rel_path in _RESTRICTED_TABLES:
        src = dataset_dir / rel_path
        if src.exists():
            dst = out_dir / rel_path
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)

    # Copy external partitions, skipping local_only ones.
    included_external: List[str] = []
    excluded_external: List[str] = []
    ext_src = dataset_dir / "external"
    if ext_src.exists():
        ext_out = out_dir / "external"
        ext_out.mkdir(exist_ok=True)
        for ds_entry in sorted(ext_src.iterdir()):
            if not ds_entry.is_dir():
                continue
            pm_path = ds_entry / "partition_manifest.json"
            if not pm_path.exists():
                continue
            pm = json.loads(pm_path.read_text(encoding="utf-8"))
            dataset_id = pm.get("dataset_id", ds_entry.name)
            if pm.get("local_only", False):
                excluded_external.append(dataset_id)
                continue
            dst_ds = ext_out / dataset_id
            dst_ds.mkdir(exist_ok=True)
            for fname in _EXTERNAL_COPY_FILES:
                src_f = ds_entry / fname
                if src_f.exists():
                    shutil.copy2(src_f, dst_ds / fname)
            included_external.append(dataset_id)

    # Copy dataset_manifest.json if present.
    src_manifest = dataset_dir / "manifests" / "dataset_manifest.json"
    if src_manifest.exists():
        shutil.copy2(src_manifest, manifests_out / "dataset_manifest.json")

    # Write datasheet stub.
    (manifests_out / "datasheet.md").write_text(
        _DATASHEET_LIMITATIONS, encoding="utf-8", newline="\n"
    )

    result: dict = {
        "included_external": included_external,
        "excluded_external": excluded_external,
    }
    (manifests_out / "public_package_manifest.json").write_text(
        json.dumps(result, indent=1), encoding="utf-8", newline="\n"
    )
    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _concat_parquet(
    src_paths: List[Path],
    dst_path: Path,
    schema: pa.Schema,
) -> int:
    """Concatenate Parquet files into dst_path; return total row count.

    Writes an empty Parquet file with the given schema when no source files
    exist or all sources are empty.
    """
    existing = [p for p in src_paths if p.exists()]
    total_rows = 0
    with pq.ParquetWriter(dst_path, schema) as writer:
        for src in existing:
            tbl = pq.read_table(src)
            if tbl.num_rows:
                writer.write_table(tbl)
            total_rows += tbl.num_rows
    return total_rows


def _file_sha256(path: Path) -> str:
    """Return the hex sha256 digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _make_readonly_best_effort(dataset_dir: Path) -> None:
    """Remove write permission from all files under dataset_dir.

    Silently ignores errors so that tests and Windows environments are
    unaffected.
    """
    try:
        for path in dataset_dir.rglob("*"):
            if path.is_file():
                try:
                    mode = path.stat().st_mode
                    path.chmod(
                        mode & ~(stat.S_IWRITE | stat.S_IWGRP | stat.S_IWOTH)
                    )
                except OSError:
                    pass
    except Exception:
        pass
