"""External benchmark partition writer.

Reads dataset-review/output/<dataset>/*.jsonl.gz and manifest.json,
verifies output file sha256 hashes, and writes Parquet partitions:

  <out>/<dataset_id>/records.parquet
      Wrapper fields (record_id, dataset_id, original_file, …)
      plus manifest columns: original_archive_sha256, original_member,
      capture_id_basis.  native_label is never present.
  <out>/<dataset_id>/labels.parquet
      record_id, dataset_id, native_label, label_granularity,
      label_source, label_inherited_from.
      Rows with label_granularity "none" are excluded.
  <out>/<dataset_id>/partition_manifest.json
      Dataset metadata, local_only flag, record/label counts, hashes.

For CADETS (all rows have label_granularity "none"): labels.parquet is
empty and groundtruth/ground_truth_sessions.json is copied as
cadets_report_truth.json in the same output directory.

Usage (CLI)::

    python -m mtgen external --dataset beth --out datasets/generated/external/
    python -m mtgen external --all --out datasets/generated/external/
"""
from __future__ import annotations

import datetime
import gzip
import hashlib
import json
import shutil
import time
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

import pyarrow as pa
import pyarrow.parquet as pq

# ---------------------------------------------------------------------------
# Arrow schemas
# ---------------------------------------------------------------------------

EXTERNAL_RECORDS_SCHEMA = pa.schema([
    ("record_id",               pa.string()),
    ("dataset_id",              pa.string()),
    ("release_version",         pa.string()),
    ("original_file",           pa.string()),
    ("original_record_id",      pa.string()),
    ("capture_id",              pa.string()),
    ("native_source_type",      pa.string()),
    ("label_granularity",       pa.string()),
    ("event_time_original",     pa.string()),
    ("clock_type",              pa.string()),
    ("event_time_utc",          pa.string()),
    ("host_id",                 pa.string()),
    ("pod_uid",                 pa.string()),
    ("container_id",            pa.string()),
    ("process_id",              pa.string()),
    ("principal",               pa.string()),
    ("request_id",              pa.string()),
    ("flow_key",                pa.string()),
    ("fields",                  pa.string()),
    ("missing",                 pa.string()),
    ("parser_version",          pa.string()),
    ("original_archive_sha256", pa.string()),
    ("original_member",         pa.string()),
    ("capture_id_basis",        pa.string()),
])

EXTERNAL_LABELS_SCHEMA = pa.schema([
    ("record_id",           pa.string()),
    ("dataset_id",          pa.string()),
    ("native_label",        pa.string()),
    ("label_granularity",   pa.string()),
    ("label_source",        pa.string()),
    ("label_inherited_from", pa.string()),
])

# Datasets whose licence restricts redistribution of adapted material.
# Determined from manifest "licence" field: if it contains "local" the
# partition is marked local_only.
_LOCAL_ONLY_LICENCE_KEYWORD = "local"

# How many records to accumulate before flushing to Parquet.
_BATCH_SIZE = 50_000

# Files produced by converters that do not follow the wrapper schema
# (no record_id / dataset_id) — skip them for records/labels, but still
# include them in hash verification.
_SKIP_FOR_RECORDS = frozenset({
    "audit_event_projection.jsonl.gz",
})

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def write_external_partition(
    dataset_dir: Path,
    out_dir: Path,
) -> dict:
    """Write records.parquet and labels.parquet for one converted dataset.

    Parameters
    ----------
    dataset_dir:
        Path to dataset-review/output/<dataset>/  (must contain manifest.json).
    out_dir:
        Root output directory.  Files are written to
        ``out_dir / <dataset_id>/``.

    Returns
    -------
    dict
        The written partition_manifest dict.

    Raises
    ------
    ValueError
        If any output file's sha256 does not match the manifest.
    FileNotFoundError
        If manifest.json is not found in dataset_dir.
    """
    manifest_path = dataset_dir / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"manifest.json not found in {dataset_dir}")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    dataset_id = manifest["dataset_id"]
    partition_dir = out_dir / dataset_id
    partition_dir.mkdir(parents=True, exist_ok=True)

    # 1. Verify all output file hashes.
    _verify_output_hashes(dataset_dir, manifest)

    # 2. Derive manifest-level metadata to add to every record row.
    sha256_by_path = {
        inp["path"]: inp["sha256"]
        for inp in manifest.get("inputs", [])
    }
    original_member = manifest.get("inputs", [{}])[0].get("member") or None
    capture_id_basis = manifest.get("capture_boundary") or None
    local_only = _is_local_only(manifest)

    # 3. Enumerate output JSONL files to process.
    output_files = [
        dataset_dir / entry["path"]
        for entry in manifest.get("outputs", [])
        if entry["path"] not in _SKIP_FOR_RECORDS
    ]

    # 4. Stream-write records.parquet and labels.parquet in batches.
    records_path = partition_dir / "records.parquet"
    labels_path = partition_dir / "labels.parquet"

    total_records = 0
    total_labels = 0

    with pq.ParquetWriter(records_path, EXTERNAL_RECORDS_SCHEMA) as rec_writer, \
         pq.ParquetWriter(labels_path, EXTERNAL_LABELS_SCHEMA) as lbl_writer:

        rec_batch: List[dict] = []
        lbl_batch: List[dict] = []

        def _flush(force: bool = False) -> None:
            nonlocal total_records, total_labels
            if force or len(rec_batch) >= _BATCH_SIZE:
                if rec_batch:
                    rec_writer.write_table(
                        _records_batch_to_table(rec_batch, EXTERNAL_RECORDS_SCHEMA)
                    )
                    total_records += len(rec_batch)
                    rec_batch.clear()
            if force or len(lbl_batch) >= _BATCH_SIZE:
                if lbl_batch:
                    lbl_writer.write_table(
                        _records_batch_to_table(lbl_batch, EXTERNAL_LABELS_SCHEMA)
                    )
                    total_labels += len(lbl_batch)
                    lbl_batch.clear()

        for gz_path in output_files:
            for raw in _iter_wrapper_records(gz_path):
                # Build original_archive_sha256 per record (handles multi-input).
                original_file = raw.get("original_file") or ""
                archive_path = original_file.split("::")[0] if "::" in original_file else original_file
                original_archive_sha256 = sha256_by_path.get(archive_path) or None

                rec_batch.append(_make_record_row(
                    raw, original_archive_sha256, original_member, capture_id_basis
                ))

                # Labels: skip if label_granularity is "none" or null.
                lg = raw.get("label_granularity") or ""
                if lg and lg.lower() != "none":
                    lbl_batch.append(_make_label_row(raw))

                _flush()

        _flush(force=True)

    # 5. For CADETS: copy ground truth sessions file.
    cadets_report_src = dataset_dir / "groundtruth" / "ground_truth_sessions.json"
    if cadets_report_src.exists():
        shutil.copy2(cadets_report_src, partition_dir / "cadets_report_truth.json")

    # 6. Write partition manifest.
    part_manifest = {
        "dataset_id": dataset_id,
        "local_only": local_only,
        "converter_version": manifest.get("converter_version", ""),
        "release_version": manifest.get("release_version", ""),
        "record_count": total_records,
        "label_count": total_labels,
        "records_sha256": _file_sha256(records_path),
        "labels_sha256": _file_sha256(labels_path),
        "written_at": datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
    }
    (partition_dir / "partition_manifest.json").write_text(
        json.dumps(part_manifest, indent=1), encoding="utf-8", newline="\n"
    )

    return part_manifest


def list_convertable_datasets(converter_out: Path) -> List[Path]:
    """Return subdirectories of converter_out that contain a manifest.json."""
    return sorted(
        p for p in converter_out.iterdir()
        if p.is_dir() and (p / "manifest.json").exists()
    )


# ---------------------------------------------------------------------------
# Row builders
# ---------------------------------------------------------------------------

def _make_record_row(
    raw: dict,
    original_archive_sha256: Optional[str],
    original_member: Optional[str],
    capture_id_basis: Optional[str],
) -> dict:
    """Build a records-table row dict from a raw wrapper record."""
    evt_utc = raw.get("event_time_utc")
    if evt_utc is not None:
        evt_utc = str(evt_utc)  # may be int (epoch ns) for CADETS

    flow_key = raw.get("flow_key")
    if flow_key is not None and not isinstance(flow_key, str):
        flow_key = json.dumps(flow_key, separators=(",", ":"))

    fields = raw.get("fields")
    if fields is None:
        fields = "{}"
    elif not isinstance(fields, str):
        fields = json.dumps(fields, separators=(",", ":"))

    missing = raw.get("missing")
    if missing is not None and not isinstance(missing, str):
        missing = json.dumps(missing, separators=(",", ":"))

    return {
        "record_id":               raw.get("record_id") or "",
        "dataset_id":              raw.get("dataset_id") or "",
        "release_version":         raw.get("release_version") or None,
        "original_file":           raw.get("original_file") or None,
        "original_record_id":      raw.get("original_record_id") or None,
        "capture_id":              raw.get("capture_id") or None,
        "native_source_type":      raw.get("native_source_type") or None,
        "label_granularity":       raw.get("label_granularity") or None,
        "event_time_original":     str(raw.get("event_time_original") or "") or None,
        "clock_type":              raw.get("clock_type") or None,
        "event_time_utc":          evt_utc,
        "host_id":                 raw.get("host_id") or None,
        "pod_uid":                 raw.get("pod_uid") or None,
        "container_id":            raw.get("container_id") or None,
        "process_id":              raw.get("process_id") or None,
        "principal":               raw.get("principal") or None,
        "request_id":              raw.get("request_id") or None,
        "flow_key":                flow_key or None,
        "fields":                  fields,
        "missing":                 missing,
        "parser_version":          raw.get("parser_version") or None,
        "original_archive_sha256": original_archive_sha256,
        "original_member":         original_member,
        "capture_id_basis":        capture_id_basis,
    }


def _make_label_row(raw: dict) -> dict:
    """Build a labels-table row dict from a raw wrapper record."""
    nl = raw.get("native_label")
    if nl is not None and not isinstance(nl, str):
        nl = json.dumps(nl, separators=(",", ":"))

    return {
        "record_id":            raw.get("record_id") or "",
        "dataset_id":           raw.get("dataset_id") or "",
        "native_label":         nl,
        "label_granularity":    raw.get("label_granularity") or None,
        "label_source":         raw.get("label_source") or None,
        "label_inherited_from": raw.get("label_inherited_from") or None,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_local_only(manifest: dict) -> bool:
    """True when the manifest licence field contains the word 'local'."""
    licence = manifest.get("licence") or ""
    return _LOCAL_ONLY_LICENCE_KEYWORD in licence.lower()


def _verify_output_hashes(dataset_dir: Path, manifest: dict) -> None:
    """Raise ValueError if any listed output file's sha256 mismatches."""
    for entry in manifest.get("outputs", []):
        path = dataset_dir / entry["path"]
        expected = entry.get("sha256", "")
        if not expected:
            continue
        if not path.exists():
            raise FileNotFoundError(f"Output file missing: {path}")
        actual = _file_sha256(path)
        if actual != expected:
            raise ValueError(
                f"Hash mismatch for {entry['path']}: "
                f"expected {expected}, got {actual}"
            )


def _iter_wrapper_records(gz_path: Path) -> Iterator[dict]:
    """Yield JSON objects from a gzipped JSONL file.

    Skips lines that do not have a 'record_id' key (non-wrapper files).
    Empty files yield nothing.
    """
    if not gz_path.exists():
        return
    with gzip.open(gz_path, "rt", encoding="utf-8") as fh:
        first = True
        for line in fh:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            # Skip non-wrapper records (e.g. alternate projection files).
            if first:
                first = False
                if "record_id" not in obj:
                    return
            yield obj


def _records_batch_to_table(rows: List[dict], schema: pa.Schema) -> pa.Table:
    """Convert a list of row dicts to a PyArrow table matching schema."""
    columns: Dict[str, list] = {f.name: [] for f in schema}
    for row in rows:
        for field in schema:
            columns[field.name].append(row.get(field.name))
    arrays = []
    for field in schema:
        try:
            arrays.append(pa.array(columns[field.name], type=field.type))
        except (pa.ArrowInvalid, pa.ArrowTypeError) as exc:
            raise ValueError(f"column {field.name!r}: {exc}") from exc
    return pa.table(
        {f.name: arr for f, arr in zip(schema, arrays)},
        schema=schema,
    )


def _file_sha256(path: Path) -> str:
    """Return the hex sha256 digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
