"""Cached offline outputs (twin safety's CACHED_DIR/<run_id>.output.jsonl),
plain or gzip-compressed (no-tactic-cases-plan T1: about 400 MB a run plain,
a tenth of that compressed). The plain file wins when both exist."""
import gzip
from pathlib import Path


def find(cached_dir, run_id):
    """The run's cached output, plain or .gz; None when there is none."""
    plain = Path(cached_dir) / f"{run_id}.output.jsonl"
    if plain.exists():
        return plain
    gz = plain.with_name(plain.name + ".gz")
    return gz if gz.exists() else None


def open_text(path):
    """Open a cached output for reading text, plain or .gz."""
    if str(path).endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8")
    return open(path, encoding="utf-8")
