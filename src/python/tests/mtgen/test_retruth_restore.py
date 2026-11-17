"""retruth_pilot restore undoes retruth_gt too (review 2026-10-26).

A run replaced by retruth_gt has base.pb, shipper/, restricted/ and its
manifest backed up in _gates/pre-retruth-gt/; restore brought back only
_gates/pre-retruth/, so the manifest no longer matched base.pb while restore
reported success.
"""
import hashlib
import importlib.util
import json
from argparse import Namespace
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]


def _rp():
    spec = importlib.util.spec_from_file_location(
        "retruth_pilot", REPO / "src" / "scripts" / "pilot" / "retruth_pilot.py")
    rp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rp)
    return rp


def _write_run(run, base, truth, shipper):
    (run / "restricted").mkdir(parents=True, exist_ok=True)
    (run / "shipper").mkdir(exist_ok=True)
    (run / "base.pb").write_bytes(base)
    (run / "restricted" / "truth_actions.pb").write_bytes(truth)
    (run / "shipper" / "a.jsonl").write_bytes(shipper)


def _manifest(run, rp):
    (run / "manifest.json").write_text(json.dumps({"hashes": {
        "truth_sha256": rp.truth_sha(run),
        "base_stream_sha256": hashlib.sha256((run / "base.pb").read_bytes()).hexdigest()}}))


def _copy(run, dst, rels):
    for rel in rels:
        (dst / rel).parent.mkdir(parents=True, exist_ok=True)
        (dst / rel).write_bytes((run / rel).read_bytes())


def test_restore_brings_back_the_retruth_gt_files_and_checks_the_manifest(tmp_path):
    rp = _rp()
    run = tmp_path / "r1"
    _write_run(run, b"base-old", b"truth-old", b"ship-old")
    _manifest(run, rp)
    rels = ["base.pb", "manifest.json", "restricted/truth_actions.pb", "shipper/a.jsonl"]
    _copy(run, tmp_path / "_gates" / "pre-retruth" / "r1", ["manifest.json", "restricted/truth_actions.pb"])
    _copy(run, tmp_path / "_gates" / "pre-retruth-gt" / "r1", rels)
    (tmp_path / "_gates" / "pre-retruth-gt" / "r1" / "SHA256SUMS").write_text("x")
    # retruth_gt apply: a new base, truth and shipper, a file the old build lacked
    _write_run(run, b"base-new", b"truth-new", b"ship-new")
    (run / "shipper" / "b.jsonl").write_bytes(b"added")
    _manifest(run, rp)

    assert rp.restore(Namespace(runs_dir=str(tmp_path), run=None)) == 0
    assert (run / "base.pb").read_bytes() == b"base-old"
    assert (run / "shipper" / "a.jsonl").read_bytes() == b"ship-old"
    assert not (run / "shipper" / "b.jsonl").exists() and not (run / "SHA256SUMS").exists()
    assert (run / "restricted" / "truth_actions.pb").read_bytes() == b"truth-old"


def test_restore_fails_when_a_run_does_not_match_its_manifest(tmp_path):
    rp = _rp()
    run = tmp_path / "r1"
    _write_run(run, b"base-old", b"truth-old", b"ship-old")
    _manifest(run, rp)
    _copy(run, tmp_path / "_gates" / "pre-retruth" / "r1", ["manifest.json", "restricted/truth_actions.pb"])
    (run / "base.pb").write_bytes(b"base-new")     # replaced, with no pre-retruth-gt backup
    assert rp.restore(Namespace(runs_dir=str(tmp_path), run=None)) == 1
