"""Phase 4.3 exit gate tests: nuisance check and audit trace.

Exit gates:
  1. Nuisance check fails on a split where nuisance features carry the label.
  2. Nuisance check passes on a balanced split (no nuisance signal).
  3. Audit trace renders for a real dev run (produces non-empty markdown).
  4. Audit refuses to run on a HELD_OUT run.
"""
import json
import os
import struct
import subprocess
import sys
from pathlib import Path
from typing import List

import pytest

import mtgen  # noqa: F401 — registers gen/ and spec/tools/ on sys.path
from mtgen.nuisance import check_nuisance, NuisanceResult
from mtgen.audit_trace import render_audit
from microtrace.v0 import dataset_pb2

REPO = Path(__file__).resolve().parents[4]
PY_SRC = REPO / "src" / "python"

DEV_SCENARIOS = "a1_lidds_php_cwe434_upload,a1_kube_ids0_sqli,a1_csic_xss"
DEV_SEED = 42
DEV_DURATION_S = 60


# ---------------------------------------------------------------------------
# Dev run fixture (session-scoped, shared with p4_02 pattern)
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
    base = tmp_path_factory.mktemp("p4_03")
    out = base / "run"
    _cli_build(out)
    return out


# ---------------------------------------------------------------------------
# Synthetic split helpers
# ---------------------------------------------------------------------------

def _write_findings_pb(path: Path, opps: list) -> None:
    """Write a list of FindingOpportunity protos as length-delimited protobuf."""
    buf = b""
    for opp in opps:
        data = opp.SerializeToString()
        buf += struct.pack(">I", len(data)) + data
    path.write_bytes(buf)


def _make_run(
    run_dir: Path,
    run_id: str,
    is_attack: bool,
    total_envelopes: int,
    seed: int,
    finding_types: List[str],
    window_start_s: int = 0,
) -> None:
    """Create a minimal run directory for the nuisance check."""
    (run_dir / "restricted").mkdir(parents=True, exist_ok=True)

    manifest = {
        "run_id": run_id,
        "split": "PILOT",
        "world_name": "Small",
        "duration_s": DEV_DURATION_S,
        "observability_profile": "clean",
        "capture_profile": "evaluated-v0",
        "seeds": {"generator_seed": seed},
        "stream_statistics": {
            "total_envelopes": total_envelopes,
            "events_per_source_family": {
                "GATEWAY": total_envelopes // 2 + 1,
                "AUDIT": total_envelopes // 4 + 1,
            },
        },
    }
    (run_dir / "manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )

    opps = []
    for i, ft in enumerate(finding_types):
        opp = dataset_pb2.FindingOpportunity()
        opp.run_id = run_id
        opp.opportunity_id = f"{run_id}-{ft}"
        opp.action_seq = i + 1
        opp.finding_type = ft
        opp.window_start.seconds = window_start_s + i * 5
        opp.window_end.seconds = window_start_s + i * 5 + 5
        if is_attack:
            opp.expected_state = dataset_pb2.PRESENT
            opp.evidence_event_ids.append(f"ev-{run_id}-{ft}")
            opp.evidence_requirements.append("ne.gateway.method")
        else:
            opp.expected_state = dataset_pb2.ABSENT
            opp.reason = "benign lookalike"
        opps.append(opp)

    _write_findings_pb(run_dir / "restricted" / "truth_findings.pb", opps)


def _make_correlated_split(tmp_path: Path, n_runs: int = 40) -> Path:
    """Split where attack runs always have high event volume.

    Attack runs: total_envelopes = 10_000 (even indices).
    Benign runs: total_envelopes = 100  (odd indices).
    AUC should be >> 0.65 for all findings.
    """
    split_dir = tmp_path / "correlated"
    split_dir.mkdir()
    finding_types = ["A1", "B1"]
    for i in range(n_runs):
        is_attack = (i % 2 == 0)
        total = 10_000 if is_attack else 100
        _make_run(
            run_dir=split_dir / f"run_{i:02d}",
            run_id=f"corr-{i:02d}",
            is_attack=is_attack,
            total_envelopes=total,
            seed=i + 1,
            finding_types=finding_types,
        )
    return split_dir


def _make_balanced_split(tmp_path: Path, n_runs: int = 40) -> Path:
    """Split where nuisance features carry no label signal.

    All runs: identical nuisance features (total_envelopes = 1000).
    Labels alternate PRESENT / ABSENT independently of any feature.
    AUC should be <= 0.65 for all findings.
    """
    split_dir = tmp_path / "balanced"
    split_dir.mkdir()
    finding_types = ["A1", "B1"]
    for i in range(n_runs):
        is_attack = (i % 2 == 0)
        _make_run(
            run_dir=split_dir / f"run_{i:02d}",
            run_id=f"bal-{i:02d}",
            is_attack=is_attack,
            total_envelopes=1000,    # same for all runs
            seed=100,                # same seed for all → no seed-based signal
            finding_types=finding_types,
        )
    return split_dir


# ---------------------------------------------------------------------------
# Exit gate 1: nuisance check fails on correlated split
# ---------------------------------------------------------------------------

def test_nuisance_fails_correlated_split(tmp_path):
    """When event_volume perfectly separates attack from benign runs,
    the nuisance check must report at least one finding as FAIL."""
    split_dir = _make_correlated_split(tmp_path)
    result = check_nuisance(split_dir, n_splits=5, permutations=200)

    assert result.findings, "no findings returned"
    failed = [f for f in result.findings if not f.passed]
    assert failed, (
        "nuisance check should fail on correlated split; "
        f"all findings passed: {[(f.finding_type, f.score) for f in result.findings]}"
    )
    # The score should be well above threshold for at least one finding
    assert any(f.score > result.threshold for f in result.findings)
    assert all(f.verdict == "FAIL" and f.p_value < result.alpha for f in failed)
    assert not result.ok


def test_nuisance_not_testable_below_min_per_label(tmp_path):
    """With 10 PRESENT and 10 ABSENT windows per finding (below the 20 per
    label minimum), a perfect leak is NOT_TESTABLE: no verdict either way,
    no p-value, and the split does not fail on it."""
    split_dir = _make_correlated_split(tmp_path, n_runs=20)
    result = check_nuisance(split_dir, n_splits=5, permutations=200)

    assert result.findings
    for f in result.findings:
        assert f.verdict == "NOT_TESTABLE"
        assert (f.n_positive, f.n_absent) == (10, 10)
        assert f.p_value is None
        assert not f.passed
    assert result.ok
    assert result.count("NOT_TESTABLE") == len(result.findings)


def test_nuisance_score_only_when_no_permutations(tmp_path):
    """permutations=0 skips the test: a score over the threshold fails alone."""
    split_dir = _make_correlated_split(tmp_path)
    result = check_nuisance(split_dir, n_splits=5, permutations=0)

    assert all(f.p_value is None for f in result.findings)
    assert any(f.verdict == "FAIL" for f in result.findings)
    assert not result.ok


# ---------------------------------------------------------------------------
# Exit gate 2: nuisance check passes on balanced split
# ---------------------------------------------------------------------------

def test_nuisance_passes_balanced_split(tmp_path):
    """When all nuisance features are identical across runs, the predictor
    has no signal and the nuisance check must pass for all findings."""
    split_dir = _make_balanced_split(tmp_path)
    result = check_nuisance(split_dir, n_splits=5, permutations=200)

    assert result.findings, "no findings returned"
    failed = [f for f in result.findings if not f.passed]
    assert not failed, (
        "nuisance check should pass on balanced split; "
        f"findings that failed: {[(f.finding_type, f.score) for f in failed]}"
    )
    assert all(f.verdict == "PASS" and f.p_value is not None
               for f in result.findings)
    assert result.ok


# ---------------------------------------------------------------------------
# Exit gate 3: audit renders for the dev run
# ---------------------------------------------------------------------------

def test_audit_renders_dev_run(dev_run, tmp_path):
    """The audit command must produce a non-empty markdown file for the dev run."""
    out_md = tmp_path / "audit.md"
    render_audit(dev_run, out_md)
    assert out_md.exists(), "audit did not produce output file"
    content = out_md.read_text(encoding="utf-8")
    assert len(content) > 200, "audit output is unexpectedly short"
    # Must contain the run_id heading
    manifest = json.loads((dev_run / "manifest.json").read_text(encoding="utf-8"))
    run_id = manifest.get("run_id", "")
    assert run_id in content, f"run_id {run_id!r} not found in audit output"
    # Must contain action sections
    assert "### " in content, "no action section headers found"
    # Must contain Events and Truth rows sections
    assert "#### Events" in content
    assert "#### Truth rows" in content
    assert "#### Manifest" in content


def test_audit_cli_renders_dev_run(dev_run, tmp_path):
    """The CLI (python -m mtgen audit) must produce exit 0 and a markdown file."""
    out_md = tmp_path / "audit_cli.md"
    env = dict(os.environ, PYTHONHASHSEED="1")
    proc = subprocess.run(
        [sys.executable, "-m", "mtgen", "audit",
         str(dev_run), "--out", str(out_md)],
        cwd=PY_SRC, env=env, capture_output=True,
    )
    assert proc.returncode == 0, (
        f"audit CLI exited {proc.returncode}: {proc.stderr.decode(errors='replace')}"
    )
    assert out_md.exists(), "audit CLI did not create output file"
    assert out_md.stat().st_size > 200, "audit CLI output is unexpectedly small"


# ---------------------------------------------------------------------------
# Exit gate 4: audit refuses HELD_OUT runs
# ---------------------------------------------------------------------------

def test_audit_refuses_held_out(tmp_path):
    """render_audit must raise ValueError when the run's split is HELD_OUT."""
    run_dir = tmp_path / "held_out_run"
    (run_dir / "restricted").mkdir(parents=True)
    manifest = {
        "run_id": "held-out-test-run",
        "split": "HELD_OUT",
        "world_name": "Small",
        "duration_s": 60,
    }
    (run_dir / "manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="HELD_OUT"):
        render_audit(run_dir, tmp_path / "should_not_exist.md")
    assert not (tmp_path / "should_not_exist.md").exists()


def test_audit_cli_refuses_held_out(tmp_path):
    """The CLI must exit 1 and not create the output file for HELD_OUT runs."""
    run_dir = tmp_path / "held_out_run"
    (run_dir / "restricted").mkdir(parents=True)
    manifest = {
        "run_id": "held-out-test-run-cli",
        "split": "HELD_OUT",
        "world_name": "Small",
        "duration_s": 60,
    }
    (run_dir / "manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    out_md = tmp_path / "should_not_exist.md"
    env = dict(os.environ, PYTHONHASHSEED="1")
    proc = subprocess.run(
        [sys.executable, "-m", "mtgen", "audit",
         str(run_dir), "--out", str(out_md)],
        cwd=PY_SRC, env=env, capture_output=True,
    )
    assert proc.returncode == 1, (
        f"audit CLI should exit 1 for HELD_OUT; got {proc.returncode}"
    )
    assert not out_md.exists(), "audit CLI must not create output for HELD_OUT"


# ---------------------------------------------------------------------------
# Bonus: nuisance CLI smoke test
# ---------------------------------------------------------------------------

def test_nuisance_cli_balanced_passes(tmp_path):
    """The CLI (python -m mtgen nuisance) must exit 0 on a balanced split."""
    split_dir = _make_balanced_split(tmp_path)
    env = dict(os.environ, PYTHONHASHSEED="1")
    proc = subprocess.run(
        [sys.executable, "-m", "mtgen", "nuisance",
         str(split_dir), "--n-splits", "5", "--permutations", "200"],
        cwd=PY_SRC, env=env, capture_output=True,
    )
    assert proc.returncode == 0, (
        f"nuisance CLI failed on balanced split: "
        f"{proc.stdout.decode(errors='replace')}\n"
        f"{proc.stderr.decode(errors='replace')}"
    )


def test_nuisance_cli_correlated_fails(tmp_path):
    """The CLI (python -m mtgen nuisance) must exit 1 on a correlated split."""
    split_dir = _make_correlated_split(tmp_path)
    env = dict(os.environ, PYTHONHASHSEED="1")
    proc = subprocess.run(
        [sys.executable, "-m", "mtgen", "nuisance",
         str(split_dir), "--n-splits", "5", "--permutations", "200"],
        cwd=PY_SRC, env=env, capture_output=True,
    )
    assert proc.returncode == 1, (
        f"nuisance CLI should exit 1 on correlated split; got {proc.returncode}\n"
        f"{proc.stdout.decode(errors='replace')}"
    )
