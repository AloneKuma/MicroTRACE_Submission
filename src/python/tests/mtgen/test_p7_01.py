"""Phase 7.1–7.4 exit gate tests: pilot run matrix, capacity metrics, nuisance check.

Tests:
  1. run-matrix.pilot.yaml validates against its JSON schema.
  2. run-matrix.pilot.yaml has exactly 241 runs (balanced layout: each scenario
     once per round, 12 rounds per world, profile rotated per scenario; one
     Large capacity run).
  3. All pilot run directories exist and have manifest.json.
  4. pilot_metrics.json exists and has entries for all runs.
  5. Every pilot run has total_envelopes > 0 and disk_size_bytes > 0.
  6. verify_results.json overall_pass is True.
  7. All 8 verify checks pass in every run reported in verify_results.json.
  8. nuisance_results.json ok is True.
  9. Nuisance threshold is 0.65 (matches generator-spec pilot_default).
 10. All finding types in nuisance_results score below the threshold.
 11. Small-world runs produce fewer events than Reference-world runs (event-rate check).
 12. Large-world run has disk_size_bytes > 1 GB (capacity gate).
"""
import json
from pathlib import Path

import jsonschema
import pytest
import yaml

REPO = Path(__file__).resolve().parents[4]
PILOT_OUT = REPO / "datasets" / "generated" / "pilot"
SPEC_DIR = REPO / "spec" / "generator"

MATRIX_PATH = SPEC_DIR / "run-matrix.pilot.yaml"
SCHEMA_PATH = SPEC_DIR / "run-matrix.schema.json"
METRICS_PATH = PILOT_OUT / "pilot_metrics.json"
VERIFY_PATH = PILOT_OUT / "verify_results.json"
NUISANCE_PATH = PILOT_OUT / "nuisance_results.json"
GEN_SPEC_PATH = SPEC_DIR / "generator-spec.v0.yaml"

# Tests 3-12 read the generated pilot runs, which are not in git
# (datasets/* is ignored); like the Kafka and Postgres tests, they skip
# where that output is absent.
pilot = pytest.mark.skipif(not PILOT_OUT.is_dir(), reason=f"no pilot output at {PILOT_OUT} (mtgen phase 7)")

EXPECTED_RUN_COUNT = 241
EXPECTED_CHECKS = frozenset({
    "schema", "contract", "time", "identity",
    "evidence", "leakage", "truth_consistency", "determinism",
})


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def matrix():
    with open(MATRIX_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


@pytest.fixture(scope="module")
def schema():
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def metrics():
    return json.loads(METRICS_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def verify_results():
    return json.loads(VERIFY_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def nuisance_results():
    return json.loads(NUISANCE_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def gen_spec():
    with open(GEN_SPEC_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


# ---------------------------------------------------------------------------
# Test 1: run-matrix.pilot.yaml validates against its JSON schema
# ---------------------------------------------------------------------------

def test_01_matrix_schema_valid(matrix, schema):
    """run-matrix.pilot.yaml must satisfy the run-matrix JSON schema."""
    jsonschema.validate(matrix, schema)


# ---------------------------------------------------------------------------
# Test 2: run-matrix.pilot.yaml has exactly EXPECTED_RUN_COUNT runs
# ---------------------------------------------------------------------------

def test_02_matrix_run_count(matrix):
    runs = matrix.get("runs", [])
    assert len(runs) == EXPECTED_RUN_COUNT, (
        f"Expected {EXPECTED_RUN_COUNT} runs in pilot matrix, got {len(runs)}"
    )


# ---------------------------------------------------------------------------
# Test 3: All pilot run directories exist and have manifest.json
# ---------------------------------------------------------------------------

@pilot
def test_03_run_dirs_exist(matrix):
    missing = []
    for run in matrix["runs"]:
        run_id = run["run_id"]
        mf = PILOT_OUT / run_id / "manifest.json"
        if not mf.exists():
            missing.append(run_id)
    assert not missing, f"Missing manifest.json for runs: {missing}"


# ---------------------------------------------------------------------------
# Test 4: pilot_metrics.json exists and covers all runs
# ---------------------------------------------------------------------------

@pilot
def test_04_metrics_covers_all_runs(matrix, metrics):
    metric_ids = {r["run_id"] for r in metrics["runs"]}
    matrix_ids = {r["run_id"] for r in matrix["runs"]}
    missing = matrix_ids - metric_ids
    assert not missing, f"Missing metrics for runs: {missing}"


# ---------------------------------------------------------------------------
# Test 5: Every pilot run has total_envelopes > 0 and disk_size_bytes > 0
# ---------------------------------------------------------------------------

@pilot
def test_05_positive_envelope_and_disk(metrics):
    bad = []
    for r in metrics["runs"]:
        if r.get("total_envelopes", 0) <= 0 or r.get("disk_size_bytes", 0) <= 0:
            bad.append(r["run_id"])
    assert not bad, f"Runs with zero events or disk size: {bad}"


# ---------------------------------------------------------------------------
# Test 6: verify_results.json overall_pass is True
# ---------------------------------------------------------------------------

@pilot
def test_06_verify_overall_pass(verify_results):
    assert verify_results["overall_pass"] is True, (
        "verify_results.json overall_pass is False — one or more runs failed verify"
    )


# ---------------------------------------------------------------------------
# Test 7: All 8 verify checks pass in every run
# ---------------------------------------------------------------------------

@pilot
def test_07_all_verify_checks_pass(verify_results):
    failures = []
    for run_name, r in verify_results["runs"].items():
        if not r.get("passed", False):
            failures.append(run_name)
        checks = r.get("checks", {})
        for check_name, passed in checks.items():
            if not passed:
                failures.append(f"{run_name}/{check_name}")
    assert not failures, f"Verify failures: {failures}"


@pilot
def test_07b_expected_checks_present(verify_results):
    """Every run must report all 8 standard check names."""
    missing_checks = {}
    for run_name, r in verify_results["runs"].items():
        checks = set(r.get("checks", {}).keys())
        absent = EXPECTED_CHECKS - checks
        if absent:
            missing_checks[run_name] = sorted(absent)
    assert not missing_checks, f"Missing checks per run: {missing_checks}"


# ---------------------------------------------------------------------------
# Test 8: nuisance_results.json ok is True
# ---------------------------------------------------------------------------

@pilot
def test_08_nuisance_pass(nuisance_results):
    assert nuisance_results["ok"] is True, (
        "Nuisance check failed. Findings exceeding threshold: "
        + str([f for f in nuisance_results["findings"] if not f["passed"]])
    )


# ---------------------------------------------------------------------------
# Test 9: Nuisance threshold is 0.65
# ---------------------------------------------------------------------------

@pilot
def test_09_nuisance_threshold(nuisance_results, gen_spec):
    spec_threshold = gen_spec["nuisance_check"]["threshold"]["pilot_default"]
    assert nuisance_results["threshold"] == pytest.approx(spec_threshold), (
        f"Nuisance threshold mismatch: results={nuisance_results['threshold']} "
        f"spec pilot_default={spec_threshold}"
    )


# ---------------------------------------------------------------------------
# Test 10: All finding types in nuisance_results score below the threshold
# ---------------------------------------------------------------------------

@pilot
def test_10_all_findings_below_threshold(nuisance_results):
    threshold = nuisance_results["threshold"]
    over = [f for f in nuisance_results["findings"] if f["score"] >= threshold]
    assert not over, (
        f"Finding types at or above threshold {threshold}: "
        + ", ".join(f"{f['finding_type']}={f['score']:.3f}" for f in over)
    )


# ---------------------------------------------------------------------------
# Test 11: Small-world runs produce fewer events than Reference-world runs
# ---------------------------------------------------------------------------

@pilot
def test_11_small_fewer_events_than_reference(metrics):
    small_runs = [r for r in metrics["runs"] if r["world"] == "Small"]
    ref_runs = [r for r in metrics["runs"] if r["world"] == "Reference"]
    if not small_runs or not ref_runs:
        pytest.skip("Need both Small and Reference runs for this check")
    max_small = max(r["total_envelopes"] for r in small_runs)
    min_ref = min(r["total_envelopes"] for r in ref_runs)
    assert max_small < min_ref, (
        f"Expected Small envelopes ({max_small}) < Reference envelopes ({min_ref}) "
        "but the ordering was violated"
    )


# ---------------------------------------------------------------------------
# Test 12: Large-world run has disk_size_bytes > 1 GB (capacity gate)
# ---------------------------------------------------------------------------

@pilot
def test_12_large_disk_size_above_1gb(metrics):
    large_runs = [r for r in metrics["runs"] if r["world"] == "Large"]
    if not large_runs:
        pytest.skip("No Large-world runs in pilot_metrics.json")
    for r in large_runs:
        assert r["disk_size_bytes"] > 1_000_000_000, (
            f"Large run {r['run_id']} disk_size_bytes={r['disk_size_bytes']} < 1 GB"
        )
