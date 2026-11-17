"""Phase 4.2 exit gate tests: Evidence, Leakage, Truth-consistency, Determinism.

Exit gates:
  1. Clean dev run passes all four new checks.
  2. Evidence: PRESENT opportunity with a missing evidence_event_id fails.
  3. Leakage: a scenario ID injected into a detector-visible NE field fails.
  4. Truth consistency: GTA with an extra expected_finding_type fails.
  5. Determinism: a tampered base.pb (hash mismatch) fails.
"""
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

import pytest

import mtgen  # noqa: F401 — registers gen/ and spec/tools/ on sys.path
from mtgen.verify import (
    check_determinism,
    check_evidence,
    check_leakage,
    check_truth_consistency,
    verify,
    _load_base_stream,
    _load_catalogue,
    _load_manifest,
    _load_truth_files,
)
from microtrace.v0 import dataset_pb2, envelope_pb2

REPO = Path(__file__).resolve().parents[4]
PY_SRC = REPO / "src" / "python"

DEV_SCENARIOS = "a1_lidds_php_cwe434_upload,a1_kube_ids0_sqli,a1_csic_xss"
DEV_SEED = 42
DEV_DURATION_S = 60


# ---------------------------------------------------------------------------
# Build fixture (session-scoped, built once for this file)
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
    base = tmp_path_factory.mktemp("p4_02")
    out = base / "run"
    _cli_build(out)
    return out


# ---------------------------------------------------------------------------
# Exit gate 1: clean run passes all new checks
# ---------------------------------------------------------------------------

def test_clean_run_passes_all_new_checks(dev_run):
    """All eight checks (phases 4a + 4b) must pass on a clean dev run."""
    result = verify(dev_run)
    bad = [(c.name, c.failures[:3]) for c in result.checks if not c.ok]
    assert result.ok, f"clean run failed checks: {bad}"


# ---------------------------------------------------------------------------
# Exit gate 2: Evidence – missing evidence_event_id
# ---------------------------------------------------------------------------

def test_evidence_clean_passes(dev_run):
    envelopes, _ = _load_base_stream(dev_run)
    actions, findings, links = _load_truth_files(dev_run)
    r = check_evidence(envelopes, actions, findings, links)
    assert r.ok, f"evidence failures on clean run: {r.failures[:5]}"


def test_evidence_fails_missing_event_id(dev_run):
    """A PRESENT FindingOpportunity whose evidence_event_id is not in the
    base stream must cause the evidence check to fail."""
    envelopes, _ = _load_base_stream(dev_run)
    actions, findings, links = _load_truth_files(dev_run)

    # Build a fake PRESENT opportunity with a bogus event ID.
    fake_opp = dataset_pb2.FindingOpportunity()
    fake_opp.run_id = "test-run"
    fake_opp.opportunity_id = "opp-missing-evidence-test"
    fake_opp.action_seq = 9999
    fake_opp.finding_type = "A1"
    fake_opp.expected_state = dataset_pb2.PRESENT
    fake_opp.evidence_event_ids.append("ev_" + "0" * 32)  # bogus — not in stream
    fake_opp.evidence_requirements.append("ne.gateway.method")

    corrupt_findings = list(findings) + [fake_opp]
    r = check_evidence(envelopes, actions, corrupt_findings, links)
    assert not r.ok, "evidence check must fail with missing evidence_event_id"
    assert any("not in" in f.lower() for f in r.failures)


# ---------------------------------------------------------------------------
# Exit gate 3: Leakage – scenario ID in a detector-visible NE field
# ---------------------------------------------------------------------------

def test_leakage_clean_passes(dev_run):
    envelopes, _ = _load_base_stream(dev_run)
    actions, _, _ = _load_truth_files(dev_run)
    catalogue = _load_catalogue()
    r = check_leakage(envelopes, actions, catalogue)
    assert r.ok, f"leakage failures on clean run: {r.failures[:5]}"
    assert r.checked > 0, "leakage check inspected no NEs"


def test_leakage_fails_scenario_word_in_ne_field(dev_run):
    """Injecting a catalogue scenario ID into the source_native_id of a NE
    must cause the leakage check to fail."""
    envelopes, _ = _load_base_stream(dev_run)
    actions, _, _ = _load_truth_files(dev_run)
    catalogue = _load_catalogue()

    scenarios = catalogue.get("scenarios", [])
    assert scenarios, "catalogue has no scenarios"
    forbidden_word = scenarios[0]["id"]  # e.g. "a1_lidds_php_cwe434_upload"

    # Find the first NE envelope to corrupt.
    ne_idx = next(
        (i for i, e in enumerate(envelopes)
         if e.WhichOneof("payload") == "normalized_event"),
        None,
    )
    assert ne_idx is not None, "no NE found in dev run"

    corrupt_env = envelope_pb2.Envelope()
    corrupt_env.CopyFrom(envelopes[ne_idx])
    # Inject the forbidden scenario ID into source_native_id (detector-visible).
    corrupt_env.normalized_event.source_native_id = (
        f"injected-{forbidden_word}-native"
    )

    corrupt_envs = list(envelopes)
    corrupt_envs[ne_idx] = corrupt_env

    r = check_leakage(corrupt_envs, actions, catalogue)
    assert not r.ok, "leakage check must fail when scenario ID in NE field"
    assert any(forbidden_word in f for f in r.failures), (
        f"failure messages did not mention {forbidden_word!r}: {r.failures[:5]}"
    )


# ---------------------------------------------------------------------------
# Exit gate 4: Truth consistency – inconsistent expected_finding_types
# ---------------------------------------------------------------------------

def test_truth_consistency_clean_passes(dev_run):
    envelopes, _ = _load_base_stream(dev_run)
    actions, findings, links = _load_truth_files(dev_run)
    r = check_truth_consistency(envelopes, actions, findings, links)
    assert r.ok, f"truth_consistency failures on clean run: {r.failures[:5]}"
    assert r.checked > 0, "truth_consistency checked nothing"


def test_truth_consistency_fails_extra_expected_type(dev_run):
    """Adding a bogus finding type to GTA.expected_finding_types that has no
    PRESENT FindingOpportunity must cause the consistency check to fail."""
    envelopes, _ = _load_base_stream(dev_run)
    actions, findings, links = _load_truth_files(dev_run)

    # Build mapping: action_seq -> finding_types of PRESENT opportunities.
    present_types: dict = defaultdict(set)
    for opp in findings:
        if opp.expected_state == dataset_pb2.PRESENT:
            present_types[opp.action_seq].add(opp.finding_type)

    # Find a GTA whose expected_finding_types match (so it's currently clean).
    target_gta = next(
        (g for g in actions
         if set(g.expected_finding_types) == present_types.get(g.action_seq, set())),
        None,
    )
    if target_gta is None:
        pytest.skip("no consistently-labelled GTA found to corrupt")

    # Copy and append a bogus finding type.
    corrupt_gta = dataset_pb2.GroundTruthAction()
    corrupt_gta.CopyFrom(target_gta)
    corrupt_gta.expected_finding_types.append("X99_NONEXISTENT")

    corrupt_actions = [
        corrupt_gta if g.action_seq == target_gta.action_seq else g
        for g in actions
    ]
    r = check_truth_consistency(envelopes, corrupt_actions, findings, links)
    assert not r.ok, "truth_consistency must fail with mismatched expected types"
    assert any("X99_NONEXISTENT" in f or "expected_finding_type" in f
               for f in r.failures)


# ---------------------------------------------------------------------------
# Exit gate 5: Determinism – tampered base.pb
# ---------------------------------------------------------------------------

def test_determinism_clean_passes(dev_run):
    manifest = _load_manifest(dev_run)
    r = check_determinism(dev_run, manifest)
    assert r.ok, f"determinism failures on clean run: {r.failures[:5]}"
    assert r.checked > 0, "determinism checked no hashes"


def test_determinism_fails_tampered_base_pb(dev_run):
    """Appending a byte to base.pb after the build makes its SHA-256 differ
    from the value recorded in manifest.json; the determinism check must fail."""
    manifest = _load_manifest(dev_run)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_run = Path(tmp) / "run"
        shutil.copytree(dev_run, tmp_run)

        # Tamper with base.pb: append one null byte.
        base_pb = tmp_run / "base.pb"
        base_pb.write_bytes(base_pb.read_bytes() + b"\x00")

        # The manifest still has the original hash — check must catch the delta.
        r = check_determinism(tmp_run, manifest)
        assert not r.ok, (
            "determinism check must fail when base.pb is tampered"
        )
        assert any(
            "mismatch" in f.lower() or "sha256" in f.lower()
            for f in r.failures
        )
