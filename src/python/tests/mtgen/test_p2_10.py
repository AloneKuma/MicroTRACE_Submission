"""Phase 2.8 exit gate tests: rebuildable manifest, opportunity windows,
hard-nonlink shared_keys, completeness counters, evidence archive.

Exit gates:
  1. from-manifest rebuild is byte-identical to original build.
  2. Manifest validates against schema and contains all required build args
     (scenario_ids, duration_s, variant_per_scenario, completeness_guarantees,
     template_usage).
  3. Every FindingOpportunity has window_start <= window_end (Timestamps).
  4. Every hard nonlink (expected ABSENT, witness UNSPECIFIED) has non-empty
     shared_keys.  Vacuously satisfied for the dev 3-scenario set.
  5. Every SourceCompleteness record in the base stream has at least one counter.
  6. Every EvidenceRef in NEs resolves to an existing object in evidence/.
  7. Dev archive (evidence/objects/) is non-empty for a run with gateway events.

Unit gate tests (fast, no CLI):
  8. CompletenessRenderer.render_completeness() populates counters from
     event_counts.
  9. Dropped counts are added for lossy (degraded_gateway) profile.
 10. TruthWriter sets window_start == window_end == step_start for UNOBSERVABLE
     findings with no events.
 11. TruthWriter spans first-to-last event for null-window PRESENT findings.
"""
import hashlib
import json
import os
import struct
import subprocess
import sys
import types
from pathlib import Path

import jsonschema
import pytest

import mtgen  # noqa: F401 — registers gen/ and spec/tools/ on sys.path
from mtgen.completeness import CompletenessRenderer
from mtgen.envelopes import deserialize_length_delimited
from mtgen.evidence import EvidenceArchive
from mtgen.truth import TruthWriter, RenderedEventInfo, read_ld_protos
from microtrace.v0 import (
    common_pb2,
    dataset_pb2,
    envelope_pb2,
    normalized_pb2,
    stream_pb2,
)

REPO = Path(__file__).resolve().parents[4]
PY_SRC = REPO / "src" / "python"

# Three scenarios used for the dev build
DEV_SCENARIOS = "a1_lidds_php_cwe434_upload,a1_kube_ids0_sqli,a1_csic_xss"
DEV_SEED = 42
DEV_DURATION_S = 60


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------

def _cli_build(out: Path, scenarios: str = DEV_SCENARIOS, seed: int = DEV_SEED,
               duration_s: int = DEV_DURATION_S) -> None:
    env = dict(os.environ, PYTHONHASHSEED="1", SOURCE_DATE_EPOCH="0")
    subprocess.run(
        [sys.executable, "-m", "mtgen", "build",
         "--world", "Small",
         "--scenarios", scenarios,
         "--seed", str(seed),
         "--duration-s", str(duration_s),
         "--out", str(out)],
        cwd=PY_SRC, env=env, check=True, capture_output=True,
    )


def _cli_from_manifest(manifest_dir: Path, out: Path) -> None:
    env = dict(os.environ, PYTHONHASHSEED="1", SOURCE_DATE_EPOCH="0")
    subprocess.run(
        [sys.executable, "-m", "mtgen", "from-manifest",
         str(manifest_dir), "--out", str(out)],
        cwd=PY_SRC, env=env, check=True, capture_output=True,
    )


def _tree(root: Path) -> dict:
    return {p.relative_to(root).as_posix(): p.read_bytes()
            for p in sorted(root.rglob("*")) if p.is_file()}


# ---------------------------------------------------------------------------
# Module-scoped CLI fixture: builds once, rebuilds once
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def dev_run(tmp_path_factory):
    """Build the 3-scenario dev run and a from-manifest rebuild."""
    base = tmp_path_factory.mktemp("p2_10")
    out_a = base / "a"
    out_b = base / "b"
    _cli_build(out_a)
    _cli_from_manifest(out_a, out_b)
    return out_a, out_b


# ---------------------------------------------------------------------------
# Exit gate 1: from-manifest rebuild is byte-identical
# ---------------------------------------------------------------------------

def test_from_manifest_rebuild_is_byte_identical(dev_run):
    a, b = dev_run
    ta, tb = _tree(a), _tree(b)
    assert ta.keys() == tb.keys(), (
        f"file set differs. only in a: {ta.keys()-tb.keys()}, "
        f"only in b: {tb.keys()-ta.keys()}"
    )
    differing = [k for k in ta if ta[k] != tb[k]]
    assert not differing, f"files differ between original and from-manifest build: {differing}"


# ---------------------------------------------------------------------------
# Exit gate 2: manifest contains required build args and validates schema
# ---------------------------------------------------------------------------

def test_manifest_has_required_build_args(dev_run):
    a, _ = dev_run
    m = json.loads((a / "manifest.json").read_text(encoding="utf-8"))
    assert "scenario_ids" in m, "manifest missing scenario_ids"
    assert isinstance(m["scenario_ids"], list), "scenario_ids must be a list"
    assert len(m["scenario_ids"]) == 3
    assert m["scenario_ids"][0] == "a1_lidds_php_cwe434_upload"

    assert "duration_s" in m, "manifest missing duration_s"
    assert m["duration_s"] == DEV_DURATION_S

    assert "variant_per_scenario" in m, "manifest missing variant_per_scenario"
    vps = m["variant_per_scenario"]
    for sid in m["scenario_ids"]:
        assert sid in vps, f"{sid} missing from variant_per_scenario"
    assert all(v == "v1" for v in vps.values())

    assert "completeness_guarantees" in m, "manifest missing completeness_guarantees"
    cg = m["completeness_guarantees"]
    assert "gateway" in cg and "audit" in cg and "ebpf" in cg and "context" in cg
    # clean profile: all complete
    for src in ("gateway", "audit", "ebpf", "context"):
        assert cg[src]["expected_complete"] is True
        assert cg[src]["loss_percentage"] == 0.0

    assert "template_usage" in m, "manifest missing template_usage"
    assert "scripted_distributions" in m["template_usage"]
    assert len(m["template_usage"]["scripted_distributions"]) >= 1


def test_manifest_validates_against_schema(dev_run):
    a, _ = dev_run
    schema = json.loads(
        (REPO / "spec/generator/build-manifest.schema.json").read_text(encoding="utf-8")
    )
    m = json.loads((a / "manifest.json").read_text(encoding="utf-8"))
    jsonschema.validate(m, schema)


# ---------------------------------------------------------------------------
# Exit gate 3: all FindingOpportunity windows are valid
# ---------------------------------------------------------------------------

def _read_opportunities(run_dir: Path):
    pb_path = run_dir / "restricted" / "truth_findings.pb"
    return read_ld_protos(pb_path, dataset_pb2.FindingOpportunity)


def _ts_to_ns(ts) -> int:
    return ts.seconds * 1_000_000_000 + ts.nanos


def test_opportunity_windows_valid(dev_run):
    a, _ = dev_run
    opps = _read_opportunities(a)
    assert opps, "no FindingOpportunity records found"
    bad = []
    for opp in opps:
        ws = _ts_to_ns(opp.window_start)
        we = _ts_to_ns(opp.window_end)
        if ws > we:
            bad.append(
                f"opp {opp.opportunity_id}: window_start ({ws}) > window_end ({we})"
            )
    assert not bad, "\n".join(bad)


# ---------------------------------------------------------------------------
# Exit gate 4: hard nonlinks have non-empty shared_keys
# ---------------------------------------------------------------------------

def _read_links(run_dir: Path):
    pb_path = run_dir / "restricted" / "truth_links.pb"
    return read_ld_protos(pb_path, dataset_pb2.ActionLink)


def test_hard_nonlinks_have_shared_keys(dev_run):
    a, _ = dev_run
    links = _read_links(a)
    bad = []
    for lnk in links:
        is_hard_nonlink = (
            lnk.expected_state == dataset_pb2.ABSENT
            and lnk.witness_type == 0  # WITNESS_TYPE_UNSPECIFIED
        )
        if is_hard_nonlink and not lnk.shared_keys:
            bad.append(f"link {lnk.link_id} is a hard nonlink but has no shared_keys")
    assert not bad, "\n".join(bad)


# ---------------------------------------------------------------------------
# Exit gate 5: SourceCompleteness counters populated
# ---------------------------------------------------------------------------

def _decode_base_stream(run_dir: Path):
    """Decode all Envelopes from base.pb."""
    base_pb = run_dir / "base.pb"
    envs = []
    with open(base_pb, "rb") as fh:
        data = fh.read()
    offset = 0
    while offset < len(data):
        if offset + 4 > len(data):
            break
        (length,) = struct.unpack(">I", data[offset:offset + 4])
        offset += 4
        env = envelope_pb2.Envelope()
        env.ParseFromString(data[offset:offset + length])
        envs.append(env)
        offset += length
    return envs


def test_source_completeness_counters_populated(dev_run):
    a, _ = dev_run
    envs = _decode_base_stream(a)
    sc_records = [
        env.source_completeness
        for env in envs
        if env.HasField("source_completeness")
    ]
    assert sc_records, "no SourceCompleteness records found in base stream"
    # At least some records should have counters (gateway events are emitted)
    with_counters = [sc for sc in sc_records if len(sc.counters) > 0]
    assert with_counters, (
        "no SourceCompleteness record has any counters; "
        f"checked {len(sc_records)} records"
    )


# ---------------------------------------------------------------------------
# Exit gate 6 & 7: EvidenceRef resolution and dev archive non-empty
# ---------------------------------------------------------------------------

def test_evidence_refs_resolve(dev_run):
    a, _ = dev_run
    evidence_dir = a / "evidence"
    index = json.loads((evidence_dir / "index.json").read_text(encoding="utf-8"))
    # index["objects"] is a list of {"sha256": ..., "size": ...} dicts
    missing = []
    for obj_info in index.get("objects", []):
        obj_key = obj_info["sha256"]
        obj_path = evidence_dir / "objects" / obj_key[:2] / obj_key
        if not obj_path.exists():
            missing.append(obj_key)
    assert not missing, f"missing evidence objects: {missing}"


def test_dev_archive_nonempty(dev_run):
    a, _ = dev_run
    objects_dir = a / "evidence" / "objects"
    all_objects = list(objects_dir.rglob("*"))
    all_files = [p for p in all_objects if p.is_file()]
    assert all_files, (
        "evidence archive is empty; gateway body_prefix_b64/body/query_params "
        "must have been decoded and archived"
    )


# ---------------------------------------------------------------------------
# Unit gate 8: CompletenessRenderer.render_completeness() fills counters
# ---------------------------------------------------------------------------

def _make_fake_world(node_uids=("node-aaa",)):
    world = types.SimpleNamespace(
        run_start_ns=1_704_067_200_000_000_000,
        run_duration_ns=60_000_000_000,
        nodes=[types.SimpleNamespace(uid=uid) for uid in node_uids],
    )
    return world


def test_completeness_counters_from_event_counts():
    world = _make_fake_world(["node-aaa"])
    r = CompletenessRenderer(world, profile_name="clean", profile={})
    event_counts = {
        "node=node-aaa": {"proc.exec": 5, "net.connect": 3},
        "gateway=1": {"gateway": 10},
        "audit-collector=1": {"audit": 7},
    }
    records = r.render_completeness(event_counts=event_counts)
    sc_by_scope = {sc.scope: sc for sc in records}

    node_sc = sc_by_scope.get("node=node-aaa")
    assert node_sc is not None
    assert node_sc.counters["proc.exec"] == 5
    assert node_sc.counters["net.connect"] == 3

    gw_sc = sc_by_scope.get("gateway=1")
    assert gw_sc is not None
    assert gw_sc.counters["gateway"] == 10


# ---------------------------------------------------------------------------
# Unit gate 9: dropped counts for lossy profile
# ---------------------------------------------------------------------------

def test_completeness_dropped_counts_degraded_gateway():
    world = _make_fake_world()
    profile = {"observer_loss_percentage": 20}
    r = CompletenessRenderer(world, profile_name="degraded_gateway", profile=profile)
    event_counts = {"gateway=1": {"gateway": 100}}
    records = r.render_completeness(event_counts=event_counts)
    sc_by_scope = {sc.scope: sc for sc in records}

    gw_sc = sc_by_scope.get("gateway=1")
    assert gw_sc is not None
    assert gw_sc.counters["gateway"] == 100
    assert "dropped:gateway" in gw_sc.counters
    assert gw_sc.counters["dropped:gateway"] == 20  # 20% of 100


def test_completeness_no_dropped_counts_clean_profile():
    world = _make_fake_world()
    r = CompletenessRenderer(world, profile_name="clean", profile={})
    event_counts = {"gateway=1": {"gateway": 100}}
    records = r.render_completeness(event_counts=event_counts)
    sc_by_scope = {sc.scope: sc for sc in records}
    gw_sc = sc_by_scope.get("gateway=1")
    assert gw_sc is not None
    assert "dropped:gateway" not in gw_sc.counters


# ---------------------------------------------------------------------------
# Unit gate 10: UNOBSERVABLE finding with no events -> degenerate window
# ---------------------------------------------------------------------------

def test_truth_writer_unobservable_no_events_window():
    """UNOBSERVABLE with no events -> window_start == window_end == step_start."""
    from mtgen import specs
    rendering_table = specs.load_evidence_rendering()
    catalogue = specs.load_scenario_catalogue()
    writer = TruthWriter("run-x", rendering_table, catalogue)

    step_start_ns = 1_704_067_210_000_000_000
    step_end_ns   = 1_704_067_220_000_000_000
    ws_ns, we_ns = writer._compute_window(
        finding_type="A1",
        expected_state="UNOBSERVABLE",
        event_infos=[],
        step_start_ns=step_start_ns,
        step_end_ns=step_end_ns,
    )
    assert ws_ns == step_start_ns
    assert we_ns == step_start_ns


# ---------------------------------------------------------------------------
# Unit gate 11: null-window PRESENT finding -> span first to last event time
# ---------------------------------------------------------------------------

def test_truth_writer_null_window_spans_event_times():
    """A1 has window: null -> window spans from first to last evidence event."""
    from mtgen import specs
    rendering_table = specs.load_evidence_rendering()
    catalogue = specs.load_scenario_catalogue()
    writer = TruthWriter("run-x", rendering_table, catalogue)

    T1 = 1_704_067_215_000_000_000
    T2 = 1_704_067_218_000_000_000
    T3 = 1_704_067_216_000_000_000
    event_infos = [
        RenderedEventInfo("e1", "gateway", "", time_ns=T1),
        RenderedEventInfo("e2", "gateway", "", time_ns=T2),
        RenderedEventInfo("e3", "gateway", "", time_ns=T3),
    ]
    step_start_ns = 1_704_067_210_000_000_000
    step_end_ns   = 1_704_067_220_000_000_000

    ws_ns, we_ns = writer._compute_window(
        finding_type="A1",
        expected_state="PRESENT",
        event_infos=event_infos,
        step_start_ns=step_start_ns,
        step_end_ns=step_end_ns,
    )
    assert ws_ns == T1, f"window_start should be min event time {T1}, got {ws_ns}"
    assert we_ns == T2, f"window_end should be max event time {T2}, got {we_ns}"
