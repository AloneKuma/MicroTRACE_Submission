"""Tests for Phase 2.5: truth writer.

Required tests (task spec):
  1. A fully rendered chain yields PRESENT with the right evidence event IDs.
  2. Removing one required source yields UNOBSERVABLE, naming it.
  3. A lookalike yields ABSENT.
  4. The links reference existing actions.
  5. The consistency check catches a mismatch.

Additional tests:
  - write_restricted creates correct files (proto + JSONL).
  - Coverage rows are produced from SourceCompleteness records.
  - Downgrade is logged when PRESENT is dropped to UNOBSERVABLE.
  - Same scenario running twice generates distinct link records.
"""
import json
import struct
from pathlib import Path

import pytest

import mtgen  # registers gen/ and spec/tools/ on sys.path
from microtrace.v0 import dataset_pb2, stream_pb2, common_pb2
from mtgen.scenarios import GroundTruthRecord
from mtgen.truth import (
    TruthWriter,
    RenderedEventInfo,
    TruthResult,
    read_ld_protos,
    write_ld_protos,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

RUN_ID = "run-test-p2-08"
RUN_START_NS = 1_704_067_200_000_000_000   # 2024-01-01 00:00:00 UTC
T0 = RUN_START_NS + 10_000_000_000         # +10 s
T1 = RUN_START_NS + 15_000_000_000         # +15 s


# Minimal rendering table covering A1 (gateway only) and D1 (ebpf only)
_RENDERING_TABLE = {
    "findings": [
        {
            "id": "A1",
            "inputs": [
                {
                    "field": "microtrace.v0.GatewayObservation.request_id",
                    "record": "gateway",
                    "derived": None,
                    "family": None,
                },
                {
                    "field": "microtrace.v0.GatewayObservation.matches",
                    "record": "gateway",
                    "derived": None,
                    "family": None,
                },
            ],
        },
        {
            "id": "D1",
            "inputs": [
                {
                    "field": "microtrace.v0.FileAccessDetail.op",
                    "record": "ebpf",
                    "derived": None,
                    "family": "file.read",
                },
                {
                    "field": "microtrace.v0.FileIdentity.dev",
                    "record": "ebpf",
                    "derived": None,
                    "family": "file.open",
                },
                {
                    "field": "microtrace.v0.ProjectedVersion.owner_pod_uid",
                    "record": "ebpf",
                    "derived": None,
                    "family": "token.file_index",
                },
                {
                    "field": "microtrace.v0.EbpfDerived.token_file",
                    "record": None,
                    "derived": "ebpf_derived",
                    "family": None,
                },
            ],
        },
    ]
}


def _make_catalogue(scenarios):
    """Wrap a list of scenario dicts into a minimal catalogue dict."""
    return {"scenarios": scenarios}


def _make_scenario(
    sid,
    kind="attack",
    steps=None,
    links=None,
    roles=None,
):
    return {
        "id": sid,
        "kind": kind,
        "steps": steps or [],
        "links": links or [],
        "roles": roles or [],
    }


def _make_gt_record(
    action_seq,
    scenario_id="scen-a1",
    variant_id="v1",
    step_label="1",
    is_attack=True,
    expected_finding_types=None,
):
    return GroundTruthRecord(
        run_id=RUN_ID,
        action_seq=action_seq,
        scenario_id=scenario_id,
        variant_id=variant_id,
        step_label=step_label,
        is_attack=is_attack,
        expected_finding_types=expected_finding_types or [],
        started_at_ns=T0,
        ended_at_ns=T1,
    )


def _gateway_event(event_id="ev-gw-001"):
    return RenderedEventInfo(event_id=event_id, record_type="gateway", family="")


def _ebpf_event(family, event_id=None):
    eid = event_id or f"ev-ebpf-{family.replace('.', '-')}"
    return RenderedEventInfo(event_id=eid, record_type="ebpf", family=family)


def _audit_event(event_id="ev-aud-001"):
    return RenderedEventInfo(event_id=event_id, record_type="audit", family="")


# ---------------------------------------------------------------------------
# Test 1: Fully rendered chain yields PRESENT with the right evidence event IDs
# ---------------------------------------------------------------------------

def test_fully_rendered_yields_present():
    """A1 step with a gateway event rendered → PRESENT with the event_id."""
    scenario = _make_scenario(
        "scen-a1",
        steps=[{
            "step": 1,
            "action": "http_request",
            "expects": [{"finding": "A1", "state": "PRESENT", "reason": "test"}],
        }],
    )
    cat = _make_catalogue([scenario])
    rec = _make_gt_record(
        action_seq=1,
        scenario_id="scen-a1",
        expected_finding_types=["A1"],
    )
    ei = _gateway_event("ev-gw-001")

    writer = TruthWriter(RUN_ID, _RENDERING_TABLE, cat)
    result = writer.write([rec], {1: [ei]})

    assert len(result.opportunities) == 1
    opp = result.opportunities[0]
    assert opp.expected_state == dataset_pb2.PRESENT
    assert "ev-gw-001" in list(opp.evidence_event_ids)
    assert len(result.consistency_errors) == 0


def test_fully_rendered_evidence_requirements_present():
    """PRESENT opportunity carries all field paths as evidence_requirements."""
    scenario = _make_scenario(
        "scen-a1",
        steps=[{
            "step": 1,
            "action": "http_request",
            "expects": [{"finding": "A1", "state": "PRESENT"}],
        }],
    )
    cat = _make_catalogue([scenario])
    rec = _make_gt_record(1, expected_finding_types=["A1"])
    # Both required sources: gateway + derived from audit (base=audit)
    rendered = [_gateway_event(), _audit_event()]

    writer = TruthWriter(RUN_ID, _RENDERING_TABLE, cat)
    result = writer.write([rec], {1: rendered})

    opp = result.opportunities[0]
    assert opp.expected_state == dataset_pb2.PRESENT
    # evidence_requirements should contain all field paths for A1
    req_set = set(opp.evidence_requirements)
    assert "microtrace.v0.GatewayObservation.request_id" in req_set
    assert "microtrace.v0.GatewayObservation.matches" in req_set


# ---------------------------------------------------------------------------
# Test 2: Missing required source yields UNOBSERVABLE naming the missing field
# ---------------------------------------------------------------------------

def test_missing_source_yields_unobservable():
    """D1 step with no rendered events → UNOBSERVABLE listing missing sources."""
    scenario = _make_scenario(
        "scen-d1",
        steps=[{
            "step": 1,
            "action": "read_token_file",
            "expects": [{"finding": "D1", "state": "PRESENT"}],
        }],
    )
    cat = _make_catalogue([scenario])
    rec = _make_gt_record(
        1, scenario_id="scen-d1", expected_finding_types=[]
    )

    writer = TruthWriter(RUN_ID, _RENDERING_TABLE, cat)
    result = writer.write([rec], {1: []})  # no events rendered

    assert len(result.opportunities) == 1
    opp = result.opportunities[0]
    assert opp.expected_state == dataset_pb2.UNOBSERVABLE
    # reason must name the missing requirements
    assert "Missing required sources" in opp.reason
    # evidence_requirements lists the missing field paths
    assert len(opp.evidence_requirements) > 0
    assert len(result.downgrades) == 1
    seq, ft, old, new, why = result.downgrades[0]
    assert seq == 1
    assert ft == "D1"
    assert old == "PRESENT"
    assert new == "UNOBSERVABLE"
    assert "Missing" in why


def test_partial_ebpf_missing_family_yields_unobservable():
    """D1 with only file.read rendered (missing file.open and token.file_index)."""
    scenario = _make_scenario(
        "scen-d1",
        steps=[{
            "step": 1,
            "action": "read_token_file",
            "expects": [{"finding": "D1", "state": "PRESENT"}],
        }],
    )
    cat = _make_catalogue([scenario])
    rec = _make_gt_record(1, scenario_id="scen-d1", expected_finding_types=[])

    writer = TruthWriter(RUN_ID, _RENDERING_TABLE, cat)
    # Render only file.read; file.open and token.file_index are missing
    result = writer.write([rec], {1: [_ebpf_event("file.read")]})

    opp = result.opportunities[0]
    assert opp.expected_state == dataset_pb2.UNOBSERVABLE
    # The missing requirements should include file.open and token.file_index fields
    req_fields = set(opp.evidence_requirements)
    assert "microtrace.v0.FileIdentity.dev" in req_fields
    assert "microtrace.v0.ProjectedVersion.owner_pod_uid" in req_fields


def test_all_required_ebpf_families_present_yields_present():
    """D1 with file.read + file.open + token.file_index → PRESENT."""
    scenario = _make_scenario(
        "scen-d1",
        steps=[{
            "step": 1,
            "action": "read_token_file",
            "expects": [{"finding": "D1", "state": "PRESENT"}],
        }],
    )
    cat = _make_catalogue([scenario])
    rec = _make_gt_record(1, scenario_id="scen-d1", expected_finding_types=["D1"])

    writer = TruthWriter(RUN_ID, _RENDERING_TABLE, cat)
    rendered = [
        _ebpf_event("file.read"),
        _ebpf_event("file.open"),
        _ebpf_event("token.file_index"),
    ]
    result = writer.write([rec], {1: rendered})

    opp = result.opportunities[0]
    assert opp.expected_state == dataset_pb2.PRESENT
    assert len(result.downgrades) == 0
    assert len(result.consistency_errors) == 0


# ---------------------------------------------------------------------------
# Test 3: Lookalike yields ABSENT
# ---------------------------------------------------------------------------

def test_lookalike_yields_absent():
    """An expects entry with state=ABSENT produces a FindingOpportunity ABSENT."""
    scenario = _make_scenario(
        "scen-lookalike",
        kind="lookalike",
        steps=[{
            "step": 1,
            "action": "http_request",
            "expects": [
                {"finding": "A1", "state": "ABSENT", "reason": "benign request"},
            ],
        }],
    )
    cat = _make_catalogue([scenario])
    rec = _make_gt_record(
        1, scenario_id="scen-lookalike",
        is_attack=False, expected_finding_types=[],
    )

    writer = TruthWriter(RUN_ID, _RENDERING_TABLE, cat)
    result = writer.write([rec], {1: [_gateway_event()]})

    assert len(result.opportunities) == 1
    opp = result.opportunities[0]
    assert opp.expected_state == dataset_pb2.ABSENT
    assert opp.finding_type == "A1"
    # evidence_event_ids still present (lookalike's rendered events)
    assert "ev-gw-001" in list(opp.evidence_event_ids)
    # No downgrade, no consistency error (ABSENT is not in expected_finding_types)
    assert len(result.downgrades) == 0
    assert len(result.consistency_errors) == 0


def test_lookalike_evidence_requirements_all_fields():
    """ABSENT opportunity carries all evidence_requirements (all were imitated)."""
    scenario = _make_scenario(
        "scen-lookalike",
        kind="lookalike",
        steps=[{"step": 1, "action": "http_request",
                "expects": [{"finding": "A1", "state": "ABSENT"}]}],
    )
    cat = _make_catalogue([scenario])
    rec = _make_gt_record(1, scenario_id="scen-lookalike", is_attack=False)

    writer = TruthWriter(RUN_ID, _RENDERING_TABLE, cat)
    result = writer.write([rec], {1: [_gateway_event()]})

    opp = result.opportunities[0]
    assert opp.expected_state == dataset_pb2.ABSENT
    # all A1 requirements should be listed
    req_set = set(opp.evidence_requirements)
    assert "microtrace.v0.GatewayObservation.request_id" in req_set


def _d1_lookalike_catalogue():
    return _make_catalogue([_make_scenario(
        "scen-d1-lookalike",
        kind="lookalike",
        steps=[{"step": 1, "action": "read_token_file",
                "expects": [{"finding": "D1", "state": "ABSENT",
                             "reason": "benign read"}]}],
    )])


def test_lookalike_dropped_source_yields_unobservable():
    """A lookalike whose required evidence was dropped is UNOBSERVABLE, not ABSENT.

    A dropped record is never scored as an observed negative: with
    token.file_index lost, the absence of D1 cannot be confirmed.
    """
    rec = _make_gt_record(1, scenario_id="scen-d1-lookalike", is_attack=False)
    writer = TruthWriter(RUN_ID, _RENDERING_TABLE, _d1_lookalike_catalogue())
    result = writer.write(
        [rec], {1: [_ebpf_event("file.read"), _ebpf_event("file.open")]},
        dropped_by_seq={1: [_ebpf_event("token.file_index")]})

    opp = result.opportunities[0]
    assert opp.expected_state == dataset_pb2.UNOBSERVABLE
    assert opp.reason.startswith("Lookalike evidence dropped: ")
    assert list(opp.evidence_requirements) == [
        "microtrace.v0.ProjectedVersion.owner_pod_uid"]
    # The surviving evidence stays referenced.
    assert set(opp.evidence_event_ids) == {
        "ev-ebpf-file-read", "ev-ebpf-file-open"}
    assert len(result.downgrades) == 1
    seq, ft, old, new, _why = result.downgrades[0]
    assert (seq, ft, old, new) == (1, "D1", "ABSENT", "UNOBSERVABLE")
    assert len(result.consistency_errors) == 0


def test_lookalike_full_evidence_stays_absent():
    """A lookalike with every required source rendered stays ABSENT."""
    rec = _make_gt_record(1, scenario_id="scen-d1-lookalike", is_attack=False)
    writer = TruthWriter(RUN_ID, _RENDERING_TABLE, _d1_lookalike_catalogue())
    result = writer.write([rec], {1: [
        _ebpf_event("file.read"),
        _ebpf_event("file.open"),
        _ebpf_event("token.file_index"),
    ]})

    opp = result.opportunities[0]
    assert opp.expected_state == dataset_pb2.ABSENT
    assert opp.reason == "benign read"
    assert len(result.downgrades) == 0


def test_lookalike_never_rendered_source_stays_absent():
    """Evidence the lookalike never renders is part of it, not a loss.

    token.file_index is missing but nothing was dropped (a clean run, or a
    lookalike that is benign because the step never happens): still ABSENT.
    """
    rec = _make_gt_record(1, scenario_id="scen-d1-lookalike", is_attack=False)
    writer = TruthWriter(RUN_ID, _RENDERING_TABLE, _d1_lookalike_catalogue())
    rendered = {1: [_ebpf_event("file.read"), _ebpf_event("file.open")]}

    for dropped in (None, {1: [_ebpf_event("file.read", "ev-other-read")]}):
        result = writer.write([rec], rendered, dropped_by_seq=dropped)
        opp = result.opportunities[0]
        assert opp.expected_state == dataset_pb2.ABSENT
        assert len(result.downgrades) == 0


# ---------------------------------------------------------------------------
# Test 4: Links reference existing actions
# ---------------------------------------------------------------------------

def test_links_reference_existing_actions():
    """ActionLink from/to_action_seq values exist in the gt_records."""
    scenario = _make_scenario(
        "scen-chain",
        steps=[
            {"step": 1, "action": "http_request",
             "expects": [{"finding": "A1", "state": "PRESENT"}]},
            {"step": 2, "action": "http_request",
             "expects": [{"finding": "A1", "state": "PRESENT"}]},
        ],
        links=[{
            "from": 1, "to": 2,
            "witness": "REQUEST_IDENTITY",
            "expected": "PRESENT",
            "shared_keys": ["request_id"],
        }],
    )
    cat = _make_catalogue([scenario])
    rec1 = _make_gt_record(
        1, scenario_id="scen-chain", step_label="1",
        expected_finding_types=["A1"],
    )
    rec2 = _make_gt_record(
        2, scenario_id="scen-chain", step_label="2",
        expected_finding_types=["A1"],
    )

    writer = TruthWriter(RUN_ID, _RENDERING_TABLE, cat)
    result = writer.write(
        [rec1, rec2],
        {
            1: [_gateway_event("ev-001")],
            2: [_gateway_event("ev-002")],
        },
    )

    existing_seqs = {r.action_seq for r in [rec1, rec2]}
    assert len(result.links) == 1
    lnk = result.links[0]
    assert lnk.from_action_seq in existing_seqs
    assert lnk.to_action_seq in existing_seqs
    assert lnk.from_action_seq != lnk.to_action_seq


def test_links_witness_type_is_set():
    """ActionLink has the correct WitnessType enum value."""
    from microtrace.v0 import witness_pb2

    scenario = _make_scenario(
        "scen-link-witness",
        steps=[
            {"step": 1, "action": "http_request", "expects": []},
            {"step": 2, "action": "http_request", "expects": []},
        ],
        links=[{
            "from": 1, "to": 2,
            "witness": "REQUEST_IDENTITY",
            "expected": "PRESENT",
        }],
    )
    cat = _make_catalogue([scenario])
    rec1 = _make_gt_record(1, scenario_id="scen-link-witness", step_label="1")
    rec2 = _make_gt_record(2, scenario_id="scen-link-witness", step_label="2")

    writer = TruthWriter(RUN_ID, _RENDERING_TABLE, cat)
    result = writer.write([rec1, rec2], {})

    assert len(result.links) == 1
    lnk = result.links[0]
    assert lnk.witness_type == witness_pb2.REQUEST_IDENTITY


def test_hard_nonlink_absent_expected_state():
    """Hard nonlink link definition produces expected_state=ABSENT."""
    scenario = _make_scenario(
        "scen-nonlink",
        steps=[
            {"step": 1, "action": "http_request", "expects": []},
            {"step": 2, "action": "api_request", "expects": []},
        ],
        links=[{
            "from": 1, "to": 2,
            "expected": "ABSENT",
            "shared_keys": ["pod_uid"],
        }],
    )
    cat = _make_catalogue([scenario])
    rec1 = _make_gt_record(10, scenario_id="scen-nonlink", step_label="1")
    rec2 = _make_gt_record(11, scenario_id="scen-nonlink", step_label="2")

    writer = TruthWriter(RUN_ID, _RENDERING_TABLE, cat)
    result = writer.write([rec1, rec2], {})

    assert len(result.links) == 1
    lnk = result.links[0]
    assert lnk.expected_state == dataset_pb2.ABSENT
    assert "pod_uid" in list(lnk.shared_keys)


# ---------------------------------------------------------------------------
# Test 5: Consistency check catches a mismatch
# ---------------------------------------------------------------------------

def test_consistency_check_catches_mismatch():
    """expected_finding_types=['A1'] but the step expects ABSENT → error."""
    scenario = _make_scenario(
        "scen-mismatch",
        steps=[{
            "step": 1,
            "action": "http_request",
            "expects": [{"finding": "A1", "state": "ABSENT"}],
        }],
    )
    cat = _make_catalogue([scenario])
    # Record declares A1 as expected, but the catalogue step has it ABSENT
    rec = _make_gt_record(
        1, scenario_id="scen-mismatch", expected_finding_types=["A1"],
    )

    writer = TruthWriter(RUN_ID, _RENDERING_TABLE, cat)
    result = writer.write([rec], {1: [_gateway_event()]})

    assert len(result.consistency_errors) == 1
    err_seq, err_msg = result.consistency_errors[0]
    assert err_seq == 1
    assert "PRESENT" in err_msg or "[]" in err_msg or "expected_finding_types" in err_msg


def test_consistency_check_passes_when_correct():
    """expected_finding_types=['A1'] with PRESENT opportunity → no error."""
    scenario = _make_scenario(
        "scen-ok",
        steps=[{
            "step": 1,
            "action": "http_request",
            "expects": [{"finding": "A1", "state": "PRESENT"}],
        }],
    )
    cat = _make_catalogue([scenario])
    rec = _make_gt_record(
        1, scenario_id="scen-ok", expected_finding_types=["A1"],
    )

    writer = TruthWriter(RUN_ID, _RENDERING_TABLE, cat)
    result = writer.write([rec], {1: [_gateway_event()]})

    assert len(result.consistency_errors) == 0


def test_consistency_check_catches_extra_present():
    """expected_finding_types=[] but step expects PRESENT → consistency error."""
    scenario = _make_scenario(
        "scen-extra",
        steps=[{
            "step": 1,
            "action": "http_request",
            "expects": [{"finding": "A1", "state": "PRESENT"}],
        }],
    )
    cat = _make_catalogue([scenario])
    # Record declares NO expected findings, but step expects PRESENT
    rec = _make_gt_record(
        1, scenario_id="scen-extra", expected_finding_types=[],
    )

    writer = TruthWriter(RUN_ID, _RENDERING_TABLE, cat)
    result = writer.write([rec], {1: [_gateway_event()]})

    assert len(result.consistency_errors) == 1


# ---------------------------------------------------------------------------
# Test: GroundTruthAction rendered_event_ids are filled
# ---------------------------------------------------------------------------

def test_gta_rendered_event_ids_filled():
    """TruthWriter fills rendered_event_ids on GroundTruthAction."""
    scenario = _make_scenario(
        "scen-a1",
        steps=[{"step": 1, "action": "http_request", "expects": []}],
    )
    cat = _make_catalogue([scenario])
    rec = _make_gt_record(5, scenario_id="scen-a1")
    eis = [_gateway_event("ev-001"), _gateway_event("ev-002")]

    writer = TruthWriter(RUN_ID, _RENDERING_TABLE, cat)
    result = writer.write([rec], {5: eis})

    assert len(result.actions) == 1
    gta = result.actions[0]
    assert gta.action_seq == 5
    assert list(gta.rendered_event_ids) == ["ev-001", "ev-002"]


# ---------------------------------------------------------------------------
# Test: write_restricted creates files on disk
# ---------------------------------------------------------------------------

def test_write_restricted_creates_files(tmp_path):
    """write_restricted creates truth_actions.pb, truth_findings.pb,
    truth_links.pb, and coverage.jsonl under <run_dir>/restricted/."""
    scenario = _make_scenario(
        "scen-a1",
        steps=[{
            "step": 1,
            "action": "http_request",
            "expects": [{"finding": "A1", "state": "PRESENT"}],
        }],
    )
    cat = _make_catalogue([scenario])
    rec = _make_gt_record(1, expected_finding_types=["A1"])

    writer = TruthWriter(RUN_ID, _RENDERING_TABLE, cat)
    result = writer.write([rec], {1: [_gateway_event()]})
    writer.write_restricted(result, tmp_path)

    restricted = tmp_path / "restricted"
    assert (restricted / "truth_actions.pb").exists()
    assert (restricted / "truth_findings.pb").exists()
    assert (restricted / "truth_links.pb").exists()
    assert (restricted / "coverage.jsonl").exists()


def test_write_restricted_round_trips_actions(tmp_path):
    """truth_actions.pb deserializes back to the correct GroundTruthAction."""
    scenario = _make_scenario(
        "scen-a1",
        steps=[{"step": 1, "action": "http_request", "expects": []}],
    )
    cat = _make_catalogue([scenario])
    rec = _make_gt_record(7, expected_finding_types=[])
    eis = [_gateway_event("ev-007")]

    writer = TruthWriter(RUN_ID, _RENDERING_TABLE, cat)
    result = writer.write([rec], {7: eis})
    writer.write_restricted(result, tmp_path)

    loaded = read_ld_protos(
        tmp_path / "restricted" / "truth_actions.pb",
        dataset_pb2.GroundTruthAction,
    )
    assert len(loaded) == 1
    gta = loaded[0]
    assert gta.run_id == RUN_ID
    assert gta.action_seq == 7
    assert list(gta.rendered_event_ids) == ["ev-007"]


def test_write_restricted_round_trips_findings(tmp_path):
    """truth_findings.pb deserializes back to the correct FindingOpportunity."""
    scenario = _make_scenario(
        "scen-a1",
        steps=[{
            "step": 1,
            "action": "http_request",
            "expects": [{"finding": "A1", "state": "PRESENT"}],
        }],
    )
    cat = _make_catalogue([scenario])
    rec = _make_gt_record(3, expected_finding_types=["A1"])

    writer = TruthWriter(RUN_ID, _RENDERING_TABLE, cat)
    result = writer.write([rec], {3: [_gateway_event("ev-003")]})
    writer.write_restricted(result, tmp_path)

    loaded = read_ld_protos(
        tmp_path / "restricted" / "truth_findings.pb",
        dataset_pb2.FindingOpportunity,
    )
    assert len(loaded) == 1
    opp = loaded[0]
    assert opp.run_id == RUN_ID
    assert opp.finding_type == "A1"
    assert opp.expected_state == dataset_pb2.PRESENT
    assert "ev-003" in list(opp.evidence_event_ids)


def test_write_restricted_round_trips_links(tmp_path):
    """truth_links.pb deserializes back to the correct ActionLink."""
    scenario = _make_scenario(
        "scen-chain",
        steps=[
            {"step": 1, "action": "http_request", "expects": []},
            {"step": 2, "action": "http_request", "expects": []},
        ],
        links=[{"from": 1, "to": 2, "witness": "REQUEST_IDENTITY",
                "expected": "PRESENT"}],
    )
    cat = _make_catalogue([scenario])
    rec1 = _make_gt_record(1, scenario_id="scen-chain", step_label="1")
    rec2 = _make_gt_record(2, scenario_id="scen-chain", step_label="2")

    writer = TruthWriter(RUN_ID, _RENDERING_TABLE, cat)
    result = writer.write([rec1, rec2], {})
    writer.write_restricted(result, tmp_path)

    loaded = read_ld_protos(
        tmp_path / "restricted" / "truth_links.pb",
        dataset_pb2.ActionLink,
    )
    assert len(loaded) == 1
    lnk = loaded[0]
    assert lnk.run_id == RUN_ID
    assert lnk.from_action_seq == 1
    assert lnk.to_action_seq == 2


# ---------------------------------------------------------------------------
# Test: coverage rows from SourceCompleteness records
# ---------------------------------------------------------------------------

def _make_sc(source_enum, scope, status=None, gap_reason=None):
    """Build a minimal SourceCompleteness proto for testing."""
    from google.protobuf.timestamp_pb2 import Timestamp
    sc = stream_pb2.SourceCompleteness()
    sc.source = source_enum
    sc.scope = scope
    sc.interval_start.CopyFrom(_ns_to_ts(RUN_START_NS))
    sc.interval_end.CopyFrom(_ns_to_ts(RUN_START_NS + 3600_000_000_000))
    sc.status = status if status is not None else stream_pb2.NO_KNOWN_GAP
    if gap_reason is not None:
        g = sc.gaps.add()
        g.reason = gap_reason
    return sc


def _ns_to_ts(ns: int):
    from google.protobuf.timestamp_pb2 import Timestamp
    ts = Timestamp()
    ts.seconds = ns // 1_000_000_000
    ts.nanos = ns % 1_000_000_000
    return ts


def test_coverage_rows_from_completeness():
    """Coverage rows are produced for each SourceCompleteness record."""
    cat = _make_catalogue([])
    writer = TruthWriter(RUN_ID, _RENDERING_TABLE, cat)

    sc_clean = _make_sc(common_pb2.GATEWAY, "gateway=1")
    sc_degraded = _make_sc(
        common_pb2.AUDIT,
        "audit-collector=1",
        status=stream_pb2.INCOMPLETE,
        gap_reason=common_pb2.DROPPED_BEFORE,
    )
    result = writer.write([], {}, completeness_records=[sc_clean, sc_degraded])

    assert len(result.coverage_rows) == 2
    by_source = {r["source_family"]: r for r in result.coverage_rows}

    assert by_source["GATEWAY"]["status"] == "NO_KNOWN_GAP"
    assert by_source["GATEWAY"]["gap_reason"] == ""

    assert by_source["AUDIT"]["status"] == "INCOMPLETE"
    assert by_source["AUDIT"]["gap_reason"] == "DROPPED_BEFORE"
    assert by_source["AUDIT"]["scope"] == "audit-collector=1"
    assert by_source["AUDIT"]["run_id"] == RUN_ID


def test_coverage_jsonl_is_valid_json(tmp_path):
    """coverage.jsonl contains valid JSON on every line."""
    cat = _make_catalogue([])
    writer = TruthWriter(RUN_ID, _RENDERING_TABLE, cat)
    sc = _make_sc(common_pb2.EBPF, "node=abc")
    result = writer.write([], {}, completeness_records=[sc])
    writer.write_restricted(result, tmp_path)

    with open(tmp_path / "restricted" / "coverage.jsonl") as fh:
        for line in fh:
            row = json.loads(line)
            assert "run_id" in row
            assert "source_family" in row


# ---------------------------------------------------------------------------
# Test: declared UNOBSERVABLE scenario step
# ---------------------------------------------------------------------------

def test_declared_unobservable_step():
    """A step with expects[state=UNOBSERVABLE] produces UNOBSERVABLE without downgrade."""
    scenario = _make_scenario(
        "scen-degraded",
        kind="degraded",
        steps=[{
            "step": 1,
            "action": "http_request",
            "expects": [{
                "finding": "A1",
                "state": "UNOBSERVABLE",
                "reason": "gateway observer SOURCE_IDLE",
            }],
        }],
    )
    cat = _make_catalogue([scenario])
    rec = _make_gt_record(
        1, scenario_id="scen-degraded", expected_finding_types=[]
    )

    writer = TruthWriter(RUN_ID, _RENDERING_TABLE, cat)
    result = writer.write([rec], {1: []})

    assert len(result.opportunities) == 1
    opp = result.opportunities[0]
    assert opp.expected_state == dataset_pb2.UNOBSERVABLE
    assert "SOURCE_IDLE" in opp.reason
    # No downgrade because it was declared UNOBSERVABLE in the catalogue
    assert len(result.downgrades) == 0


# ---------------------------------------------------------------------------
# Test: same scenario run twice produces distinct links
# ---------------------------------------------------------------------------

def test_same_scenario_twice_distinct_links():
    """Running the same scenario twice produces separate link records."""
    scenario = _make_scenario(
        "scen-chain",
        steps=[
            {"step": 1, "action": "http_request", "expects": []},
            {"step": 2, "action": "http_request", "expects": []},
        ],
        links=[{"from": 1, "to": 2, "witness": "REQUEST_IDENTITY",
                "expected": "PRESENT"}],
    )
    cat = _make_catalogue([scenario])

    # First execution: action_seqs 1 and 2
    rec1a = _make_gt_record(1, scenario_id="scen-chain", step_label="1")
    rec1b = _make_gt_record(2, scenario_id="scen-chain", step_label="2")
    # Second execution: action_seqs 3 and 4
    rec2a = _make_gt_record(3, scenario_id="scen-chain", step_label="1")
    rec2b = _make_gt_record(4, scenario_id="scen-chain", step_label="2")

    writer = TruthWriter(RUN_ID, _RENDERING_TABLE, cat)
    result = writer.write([rec1a, rec1b, rec2a, rec2b], {})

    # Two executions × 1 link each = 2 link records
    assert len(result.links) == 2
    link_pairs = {(lnk.from_action_seq, lnk.to_action_seq) for lnk in result.links}
    assert (1, 2) in link_pairs
    assert (3, 4) in link_pairs
