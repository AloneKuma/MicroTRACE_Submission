"""Agent A (A1, A2) against rulebook.v0."""
import agent_fixtures as F
from agent_testlib import ABSTAINED, FIRED, NOT_FIRED, covers, of, outcomes, reasons, run


@covers("A1", "positive")
def test_a1_fires_on_declared_pattern():
    findings, evals, _ = run(F.stream(F.gateway(1, matches=[("sqli-union", "QUERY")])), ["A1"])
    [f] = of(findings, "A1")
    assert f.attributes["pattern_id"] == "sqli-union" and f.attributes["match_location"] == "QUERY"
    assert f.agent_id == "A" and not f.HasField("primary_tactic")
    assert f.detection_path == 1 and f.ml_status == 1   # PREDICATE, ML_NOT_APPLICABLE
    assert any(v.startswith("P_A@sha256:") for v in f.artifact_versions)
    assert outcomes(evals, "A1") == [FIRED]


@covers("A1", "neg:0")
def test_a1_ignores_pattern_outside_the_set():
    findings, evals, _ = run(F.stream(F.gateway(1, matches=[("json-string-token", "REQUEST_BODY")])), ["A1"])
    assert not of(findings, "A1") and outcomes(evals, "A1") == [NOT_FIRED]


@covers("A1", "abstain:0")
def test_a1_body_match_withheld_when_body_truncated_but_path_match_emits():
    _, evals, _ = run(F.stream(F.gateway(1, request_id="r1", matches=[("sqli-union", "REQUEST_BODY")],
                                         truncated=True)), ["A1"])
    assert outcomes(evals, "A1") == [ABSTAINED] and reasons(evals, "A1") == ["TRUNCATED"]
    findings, _, _ = run(F.stream(F.gateway(1, request_id="r2", matches=[("sqli-union", "REQUEST_BODY"),
                                                                          ("path-traversal", "PATH")],
                                            truncated=True)), ["A1"])
    assert of(findings, "A1")[0].attributes["pattern_id"] == "path-traversal"


def test_a1_workload_supplied_request_id_is_weak():
    findings, _, _ = run(F.stream(F.gateway(1, matches=[("sqli-union", "PATH")], origin="WORKLOAD")), ["A1"])
    req = [e for e in of(findings, "A1")[0].entities if e.type == 11][0]   # HTTP_REQUEST
    assert req.strength_class == 3                                          # STRENGTH_LOW


@covers("A2", "positive")
def test_a2_fires_with_declared_indicator_and_a1_also_fires():
    findings, _, _ = run(F.stream(F.gateway(1, matches=[("sqli-union", "QUERY")], indicators=["row-dump"])),
                         ["A1", "A2"])
    [a2] = of(findings, "A2")
    assert a2.primary_tactic == 1 and a2.attributes["indicator_id"] == "row-dump"   # INITIAL_ACCESS
    assert len(of(findings, "A1")) == 1


@covers("A2", "neg:0")
def test_a2_generic_error_page_is_not_an_indicator():
    findings, evals, _ = run(F.stream(F.gateway(1, matches=[("sqli-union", "QUERY")], status=500,
                                                indicators=["generic-500"])), ["A1", "A2"])
    assert not of(findings, "A2") and outcomes(evals, "A2") == [NOT_FIRED]
    assert len(of(findings, "A1")) == 1          # weaker output A1 remains


@covers("A2", "abstain:0")
def test_a2_abstains_when_response_unobserved_and_a1_emits():
    findings, evals, _ = run(F.stream(F.gateway(1, matches=[("sqli-union", "PATH")], loss=True)), ["A1", "A2"])
    assert outcomes(evals, "A2") == [ABSTAINED] and len(of(findings, "A1")) == 1


def test_common_abstention_gap_overlap_and_missing_field():
    rec = F.stream(F.gateway(10, matches=[("sqli-union", "PATH")]), F.loss(5, 15, source="GATEWAY"))
    findings, evals, _ = run(rec, ["A1"])
    assert not findings and reasons(evals, "A1") == ["DROPPED_BEFORE"]
    # A gap on another source, or outside the window, does not apply.
    rec = F.stream(F.gateway(10, matches=[("sqli-union", "PATH")]), F.loss(5, 15, source="AUDIT"),
                   F.loss(20, 30, source="GATEWAY"))
    findings, _, _ = run(rec, ["A1"])
    assert len(findings) == 1
    # An open-ended gap (unset end) is ended by the next event of its source:
    # that event and later ones are evaluated normally (test_agent_gaps.py).
    findings, _, _ = run(F.stream(F.gateway(10, matches=[("sqli-union", "PATH")]),
                                  F.loss(5, None, source="GATEWAY")), ["A1"])
    assert len(findings) == 1
