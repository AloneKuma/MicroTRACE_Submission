"""Agent B (B1, B2, B3) against rulebook.v0."""
import agent_fixtures as F
from agent_testlib import ABSTAINED, NOT_FIRED, covers, of, outcomes, run

SA = "system:serviceaccount:shop:checkout"


def reads(n_kinds, t0=1, principal=SA, verb="list"):
    """n_kinds distinct (resource, namespace) successful reads by principal."""
    return [F.audit(t0 + i, verb=verb, resource=f"res{i % 7}", namespace=f"ns{i // 7}", principal=principal)
            for i in range(n_kinds)]


@covers("B1", "positive")
def test_b1_fires_above_principal_baseline():
    findings, evals, _ = run(F.stream(*reads(6)), ["B1"])   # Q_B1 = 4
    [f] = of(findings, "B1")
    assert f.attributes["distinct_resource_count"] == "6" and f.primary_tactic == 6   # DISCOVERY
    assert f.baseline_version.startswith("Q_B1@sha256:")
    assert f.ml_status == 2                                   # ML_DISABLED: no model loaded


@covers("B1", "neg:0")
def test_b1_within_baseline_and_unbaselined_principal():
    findings, evals, _ = run(F.stream(*reads(4)), ["B1"])
    assert not findings and outcomes(evals, "B1") == [NOT_FIRED]
    findings, evals, _ = run(F.stream(*reads(9, principal="system:serviceaccount:shop:new")), ["B1"])
    assert not findings and outcomes(evals, "B1") == [ABSTAINED]


@covers("B1", "abstain:0", "abstain:1")
def test_b1_unbaselined_principal_is_reported_not_scored():
    _, evals, _ = run(F.stream(*reads(9, principal="system:serviceaccount:shop:new")), ["B1"])
    [e] = [e for e in evals if e.rule_id == "B1"]
    assert e.outcome == ABSTAINED and "baseline" in e.features["abstain"]


@covers("B1", "abstain:2")
def test_b1_no_reads_in_feed_gives_no_finding():
    # Only mutations from the principal: no read evidence, so nothing is claimed.
    findings, evals, _ = run(F.stream(*[F.audit(i, verb="create", resource="configmaps") for i in range(5)]), ["B1"])
    assert not findings and outcomes(evals, "B1") == [NOT_FIRED]


def test_b1_stages_of_one_request_count_once_and_failures_do_not_count():
    evs = []
    for i in range(6):
        aid = f"a{i}"
        evs.append(F.audit(1 + i, resource=f"r{i}", stage="RequestReceived", audit_id=aid))
        evs.append(F.audit(1 + i, resource=f"r{i}", audit_id=aid, code=403 if i >= 3 else 200))
    findings, evals, _ = run(F.stream(*evs), ["B1"])
    assert not findings   # only 3 successful kinds


def failures(n, code=401, t0=1, source="10.9.9.9"):
    return [F.audit(t0 + i, code=code, failed=(code == 401), observed_source=source, principal=None)
            for i in range(n)]


@covers("B2", "positive")
def test_b2_fires_on_401_burst_from_one_source():
    findings, _, _ = run(F.stream(*failures(12), *failures(3, code=403, t0=20)), ["B2"])   # N_B2 = 10
    [f] = of(findings, "B2")
    assert f.attributes["failure_count"] == "12" and f.attributes["forbidden_count_separate"] == "3"
    [e] = f.entities
    assert e.type == 19 and e.strength_class == 4    # UNAUTHENTICATED_SOURCE, STRENGTH_CONTEXT


@covers("B2", "neg:0")
def test_b2_403_burst_and_retries_below_threshold_do_not_fire():
    findings, evals, _ = run(F.stream(*failures(30, code=403)), ["B2"])
    assert not findings and set(outcomes(evals, "B2")) == {NOT_FIRED}
    findings, _, _ = run(F.stream(*failures(5)), ["B2"])
    assert not findings


@covers("B2", "abstain:0")
def test_b2_no_401_events_no_finding():
    findings, evals, _ = run(F.stream(*failures(4, code=404)), ["B2"])
    assert not findings and outcomes(evals, "B2") == [NOT_FIRED]


def test_b2_sources_are_separate_keys():
    findings, _, _ = run(F.stream(*failures(6, source="10.0.0.1"), *failures(6, source="10.0.0.2")), ["B2"])
    assert not findings


@covers("B3", "positive")
def test_b3_fires_above_rate_baseline():
    evs = [F.audit(i * 0.5, verb="get", resource="configmaps") for i in range(70)]   # Q_B3 = 60 per W_B3=60 s
    findings, _, _ = run(F.stream(*evs), ["B3"])
    [f] = of(findings, "B3")
    assert f.attributes["request_count"] == "70" and not f.HasField("primary_tactic")


@covers("B3", "neg:0")
def test_b3_batch_job_within_baseline():
    findings, evals, _ = run(F.stream(*[F.audit(i, resource="configmaps") for i in range(50)]), ["B3"])
    assert not findings and outcomes(evals, "B3") == [NOT_FIRED]


@covers("B3", "abstain:0")
def test_b3_unbaselined_principal_abstains():
    _, evals, _ = run(F.stream(*[F.audit(i * 0.5, principal="system:serviceaccount:x:y") for i in range(90)]), ["B3"])
    assert outcomes(evals, "B3") == [ABSTAINED]


def test_tumbling_windows_are_epoch_aligned():
    # 70 requests split across a window boundary at 60 s: 35 + 35, below Q_B3.
    evs = [F.audit(25 + i, resource="configmaps") for i in range(70)]
    findings, evals, _ = run(F.stream(*evs), ["B3"])
    assert not findings and len([e for e in evals if e.rule_id == "B3"]) >= 2
