"""Isolation Forest path: exported scoring equals sklearn, training refuses
HELD_OUT, OR-with-provenance, cold start, and No-ML parity."""
import pytest

sklearn = pytest.importorskip("sklearn")

import numpy as np  # noqa: E402
from sklearn.ensemble import IsolationForest  # noqa: E402

import agent_fixtures as F  # noqa: E402
from agent_testlib import of, params, run  # noqa: E402
from mtcore.agents.ml import ARTIFACT_FORMAT, iforest, model_version  # noqa: E402
from mtcore.agents.ml.scorer import Scorer  # noqa: E402
from mtcore.agents.ml.train import SplitError, train  # noqa: E402

SA = "system:serviceaccount:shop:checkout"


@pytest.mark.parametrize("max_features,bootstrap", [(1.0, False), (0.6, True)])
def test_exported_trees_score_exactly_like_sklearn(max_features, bootstrap):
    rng = np.random.default_rng(7)
    X = rng.normal(size=(300, 4)) * [1, 10, 100, 0.01]
    m = IsolationForest(n_estimators=50, max_samples=128, max_features=max_features, bootstrap=bootstrap,
                        random_state=3).fit(X)
    probe = np.vstack([X[:20], rng.normal(size=(20, 4)) * 50])
    ours = iforest.score(iforest.export(m, ["a", "b", "c", "d"]), probe)
    assert np.max(np.abs(ours - (-m.score_samples(probe)))) < 1e-12


def benign(windows=20, principal=SA, split="PILOT"):
    """Get-only traffic, 20-40 requests per 60 s window (W_B3)."""
    recs = []
    for w in range(windows):
        for i in range(20 + (w * 7) % 21):
            env = F.audit(w * 60 + i, verb="get", resource="configmaps", principal=principal)
            env.run.split = {"PILOT": 2, "RESEARCH": 3, "HELD_OUT": 4}[split]
            recs.append(("norm.events.v0", env))
    return recs


def b_artifact(p):
    arts = train(benign(), p, agents=["B"])
    art = arts["B"]
    assert art["model_version"] == model_version(art)
    assert art["types"]["B3"]["entities"][SA] == 20 and art["types"]["B3"]["training_windows"] == 20
    return art


def test_training_refuses_held_out():
    with pytest.raises(SplitError):
        train(benign(windows=2) + benign(windows=1, split="HELD_OUT"), params(), agents=["B"])


def burst(t0, n, verbs=("get",), principal=SA):
    return [F.audit(t0 + i * 0.1, verb=verbs[i % len(verbs)], resource="configmaps", principal=principal)
            for i in range(n)]


def score_of(art, feats):
    return iforest.score(art["types"]["B3"]["forest"], iforest.vector(art["types"]["B3"]["forest"], feats))[0]


def test_or_with_provenance_cold_start_and_no_ml_parity():
    p = params()
    art = b_artifact(p)
    normal = {"request_count": 30, "distinct_verb_count": 1, "mutating_request_fraction": 0.0}
    odd = {"request_count": 50, "distinct_verb_count": 5, "mutating_request_fraction": 0.8}
    s_normal, s_odd = score_of(art, normal), score_of(art, odd)
    assert s_odd > s_normal
    gamma = (s_normal + s_odd) / 2
    p_ml = p.with_overrides(ml={"gamma": {"B1": 1.0, "B2": 1.0, "B3": gamma, "G1a": 1.0, "H1": 1.0}},
                            artifacts={"Q_B3": {SA: 45, "system:serviceaccount:shop:new": 45}})
    scorer = Scorer([art], p_ml.n_cold)
    mixed = ["get", "create", "update", "patch", "delete"]
    recs = F.stream(*burst(10_000, 30),                        # normal, below Q_B3: nothing
                    *burst(10_060, 50, verbs=mixed),             # ML only (50 > 45? no: 50 > 45 yes)
                    )
    findings, evals, _ = run(recs, ["B3"], p=p_ml, scorer=scorer)
    paths = {f.attributes["request_count"]: (f.detection_path, f.ml_status) for f in of(findings, "B3")}
    # 50 mixed requests: predicate (50 > 45) and model both fire.
    assert paths == {"50": (3, 4)}                              # BOTH, ML_SCORED
    f = of(findings, "B3")[0]
    assert f.model_version == art["model_version"] and f.anomaly_score >= gamma
    ev = [e for e in evals if e.rule_id == "B3" and e.features.get("request_count") == "30"][0]
    assert ev.features["ml_status"] == "ML_SCORED" and "anomaly_score" in ev.features

    # ML only: raise the predicate threshold out of reach.
    p_ml_only = p_ml.with_overrides(artifacts={"Q_B3": {SA: 1000}})
    findings, _, _ = run(F.stream(*burst(10_060, 50, verbs=mixed)), ["B3"], p=p_ml_only, scorer=scorer)
    assert [(f.detection_path, f.ml_status) for f in findings] == [(2, 4)]      # ML

    # Predicate only: a normal-looking window above the threshold.
    p_pred = p_ml.with_overrides(artifacts={"Q_B3": {SA: 25}})
    findings, _, _ = run(F.stream(*burst(10_000, 30)), ["B3"], p=p_pred, scorer=scorer)
    assert [(f.detection_path, f.ml_status) for f in findings] == [(1, 4)]      # PREDICATE

    # Cold start: a principal the model never saw; only the predicate decides.
    new = "system:serviceaccount:shop:new"
    findings, evals, _ = run(F.stream(*burst(10_060, 50, verbs=mixed, principal=new)), ["B3"], p=p_ml, scorer=scorer)
    assert [(f.detection_path, f.ml_status) for f in findings] == [(1, 3)]      # PREDICATE, ML_COLD_START

    # No-ML ablation: exactly the predicate findings, same IDs.
    recs = F.stream(*burst(10_000, 30), *burst(10_060, 50, verbs=mixed), *burst(10_120, 50, verbs=mixed))
    with_ml, _, _ = run(recs, ["B3"], p=p_ml_only.with_overrides(artifacts={"Q_B3": {SA: 45}}), scorer=scorer)
    no_ml, _, _ = run(recs, ["B3"], p=p_ml.with_overrides(ml={"enabled": False}), scorer=scorer)
    pred_ids = sorted(f.finding_id for f in with_ml if f.detection_path in (1, 3))
    assert sorted(f.finding_id for f in no_ml) == pred_ids
    assert all(f.ml_status == 2 for f in no_ml)                                   # ML_DISABLED


def test_veto_drops_normal_looking_predicate_findings_and_fails_open():
    p = params()
    art = b_artifact(p)
    normal = {"request_count": 30, "distinct_verb_count": 1, "mutating_request_fraction": 0.0}
    odd = {"request_count": 50, "distinct_verb_count": 5, "mutating_request_fraction": 0.8}
    s_normal, s_odd = score_of(art, normal), score_of(art, odd)
    assert s_odd > s_normal
    cut = (s_normal + s_odd) / 2
    mixed = ["get", "create", "update", "patch", "delete"]
    base = p.with_overrides(ml={"gamma": {"B1": 1.0, "B2": 1.0, "B3": 0.0, "G1a": 1.0, "H1": 1.0},
                                "or_path": False, "veto": {"B3": cut}},
                            artifacts={"Q_B3": {SA: 25, "system:serviceaccount:shop:new": 25}})
    scorer = Scorer([art], base.n_cold)
    # Both windows pass the predicate (30, 50 > 25); only the odd one survives the veto.
    findings, _, _ = run(F.stream(*burst(10_000, 30), *burst(10_060, 50, verbs=mixed)), ["B3"], p=base, scorer=scorer)
    assert [(f.detection_path, f.ml_status) for f in of(findings, "B3")] == [(1, 4)]   # PREDICATE, ML_SCORED
    assert of(findings, "B3")[0].anomaly_score >= cut
    # or_path false: gamma 0 would fire every scored window, yet nothing below the predicate fires.
    findings, _, _ = run(F.stream(*burst(10_000, 20)), ["B3"], p=base, scorer=scorer)
    assert of(findings, "B3") == []
    # Fail-open: a cold-start principal keeps its predicate finding.
    new = "system:serviceaccount:shop:new"
    findings, _, _ = run(F.stream(*burst(10_000, 50, principal=new)), ["B3"], p=base, scorer=scorer)
    assert [(f.detection_path, f.ml_status) for f in findings] == [(1, 3)]             # PREDICATE, ML_COLD_START
    # Defaults (no or_path / veto keys) keep the OR behaviour.
    assert params().ml_or is True and params().veto == {}


def test_training_records_the_rulebook_cold_start():
    assert b_artifact(params())["types"]["B3"]["cold_start"] == "N_cold"


@pytest.mark.parametrize("cold_start,status", [("none", "ML_SCORED"), ("N_cold", "ML_COLD_START")])
def test_b2_scores_a_source_never_seen_in_training(cold_start, status):
    """B2 (rulebook cold_start: none) scores every observed source; an
    N_cold type withholds the score for an unseen key."""
    X = np.random.default_rng(1).normal(size=(64, 4))
    names = ["unauthorized_401_count", "forbidden_403_count", "distinct_user_agent_count", "request_count"]
    forest = iforest.export(IsolationForest(n_estimators=10, random_state=0).fit(X), names)
    art = {"format": ARTIFACT_FORMAT, "agent": "B",
           "types": {"B2": {"forest": forest, "entities": {"10.0.0.5": 64}, "cold_start": cold_start}}}
    art["model_version"] = model_version(art)
    got, score, _ = Scorer([art], 3).score("B2", "172.16.0.50", dict.fromkeys(names, 25))
    assert got == status and (score is not None) == (status == "ML_SCORED")


def test_tampered_artifact_is_rejected():
    art = b_artifact(params())
    art["types"]["B3"]["entities"][SA] = 999
    with pytest.raises(ValueError):
        Scorer([art], 3)
