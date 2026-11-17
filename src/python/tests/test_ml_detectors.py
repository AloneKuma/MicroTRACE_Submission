"""Detectors of the ML model comparison (mtcore.agents.ml.detectors)."""
import json
import math

import numpy as np
import pytest

from mtcore.agents.ml import detectors as D


def test_ecod_hand_values():
    # one feature, training 1..4 (skew 0 -> right tail), n = 4
    m = D.ECOD().fit(np.array([[1.0], [2.0], [3.0], [4.0]]))
    s = m.score(np.array([[4.0], [10.0], [0.0]]))
    # x = 4: left (4+1)/5, right (1+1)/5 -> max(-log 1, -log .4, right) = -log .4
    assert s[0] == pytest.approx(-math.log(2 / 5))
    # x = 10: right count 0 -> (0+1)/5
    assert s[1] == pytest.approx(-math.log(1 / 5))
    # x = 0: left count 0 -> (0+1)/5 (the max takes the left sum)
    assert s[2] == pytest.approx(-math.log(1 / 5))


def test_ecod_ranks_extreme_higher():
    rng = np.random.default_rng(0)
    X = rng.poisson(5, size=(500, 3)).astype(float)
    m = D.ECOD().fit(X)
    s = m.score(np.array([[5.0, 5.0, 5.0], [40.0, 5.0, 5.0]]))
    assert s[1] > s[0]


def test_hbos_hand_values():
    X = np.array([[0.0], [0.0], [0.0], [10.0]])
    m = D.HBOS(n_bins=2, alpha=0.1, tol=0.5).fit(X)
    # bins [0,5) and [5,10]: densities 3/(4*5) = .15 and 1/(4*5) = .05
    s = m.score(np.array([[0.0], [10.0], [12.0], [100.0]]))
    assert s[0] == pytest.approx(-math.log(0.15 + 0.1))
    assert s[1] == pytest.approx(-math.log(0.05 + 0.1))
    assert s[2] == pytest.approx(-math.log(0.05 + 0.1))      # within tol: edge bin
    assert s[3] == pytest.approx(-math.log(0.05 + 0.1))      # far: lowest density


def test_hbos_constant_feature():
    m = D.HBOS().fit(np.array([[3.0]] * 10))
    s = m.score(np.array([[3.0], [50.0]]))
    assert s[1] >= s[0]


@pytest.mark.parametrize("name", D.NAMES)
def test_detectors_flag_outlier_and_repeat(name):
    pytest.importorskip("sklearn")
    rng = np.random.default_rng(1)
    X = rng.poisson(4, size=(400, 3)).astype(float)
    probe = np.array([[4.0, 4.0, 4.0], [60.0, 0.0, 60.0]])
    a = D.make(name).fit(X).score(probe)
    b = D.make(name).fit(X).score(probe)
    assert a[1] > a[0]
    assert np.array_equal(a, b)                              # deterministic


def test_robust_scale_zero_iqr():
    sc = D.RobustScale().fit(np.array([[1.0, 0.0], [1.0, 2.0], [1.0, 4.0]]))
    z = sc(np.array([[1.0, 2.0]]))
    assert z[0, 0] == 0.0 and np.isfinite(z).all()


def test_rank_mix():
    mix = D.RankMix({"a": [1, 2, 3, 4], "b": [10, 20, 30, 40]})
    s = mix.score({"a": np.array([0, 4]), "b": np.array([25, 40])})
    assert s[0] == pytest.approx((0 / 4 + 2 / 4) / 2)
    assert s[1] == pytest.approx((4 / 4 + 4 / 4) / 2)


@pytest.mark.parametrize("name", ["knn", "ocsvm"])
def test_export_scores_equal_the_fitted_model(name):
    pytest.importorskip("sklearn")
    rng = np.random.default_rng(5)
    X = rng.poisson(6, size=(300, 3)).astype(float)
    Q = np.vstack([rng.poisson(6, size=(40, 3)).astype(float), [[90.0, 0.0, 50.0]]])
    m = D.make(name).fit(X)
    e = D.export(m)
    assert e["kind"] == name
    assert np.allclose(D.score_export(e, Q), m.score(Q), rtol=1e-9, atol=1e-9)
    e2 = json.loads(json.dumps(e))                      # survives a JSON round trip
    assert np.allclose(D.score_export(e2, Q), m.score(Q), rtol=1e-9, atol=1e-9)


def _det_artifact(type_id, replaces="iforest"):
    from mtcore.agents.ml import DETECTOR_FORMAT, model_version
    rng = np.random.default_rng(9)
    m = D.make("knn").fit(rng.poisson(5, size=(50, 3)).astype(float))
    t = {"detector": D.export(m), "features": ["a", "b", "c"], "entities": {"w": 10}, "cold_start": "N_cold",
         "training_windows": 50}
    if replaces:
        t["replaces"] = replaces
    art = {"format": DETECTOR_FORMAT, "agent": type_id, "types": {type_id: t}}
    art["model_version"] = model_version(art)
    return art, m


def _forest_artifact():
    from sklearn.ensemble import IsolationForest
    from mtcore.agents.ml import ARTIFACT_FORMAT, iforest, model_version
    rng = np.random.default_rng(2)
    f = IsolationForest(n_estimators=10, max_samples=32, random_state=0).fit(rng.poisson(5, size=(60, 3)))
    art = {"format": ARTIFACT_FORMAT, "agent": "H", "types": {"H1": {"forest": iforest.export(f, ["a", "b", "c"]),
                                                                   "entities": {"w": 10}}}}
    art["model_version"] = model_version(art)
    return art


def test_scorer_uses_a_detector_that_replaces_the_forest():
    pytest.importorskip("sklearn")
    from mtcore.agents.ml.scorer import Scorer
    forest = _forest_artifact()
    assert forest["model_version"].startswith("IF_H@")
    det, m = _det_artifact("H1")
    assert det["model_version"].startswith("DET_H1@")
    s = Scorer([forest, det], n_cold=3)
    status, score, version = s.score("H1", "w", {"a": 4, "b": 5, "c": 6})
    assert status == "ML_SCORED" and version == det["model_version"]
    assert score == pytest.approx(float(m.score(np.array([[4.0, 5.0, 6.0]]))[0]))
    assert s.score("H1", "new-workload", {"a": 1, "b": 1, "c": 1})[0] == "ML_COLD_START"


def test_scorer_refuses_ambiguous_detectors():
    pytest.importorskip("sklearn")
    from mtcore.agents.ml.scorer import Scorer
    forest = _forest_artifact()
    det, _ = _det_artifact("H1", replaces=None)
    with pytest.raises(ValueError, match="replaces"):
        Scorer([forest, det], n_cold=3)
    det, _ = _det_artifact("H1")
    with pytest.raises(ValueError, match="two"):
        Scorer([forest, det, det], n_cold=3)
    bad = dict(det, model_version="DET_H1@sha256:0000")
    with pytest.raises(ValueError, match="hash"):
        Scorer([bad], n_cold=3)
