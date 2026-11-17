"""PILOT fit thresholds (src/scripts/pilot/fit_params.py), --threshold
conformal: Q_B1/Q_B3/Q_H1 are split-conformal thresholds at a declared alpha,
not the plain FIT maximum (the default)."""
import importlib.util
import random
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parents[2] / "scripts" / "pilot" / "fit_params.py"
_spec = importlib.util.spec_from_file_location("fit_params", _PATH)
fit_params = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fit_params)


def test_threshold_is_the_conformal_order_statistic_in_each_keys_units():
    proper = [{"a": [10, 10, 10], "b": [100, 104, 96, 100]}]   # a: MAD 0 -> floor 1; b: MAD 2
    calib = [{"a": [i for i in range(1, 21)]}]                 # scores -9 .. 10
    q, st = fit_params.calibrate(proper, calib, alpha=0.1, min_windows=1)
    # n = 20, k = ceil(21 * 0.9) = 19 -> 19th smallest score = 9
    assert st["factor"] == 9 and st["calibration_windows"] == 20
    assert q == {"a": 19, "b": 118}


def test_log_space_threshold_maps_back_to_bytes():
    proper = [{"w": [1000, 2000, 4000]}]
    calib = [{"w": [1000, 2000, 4000] * 10}]
    q, st = fit_params.calibrate(proper, calib, alpha=0.05, space="log", floor=0.05, min_windows=1)
    assert 3999 <= q["w"] <= 4001 and st["space"] == "log"


def test_constant_benign_feature_keeps_the_benign_value():
    proper = [{"p": [7, 7]}, {"p": [7]}]
    calib = [{"p": [7] * 30}]
    q, st = fit_params.calibrate(proper, calib, alpha=0.05, min_windows=1)
    assert q == {"p": 7} and st["factor"] == 0


def test_key_only_in_calibration_runs_is_unbaselined():
    q, st = fit_params.calibrate([{"a": [5]}], [{"a": [5] * 20, "z": [9]}], alpha=0.1, min_windows=1)
    assert "z" not in q and st["keys_only_in_calibration"] == 1


def test_key_with_too_few_proper_windows_is_unbaselined():
    q, st = fit_params.calibrate([{"a": [5] * 10, "thin": [3, 4]}], [{"a": [5] * 20, "thin": [9]}], alpha=0.1)
    assert q == {"a": 5} and st["keys_too_few_windows"] == 1


def test_too_few_calibration_windows_for_alpha_is_an_error():
    with pytest.raises(ValueError, match="cannot certify"):
        fit_params.calibrate([{"a": [5]}], [{"a": [5] * 50}], alpha=0.01, min_windows=1)


def test_benign_false_alarm_rate_stays_near_alpha_on_fresh_data():
    """The point of the method: on new benign data from the same process, the
    fraction of windows above Q stays near alpha (the plain maximum does not
    bound it; it depends on how many windows the fit happened to see)."""
    rng = random.Random(7)
    scales = {f"k{i}": rng.uniform(50, 500) for i in range(20)}

    def runs(n):
        return [{k: [int(s * rng.lognormvariate(0, 0.4)) for _ in range(10)] for k, s in scales.items()}
                for _ in range(n)]
    alpha = 0.01
    q, _ = fit_params.calibrate(runs(10), runs(10), alpha)
    fresh = runs(50)
    fires = sum(v > q[k] for r in fresh for k, vs in r.items() for v in vs)
    total = sum(len(vs) for r in fresh for vs in r.values())
    assert fires / total < 2 * alpha


def test_merge_keeps_per_run_window_values():
    def run(b3):
        return {"Q_B1": {}, "Q_B3": {"x": max(b3)}, "N_H3": 0, "Q_H1": {}, "Q_H2": {}, "Q_G1a": set(), "E_D1": {},
                "E_E2": {}, "E_F1": {}, "windows": {"Q_B1": {}, "Q_B3": {"x": b3}, "Q_H1": {}},
                "events": 0, "skipped": 0, "unowned_pods": 0, "owned_pods": 1}
    m, _ = fit_params.merge([("r1", run([100, 90])), ("r2", run([125]))])
    assert m["Q_B3"] == {"x": 125}
