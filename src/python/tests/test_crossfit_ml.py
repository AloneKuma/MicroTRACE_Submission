"""Cross-fitted ML choice (src/scripts/pilot/crossfit_ml.py): the conformal
gamma rule and the fold split."""
import importlib.util
import math
import random
import sys
from pathlib import Path

_DIR = Path(__file__).resolve().parents[2] / "scripts" / "pilot"
sys.path.insert(0, str(_DIR))
_spec = importlib.util.spec_from_file_location("crossfit_ml", _DIR / "crossfit_ml.py")
crossfit_ml = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(crossfit_ml)


def test_gamma_fires_strictly_above_the_conformal_order_statistic():
    scores = [i / 100 for i in range(1, 21)]          # n = 20
    g = crossfit_ml.conformal_gamma(scores, 0.1)      # k = ceil(21 * 0.9) = 19 -> c = 0.19
    assert 0.19 < g < 0.19 + 1e-12
    assert not (0.19 >= g) and 0.2 >= g


def test_gamma_is_none_when_n_cannot_certify_alpha():
    assert crossfit_ml.conformal_gamma([0.5] * 98, 0.01) is None      # needs n >= 99
    assert crossfit_ml.conformal_gamma([0.5] * 99, 0.01) is not None
    assert crossfit_ml.conformal_gamma([], 0.1) is None


def test_ties_never_fire_at_the_benign_value():
    g = crossfit_ml.conformal_gamma([0.4] * 50, 0.05)
    assert g > 0.4 and math.isclose(g, 0.4)


def test_benign_false_alarm_rate_is_bounded_by_alpha():
    rng = random.Random(1)
    alpha, fired, trials = 0.05, 0, 400
    for _ in range(trials):
        calib = [rng.random() for _ in range(99)]
        fired += rng.random() >= crossfit_ml.conformal_gamma(calib, alpha)
    assert fired / trials <= alpha + 0.03
