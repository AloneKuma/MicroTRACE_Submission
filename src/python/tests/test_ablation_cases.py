"""No-Tactic cases (no-tactic-cases-plan T0): a path that leaves or enters
the top K counts, split into helps and hurts; a reordered path is reorder."""
import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]


def _ac():
    spec = importlib.util.spec_from_file_location(
        "ablation_cases", REPO / "src" / "scripts" / "pilot" / "ablation_cases.py")
    ac = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ac)
    return ac


def test_tactic_cases_count_top_k_membership_and_split_helps_and_hurts():
    ac = _ac()
    true_paths = {("d1", "h4"), ("x", "y")}
    full = {("d1", "h4"): 0, ("h2a", "h4"): 1, ("x", "y"): 0, ("solo",): 1}
    abl = {("h2a", "h4"): 0, ("h2b", "h4"): 1, ("x", "y"): 1, ("solo",): 0}
    got = ac.tactic_cases(full, abl, lambda p: p in true_paths)
    # Full alone keeps the true d1->h4 (helps); No-Tactic alone keeps the
    # false h2b->h4 (helps); h2a->h4 and x->y change rank (reorder); a
    # single-finding path is not a chain.
    assert got == {"helps": 2, "hurts": 0, "reorder": 2}
    assert ac.tactic_cases(abl, full, lambda p: p in true_paths) == {"helps": 0, "hurts": 2, "reorder": 2}
