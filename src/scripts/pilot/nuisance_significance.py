"""Permutation significance for the nuisance check of a split.

For each finding type, compare the cross-validated nuisance score with a
null distribution obtained by shuffling the labels among that finding's
windows (keeping every run's features). A score at or above the threshold
that the null reaches often is a small-sample effect, not leakage.

Writes <split_dir>/nuisance_significance.json and prints one line per finding.

Usage (from the repository root):
    python src/scripts/pilot/nuisance_significance.py datasets/generated/pilot --permutations 200
"""
import argparse
import json
import sys
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "src" / "python"))
import mtgen  # noqa: E402,F401
from mtgen import nuisance as N  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("split_dir")
    ap.add_argument("--permutations", type=int, default=200)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args(argv)

    split = Path(args.split_dir)
    threshold = N.check_nuisance(split).threshold
    rows = N._load_split(split)
    rng = np.random.default_rng(args.seed)
    out = {"threshold": threshold, "permutations": args.permutations, "findings": {}}
    for ft in sorted({r.finding_type for r in rows}):
        sub = [r for r in rows if r.finding_type == ft]
        obs = N._check_finding(sub, ft, threshold)
        if obs.metric == "insufficient_labels":
            out["findings"][ft] = {"metric": obs.metric}
            print(f"{ft:4s} insufficient labels")
            continue
        labels = np.array([r.label for r in sub])
        null = []
        for _ in range(args.permutations):
            perm = rng.permutation(labels)
            shuffled = [N.OppRow(r.run_id, r.finding_type, int(perm[i]), r.features)
                        for i, r in enumerate(sub)]
            null.append(N._check_finding(shuffled, ft, threshold).score)
        null = np.array(null)
        p = float((np.sum(null >= obs.score) + 1) / (len(null) + 1))
        rec = {
            "metric": obs.metric, "score": round(obs.score, 4),
            "windows": obs.n_windows, "positive": obs.n_positive,
            "null_mean": round(float(null.mean()), 4),
            "null_p95": round(float(np.percentile(null, 95)), 4),
            "p_value": round(p, 4),
            "over_threshold": obs.score >= threshold,
        }
        out["findings"][ft] = rec
        flag = "OVER" if rec["over_threshold"] else "    "
        print(f"{ft:4s} {flag} score={rec['score']:.3f} p={rec['p_value']:.3f} "
              f"null_mean={rec['null_mean']:.2f} null_p95={rec['null_p95']:.2f} "
              f"windows={rec['windows']} positive={rec['positive']}")
    (split / "nuisance_significance.json").write_text(json.dumps(out, indent=2),
                                                      encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
