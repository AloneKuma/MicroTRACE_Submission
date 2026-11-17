"""Freeze non-forest detectors for chosen ML types and write the parameter set that
filters with them (user choice 2026-11-12 after the ML model comparison:
H1 kNN, B1 one-class SVM; docs/plans/ml-model-compare-plan.md, ROADMAP 2b).

    python src/scripts/pilot/freeze_detectors.py --pilot PILOT --rows ROWS --runs folds.json:all \\
        --types B1:ocsvm,H1:knn --base src/params/frozen/pilot-multistep-fit.K10.mlB3.yaml \\
        --models-dir src/params/frozen/models/pilot-multistep-fit \\
        --out src/params/frozen/pilot-multistep-fit.K10.mlv2.yaml --version PILOT-FIT-v0-mlv2

Same data and halves as the frozen Isolation Forests (experiments/ml-crossfit/freeze.sh):
the rows of all FIT runs with scenario events removed, split by fit_params.calibration_split;
each detector is fitted on the proper half, its cut is split-conformal at alpha 0.001 on the
calibration half's scored windows (cold-start rule as the scorer's). The type's predicate
findings scored below the cut are dropped (ml.veto); with no score they stand (fail open).
"""
import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import yaml

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "src" / "python"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import crossfit_ml  # noqa: E402
import fit_params  # noqa: E402
from mtcore.agents.ml import DETECTOR_FORMAT, canonical, detectors, model_version  # noqa: E402
from mtcore.agents.ml.train import _rulebook_ml  # noqa: E402


def freeze_type(type_id, kind, pilot, rows_dir, runs, alpha, n_cold):
    rb = _rulebook_ml()[type_id]
    names, cold = list(rb["features"]), rb.get("cold_start", "N_cold")
    proper, calib = fit_params.calibration_split(pilot, runs)
    rows = {"proper": [], "calib": []}
    for r in runs:
        for t, e, f in json.load(open(os.path.join(rows_dir, r + ".json"), encoding="utf-8"))["rows"]:
            if t == type_id:
                rows["proper" if r in proper else "calib"].append((e or "", [float(f[n]) for n in names]))
    if not rows["proper"]:
        raise SystemExit(f"{type_id}: no training rows")
    ents = Counter(e for e, _ in rows["proper"])
    Xp = np.array([x for _, x in rows["proper"]])
    det = detectors.export(detectors.make(kind).fit(Xp))
    cal = [x for e, x in rows["calib"] if cold == "none" or ents[e] >= n_cold]
    sc = detectors.score_export(det, np.array(cal)) if cal else np.zeros(0)
    cut = crossfit_ml.conformal_gamma(sc.tolist(), alpha)
    if cut is None:
        raise SystemExit(f"{type_id}: {len(cal)} calibration windows cannot certify alpha {alpha}")
    from sklearn import __version__ as sk
    art = {"format": DETECTOR_FORMAT, "agent": type_id,
           "types": {type_id: {"detector": det, "features": names, "entities": dict(sorted(ents.items())),
                               "cold_start": cold, "training_windows": len(Xp), "replaces": "iforest"}},
           "training": {"runs": len(runs), "proper_runs": len(proper), "calibration_runs": len(calib),
                        "calibration_windows_scored": len(cal), "alpha": alpha, "cut": cut, "kind": kind},
           "libraries": {"scikit-learn": sk, "numpy": np.__version__}}
    art["model_version"] = model_version(art)
    return art, cut


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--pilot", required=True); ap.add_argument("--rows", required=True)
    ap.add_argument("--runs", required=True); ap.add_argument("--types", required=True)
    ap.add_argument("--alpha", type=float, default=0.001); ap.add_argument("--base", required=True)
    ap.add_argument("--models-dir", required=True); ap.add_argument("--out", required=True)
    ap.add_argument("--version", required=True)
    a = ap.parse_args(argv)
    base = yaml.safe_load(open(a.base, encoding="utf-8"))
    runs = crossfit_ml.runs_arg(a.runs)
    n_cold = int(base["ml"]["N_cold"])
    out_dir = os.path.dirname(os.path.abspath(a.out))
    summary = {}
    for spec in a.types.split(","):
        type_id, kind = spec.split(":")
        art, cut = freeze_type(type_id, kind, a.pilot, a.rows, runs, a.alpha, n_cold)
        path = os.path.join(a.models_dir, f"DET_{type_id}.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(canonical(art))
        base["ml"]["models"][type_id] = os.path.relpath(path, out_dir).replace(os.sep, "/")
        base["ml"].setdefault("veto", {})[type_id] = cut
        summary[type_id] = {"kind": kind, "cut": cut, "model_version": art["model_version"], **art["training"]}
        print(json.dumps({type_id: summary[type_id]}))
    base["parameter_set_version"] = a.version
    base.setdefault("fit", {})["detectors"] = {t: f"{v['kind']} cut {v['cut']} at alpha {a.alpha}"
                                               for t, v in summary.items()}
    with open(a.out, "w", encoding="utf-8") as fh:
        fh.write("# Generated by src/scripts/pilot/freeze_detectors.py from "
                 f"{os.path.basename(a.base)}: {a.types} filters (ml.veto), alpha {a.alpha}.\n"
                 "# gamma of B1/H1 is unused (or_path false); their anomaly scores are on the detector's scale.\n")
        yaml.safe_dump(base, fh, sort_keys=False, allow_unicode=True, width=120)
    json.dump(summary, open(os.path.join(a.models_dir, "detectors.json"), "w"), indent=1, sort_keys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
