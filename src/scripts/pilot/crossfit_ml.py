"""Cross-fitted choice of the conformal alphas and the ML models (plan:
docs/plans/ml-threshold-crossfit-plan.md; choice rule fixed before any score).

Stages (each writes its output and can be rerun):

  fitcache  fit_params.fit_run over every FIT run -> one pickle (alpha-free)
  checkmax  rebuild the max-threshold set over all FIT runs from the cache and
            compare it with the existing fitted file (reproduction gate)
  folds     FIT -> folds A and B: per (world, profile), SHA-256("fold:" + run ID)
            order, dealt alternately
  params    conformal parameter set fitted on a run list at one alpha
  extract   ML feature rows of agents B, G, H over a run list, scenario events
            removed (as in fit_params), one JSON file per run
  train     Isolation Forests on the proper half of a run list; gamma per type
            and alpha on its calibration half (split-conformal on anomaly scores)
  config    a parameter set + one fold's models + gamma at one alpha
  summarize score_pilot's summary over a run list scored with several params
  select    apply the choice rule to the CV summaries

Run lists are given as FILE.json:KEY (e.g. folds.json:A, split.json:fit).
restricted/truth_actions.pb is read only for the scenario-event filter, as in
fit_params.py; labels are read only by the scoring harness.
"""
import argparse
import glob
import json
import math
import os
import pickle
import sys
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import yaml

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "src" / "python"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import fit_params  # noqa: E402
from mtcore.agents import routing  # noqa: E402
from mtcore.agents.engine import Engine  # noqa: E402
from mtcore.agents.events import Ev  # noqa: E402
from mtcore.agents.ml import ML_TYPES, canonical  # noqa: E402
from mtcore.agents.ml.scorer import Recorder, Scorer  # noqa: E402
from mtcore.agents.params import Params  # noqa: E402
from mtcore.agents.rules import for_agents  # noqa: E402

ML_AGENTS = ("B", "G", "H")


def runs_arg(spec):
    path, key = spec.rsplit(":", 1)
    return sorted(json.load(open(path, encoding="utf-8"))[key])


def hashed_halves(pilot, runs, salt):
    """Per (world, profile), SHA-256(salt + run ID) order, dealt alternately."""
    import hashlib
    groups = defaultdict(list)
    for r in runs:
        m = json.load(open(os.path.join(pilot, r, "manifest.json"), encoding="utf-8"))
        groups[(m["world_name"], m["observability_profile"])].append(r)
    a, b = [], []
    for key in sorted(groups):
        for i, r in enumerate(sorted(groups[key], key=lambda r: hashlib.sha256((salt + r).encode()).hexdigest())):
            (a if i % 2 == 0 else b).append(r)
    return sorted(a), sorted(b)


# ---- conformal gamma -------------------------------------------------------

def conformal_gamma(scores, alpha):
    """Smallest gamma with: fire iff score >= gamma <=> score > c, where c is the
    ceil((n+1)(1-alpha))-th smallest calibration score. None if n is too small
    to certify alpha (n < 1/alpha - 1)."""
    s = sorted(scores)
    n = len(s)
    k = math.ceil((n + 1) * (1 - alpha))
    if n == 0 or k > n:
        return None
    return math.nextafter(s[k - 1], math.inf)


def calibration_scores(arts, n_cold, rows):
    """{type: [anomaly score]} of the ML_SCORED calibration windows."""
    sc = Scorer(list(arts.values()), n_cold)
    out = defaultdict(list)
    for type_id, entity, feats in rows:
        status, score, _v = sc.score(type_id, entity, feats)
        if status == "ML_SCORED":
            out[type_id].append(score)
    return dict(out)


# ---- stages ----------------------------------------------------------------

def st_fitcache(a):
    runs = runs_arg(a.runs)
    base = yaml.safe_load(open(a.base, encoding="utf-8"))
    jobs = [(os.path.join(a.pilot, r), base["windows_s"]) for r in runs]
    results = []
    with ProcessPoolExecutor(max_workers=a.workers) as pool:
        for i, res in enumerate(pool.map(fit_params.fit_run, jobs), 1):
            results.append(res)
            print(f"{i}/{len(jobs)} {res[0]} events={res[1]['events']}", file=sys.stderr, flush=True)
    with open(a.out + ".tmp", "wb") as fh:
        pickle.dump(results, fh)
    os.replace(a.out + ".tmp", a.out)
    return 0


def load_cache(path):
    with open(path, "rb") as fh:
        return pickle.load(fh)


def st_checkmax(a):
    base = yaml.safe_load(open(a.base, encoding="utf-8"))
    results = load_cache(a.cache)
    fit = [r for r, _ in results]
    out = fit_params.build(base, results, a.pilot, fit, "max", None, base["parameter_set_version"], "-", 0)
    diff = [k for k in sorted(set(out["artifacts"]) | set(base["artifacts"]))
            if out["artifacts"].get(k) != base["artifacts"].get(k)]
    if out["thresholds"] != base["thresholds"]:
        diff.append("thresholds")
    print(json.dumps({"runs": len(fit), "differs": diff}))
    return 1 if diff else 0


def st_folds(a):
    fit = runs_arg(a.runs)
    fa, fb = hashed_halves(a.pilot, fit, "fold:")
    json.dump({"rule": "FIT per (world, profile): SHA-256('fold:' + run_id) order, even A, odd B",
               "A": fa, "B": fb, "all": sorted(fit)}, open(a.out, "w", encoding="utf-8"), indent=1)
    print(f"A {len(fa)} B {len(fb)}")
    return 0


def st_params(a):
    base = yaml.safe_load(open(a.base, encoding="utf-8"))
    runs = runs_arg(a.runs)
    out = fit_params.build(base, load_cache(a.cache), a.pilot, runs, a.threshold, a.alpha, a.version,
                           os.path.basename(a.runs), 0)
    out["fit"]["alpha"] = a.alpha if a.threshold == "conformal" else "max"
    out["fit"]["runs_from"] = a.runs
    with open(a.out, "w", encoding="utf-8") as fh:
        fh.write(f"# Generated by src/scripts/pilot/crossfit_ml.py params (alpha {a.alpha}, runs {a.runs}).\n")
        yaml.safe_dump(out, fh, sort_keys=False, allow_unicode=True, width=120)
    print(json.dumps(out["fit"].get("calibration"), sort_keys=True))
    return 0


def extract_run(args):
    """[(type, entity, features)] over a run's benign events, as the agents see them."""
    run_dir, params_path, out = args
    if os.path.exists(out):
        return os.path.basename(run_dir), "cached"
    from mtcore.harness.offline import read_shipper
    params = Params.load(params_path).with_overrides(ml={"enabled": True})
    skip = fit_params.scenario_event_ids(run_dir)
    rec = Recorder()
    eng = Engine(for_agents(list(ML_AGENTS)), params, scorer=rec)
    dropped = 0
    for topic, env in read_shipper(run_dir):
        if topic == "norm.events.v0" and env.HasField("normalized_event"):
            ev = Ev(env)
            if ev.id in skip:
                dropped += 1
                continue
            for atopic, key in routing.routes(ev):
                if key is not None:
                    eng.feed(env, atopic, key=key)
        else:
            eng.feed(env, topic)
    eng.finish()
    for _ in eng.drain():
        pass
    with open(out + ".tmp", "w", encoding="utf-8") as fh:
        json.dump({"scenario_events_dropped": dropped, "rows": rec.rows}, fh)
    os.replace(out + ".tmp", out)
    return os.path.basename(run_dir), f"{len(rec.rows)} rows, {dropped} scenario events dropped"


def st_extract(a):
    os.makedirs(a.out_dir, exist_ok=True)
    runs = runs_arg(a.runs)
    jobs = [(os.path.join(a.pilot, r), os.path.abspath(a.params), os.path.join(a.out_dir, r + ".json"))
            for r in runs]
    with ProcessPoolExecutor(max_workers=a.workers) as pool:
        for i, (r, msg) in enumerate(pool.map(extract_run, jobs), 1):
            print(f"{i}/{len(jobs)} {r} {msg}", file=sys.stderr, flush=True)
    return 0


def read_rows(rows_dir, runs):
    out = []
    for r in runs:
        out += [tuple(x) for x in json.load(open(os.path.join(rows_dir, r + ".json"), encoding="utf-8"))["rows"]]
    return out


def st_train(a):
    from mtcore.agents.ml.train import fit_forests
    params = Params.load(a.params)
    runs = runs_arg(a.runs)
    proper, calib = fit_params.calibration_split(a.pilot, runs)   # the same halves as the Q thresholds
    by_type = defaultdict(list)
    for t, e, f in read_rows(a.rows_dir, sorted(proper)):
        by_type[t].append((e, f))
    arts = fit_forests(dict(by_type), params, ML_AGENTS, None,
                       [{"rows_dir": os.path.abspath(a.rows_dir), "runs": a.runs, "half": "proper",
                         "proper_runs": len(proper)}])
    os.makedirs(a.out_dir, exist_ok=True)
    for agent, art in arts.items():
        with open(os.path.join(a.out_dir, f"IF_{agent}.json"), "w", encoding="utf-8") as fh:
            fh.write(canonical(art))
    scores = calibration_scores(arts, params.n_cold, read_rows(a.rows_dir, sorted(calib)))
    alphas = [float(x) for x in a.alphas.split(",")]
    types = sorted(t for art in arts.values() for t in art["types"])
    gamma = {str(al): {t: conformal_gamma(scores.get(t, []), al) for t in types} for al in alphas}
    report = {"proper_runs": len(proper), "calibration_runs": len(calib),
              "training_windows": {t: art["types"][t]["training_windows"] for art in arts.values() for t in art["types"]},
              "calibration_windows_scored": {t: len(scores.get(t, [])) for t in types},
              "untrained_types": sorted(set(sum(ML_TYPES.values(), [])) - set(types)),
              "feasible": {str(al): all(gamma[str(al)][t] is not None for t in types) for al in alphas},
              "gamma": gamma,
              "models": {agent: art["model_version"] for agent, art in arts.items()}}
    json.dump(report, open(os.path.join(a.out_dir, "train.json"), "w", encoding="utf-8"), indent=1)
    print(json.dumps({k: report[k] for k in ("training_windows", "calibration_windows_scored", "feasible",
                                              "untrained_types")}))
    return 0


def st_config(a):
    data = yaml.safe_load(open(a.params, encoding="utf-8"))
    tr = json.load(open(os.path.join(a.models, "train.json"), encoding="utf-8"))
    g = tr["gamma"][str(a.alpha_g)]
    if any(v is None for v in g.values()):
        raise SystemExit(f"alpha {a.alpha_g} is not feasible for every type: {g}")
    ml = dict(data.get("ml") or {})
    ml["enabled"] = True
    # types without a model are never scored; keep their declared value so the key exists
    ml["gamma"] = dict(ml.get("gamma") or {}, **g)
    ml["models"] = {agent: os.path.abspath(os.path.join(a.models, f"IF_{agent}.json")) for agent in tr["models"]}
    data["ml"] = ml
    data["parameter_set_version"] = a.version
    data.setdefault("fit", {})["alpha_gamma"] = a.alpha_g
    with open(a.out, "w", encoding="utf-8") as fh:
        fh.write(f"# Generated by src/scripts/pilot/crossfit_ml.py config (alpha_gamma {a.alpha_g}).\n")
        yaml.safe_dump(data, fh, sort_keys=False, allow_unicode=True, width=120)
    return 0


def st_summarize(a):
    import score_pilot
    ns = SimpleNamespace(pilot=a.pilot, out_dir=a.out_dir, params=a.label, split=a.runs, half="fit",
                         correlator="go", sage_variant=None)
    s = score_pilot.summarize(ns, runs_arg(a.runs))
    print(json.dumps({"runs_scored": s["runs_scored"], "missing": len(s["runs_missing"]),
                      "findings_f1": s["findings"]["f1"], "links_f1": s["links"]["f1"]}))
    return 1 if s["runs_missing"] else 0


def _alpha(x):
    """'max' (benign maximum) and 'none' (no ML) rank as the smallest alphas."""
    return 0.0 if x in ("max", "none") else float(x)


def st_select(a):
    """Rule (fixed 2026-11-09): highest out-of-fold finding F1; within 0.005 of the
    best, highest link F1; then the smaller alpha_q, then the smaller alpha_g.
    Addendum (user, 2026-11-09, before any arm was scored): the cross-fitted
    max-threshold arms qmax_gnone and qmax_g0.001 are candidates too; max and
    none count as the smallest alphas."""
    rows = []
    for f in sorted(glob.glob(os.path.join(a.cv_dir, "q*_g*", "summary.json"))):
        name = os.path.basename(os.path.dirname(f))
        aq, ag = name[1:].split("_g")
        s = json.load(open(f, encoding="utf-8"))
        if s["runs_missing"]:
            raise SystemExit(f"{name}: {len(s['runs_missing'])} runs missing")
        rows.append({"config": name, "alpha_q": aq, "alpha_g": ag,
                     "findings_f1": s["findings"]["f1"], "findings_precision": s["findings"]["precision"],
                     "findings_recall": s["findings"]["recall"], "links_f1": s["links"]["f1"],
                     "links_precision": s["links"]["precision"], "links_recall": s["links"]["recall"]})
    best = max(r["findings_f1"] for r in rows)
    near = [r for r in rows if r["findings_f1"] >= best - 0.005]
    near.sort(key=lambda r: (-r["links_f1"], _alpha(r["alpha_q"]), _alpha(r["alpha_g"])))
    out = {"rule": st_select.__doc__.split("\n", 1)[1].strip(), "candidates": rows,
           "within_0.005": [r["config"] for r in near], "chosen": near[0]}
    json.dump(out, open(a.out, "w", encoding="utf-8"), indent=1)
    print(json.dumps(out["chosen"]))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="stage", required=True)
    p = sub.add_parser("fitcache")
    p.add_argument("--pilot", required=True); p.add_argument("--runs", required=True)
    p.add_argument("--base", required=True); p.add_argument("--out", required=True)
    p.add_argument("--workers", type=int, default=4)
    p = sub.add_parser("checkmax")
    p.add_argument("--pilot", required=True); p.add_argument("--cache", required=True)
    p.add_argument("--base", required=True)
    p = sub.add_parser("folds")
    p.add_argument("--pilot", required=True); p.add_argument("--runs", required=True)
    p.add_argument("--out", required=True)
    p = sub.add_parser("params")
    p.add_argument("--pilot", required=True); p.add_argument("--cache", required=True)
    p.add_argument("--base", required=True); p.add_argument("--runs", required=True)
    p.add_argument("--alpha", type=float, default=None); p.add_argument("--version", required=True)
    p.add_argument("--threshold", choices=("conformal", "max"), default="conformal")
    p.add_argument("--out", required=True)
    p = sub.add_parser("extract")
    p.add_argument("--pilot", required=True); p.add_argument("--params", required=True)
    p.add_argument("--runs", required=True); p.add_argument("--out-dir", required=True)
    p.add_argument("--workers", type=int, default=4)
    p = sub.add_parser("train")
    p.add_argument("--pilot", required=True); p.add_argument("--params", required=True)
    p.add_argument("--rows-dir", required=True); p.add_argument("--runs", required=True)
    p.add_argument("--out-dir", required=True); p.add_argument("--alphas", default="0.01,0.001,0.0001")
    p = sub.add_parser("config")
    p.add_argument("--params", required=True); p.add_argument("--models", required=True)
    p.add_argument("--alpha-g", type=float, required=True); p.add_argument("--version", required=True)
    p.add_argument("--out", required=True)
    p = sub.add_parser("summarize")
    p.add_argument("--pilot", required=True); p.add_argument("--out-dir", required=True)
    p.add_argument("--runs", required=True); p.add_argument("--label", default="crossfit (params per fold)")
    p = sub.add_parser("select")
    p.add_argument("--cv-dir", required=True); p.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    return globals()["st_" + a.stage](a)


if __name__ == "__main__":
    sys.exit(main())
