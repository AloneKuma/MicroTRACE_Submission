"""ML model comparison: five anomaly detectors and two rank mixes against the
Isolation Forest, as filters of rule findings (plan:
docs/plans/ml-model-compare-plan.md; rule: experiments/ml-compare/RULE-modelcompare.md,
fixed before any number). PILOT FIT runs only, folds A/B of ~/microtrace-ml.

Stages (each writes its output; reruns skip finished work where noted):

  cfg      a fold's scoring config: qmax_g0.001 with or_path off and no veto, so the
           Isolation Forest scores every finding and changes none (rules-only set)
  table    per run, from score_pilot's output of that config: one row per finding of
           an ML type with its feature vector, Isolation Forest status and score, and
           its label (true / false / unobs); resumable per run
  check1   C1: the table run's findings and links equal qmax_gnone's
  check2   C2: the table's Isolation Forest scores equal qmax_confirmB3's findings
  compare  fit every arm per fold and type on the other fold's benign rows, cut,
           measure, bootstrap -> compare.json and per-record decisions
  select1  rule step 1 -> candidates and the step 2 configurations (drop sets)
  filter   one configuration's cached outputs (findings it drops removed)
  check3   C3: replay of 'none' equals qmax_gnone, of 'frozen' equals qmax_confirmB3
  select2  rule step 2 over the replayed scores -> step2.json
  report   REPORT.md from compare.json, step1.json and step2.json

Run lists: FILE.json:KEY. Labels are read from the runs' restricted/ truth, which is
allowed for PILOT FIT (development) data; held-out data is never read.
"""
import argparse
import gzip
import json
import math
import os
import sys
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import numpy as np
import yaml

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "src" / "python"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

ML_TYPES = ("B1", "B2", "B3", "G1a", "H1")
ARMS = ("iforest", "ecod", "hbos", "knn", "lof", "ocsvm", "mix_all", "mix_best3")
SINGLE = ARMS[:6]
LARGE = "226278d9-aff7-5a1d-8778-96ee1ee40480"
ALPHAS = (0.001, 0.01)
DRAWS = 2000
SEED = 20261111


def runs_arg(spec):
    path, key = spec.rsplit(":", 1)
    return sorted(json.load(open(path, encoding="utf-8"))[key])


def jdump(obj, path):
    tmp = str(path) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=1, sort_keys=True)
    os.replace(tmp, path)


def open_text(path):
    return gzip.open(path, "rt", encoding="utf-8") if str(path).endswith(".gz") else open(path, encoding="utf-8")


def ts_ns(s):
    from google.protobuf.timestamp_pb2 import Timestamp
    t = Timestamp()
    t.FromJsonString(s)
    return t.ToNanoseconds()


def feature_names():
    from mtcore.agents.ml.train import _rulebook_ml
    rb = _rulebook_ml()
    return {t: list(rb[t]["features"]) for t in ML_TYPES}, {t: rb[t].get("cold_start", "N_cold") for t in ML_TYPES}


# ---- measures (sklearn-equivalent, numpy only so the bootstrap is fast) ------------------
def average_precision(y, s):
    """sklearn.metrics.average_precision_score (ties share a threshold)."""
    y, s = np.asarray(y, dtype=bool), np.asarray(s, dtype=np.float64)
    P = y.sum()
    if P == 0 or P == len(y):
        return None
    order = np.argsort(-s, kind="mergesort")
    y, s = y[order], s[order]
    last = np.r_[np.nonzero(np.diff(s))[0], len(s) - 1]       # last index of each distinct score
    tp = np.cumsum(y)[last]
    fp = (last + 1) - tp
    prec = tp / (tp + fp)
    rec = tp / P
    return float(np.sum(np.diff(np.r_[0.0, rec]) * prec))


def roc_auc(y, s):
    y, s = np.asarray(y, dtype=bool), np.asarray(s, dtype=np.float64)
    P, N = y.sum(), (~y).sum()
    if P == 0 or N == 0:
        return None
    from scipy.stats import rankdata
    r = rankdata(s)
    return float((r[y].sum() - P * (P + 1) / 2) / (P * N))


def mcc(tp, fp, fn, tn):
    d = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return (tp * tn - fp * fn) / d if d else None


# ---- labels ---------------------------------------------------------------------------
def labeller(restricted):
    """finding (type, input_event_ids) -> 'true' | 'false' | 'unobs', as
    mtcore.harness.score.score_findings decides per record (no fault log in FIT runs)."""
    from mtcore.harness import score as S
    return make_label(S.Truth.load(restricted))


def make_label(truth):
    from mtcore.harness import score as S
    states = S.effective_states(truth, set())
    idx = defaultdict(lambda: defaultdict(list))
    for o in truth.opportunities:
        for ev in o.evidence_event_ids:
            idx[o.finding_type][ev].append(o.opportunity_id)

    def label(ftype, events):
        st = {states[k] for ev in events for k in idx[ftype].get(ev, ())}
        if S.PRESENT in st:
            return "true"
        if S.UNOBSERVABLE in st:
            return "unobs"
        return "false"
    return label


# ---- stage cfg ----------------------------------------------------------------------------
def st_cfg(a):
    d = yaml.safe_load(open(a.src, encoding="utf-8"))
    d["ml"]["or_path"] = False
    d["ml"]["veto"] = {}
    d["parameter_set_version"] = a.version
    d.setdefault("fit", {})["model_compare"] = "scores only: or_path false, no veto (rules-only findings)"
    with open(a.out, "w", encoding="utf-8") as fh:
        fh.write("# Generated by src/scripts/pilot/model_compare.py cfg (Isolation Forest scores, no effect).\n")
        yaml.safe_dump(d, fh, sort_keys=False, allow_unicode=True, width=120)
    return 0


# ---- stage table ------------------------------------------------------------------------
def table_run(args):
    run, fold, raw_dir, pilot, out = args
    if os.path.exists(out):
        return run, "cached"
    names, _cold = feature_names()
    src = os.path.join(raw_dir, "runs", run, "output.jsonl.gz")
    findings, evals, g1a_windows = {}, {}, defaultdict(list)
    with open_text(src) as fh:
        for line in fh:
            o = json.loads(line)
            t, r = o.get("topic"), o.get("record")
            if r is None:
                continue
            if t == "findings.v0" and r.get("findingType") in ML_TYPES:
                findings[r["findingId"]] = r
            elif t == "rule.evaluations.v0" and r.get("ruleId") in ML_TYPES:
                f = r.get("features", {})
                if r["ruleId"] == "G1a" and "connect_count" in f:
                    g1a_windows[r["stateKeyHex"]].append(
                        (ts_ns(r["windowStart"]), ts_ns(r["windowEnd"]), f))
                elif r.get("findingId"):
                    evals[r["findingId"]] = r
    label = labeller(os.path.join(pilot, run, "restricted"))
    rows = []
    for fid, f in sorted(findings.items()):
        typ = f["findingType"]
        ev = evals.get(fid)
        if ev is None:
            raise SystemExit(f"{run}: finding {fid} has no evaluation")
        feats, status, score = ev.get("features", {}), f.get("mlStatus", "ML_STATUS_UNSPECIFIED"), f.get("anomalyScore")
        if typ == "G1a":
            t = ts_ns(ev["windowEnd"])
            win = [w for w in g1a_windows.get(ev["stateKeyHex"], []) if w[0] <= t <= w[1]]
            if len(win) > 1:
                raise SystemExit(f"{run}: G1a finding {fid} lies in {len(win)} model windows")
            if not win:
                feats, status, score = {}, "NO_WINDOW", None
            else:
                feats = win[0][2]
                status = feats.get("ml_status", "ML_STATUS_UNSPECIFIED")
                score = float(feats["anomaly_score"]) if "anomaly_score" in feats else None
        x = [float(feats[n]) for n in names[typ]] if all(n in feats for n in names[typ]) else None
        if status == "ML_SCORED" and (x is None or score is None):
            raise SystemExit(f"{run}: scored finding {fid} without features or score")
        own = f.get("anomalyScore")
        rows.append({"run": run, "fold": fold, "type": typ, "fid": fid,
                     "label": label(typ, f.get("inputEventIds", [])), "status": status,
                     "if_score": None if score is None else float(score), "x": x,
                     "finding_score": None if own is None else float(own)})
    with open(out + ".tmp", "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    os.replace(out + ".tmp", out)
    return run, f"{len(rows)} rows " + json.dumps(dict(Counter(r['type'] for r in rows)), sort_keys=True)


def st_table(a):
    folds = json.load(open(a.folds, encoding="utf-8"))
    os.makedirs(a.out_dir, exist_ok=True)
    jobs = [(r, F, a.raw, a.pilot, os.path.join(a.out_dir, r + ".jsonl")) for F in ("A", "B") for r in folds[F]]
    bad = 0
    with ProcessPoolExecutor(max_workers=a.workers) as pool:
        for i, res in enumerate(pool.map(_safe(table_run), jobs), 1):
            print(f"{i}/{len(jobs)} {res[0]} {res[1]}", file=sys.stderr, flush=True)
            bad += res[1].startswith("FAILED")
    return 1 if bad else 0


class _safe:
    def __init__(self, fn):
        self.fn = fn

    def __call__(self, args):
        try:
            return self.fn(args)
        except BaseException as e:  # noqa: BLE001  (reported per run, stage fails)
            return args[0], f"FAILED {type(e).__name__}: {e}"


def read_table(table_dir, runs):
    out = []
    for r in runs:
        with open(os.path.join(table_dir, r + ".jsonl"), encoding="utf-8") as fh:
            out += [json.loads(ln) for ln in fh if ln.strip()]
    return out


# ---- checks ---------------------------------------------------------------------------------
def score_view(path):
    s = json.load(open(path, encoding="utf-8"))
    f, l = s["findings"], s["links"]
    keys = ("tp", "fp", "fn", "on_unobservable", "fp_absent", "fp_background")
    return {"overall": {k: f["overall"].get(k) for k in keys},
            "per_type": {t: {k: v.get(k) for k in keys} for t, v in sorted(f["per_type"].items())},
            "false_findings": sorted(f["false_findings"]),
            "links": {k: l.get(k) for k in ("tp", "fp", "fn")}}


def same_scores(mine_dir, ref_dir, runs):
    bad = []
    for r in runs:
        a = score_view(os.path.join(mine_dir, "runs", r, "score.json"))
        b = score_view(os.path.join(ref_dir, "runs", r, "score.json"))
        if a != b:
            bad.append(r)
    return bad


def st_check1(a):
    bad = same_scores(a.raw, a.ref, runs_arg(a.runs))
    print(json.dumps({"check": "C1", "runs_differ": len(bad), "first": bad[:3]}))
    return 1 if bad else 0


def st_check2(a):
    """Every finding qmax_confirmB3 kept carries the same Isolation Forest score (6 dp)
    in our table; every B3 finding it dropped scores below its cut here."""
    runs = runs_arg(a.runs)
    folds = json.load(open(a.folds, encoding="utf-8"))
    fold_of = {r: F for F in ("A", "B") for r in folds[F]}
    cuts = {F: json.load(open(os.path.join(a.models, f"fold{F}-max", "train.json")))["gamma"]["0.001"]["B3"]
            for F in ("A", "B")}
    n, bad = 0, []
    for r in runs:
        mine = {x["fid"]: x for x in read_table(a.table, [r])}
        ref = {x["findingId"]: x for x in json.load(open(os.path.join(a.ref, "runs", r, "findings.json")))
               if x["findingType"] in ML_TYPES}
        for fid, x in ref.items():
            m = mine.get(fid)
            n += 1
            if m is None:
                bad.append((r, fid, "missing"))
            elif (x.get("anomalyScore") is None) != (m["finding_score"] is None) or (
                    x.get("anomalyScore") is not None and round(x["anomalyScore"], 6) != round(m["finding_score"], 6)):
                bad.append((r, fid, "score"))
        for fid, m in mine.items():
            if fid in ref:
                continue
            n += 1
            ok = m["type"] == "B3" and m["status"] == "ML_SCORED" and m["if_score"] < cuts[fold_of[r]]
            if not ok:
                bad.append((r, fid, "dropped but not a B3 below the cut"))
    print(json.dumps({"check": "C2", "compared": n, "bad": len(bad), "first": bad[:3]}))
    return 1 if bad else 0


def st_check3(a):
    runs = runs_arg(a.runs)
    out = {}
    for mine, ref in ((a.none, a.ref_none), (a.frozen, a.ref_frozen)):
        out[os.path.basename(mine.rstrip("/"))] = same_scores(mine, ref, runs)
    print(json.dumps({"check": "C3", **{k: len(v) for k, v in out.items()},
                      "first": {k: v[:3] for k, v in out.items()}}))
    return 1 if any(out.values()) else 0


# ---- stage compare ------------------------------------------------------------------------
def conformal_cut(scores, alpha):
    import crossfit_ml
    return crossfit_ml.conformal_gamma(list(scores), alpha)


def fold_type(args):
    """Fit every single arm for one (fold, type); score its calibration rows and its
    findings. Returns arrays and cuts (mixes are built afterwards)."""
    F, typ, pilot, rows_dir, models_dir, train_runs, recs = args
    import fit_params
    from mtcore.agents.ml import detectors as D, iforest
    names, cold = feature_names()
    proper, calib = fit_params.calibration_split(pilot, train_runs)
    tr = defaultdict(list)
    for r in train_runs:
        for t, e, f in json.load(open(os.path.join(rows_dir, f"fold{F}-max", r + ".json")))["rows"]:
            if t == typ:
                tr["proper" if r in proper else "calib"].append((e, [float(f[n]) for n in names[typ]]))
    art_path = os.path.join(models_dir, f"fold{F}-max", f"IF_{typ[0]}.json")
    art = json.load(open(art_path, encoding="utf-8")) if os.path.exists(art_path) else {"types": {}}
    if not tr["proper"] or typ not in art["types"]:
        return F, typ, None             # no benign rows or no Isolation Forest to compare with
    forest = art["types"][typ]["forest"]
    ents = Counter(e for e, _ in tr["proper"])
    Xp = np.array([x for _, x in tr["proper"]])
    cal = [x for e, x in tr["calib"] if cold[typ] == "none" or ents[e] >= 3]
    Xc = np.array(cal) if cal else np.zeros((0, len(names[typ])))
    alpha = next((al for al in ALPHAS if conformal_cut(np.zeros(len(Xc)), al) is not None), None)
    scored = [i for i, r in enumerate(recs) if r["status"] == "ML_SCORED"]
    Xf = np.array([recs[i]["x"] for i in scored]) if scored else np.zeros((0, len(names[typ])))
    res = {"alpha": alpha, "n_proper": len(Xp), "n_calib_scored": len(Xc), "scored_idx": scored, "arms": {}}
    for arm in SINGLE:
        if arm == "iforest":
            sc = lambda X: iforest.score(forest, np.asarray(X, dtype=np.float64)) if len(X) else np.zeros(0)  # noqa: E731
        else:
            m = D.make(arm).fit(Xp)
            sc = lambda X, m=m: m.score(X) if len(X) else np.zeros(0)  # noqa: E731
        sp, scal, sf = sc(Xp), sc(Xc), sc(Xf)
        res["arms"][arm] = {"proper": sp.tolist(), "calib": scal.tolist(), "find": sf.tolist(),
                            "cut": conformal_cut(scal, alpha) if alpha else None}
    # gate: our Isolation Forest scores and cut equal the frozen fold model's
    tj = json.load(open(os.path.join(models_dir, f"fold{F}-max", "train.json")))
    g = tj["gamma"].get("0.001", {}).get(typ)
    if alpha == 0.001 and g is not None and res["arms"]["iforest"]["cut"] != g:
        raise SystemExit(f"fold {F} {typ}: Isolation Forest cut {res['arms']['iforest']['cut']} != train.json {g}")
    for k, i in enumerate(scored):
        if round(res["arms"]["iforest"]["find"][k], 6) != round(recs[i]["if_score"], 6):
            raise SystemExit(f"fold {F} {typ}: recomputed Isolation Forest score differs for {recs[i]['fid']}")
    return F, typ, res


def add_mix(res, arms, name):
    from mtcore.agents.ml.detectors import RankMix
    mix = RankMix({a: res["arms"][a]["proper"] for a in arms})
    part = {k: mix.score({a: res["arms"][a][k] for a in arms}).tolist() if len(res["arms"][arms[0]][k]) else []
            for k in ("proper", "calib", "find")}
    part["cut"] = conformal_cut(part["calib"], res["alpha"]) if res["alpha"] else None
    part["members"] = list(arms)
    res["arms"][name] = part


def measures(recs, idx, scores, cut, runs_keep=None):
    """Measures over labelled records (true/false) of the given scored indices."""
    y, s, lost, removed = [], [], 0, 0
    tp = fp = fn = tn = 0
    for k, i in enumerate(idx):
        r = recs[i]
        if runs_keep is not None and r["run"] not in runs_keep:
            continue
        if r["label"] == "unobs":
            continue
        keep = cut is None or scores[k] >= cut
        t = r["label"] == "true"
        y.append(t)
        s.append(scores[k])
        tp += t and keep
        fn += t and not keep
        fp += (not t) and keep
        tn += (not t) and not keep
    return {"n_true": int(sum(y)), "n_false": len(y) - int(sum(y)), "pr_auc": average_precision(y, s),
            "roc_auc": roc_auc(y, s), "mcc": mcc(tp, fp, fn, tn), "false_removed": tn, "true_lost": fn}


def st_compare(a):
    folds = json.load(open(a.folds, encoding="utf-8"))
    other = {"A": "B", "B": "A"}
    table = {F: read_table(a.table, folds[F]) for F in ("A", "B")}
    by = {(F, t): [r for r in table[F] if r["type"] == t] for F in ("A", "B") for t in ML_TYPES}
    jobs = [(F, t, a.pilot, a.rows, a.models, folds[other[F]], by[(F, t)]) for F in ("A", "B") for t in ML_TYPES]
    res = {}
    with ProcessPoolExecutor(max_workers=a.workers) as pool:
        for F, t, r in pool.map(fold_type, jobs):
            res[(F, t)] = r
            print(f"fitted fold {F} {t}", file=sys.stderr, flush=True)
    out, decisions = {"rule_sha": a.rule_sha, "types": {}}, {}
    rng = np.random.default_rng(SEED)
    for t in ML_TYPES:
        if res[("A", t)] is None or res[("B", t)] is None:
            out["types"][t] = {"testable": False, "why": "no training rows"}
            continue
        for F in ("A", "B"):
            add_mix(res[(F, t)], list(SINGLE), "mix_all")
        # best 3 for fold F: by PR AUC on the other fold's findings (its own models)
        single_ap = {F: {arm: measures(by[(F, t)], res[(F, t)]["scored_idx"], res[(F, t)]["arms"][arm]["find"],
                                       None)["pr_auc"] or 0.0 for arm in SINGLE} for F in ("A", "B")}
        for F in ("A", "B"):
            ranked = sorted(SINGLE, key=lambda arm: (-single_ap[other[F]][arm], SINGLE.index(arm)))
            add_mix(res[(F, t)], ranked[:3], "mix_best3")
        T = {"testable": True, "folds": {}, "arms": {}}
        for F in ("A", "B"):
            m0 = measures(by[(F, t)], res[(F, t)]["scored_idx"], res[(F, t)]["arms"]["iforest"]["find"], None)
            T["folds"][F] = {"alpha": res[(F, t)]["alpha"], "n_proper": res[(F, t)]["n_proper"],
                             "n_calib_scored": res[(F, t)]["n_calib_scored"],
                             "n_records": len(by[(F, t)]), "n_scored": len(res[(F, t)]["scored_idx"]),
                             "n_true": m0["n_true"], "n_false": m0["n_false"]}
            if m0["n_true"] < 20 or m0["n_false"] < 20:
                T["testable"] = False
        no_large = {r for F in ("A", "B") for r in folds[F] if r != LARGE}
        for arm in ARMS:
            A = {}
            for F in ("A", "B"):
                rf = res[(F, t)]
                part = rf["arms"][arm]
                A[F] = {"cut": part["cut"], "members": part.get("members"),
                        **measures(by[(F, t)], rf["scored_idx"], part["find"], part["cut"]),
                        "without_large": measures(by[(F, t)], rf["scored_idx"], part["find"], part["cut"], no_large)}
            T["arms"][arm] = A
            for F in ("A", "B"):
                rf = res[(F, t)]
                cut = rf["arms"][arm]["cut"]
                decisions.setdefault(arm, {}).setdefault(t, {})[F] = sorted(
                    by[(F, t)][i]["fid"] + "@" + by[(F, t)][i]["run"]
                    for k, i in enumerate(rf["scored_idx"]) if cut is not None and rf["arms"][arm]["find"][k] < cut)
        if T["testable"]:
            T["bootstrap"] = bootstrap_gain(by, res, t, folds, rng)
        out["types"][t] = T
    os.makedirs(a.out_dir, exist_ok=True)
    jdump(out, os.path.join(a.out_dir, "compare.json"))
    jdump(decisions, os.path.join(a.out_dir, "drops.json"))
    print(json.dumps({t: (v["testable"], {arm: [v["arms"][arm][F]["pr_auc"] for F in "AB"] for arm in ARMS}
                          if v.get("arms") else None) for t, v in out["types"].items()}))
    return 0


def bootstrap_gain(by, res, t, folds, rng):
    """Per arm: 2.5 / 50 / 97.5 percentiles over DRAWS of the mean over folds of
    (PR AUC arm - PR AUC iforest), runs resampled within each fold."""
    prep = {}
    for F in ("A", "B"):
        rf, recs = res[(F, t)], by[(F, t)]
        idx = [k for k, i in enumerate(rf["scored_idx"]) if recs[i]["label"] != "unobs"]
        runs = [recs[rf["scored_idx"][k]]["run"] for k in idx]
        y = np.array([recs[rf["scored_idx"][k]]["label"] == "true" for k in idx])
        S = {arm: np.asarray(rf["arms"][arm]["find"])[idx] for arm in ARMS}
        per_run = defaultdict(list)
        for j, r in enumerate(runs):
            per_run[r].append(j)
        prep[F] = (y, S, [np.array(per_run[r], dtype=int) for r in folds[F] if r in per_run], len(folds[F]))
    gains = {arm: [] for arm in ARMS if arm != "iforest"}
    for _ in range(DRAWS):
        g = {arm: [] for arm in gains}
        for F in ("A", "B"):
            y, S, groups, nruns = prep[F]
            pick = rng.integers(0, nruns, size=nruns)
            sel = np.concatenate([groups[p] for p in pick if p < len(groups)] or [np.zeros(0, dtype=int)])
            base = average_precision(y[sel], S["iforest"][sel])
            for arm in gains:
                v = average_precision(y[sel], S[arm][sel])
                g[arm].append(None if v is None or base is None else v - base)
        for arm in gains:
            if None not in g[arm]:
                gains[arm].append(sum(g[arm]) / 2)
    return {arm: {"draws": len(v), "lo": float(np.percentile(v, 2.5)) if v else None,
                  "mid": float(np.percentile(v, 50)) if v else None,
                  "hi": float(np.percentile(v, 97.5)) if v else None} for arm, v in gains.items()}


# ---- select1 --------------------------------------------------------------------------
def st_select1(a):
    c = json.load(open(a.compare, encoding="utf-8"))
    drops = json.load(open(os.path.join(os.path.dirname(a.compare), "drops.json"), encoding="utf-8"))
    out = {"types": {}, "candidates": {}}
    for t, T in c["types"].items():
        if not T.get("testable"):
            out["types"][t] = {"verdict": "NOT TESTABLE"}
            continue
        base = T["arms"]["iforest"]
        lost0 = sum(base[F]["true_lost"] for F in "AB")
        passing = []
        for arm in ARMS[1:]:
            A = T["arms"][arm]
            gains = [None if A[F]["pr_auc"] is None or base[F]["pr_auc"] is None else A[F]["pr_auc"] - base[F]["pr_auc"]
                     for F in "AB"]
            ok = bool(None not in gains and all(g >= 0.05 for g in gains)
                      and (T["bootstrap"][arm]["lo"] or 0) > 0
                      and sum(A[F]["true_lost"] for F in "AB") <= lost0)
            out["types"].setdefault(t, {"arms": {}})["arms"][arm] = {"gains": gains, "boot_lo": T["bootstrap"][arm]["lo"],
                                                                     "pass": ok}
            if ok:
                passing.append((-(sum(A[F]["pr_auc"] for F in "AB") / 2), arm.startswith("mix"), ARMS.index(arm), arm))
        if passing:
            out["types"][t]["candidate"] = sorted(passing)[0][3]
            out["candidates"][t] = sorted(passing)[0][3]
        out["types"][t]["verdict"] = "CANDIDATE " + out["candidates"][t] if passing else "IF STAYS"
    # step 2 configurations: drop sets of fid@run
    frozen = {"B3": "iforest"}
    configs = {"none": {}, "frozen": dict(frozen)}
    for t, arm in sorted(out["candidates"].items()):
        configs[f"cand_{t}_{arm}"] = {**frozen, t: arm}
    if len(out["candidates"]) > 1:
        configs["all"] = {**frozen, **out["candidates"]}
    out["configs"] = configs
    frozen_b3 = json.load(open(a.frozen_drops, encoding="utf-8"))["B3"]
    dsets = {}
    for name, cfg in configs.items():
        s = set()
        for t, arm in cfg.items():
            if (t, arm) == ("B3", "iforest"):
                s.update(frozen_b3)            # exactly qmax_confirmB3's filter (check C3)
            else:
                for F in "AB":
                    s.update(drops[arm][t][F])
        dsets[name] = sorted(s)
    jdump(out, a.out)
    jdump(dsets, os.path.join(os.path.dirname(a.out), "dropsets.json"))
    print(json.dumps({"candidates": out["candidates"], "configs": list(configs)}))
    return 0


# ---- filter ---------------------------------------------------------------------------
def filter_run(args):
    run, src, dst, drop = args
    if os.path.exists(dst):
        return run, "cached"
    kept = dropped = 0
    with open_text(src) as fi, gzip.open(dst + ".tmp", "wt", encoding="utf-8") as fo:
        for line in fi:
            if '"findings.v0"' in line:
                o = json.loads(line)
                if o.get("topic") == "findings.v0" and o["record"]["findingId"] in drop:
                    dropped += 1
                    continue
                kept += 1
            fo.write(line)
    if dropped != len(drop):
        os.remove(dst + ".tmp")
        return run, f"FAILED dropped {dropped} of {len(drop)}"
    os.replace(dst + ".tmp", dst)
    return run, f"kept {kept} dropped {dropped}"


def st_filter(a):
    ds = json.load(open(a.dropsets, encoding="utf-8"))[a.config]
    per = defaultdict(set)
    for x in ds:
        fid, run = x.rsplit("@", 1)
        per[run].add(fid)
    os.makedirs(a.out_dir, exist_ok=True)
    runs = runs_arg(a.runs)
    jobs = [(r, os.path.join(a.raw, "runs", r, "output.jsonl.gz"), os.path.join(a.out_dir, r + ".output.jsonl.gz"),
             per.get(r, set())) for r in runs]
    bad = 0
    with ProcessPoolExecutor(max_workers=a.workers) as pool:
        for r, msg in pool.map(_safe(filter_run), jobs):
            bad += msg.startswith("FAILED")
            if msg.startswith("FAILED"):
                print(r, msg, file=sys.stderr)
    print(json.dumps({"config": a.config, "runs": len(runs), "dropped": len(ds), "failed": bad}))
    return 1 if bad else 0


# ---- select2 --------------------------------------------------------------------------
def run_counts(d, runs):
    out = {}
    for r in runs:
        s = json.load(open(os.path.join(d, "runs", r, "score.json"), encoding="utf-8"))
        o, l = s["findings"]["overall"], s["links"]
        out[r] = (o["tp"], o["fp"], o["fn"], l["tp"], l["fp"], l["fn"])
    return out


def f1(tp, fp, fn):
    return 2 * tp / (2 * tp + fp + fn) if tp else 0.0


def st_select2(a):
    runs = runs_arg(a.runs)
    s1 = json.load(open(a.step1, encoding="utf-8"))
    base = run_counts(os.path.join(a.step2_dir, "frozen"), runs)
    out = {"baseline": "frozen (= qmax_confirmB3, check C3)", "configs": {}}

    def pooled(cnt, rs):
        v = np.array([cnt[r] for r in rs]).sum(axis=0)
        return {"finding_tp": int(v[0]), "finding_fp": int(v[1]), "finding_f1": round(f1(v[0], v[1], v[2]), 4),
                "link_f1": round(f1(v[3], v[4], v[5]), 4)}

    for name in s1["configs"]:
        if name in ("none", "frozen") or not os.path.isdir(os.path.join(a.step2_dir, name)):
            continue
        cnt = run_counts(os.path.join(a.step2_dir, name), runs)
        res = {}
        for tag, rs in (("all_runs", runs), ("without_large", [r for r in runs if r != LARGE])):
            p, b = pooled(cnt, rs), pooled(base, rs)
            fall = 1 - p["finding_fp"] / b["finding_fp"] if b["finding_fp"] else 0.0
            arr_c = np.array([cnt[r][1] for r in rs])
            arr_b = np.array([base[r][1] for r in rs])
            draws = []
            rng = np.random.default_rng(SEED + 2)            # same draws for every config
            for _ in range(DRAWS):
                pk = rng.integers(0, len(rs), size=len(rs))
                sb = arr_b[pk].sum()
                draws.append(1 - arr_c[pk].sum() / sb if sb else 0.0)
            lo = float(np.percentile(draws, 2.5))
            ok = bool(fall >= 0.10 and lo > 0 and p["finding_tp"] >= b["finding_tp"] and p["link_f1"] >= b["link_f1"])
            res[tag] = {"config": p, "frozen": b, "fp_fall": round(fall, 4), "fp_fall_lo": round(lo, 4), "pass": ok}
        res["adopt_worthy"] = res["all_runs"]["pass"] and res["without_large"]["pass"]
        out["configs"][name] = res
    jdump(out, a.out)
    print(json.dumps({k: v["adopt_worthy"] for k, v in out["configs"].items()}))
    return 0


# ---- report ---------------------------------------------------------------------------
def fmt(x, n=3):
    return "-" if x is None else f"{x:.{n}f}"


def st_report(a):
    c = json.load(open(a.compare, encoding="utf-8")) if os.path.exists(a.compare) else None
    s1 = json.load(open(a.step1, encoding="utf-8")) if os.path.exists(a.step1) else None
    s2 = json.load(open(a.step2, encoding="utf-8")) if os.path.exists(a.step2) else None
    L = ["# ML model comparison: report", "",
         f"Rule `RULE-modelcompare.md` sha `{c['rule_sha'] if c else '?'}`. PILOT FIT, folds A/B, out of fold.", ""]
    if a.skipped:
        L += [f"**Skipped by the soft deadline:** {a.skipped}", ""]
    if c:
        L += ["## Step 1: PR AUC per type (fold A / fold B), true vs false rule findings", "",
              "| Type | testable | " + " | ".join(ARMS) + " |", "|---" * (len(ARMS) + 2) + "|"]
        for t, T in c["types"].items():
            if not T.get("arms"):
                L.append(f"| {t} | no | " + " | ".join("-" for _ in ARMS) + " |")
                continue
            L.append(f"| {t} | {'yes' if T['testable'] else 'no'} | " + " | ".join(
                f"{fmt(T['arms'][arm]['A']['pr_auc'])} / {fmt(T['arms'][arm]['B']['pr_auc'])}" for arm in ARMS) + " |")
        L += ["", "Records (true / false, fold A; fold B), alpha used for the cut:", ""]
        for t, T in c["types"].items():
            if T.get("folds"):
                fa, fb = T["folds"]["A"], T["folds"]["B"]
                L.append(f"- {t}: {fa['n_true']}/{fa['n_false']}; {fb['n_true']}/{fb['n_false']}; "
                         f"alpha {fa['alpha']} / {fb['alpha']}")
        L += ["", "At the cut (both folds summed): false removed / true lost; MCC fold A / B", ""]
        for t, T in c["types"].items():
            if T.get("arms"):
                L.append(f"- {t}: " + "; ".join(
                    f"{arm} {sum(T['arms'][arm][F]['false_removed'] for F in 'AB')}/"
                    f"{sum(T['arms'][arm][F]['true_lost'] for F in 'AB')} "
                    f"({fmt(T['arms'][arm]['A']['mcc'], 2)}, {fmt(T['arms'][arm]['B']['mcc'], 2)})" for arm in ARMS))
    if s1:
        L += ["", "## Step 1 verdicts", ""]
        for t, v in s1["types"].items():
            L.append(f"- {t}: {v['verdict']}")
    if s2:
        L += ["", "## Step 2: system check (against the frozen setup)", "",
              "| Config | fp fall (lo) | finding tp | finding F1 | link F1 | w/o Large fall (lo) | adopt-worthy |",
              "|---|---|---|---|---|---|---|"]
        for n, r in s2["configs"].items():
            x, w = r["all_runs"], r["without_large"]
            L.append(f"| {n} | {x['fp_fall']} ({x['fp_fall_lo']}) | {x['config']['finding_tp']} vs {x['frozen']['finding_tp']}"
                     f" | {x['config']['finding_f1']} vs {x['frozen']['finding_f1']} | {x['config']['link_f1']} vs "
                     f"{x['frozen']['link_f1']} | {w['fp_fall']} ({w['fp_fall_lo']}) | {r['adopt_worthy']} |")
        if not s2["configs"]:
            L.append("No step 1 candidate, so no step 2 configuration.")
    worthy = [n for n, r in (s2 or {}).get("configs", {}).items() if r["adopt_worthy"]]
    L += ["", "## Conclusion", "",
          (f"Adopt-worthy: {', '.join(worthy)}. Adopting is the user's decision (unfreeze, refit, new paper version)."
           if worthy else "No configuration is adopt-worthy: the Isolation Forest setup stays.") if s2 else
          "Step 2 did not run; no conclusion on the system level."]
    Path(a.out).write_text("\n".join(L) + "\n", encoding="utf-8")
    print(a.out)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="stage", required=True)
    p = sub.add_parser("cfg")
    p.add_argument("--src", required=True); p.add_argument("--out", required=True)
    p.add_argument("--version", required=True)
    p = sub.add_parser("table")
    p.add_argument("--pilot", required=True); p.add_argument("--raw", required=True)
    p.add_argument("--folds", required=True); p.add_argument("--out-dir", required=True)
    p.add_argument("--workers", type=int, default=4)
    p = sub.add_parser("check1")
    p.add_argument("--raw", required=True); p.add_argument("--ref", required=True); p.add_argument("--runs", required=True)
    p = sub.add_parser("check2")
    p.add_argument("--table", required=True); p.add_argument("--ref", required=True)
    p.add_argument("--models", required=True); p.add_argument("--folds", required=True)
    p.add_argument("--runs", required=True)
    p = sub.add_parser("compare")
    p.add_argument("--pilot", required=True); p.add_argument("--table", required=True)
    p.add_argument("--rows", required=True); p.add_argument("--models", required=True)
    p.add_argument("--folds", required=True); p.add_argument("--out-dir", required=True)
    p.add_argument("--rule-sha", required=True); p.add_argument("--workers", type=int, default=10)
    p = sub.add_parser("select1")
    p.add_argument("--compare", required=True); p.add_argument("--out", required=True)
    p.add_argument("--frozen-drops", required=True, help="JSON {B3: [fid@run]} of the frozen B3 filter")
    p = sub.add_parser("frozen-drops")
    p.add_argument("--table", required=True); p.add_argument("--models", required=True)
    p.add_argument("--folds", required=True); p.add_argument("--out", required=True)
    p = sub.add_parser("filter")
    p.add_argument("--raw", required=True); p.add_argument("--dropsets", required=True)
    p.add_argument("--config", required=True); p.add_argument("--runs", required=True)
    p.add_argument("--out-dir", required=True); p.add_argument("--workers", type=int, default=8)
    p = sub.add_parser("check3")
    p.add_argument("--none", required=True); p.add_argument("--frozen", required=True)
    p.add_argument("--ref-none", required=True); p.add_argument("--ref-frozen", required=True)
    p.add_argument("--runs", required=True)
    p = sub.add_parser("select2")
    p.add_argument("--step1", required=True); p.add_argument("--step2-dir", required=True)
    p.add_argument("--runs", required=True); p.add_argument("--out", required=True)
    p = sub.add_parser("report")
    p.add_argument("--compare", required=True); p.add_argument("--step1", required=True)
    p.add_argument("--step2", required=True); p.add_argument("--out", required=True)
    p.add_argument("--skipped", default="")
    a = ap.parse_args(argv)
    return {"frozen-drops": st_frozen_drops}.get(a.stage, globals().get("st_" + a.stage))(a)


def st_frozen_drops(a):
    """The frozen B3 filter (qmax_confirmB3): a scored B3 finding below the fold's
    train.json gamma at alpha 0.001 is dropped."""
    folds = json.load(open(a.folds, encoding="utf-8"))
    out = []
    for F in ("A", "B"):
        cut = json.load(open(os.path.join(a.models, f"fold{F}-max", "train.json")))["gamma"]["0.001"]["B3"]
        for r in read_table(a.table, folds[F]):
            if r["type"] == "B3" and r["status"] == "ML_SCORED" and r["if_score"] < cut:
                out.append(r["fid"] + "@" + r["run"])
    jdump({"B3": sorted(out)}, a.out)
    print(json.dumps({"frozen_B3_drops": len(out)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
