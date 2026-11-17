#!/usr/bin/env python3
"""Run-level bootstrap CIs for the held-out Exp. 1-2 results (aggregation only, no re-scoring).

Reads the per-run score files written by the one-time held-out scoring of 2026-11-16
(`runs/<run>/score.json`, and `score_nofault.json` for the Exp. 1 "Without X" rows),
pools their counts exactly as the scorer's summary does (e.g. finding precision =
sum tp / (sum tp + sum fp)), and checks every pooled value against the committed
`summary.json` (or RESULTS.md where no summary is committed). It then resamples runs
with replacement (seed 20261116, 10,000 resamples) and reports the 95% percentile
interval of each pooled metric, plus paired differences (both rows evaluated on the
same resampled runs).

Usage:
  python experiments/heldout/bootstrap_ci.py --root <dir holding scored/2026-11-16 per-run files> \
      --out experiments/heldout/scored/2026-11-16/CI
The root mirrors s3://<work>/scored/2026-11-16/ (only */runs/*/score*.json are needed).
"""
import argparse
import glob
import json
import os
import sys

import numpy as np

SEED = 20261116
B = 10_000

# (set, row label, path under root, kind). kind "go" rows have findings + links + paths;
# "drop" rows also have score_nofault.json (end-to-end recall); "corr" rows are baselines
# that receive another row's findings, so only links and paths are theirs.
ROWS = [
    ("core", "go_main", "held_out/heldout-a/go_main", "go"),
    ("core", "go_mlB3", "held_out/heldout-a/go_mlB3", "go"),
    ("core", "go_rules", "held_out/heldout-a/go_rules", "go"),
    ("core", "go_no_ebpf", "held_out/heldout-a/go_no_ebpf", "drop"),
    ("core", "go_no_gateway", "held_out/heldout-a/go_no_gateway", "drop"),
    ("core", "go_no_admission", "held_out/heldout-a/go_no_admission", "drop"),
    ("core", "go_no_api_audit", "held_out/heldout-a/go_no_api_audit", "drop"),
    ("core", "sage_ag", "held_out/heldout-a/sage_ag", "corr"),
    ("core", "sage_seq", "held_out/heldout-a/sage_seq", "corr"),
    ("core", "seeded_orthrus", "held_out/heldout-b1/seeded/score-held_out", "corr"),
    ("core", "orthrus_context", "held_out/heldout-b1/pidsmaker/results/orthrus_MT_HELD_OUT/score", "corr"),
    ("targeted", "cases_full", "held_out_cases/heldout-a/cases_full", "go"),
    ("targeted", "cases_no_conflict", "held_out_cases/heldout-a/cases_no_conflict", "go"),
    ("targeted", "cases_no_distinct", "held_out_cases/heldout-a/cases_no_distinct", "go"),
    ("targeted", "cases_no_origin", "held_out_cases/heldout-a/cases_no_origin", "go"),
    ("targeted", "cases_no_tactic", "held_out_cases/heldout-a/cases_no_tactic", "go"),
    ("targeted", "cases_no_witness", "held_out_cases/heldout-a/cases_no_witness", "go"),
    ("targeted", "cases_sage_ag", "held_out_cases/heldout-a/cases_sage_ag", "corr"),
    ("targeted", "cases_sage_seq", "held_out_cases/heldout-a/cases_sage_seq", "corr"),
    ("targeted", "seeded_orthrus", "held_out_cases/heldout-b2/seeded/score-held_out_cases", "corr"),
    ("targeted", "orthrus_context", "held_out_cases/heldout-b2/pidsmaker/results/orthrus_MT_HELD_OUT_CASES/score", "corr"),
]

# (set, metric, row A, row B): difference A - B on the same resampled runs.
PAIRS = [
    ("core", "link_f1", "go_main", "sage_seq"),
    ("core", "path_recall", "go_main", "sage_seq"),
    ("core", "link_f1", "go_main", "seeded_orthrus"),
    ("core", "path_recall", "go_main", "seeded_orthrus"),
    ("core", "finding_f1", "go_main", "go_rules"),
    ("targeted", "link_f1", "cases_full", "cases_sage_seq"),
    ("targeted", "path_recall", "cases_full", "cases_sage_seq"),
    ("targeted", "link_f1", "cases_full", "seeded_orthrus"),
    ("targeted", "path_recall", "cases_full", "seeded_orthrus"),
    ("core", "finding_f1", "go_main", "go_mlB3"),
] + [
    ("targeted", met, "cases_full", abl)
    for abl in ("cases_no_witness", "cases_no_conflict", "cases_no_distinct", "cases_no_origin", "cases_no_tactic")
    for met in ("link_f1", "path_recall", "fcr")
]

# Count columns pulled from each run.
def run_counts(score, nofault):
    f = score["findings"]["overall"]
    li = score["links"]
    pa = score["paths"]
    c = {
        "f_tp": f["tp"], "f_fp": f["fp"], "f_present": f["present"],
        "l_tp": li["tp"], "l_fp": li["fp"], "l_present": li["present"],
        "p_rec": pa["recovered"], "p_ref": pa["reference_paths"],
        "p_false": pa["false_chains"], "p_multi": pa["retained_multi"],
    }
    if nofault is not None:
        g = nofault["findings"]["overall"]
        c["e_tp"] = g["tp"]
        c["e_present"] = g["present"]
    return c


def div(a, b):
    with np.errstate(divide="ignore", invalid="ignore"):
        return np.where(b > 0, a / np.where(b > 0, b, 1), np.nan)


def f1(tp, fp, present):
    p = div(tp, tp + fp)
    r = div(tp, present)
    with np.errstate(divide="ignore", invalid="ignore"):
        return np.where((p + r) > 0, 2 * p * r / np.where((p + r) > 0, p + r, 1), np.nan)


def metrics(S, kind):
    """S: dict of summed counts (scalars or arrays over resamples)."""
    m = {}
    if kind in ("go", "drop"):
        m["finding_p"] = div(S["f_tp"], S["f_tp"] + S["f_fp"])
        m["finding_r"] = div(S["f_tp"], S["f_present"])
        m["finding_f1"] = f1(S["f_tp"], S["f_fp"], S["f_present"])
    if kind == "drop":
        m["e2e_recall"] = div(S["e_tp"], S["e_present"])
    if kind != "drop":
        m["link_p"] = div(S["l_tp"], S["l_tp"] + S["l_fp"])
        m["link_r"] = div(S["l_tp"], S["l_present"])
        m["link_f1"] = f1(S["l_tp"], S["l_fp"], S["l_present"])
        m["path_recall"] = div(S["p_rec"], S["p_ref"])
        m["fcr"] = div(S["p_false"], S["p_multi"])
    return m


# Committed pooled values to check against (summary.json keys or RESULTS.md numbers).
def committed(path_in_repo, kind):
    p = os.path.join(path_in_repo, "summary.json")
    if not os.path.exists(p):
        return None
    d = json.load(open(p))
    out = {}
    fo = d.get("findings", {})
    fo = fo.get("overall", fo)
    if "precision" in fo and kind in ("go", "drop"):
        out["finding_p"], out["finding_r"], out["finding_f1"] = fo["precision"], fo["recall"], fo["f1"]
    li = d.get("links", {})
    li = li.get("overall", li)
    if "precision" in li and kind != "drop":
        out["link_p"], out["link_r"], out["link_f1"] = li.get("precision"), li.get("recall"), li.get("f1")
    pa = d.get("paths", {})
    if "top_k_path_recall" in pa and kind != "drop":
        out["path_recall"], out["fcr"] = pa.get("top_k_path_recall"), pa.get("false_chain_rate")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--repo-scored", default="experiments/heldout/scored/2026-11-16")
    ap.add_argument("--out", required=True, help="output path without extension (.json and .md written)")
    a = ap.parse_args()

    data = {}  # (set,row) -> (run ids, count arrays, kind, rel)
    missing = []
    for st, row, rel, kind in ROWS:
        files = sorted(glob.glob(os.path.join(a.root, rel, "runs", "*", "score.json")))
        if not files:
            missing.append((st, row, rel))
            continue
        ids, rows = [], []
        for fp in files:
            rid = os.path.basename(os.path.dirname(fp))
            sc = json.load(open(fp))
            nf = None
            if kind == "drop":
                nf = json.load(open(os.path.join(os.path.dirname(fp), "score_nofault.json")))
            ids.append(rid)
            rows.append(run_counts(sc, nf))
        keys = rows[0].keys()
        arr = {k: np.array([r[k] for r in rows], dtype=float) for k in keys}
        data[(st, row)] = (ids, arr, kind, rel)

    # Same run order within a set, so resampled indices pair across rows.
    sets = {}
    for (st, row), (ids, arr, kind, rel) in data.items():
        sets.setdefault(st, ids)
        if ids != sets[st]:
            sys.exit(f"run ids of {st}/{row} differ from the set's other rows")

    rng = np.random.default_rng(SEED)
    W = {}
    for st, ids in sorted(sets.items()):
        n = len(ids)
        idx = rng.integers(0, n, size=(B, n))
        W[st] = np.stack([np.bincount(r, minlength=n) for r in idx]).astype(float)

    out = {"seed": SEED, "resamples": B, "runs": {k: len(v) for k, v in sets.items()},
           "rows": {}, "pairs": [], "no_per_run_scores": [list(m) for m in missing], "check": []}
    boot = {}
    for (st, row), (ids, arr, kind, rel) in data.items():
        point = metrics({k: v.sum() for k, v in arr.items()}, kind)
        bs = metrics({k: W[st] @ v for k, v in arr.items()}, kind)
        boot[(st, row)] = bs
        res = {}
        for k, pv in point.items():
            b = bs[k]
            nan = int(np.isnan(b).sum())
            lo, hi = (np.nanpercentile(b, [2.5, 97.5]).tolist() if nan < B else [None, None])
            res[k] = {"pooled": None if np.isnan(pv) else float(pv), "ci95": [lo, hi], "undefined_resamples": nan}
        if kind == "drop":
            res["e2e_counts"] = {"tp": int(arr["e_tp"].sum()), "present": int(arr["e_present"].sum())}
        out["rows"][f"{st}/{row}"] = res
        com = committed(os.path.join(a.repo_scored, rel), kind)
        if com:
            for k, v in com.items():
                if v is None:
                    continue
                pv = res[k]["pooled"]
                ok = pv is not None and round(pv, 4) == round(v, 4)
                out["check"].append({"row": f"{st}/{row}", "metric": k, "committed": v, "pooled": pv, "ok": ok})

    for st, met, ra, rb in PAIRS:
        if (st, ra) not in boot or (st, rb) not in boot:
            out["pairs"].append({"set": st, "metric": met, "a": ra, "b": rb, "note": "no per-run scores"})
            continue
        pa_, pb_ = out["rows"][f"{st}/{ra}"][met]["pooled"], out["rows"][f"{st}/{rb}"][met]["pooled"]
        d = boot[(st, ra)][met] - boot[(st, rb)][met]
        nan = int(np.isnan(d).sum())
        lo, hi = np.nanpercentile(d, [2.5, 97.5]).tolist()
        out["pairs"].append({"set": st, "metric": met, "a": ra, "b": rb,
                             "diff": pa_ - pb_, "ci95": [lo, hi], "undefined_resamples": nan})

    with open(a.out + ".json", "w") as fh:
        json.dump(out, fh, indent=1)

    def f4(x):
        return "n/a" if x is None else f"{x:.4f}"

    L = ["# Held-out Exp. 1-2: run-level bootstrap 95% CIs", "",
         f"Made by `experiments/heldout/bootstrap_ci.py` from the per-run `score.json` files of the 2026-11-16 scoring",
         f"(no re-scoring). Point values are pooled over runs (sums of counts, as in `summary.json`); the interval is the",
         f"2.5-97.5 percentile of the pooled metric over {B:,} resamples of runs with replacement (seed {SEED}).",
         f"Runs: Core {out['runs'].get('core')}, Targeted {out['runs'].get('targeted')}. Paired differences use the same",
         "resampled runs for both rows. `undef` = resamples where the metric has a zero denominator (left out).", ""]
    names = {"finding_p": "Finding P", "finding_r": "Finding R", "finding_f1": "Finding F1",
             "e2e_recall": "End-to-end R", "link_p": "Link P", "link_r": "Link R", "link_f1": "Link F1",
             "path_recall": "Path R", "fcr": "FCR"}
    for st in ("core", "targeted"):
        L += [f"## {st.capitalize()} set", "", "| Row | Metric | Pooled | 95% CI | undef |", "|---|---|---|---|---|"]
        for key, res in out["rows"].items():
            if not key.startswith(st + "/"):
                continue
            for k, v in res.items():
                if k == "e2e_counts":
                    continue
                L.append(f"| {key.split('/')[1]} | {names[k]} | {f4(v['pooled'])} | "
                         f"[{f4(v['ci95'][0])}, {f4(v['ci95'][1])}] | {v['undefined_resamples']} |")
        L.append("")
    L += ["## Paired differences (A - B)", "", "| Set | Metric | A | B | A - B | 95% CI | undef |", "|---|---|---|---|---|---|---|"]
    for p in out["pairs"]:
        if "note" in p:
            L.append(f"| {p['set']} | {names[p['metric']]} | {p['a']} | {p['b']} | {p['note']} | | |")
        else:
            L.append(f"| {p['set']} | {names[p['metric']]} | {p['a']} | {p['b']} | {p['diff']:.4f} | "
                     f"[{p['ci95'][0]:.4f}, {p['ci95'][1]:.4f}] | {p['undefined_resamples']} |")
    L += ["", "## Rows without per-run scores (no CI)", ""]
    L += [f"- {s}/{r} (`{rel}`)" for s, r, rel in missing] or ["- none"]
    bad = [c for c in out["check"] if not c["ok"]]
    L += ["", "## Check against committed summaries", "",
          f"{len(out['check'])} pooled values compared with `summary.json` (4 decimals); mismatches: {len(bad)}."]
    for c in bad:
        L.append(f"- {c['row']} {c['metric']}: committed {c['committed']}, pooled {c['pooled']}")
    with open(a.out + ".md", "w") as fh:
        fh.write("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
