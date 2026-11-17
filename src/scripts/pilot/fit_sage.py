"""Fit SAGE's two time windows on the PILOT FIT half (SAGE baseline, Exp. 2).

    python src/scripts/pilot/fit_sage.py --pilot DIR --split SPLIT.json --findings-from GO_OUT \\
        --out-dir OUT [--grid-t 0.5,1,2,5] [--grid-w 15,30,45,60,90,150] [--variant ag] \\
        [--write-params src/params/sage.v0.yaml] [--workers 4]

GO_OUT is a directory with the cached agent findings of each FIT run, either
score_pilot.py's layout (runs/<run_id>/output.jsonl.gz) or twin_safety's
(<run_id>.output.jsonl). For each (t, w) of the grid, SAGE runs once over all
FIT runs (one alert file per run) and every run is scored against its
restricted/ truth for both variants. The selection is by directed-link F1 of
--variant on the FIT half, ties broken by the lower false-chain rate, then the
smaller w, then the smaller t. OUT/grid.json holds every cell; with
--write-params the chosen t and w are written into the params file with
fitted: true and the mapping's hash. The SCORE half is never read.
"""
import argparse
import glob
import json
import os
import sys
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "src" / "python"))

import yaml  # noqa: E402

from mtcore.baselines.sage import mapping as M  # noqa: E402
from mtcore.baselines.sage import project as P  # noqa: E402
from mtcore.baselines.sage import run as R  # noqa: E402
from mtcore.harness import score as S  # noqa: E402

LINK_KEYS = ("present", "tp", "fp", "fn")
PATH_KEYS = ("reference_paths", "recovered", "false_chains", "retained_multi")


def cached_findings(root, runs):
    out = {}
    for r in runs:
        hits = (glob.glob(os.path.join(root, "runs", r, "output.jsonl*")) +
                glob.glob(os.path.join(root, r + ".output.jsonl*")))
        if not hits:
            raise SystemExit(f"no cached findings for run {r} under {root}")
        out[r] = sorted(hits)[0]
    return out


def score_one(job):
    truth_dir, output = job
    s = S.score(S.Truth.load(truth_dir), S.Output.load(output))
    return {"links": {k: s["links"][k] for k in LINK_KEYS},
            "paths": {k: s["paths"][k] for k in PATH_KEYS},
            "violated_nonlinks": len(s["links"]["violated_nonlinks"])}


def summarize(rows):
    tot = defaultdict(int)
    for r in rows:
        for k in LINK_KEYS:
            tot[k] += r["links"][k]
        for k in PATH_KEYS:
            tot[k] += r["paths"][k]
        tot["violated_nonlinks"] += r["violated_nonlinks"]
    p = tot["tp"] / (tot["tp"] + tot["fp"]) if tot["tp"] + tot["fp"] else 0.0
    rc = tot["tp"] / tot["present"] if tot["present"] else 0.0
    f1 = 2 * p * rc / (p + rc) if p + rc else 0.0
    fcr = tot["false_chains"] / tot["retained_multi"] if tot["retained_multi"] else None
    rec = tot["recovered"] / tot["reference_paths"] if tot["reference_paths"] else None
    return dict(tot, precision=round(p, 4), recall=round(rc, 4), f1=round(f1, 4),
                false_chain_rate=None if fcr is None else round(fcr, 4),
                top_k_path_recall=None if rec is None else round(rec, 4))


def main(argv=None):
    ap = argparse.ArgumentParser(description="Fit SAGE's t and w on the PILOT FIT half.")
    ap.add_argument("--pilot", required=True)
    ap.add_argument("--split", required=True)
    ap.add_argument("--findings-from", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--sage-home", default=os.environ.get("MT_SAGE_HOME"))
    ap.add_argument("--params", default=str(REPO / "src" / "params" / "sage.v0.yaml"))
    ap.add_argument("--grid-t", default="0.5,1,2,5")
    ap.add_argument("--grid-w", default="15,30,45,60,90,150")
    ap.add_argument("--variant", default="ag", choices=P.VARIANTS, help="variant whose link F1 selects")
    ap.add_argument("--write-params", default=None, help="write the fitted t and w into this params file")
    ap.add_argument("--workers", type=int, default=4)
    a = ap.parse_args(argv)
    if not a.sage_home:
        ap.error("--sage-home or MT_SAGE_HOME is required")
    prm = R.load_params(a.params)
    mapping = M.load(str(REPO / prm["mapping"]))
    runs = sorted(json.load(open(a.split))["fit"])
    inputs = cached_findings(a.findings_from, runs)
    grid = [(float(t), int(w)) for t in a.grid_t.split(",") for w in a.grid_w.split(",")]
    cells = []
    for t, w in grid:
        cell_dir = os.path.join(a.out_dir, "grid", f"t{t:g}_w{w}")
        stats_file = os.path.join(cell_dir, "cell.json")
        if os.path.exists(stats_file):
            cells.append(json.load(open(stats_file)))
            print(f"t={t:g} w={w} cached", flush=True)
            continue
        stats = R.run([inputs[r] for r in runs], cell_dir, a.sage_home, mapping, t, w, prm["k"])
        jobs = {v: [(os.path.join(a.pilot, r, "restricted"), os.path.join(cell_dir, v, r + ".jsonl")) for r in runs]
                for v in P.VARIANTS}
        with ProcessPoolExecutor(max_workers=a.workers) as pool:
            result = {v: summarize(list(pool.map(score_one, jobs[v]))) for v in P.VARIANTS}
        cell = {"t": t, "w": w, "sage_exit": stats["sage_exit"], "sage_status": stats["sage_status"],
                "episode_traces": stats["episode_traces"], "skipped": stats["skipped"], **result}
        with open(stats_file, "w") as fh:
            json.dump(cell, fh, indent=2)
        cells.append(cell)
        r = result[a.variant]
        print(f"t={t:g} w={w} {stats['sage_status']} {a.variant}: F1 {r['f1']} P {r['precision']} "
              f"R {r['recall']} FCR {r['false_chain_rate']}", flush=True)
    ok = [c for c in cells if c.get("sage_status", "ok") != "failed"]
    if not ok:
        raise SystemExit("SAGE failed in every grid cell")

    def rank(c):
        r = c[a.variant]
        fcr = r["false_chain_rate"] if r["false_chain_rate"] is not None else 1.0
        return (-r["f1"], fcr, c["w"], c["t"])
    best = min(ok, key=rank)
    out = {"variant": a.variant, "runs": len(runs), "mapping_sha256": mapping.sha256,
           "chosen": {"t": best["t"], "w": best["w"]}, "cells": cells}
    with open(os.path.join(a.out_dir, "grid.json"), "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"chosen t={best['t']:g} w={best['w']}: {json.dumps(best[a.variant])}", flush=True)
    if a.write_params:
        with open(a.write_params, encoding="utf-8") as fh:
            text = fh.read()
        doc = yaml.safe_load(text)
        doc.update(fitted=True, t=best["t"], w=best["w"], mapping_sha256=mapping.sha256,
                   fit={"split": os.path.basename(a.split), "fit_runs": len(runs), "variant": a.variant,
                        "grid_t": a.grid_t, "grid_w": a.grid_w,
                        "fit_link_f1": best[a.variant]["f1"]})
        header = "".join(ln for ln in text.splitlines(keepends=True) if ln.startswith("#"))
        header = header.replace("Status: UNFITTED.", "Status: FITTED (values under fit:).")
        with open(a.write_params, "w", encoding="utf-8") as fh:
            fh.write(header + yaml.safe_dump(doc, sort_keys=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
