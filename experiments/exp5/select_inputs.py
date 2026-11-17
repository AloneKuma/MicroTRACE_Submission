"""Exp. 5 input selection (rule fixed by the user 2026-11-16, before any Exp. 5 run; SETTINGS.md).

Candidates: the HELD_OUT runs with world_name Reference and observability_profile clean
(spec/generator/run-matrix.held_out.yaml: 32 runs). Only the readable side of each run is used
(shipper/*.jsonl); no truth, no score of any experiment.

  inputs  the 3 candidates whose event count (lines over shipper/*.jsonl) is closest to the
          candidates' median, ties by run_id;
  sweep   the first of those 3 (in that order) whose earlier history covers 14,400 s of event
          time; if none does, the one with the longest earlier history;
  history for the sweep input: the other candidates (not the 3 inputs) whose last event is
          before the input's first event, concatenated per node of the input in event-time
          order (history/<node>.jsonl); crashrun --history-s keeps the last H s of it.

    python experiments/exp5/select_inputs.py --matrix spec/generator/run-matrix.held_out.yaml \
        --runs <dir with the candidate run folders> --out <dir>
Writes <out>/selection.json and <out>/history/<node>.jsonl.
"""
import argparse
import glob
import json
import os
import statistics
import sys

import yaml

from mtcore.harness import crashrun as CR

HISTORY_NEED_S = 14400.0


def candidates(matrix):
    m = yaml.safe_load(open(matrix, encoding="utf-8"))
    return sorted(r["run_id"] for r in m["runs"]
                  if r["world_name"] == "Reference" and r["observability_profile"] == "clean")


def describe(run_dir):
    files = sorted(glob.glob(os.path.join(run_dir, "shipper", "*.jsonl")))
    if not files:
        sys.exit(f"no shipper files in {run_dir}")
    n, ts = 0, []
    for f in files:
        for _, t in CR._times(f):
            n += 1
            if t is not None:
                ts.append(t)
    return {"files": {os.path.basename(f)[:-len(".jsonl")]: f for f in files}, "events": n,
            "first_s": min(ts) if ts else None, "last_s": max(ts) if ts else None}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--matrix", required=True)
    ap.add_argument("--runs", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    cand = candidates(a.matrix)
    info = {r: describe(os.path.join(a.runs, r)) for r in cand}
    med = statistics.median(info[r]["events"] for r in cand)
    order = sorted(cand, key=lambda r: (abs(info[r]["events"] - med), r))
    inputs = order[:3]
    pool = [r for r in cand if r not in inputs]

    def earlier(r):
        first = info[r]["first_s"]
        hist = sorted((x for x in pool if info[x]["last_s"] is not None and first is not None
                       and info[x]["last_s"] < first), key=lambda x: info[x]["first_s"])
        span = (first - info[hist[0]]["first_s"]) if hist else 0.0
        return hist, span

    spans = {r: earlier(r) for r in inputs}
    full = [r for r in inputs if spans[r][1] >= HISTORY_NEED_S]
    sweep = full[0] if full else max(inputs, key=lambda r: (spans[r][1], -inputs.index(r)))
    hist_runs, span = spans[sweep]
    os.makedirs(os.path.join(a.out, "history"), exist_ok=True)
    nodes = sorted(info[sweep]["files"])
    kept = {}
    for node in nodes:
        dst = os.path.join(a.out, "history", f"{node}.jsonl")
        k = 0
        with open(dst, "w", encoding="utf-8") as out:
            for r in hist_runs:
                src = info[r]["files"].get(node)
                if src:
                    with open(src, encoding="utf-8") as fh:
                        for line in fh:
                            out.write(line if line.endswith("\n") else line + "\n")
                            k += 1
        kept[node] = k
    sel = {"rule": "SETTINGS.md (user 2026-11-16)", "candidates": len(cand), "median_events": med,
           "inputs": [{"run_id": r, "events": info[r]["events"], "distance": abs(info[r]["events"] - med),
                       "first_s": info[r]["first_s"], "earlier_history_s": spans[r][1],
                       "nodes": sorted(info[r]["files"])} for r in inputs],
           "sweep_input": sweep, "history_runs": hist_runs, "history_span_s": span,
           "history_covers_14400": span >= HISTORY_NEED_S, "history_lines_per_node": kept,
           "all": {r: {k: v for k, v in info[r].items() if k != "files"} for r in cand}}
    with open(os.path.join(a.out, "selection.json"), "w", encoding="utf-8") as fh:
        json.dump(sel, fh, indent=2, sort_keys=True)
    print(json.dumps({k: sel[k] for k in ("median_events", "sweep_input", "history_span_s",
                                          "history_covers_14400")}, indent=2))
    for x in sel["inputs"]:
        print(x["run_id"], x["events"], x["distance"], x["earlier_history_s"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
