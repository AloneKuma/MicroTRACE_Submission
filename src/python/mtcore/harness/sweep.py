"""Exp. 5 part A sweeps (build step 8g): input rate, outage length, history.

    python -m mtcore.harness.sweep --input node-1=stream.jsonl --out sweeps/ \
        [--prefill node-1=history.jsonl] [--paces 1,2,4] [--outages 3,60,600] \
        [--histories 600,3600,14400] [--base-pace 1] [--base-outage 3] [--base-history 600] \
        [--points go.after_flush_before_commit,...] [--reps 5] [--parallel 3] [--factorial]

Values (chosen 2026-10-12): replay pace x1, x2, x4 (faultinject -pace);
outage 3 s (below the dev max_idle of 10 s), 60 s (above it, within the
~300 s posting horizon) and 600 s (beyond it); history 10 min, 1 h and 4 h
of prefill. By default one factor varies at a time around the baseline
(pace 1, outage 3 s, the shortest history), so the baseline runs once; with
--factorial every combination runs. Without --prefill there is no history
factor. Each setting is a full crash-runner matrix (crashrun.run_setting)
in <out>/<setting>/, e.g. pace-2/, outage-60/, history-3600/, base/;
sweep.json lists the settings and their summaries.
"""
import argparse
import itertools
import json
import os
import sys

from mtcore import failpoint as FP
from mtcore.harness import crashrun as CR


def _num(x):
    return int(x) if float(x).is_integer() else float(x)


def settings(paces, outages, histories, base, factorial=False):
    """[(name, {"pace", "outage_s", "history_s"})]; base = (pace, outage, history).
    histories may be empty (no prefill): history_s is then 0."""
    hist = list(histories) or [0]
    if factorial:
        return [(f"pace-{_num(p)}_outage-{_num(o)}_history-{_num(h)}",
                 {"pace": p, "outage_s": o, "history_s": h}) for p, o, h in itertools.product(paces, outages, hist)]
    bp, bo, bh = base
    if not histories:
        bh = 0
    out = [("base", {"pace": bp, "outage_s": bo, "history_s": bh})]
    for key, values in (("pace", paces), ("outage_s", outages), ("history_s", histories)):
        for v in values:
            cfg = {**out[0][1], key: v}
            if cfg != out[0][1]:
                out.append((f"{key.split('_')[0]}-{_num(v)}", cfg))
    return out


def _floats(s):
    return [float(x) for x in s.split(",") if x]


def main(argv=None):
    ap = argparse.ArgumentParser(description="Exp. 5 part A sweeps over pace, outage and history.")
    ap.add_argument("--input", action="append", required=True, help="NODE=PATH measured input (repeatable)")
    ap.add_argument("--prefill", action="append", default=[], help="NODE=PATH history (repeatable)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--paces", default="1,2,4")
    ap.add_argument("--outages", default="3,60,600")
    ap.add_argument("--histories", default="600,3600,14400", help="seconds; ignored without --prefill")
    ap.add_argument("--base-pace", type=float, default=1.0)
    ap.add_argument("--base-outage", type=float, default=3.0)
    ap.add_argument("--base-history", type=float, default=None, help="default: the shortest history")
    ap.add_argument("--factorial", action="store_true", help="every combination instead of one factor at a time")
    ap.add_argument("--points", default=",".join(FP.POINTS + (CR.PG_CRASH,)))
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--modes", default="", help="GO restart modes to run, e.g. C (default: B,C,D)")
    ap.add_argument("--max-nth", type=int, default=5)
    ap.add_argument("--parallel", type=int, default=3)
    ap.add_argument("--settle-s", type=float, default=15.0)
    ap.add_argument("--hold-s", type=float, default=30.0)
    ap.add_argument("--params", default=None)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--dry-run", action="store_true", help="print the settings and exit")
    a = ap.parse_args(argv)
    prefill = dict(x.split("=", 1) for x in a.prefill)
    histories = _floats(a.histories) if prefill else []
    base_h = a.base_history if a.base_history is not None else min(histories, default=0)
    plan = settings(_floats(a.paces), _floats(a.outages), histories, (a.base_pace, a.base_outage, base_h),
                    a.factorial)
    if a.dry_run:
        print(json.dumps(plan, indent=2))
        return 0
    os.makedirs(a.out, exist_ok=True)
    inputs = dict(x.split("=", 1) for x in a.input)
    points = [p for p in a.points.split(",") if p]
    results = {}
    for name, cfg in plan:
        summary = CR.run_setting(inputs, os.path.join(a.out, name), points, reps=a.reps, max_nth=a.max_nth,
                                 seed=a.seed, parallel=a.parallel, params=a.params, outage_s=cfg["outage_s"],
                                 settle_s=a.settle_s, keep=False, pace=cfg["pace"], prefill=prefill or None,
                                 history_s=cfg["history_s"], hold_s=a.hold_s,
                                 modes=[m for m in a.modes.split(",") if m] or None)
        results[name] = {**cfg, "summary": summary}
        with open(os.path.join(a.out, "sweep.json"), "w") as fh:      # rewritten after each setting
            json.dump(results, fh, indent=2, sort_keys=True)
    print(json.dumps({k: {x: v[x] for x in ("pace", "outage_s", "history_s")} for k, v in results.items()},
                     indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
