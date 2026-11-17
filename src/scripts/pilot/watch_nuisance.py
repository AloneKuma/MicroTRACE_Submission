"""Re-run the nuisance check each time another run of a split finishes.

Appends one block per check to <split_dir>/_nuisance_progress.log and writes
the latest result to <split_dir>/_nuisance_latest.json. A finding is

  FAIL     tested (enough PRESENT and non-PRESENT windows) and at or above the
           threshold: the run's metadata predicts its label;
  pending  not yet testable (fewer than two windows of a class, or too few
           runs); expected early in a build;
  ok       tested and below the threshold.

A run counts once its manifest.json exists (the build writes it last).
Stops when --expect runs are present and checked, or when --stop-file exists.

Usage (from the repository root):
    python src/scripts/pilot/watch_nuisance.py datasets/generated/pilot --expect 61
"""
import argparse
import json
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "src" / "python"))
import mtgen  # noqa: E402,F401
from mtgen.nuisance import check_nuisance  # noqa: E402


def _state(f, threshold):
    if f.verdict == "NOT_TESTABLE":
        return "pending"
    return "FAIL" if f.verdict == "FAIL" else "ok"


def check(split: Path, n_runs: int, log):
    # No permutations while the split grows: a score at the threshold fails
    # alone, which is stricter than the gate's final rule.
    result = check_nuisance(split, permutations=0)
    rows = [(f, _state(f, result.threshold)) for f in result.findings]
    fails = [f.finding_type for f, s in rows if s == "FAIL"]
    pending = [f.finding_type for f, s in rows if s == "pending"]
    stamp = time.strftime("%H:%M:%S")
    lines = [f"{stamp} runs={n_runs} tested={len(rows) - len(pending)} "
             f"pending={len(pending)} FAIL={fails or 'none'}"]
    for f, s in rows:
        lines.append(f"    {f.finding_type:4s} {s:7s} {f.metric}={f.score:.3f} "
                     f"windows={f.n_windows} positive={f.n_positive}")
    log.write("\n".join(lines) + "\n")
    log.flush()
    print(lines[0], flush=True)
    (split / "_nuisance_latest.json").write_text(json.dumps({
        "runs": n_runs, "threshold": result.threshold, "fail": fails,
        "pending": pending, "result": result.to_dict(),
    }, indent=2), encoding="utf-8")
    return fails


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("split_dir")
    ap.add_argument("--expect", type=int, required=True,
                    help="stop after this many runs have been checked")
    ap.add_argument("--poll-s", type=int, default=30)
    ap.add_argument("--stop-file", default="")
    args = ap.parse_args(argv)

    split = Path(args.split_dir)
    seen = -1
    with open(split / "_nuisance_progress.log", "a", encoding="utf-8") as log:
        while True:
            n = sum(1 for d in split.iterdir()
                    if d.is_dir() and (d / "manifest.json").exists())
            if n != seen and n >= 2:
                try:
                    check(split, n, log)
                except Exception as exc:  # a run still being written, retry next poll
                    log.write(f"{time.strftime('%H:%M:%S')} runs={n} check error: {exc}\n")
                    log.flush()
                    time.sleep(args.poll_s)
                    continue
                seen = n
            if n >= args.expect and seen == n:
                return 0
            if args.stop_file and Path(args.stop_file).exists():
                return 0
            time.sleep(args.poll_s)


if __name__ == "__main__":
    sys.exit(main())
