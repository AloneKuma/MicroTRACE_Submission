"""Checks of an Exp. 3 local dry run (experiments/exp3/tests/dryrun_exp3.sh; worklog section 6).

    python experiments/exp3/tests/dryrun_checks.py --w1 W1 --w2 W2 --reference REF --out checks.json

D1 lossless transport: in the no-fault fast condition every base record arrived (check.py) and the
   Full pass on what arrived equals the offline pipeline on the original run (REF/<run>.jsonl:
   mtcore.harness.offline output), findings and final witness statuses alike.
D2 same seed, same result: a second work dir W2 with the same condition gives the same fault-log
   entries, the same received records (as sets) and the same Full output.
D3 fault-log consistency (mtcore.exp3.check) in every condition of W1.
D5 the ablation passes ran on the same degraded stream as Full (same runs, outputs present), with
   their witness statuses beside Full's.
D6 the live pass carries Kafka timestamps (arrival lines for latency).
Every comparison leaves out wall-clock fields (publishTime) and Kafka positions.
"""
import argparse
import glob
import gzip
import json
import os
import subprocess
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
WALL = ("publishTime", "publish_time")


def _strip(d):
    if isinstance(d, dict):
        return {k: _strip(v) for k, v in sorted(d.items()) if k not in WALL}
    if isinstance(d, list):
        return [_strip(x) for x in d]
    return d


def output_view(path):
    """(findings by ID, last witness record by ID) of an output file, wall-clock fields left out."""
    op = gzip.open if path.endswith(".gz") else open
    f, w = {}, {}
    with op(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            o = json.loads(line)
            r = o.get("record")
            if r is None:
                continue
            if o["topic"] == "findings.v0":
                f[r["findingId"]] = _strip(r)
            elif o["topic"] == "witness.decisions.v0":
                w[r["witnessId"]] = _strip(r)
    return f, w


def same_output(a, b):
    fa, wa = output_view(a)
    fb, wb = output_view(b)
    return {"findings": [len(fa), len(fb)], "witnesses": [len(wa), len(wb)],
            "findings_equal": fa == fb, "witnesses_equal": wa == wb,
            "finding_ids_only_in_a": sorted(set(fa) - set(fb))[:5], "finding_ids_only_in_b": sorted(set(fb) - set(fa))[:5]}


def received_set(path):
    op = gzip.open if path.endswith(".gz") else open
    out = Counter()
    with op(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            o = json.loads(line)
            out[json.dumps({"topic": o["topic"], "envelope": o["envelope"]}, sort_keys=True)] += 1
    return out


def fault_entries(path):
    with open(path, encoding="utf-8") as fh:
        return sorted(line.strip() for line in fh if line.strip())


def rx(w, cond, run):
    p = os.path.join(w, "received", cond, run, "shipper", "received.jsonl")
    return p if os.path.exists(p) else p + ".gz"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--w1", required=True)
    ap.add_argument("--w2", default=None)
    ap.add_argument("--reference", default=None, help="folder of <run>.jsonl offline outputs on the original runs")
    ap.add_argument("--det-condition", default="loss-transit-20")
    ap.add_argument("--fast-condition", default="nofault-fast")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    res = {}
    runs = json.load(open(os.path.join(a.w1, "runs.json")))["runs"]
    if a.reference:
        d1 = {}
        for r in runs:
            ref = os.path.join(a.reference, r + ".jsonl")
            got = os.path.join(a.w1, "detect", a.fast_condition, "full", "runs", r, "output.jsonl.gz")
            if os.path.exists(ref) and os.path.exists(got):
                d1[r] = same_output(ref, got)
        res["D1_lossless_full_equals_offline_on_original"] = d1
    if a.w2:
        d2 = {}
        c = a.det_condition
        for r in runs:
            f1 = os.path.join(a.w1, "faultlogs", c, r, "faults.jsonl")
            f2 = os.path.join(a.w2, "faultlogs", c, r, "faults.jsonl")
            if not (os.path.exists(f1) and os.path.exists(f2)):
                continue
            e1, e2 = fault_entries(f1), fault_entries(f2)
            r1, r2 = received_set(rx(a.w1, c, r)), received_set(rx(a.w2, c, r))
            o1 = os.path.join(a.w1, "detect", c, "full", "runs", r, "output.jsonl.gz")
            o2 = os.path.join(a.w2, "detect", c, "full", "runs", r, "output.jsonl.gz")
            d2[r] = {"fault_log_entries": [len(e1), len(e2)], "fault_logs_equal": e1 == e2,
                     "received_records": [sum(r1.values()), sum(r2.values())], "received_equal": r1 == r2,
                     "received_differ": sum(((r1 - r2) + (r2 - r1)).values()),
                     "full": same_output(o1, o2) if os.path.exists(o1) and os.path.exists(o2) else None}
        res["D2_same_seed_same_result"] = d2
    d3 = {}
    for cdir in sorted(glob.glob(os.path.join(a.w1, "received", "*"))):
        c = os.path.basename(cdir)
        out = os.path.join(a.w1, f"check-{c}.json")
        rc = subprocess.run([sys.executable, "-m", "mtcore.exp3.check", "--base", os.path.join(a.w1, "base"),
                             "--received", cdir, "--faultlogs", os.path.join(a.w1, "faultlogs", c), "--out", out],
                            cwd=os.path.join(REPO, "src", "python"), capture_output=True, text=True).returncode
        chk = json.load(open(out))
        d3[c] = {"ok": rc == 0 and chk["ok"], "runs": {r: {k: v[k] for k in ("base_records", "received", "dropped",
                                                                         "forged", "transit_dropped",
                                                                         "receiver_gap_seqs", "held_at_stream_end",
                                                                         "failures")}
                                                     for r, v in chk["runs"].items()}}
    res["D3_fault_log_consistency"] = d3
    d5 = {}
    for cdir in sorted(glob.glob(os.path.join(a.w1, "detect", "*"))):
        c = os.path.basename(cdir)
        row = {}
        for pdir in sorted(glob.glob(os.path.join(cdir, "*"))):
            st = Counter()
            outs = sorted(glob.glob(os.path.join(pdir, "runs", "*", "output.jsonl.gz")))
            for o in outs:
                _, w = output_view(o)
                st.update(x.get("status") for x in w.values())
            row[os.path.basename(pdir)] = {"runs": len(outs), "witness_status": dict(sorted(st.items()))}
        d5[c] = row
    res["D5_passes_on_the_degraded_stream"] = d5
    d6 = {}
    for o in sorted(glob.glob(os.path.join(a.w1, "detect", "*", "live_full", "runs", "*", "output.jsonl.gz"))):
        n_ev = n_ts = 0
        with gzip.open(o, "rt", encoding="utf-8") as fh:
            for line in fh:
                x = json.loads(line)
                n_ev += "event" in x
                n_ts += x.get("timestamp_ms") is not None
        d6[os.path.relpath(o, a.w1)] = {"event_arrival_lines": n_ev, "lines_with_timestamp": n_ts}
    res["D6_live_output_timestamps"] = d6
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=2, sort_keys=True)
    print(json.dumps({k: (v if k.startswith("D3") else "see file") for k, v in res.items()}, indent=1)[:3000])
    return 0


if __name__ == "__main__":
    sys.exit(main())
