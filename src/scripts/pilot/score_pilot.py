"""Score the PILOT SCORE half offline and sum the results (build step 9).

    python src/scripts/pilot/score_pilot.py --pilot DIR --split src/params/pilot-split.v0.json \\
        --params src/params/pilot.v0.yaml --out-dir OUT [--workers 3] [--no-ml]

For each SCORE run: mtcore.harness.offline (agents, then GO) and
mtcore.harness.score against the run's restricted/ files. Per run, OUT/runs/
<run_id>/ holds score.json, offline.log and output.jsonl.gz. Resumable: a run
with a score.json is not redone. OUT/summary.json and OUT/summary.md sum the
counts over all runs, overall, per finding type and per observability profile.

    ... --correlator sage --findings-from GO_OUT [--sage-variant ag|seq] [--sage-params P]

scores the SAGE baseline instead of the GO, on the same agent findings: the
cached findings of a GO run of this script (GO_OUT/runs/<run_id>/
output.jsonl.gz) go to one SAGE call over all SCORE runs (OUT/sage/), and
each run's SAGE output is scored as above, so the summaries compare directly.

Held-out (sealed truth): --stage detect runs the pipeline only and never opens
restricted/ (OUT/runs/<run_id>/output.jsonl.gz and time.json); --stage score later
scores those outputs against --truth-root ROOT/<run_id>/restricted (default: the
run's own folder). --stage all (default) does both, as before. time.json holds the
wall time and, where /usr/bin/time exists, the peak memory of the pipeline process.

Exp. 1 (decided 2026-11-15): --drop-source SRC runs the telemetry ablation (offline
--drop-source: the source is dropped and declared not shipped); the detect stage keeps
the dropped IDs in OUT/runs/<run_id>/dropped.jsonl.gz, built from the input stream only,
and the score stage passes them as --fault-log, so opportunities whose evidence lost a
record are UNOBSERVABLE (reported as unresolved, not as misses). summary.json also has
per_agent (the per-type counts summed over each agent's own types: the "Agent X only"
rows) and host_steps (the same over the host types KAIROS is scored on). A drop-source pass is
also scored without the fault log (runs/<run_id>/score_nofault.json); summary.json end_to_end
holds that recall over the Full row's opportunities and the unresolved opportunities (PRESENT
before the adjustment, UNOBSERVABLE after it), split into still detected and missed (decided
2026-11-15).

Exp. 3: --fault-log-root ROOT (score stage, or all) scores each run with the injector's fault log
ROOT/<run_id>/faults.jsonl (mtcore.exp3: the source and transit logs of every node of that run),
passed to mtcore.harness.score --fault-log as the drop-source log is; like a drop-source pass, each
run is also scored without it (score_nofault.json) and summary.json gets end_to_end. The fault log
is truth-side material: it is refused at the detect stage, and a run without its log fails rather
than being scored as fault-free. SAGE passes take it the same way.

Exp. 3 No-OffNode (decided 2026-11-16): --drop-source PATH_FLOW drops the flow export S_F as
Exp. 1 drops a security source. With --fault-log-root as well, the score stage scores against
both logs at once (runs/<run_id>/faults_merged.jsonl, removed after scoring: the injector's
records and the dropped flow records); without --fault-log-root nothing changes.
"""
import argparse
import glob
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
PY = REPO / "src" / "python"
COUNTS = ("present", "tp", "fn", "fp", "fp_absent", "fp_background", "on_unobservable")
# Host types: the steps KAIROS is scored on (mtcore.baselines.provenance.convert.HOST_TYPES).
NOFAULT = "score_nofault.json"     # drop-source passes: the same output scored without the fault log
HOST_TYPES = ("C1a", "C1b", "C2", "D1", "E2", "F1", "G1a", "G1c", "H1", "H2", "H4")


TIME = "/usr/bin/time"


def stamp(a):
    """What made an output: the params file's hash and the code commit (cached outputs
    with another stamp are redone, never reused)."""
    if not hasattr(a, "_stamp"):
        with open(a.params, "rb") as fh:
            ph = hashlib.sha256(fh.read()).hexdigest()
        try:
            commit = subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True,
                                    text=True).stdout.strip() or None
        except OSError:
            commit = None
        a._stamp = {"params_sha256": ph, "code": commit, "no_ml": bool(a.no_ml),
                    "drop_source": getattr(a, "drop_source", None)}
    return a._stamp


def detect_done(out, a, keys=("params_sha256", "code", "no_ml", "drop_source")):
    """A finished detection output made with these params (and, for the detect cache, this
    code). The score stage checks params only: a later scoring fix must not force a rerun."""
    t = out / "time.json"
    if not (out / "output.jsonl.gz").exists() or not t.exists():
        return False
    if getattr(a, "drop_source", None) and not (out / "dropped.jsonl.gz").exists():
        return False
    rec = json.loads(t.read_text())
    want = stamp(a)
    return rec.get("exit") == 0 and all(rec.get(k) == want[k] for k in keys)


def exp3_fault_log(a, run_id):
    """The run's Exp. 3 fault log under --fault-log-root, or None without one (FileNotFoundError
    when the root is given but the run's log is missing: never scored as fault-free)."""
    root = getattr(a, "fault_log_root", None)
    if not root:
        return None
    p = Path(root) / run_id / "faults.jsonl"
    if not p.exists():
        raise FileNotFoundError(f"no fault log {p}")
    return p


def merged_log(out, flog, xlog):
    """The fault log to score with: the drop-source log, the Exp. 3 injector log, or (No-OffNode on a
    degraded stream) both concatenated (mtcore.harness.score skips every header line)."""
    if not (flog and xlog):
        return flog or xlog
    m = out / "faults_merged.jsonl"
    with open(m, "wb") as dst:
        for src in (xlog, flog):
            with open(src, "rb") as fh:
                data = fh.read()
            dst.write(data if not data or data.endswith(b"\n") else data + b"\n")
    return m


def truth_dir(a, run_id):
    return Path(a.truth_root or a.pilot) / run_id / "restricted"


def timed(cmd, out, log, a):
    """Run cmd; write out/time.json (wall seconds, peak RSS in MB when /usr/bin/time exists)."""
    tf = out / "time.txt"
    # %M peak RSS (KB), %U and %S user and system CPU seconds: CPU seconds sit beside wall time so a
    # system's parallelism alone does not decide a timing comparison (decided 2026-11-15).
    wrap = [TIME, "-f", "%M %U %S", "-o", str(tf)] if os.path.exists(TIME) else []
    t0 = time.monotonic()
    r = subprocess.run(wrap + cmd, cwd=PY, stdout=log, stderr=subprocess.STDOUT)
    rec = {"wall_s": round(time.monotonic() - t0, 3), "peak_rss_mb": None, "cpu_user_s": None, "cpu_sys_s": None,
           "exit": r.returncode, **stamp(a)}
    if wrap and tf.exists():
        rec.update(parse_time(tf.read_text()))
        tf.unlink()
    (out / "time.json").write_text(json.dumps(rec))
    return r


def parse_time(text):
    """/usr/bin/time -f '%M %U %S' output (last line; earlier lines are notes such as a signal) ->
    peak RSS MB and CPU seconds; fields it cannot read stay None."""
    lines = text.strip().splitlines()
    parts = lines[-1].split() if lines else []
    out = {"peak_rss_mb": None, "cpu_user_s": None, "cpu_sys_s": None}
    if len(parts) == 3:
        try:
            out = {"peak_rss_mb": round(int(parts[0]) / 1024, 1), "cpu_user_s": float(parts[1]),
                   "cpu_sys_s": float(parts[2])}
        except ValueError:
            pass
    return out


def score_output(run_id, a, out, output, log, fault_log=None):
    """score.json.tmp; with a fault log (a drop-source pass) also score_nofault.json.tmp, the same
    output scored without the lost-evidence adjustment (decided 2026-11-15: the "Without X" rows
    report recall over the Full row's opportunities beside the adjusted numbers)."""
    def one(target, extra):
        return subprocess.run([sys.executable, "-m", "mtcore.harness.score", "--truth", str(truth_dir(a, run_id)),
                               "--output", str(output), "--out", str(out / target)] + extra,
                              cwd=PY, stdout=log, stderr=subprocess.STDOUT)
    if fault_log:
        r = one(NOFAULT + ".tmp", [])
        if r.returncode != 0:
            return r
        return one("score.json.tmp", ["--fault-log", str(fault_log)])
    return one("score.json.tmp", [])


def finish_scores(out):
    """Move finished scores into place; score.json last, as it marks the run done."""
    if (out / (NOFAULT + ".tmp")).exists():
        os.replace(out / (NOFAULT + ".tmp"), out / NOFAULT)
    os.replace(out / "score.json.tmp", out / "score.json")


def gunzip(src_gz, dst):
    with gzip.open(src_gz, "rb") as src, open(dst, "wb") as fh:
        shutil.copyfileobj(src, fh)


def gzip_to(src, dst_gz):
    tmp = Path(str(dst_gz) + ".tmp")
    with open(src, "rb") as fh, gzip.open(tmp, "wb") as dst:
        shutil.copyfileobj(fh, dst)
    os.replace(tmp, dst_gz)                      # never a half-written gz under the final name
    Path(src).unlink()


def run_one(run_id, a):
    out = Path(a.out_dir) / "runs" / run_id
    gz = out / "output.jsonl.gz"
    drop = getattr(a, "drop_source", None)
    twice = drop or getattr(a, "fault_log_root", None)        # also scored without the fault log
    if ((out / "score.json").exists() and (not twice or (out / NOFAULT).exists())) or \
            (a.stage == "detect" and detect_done(out, a)):
        return run_id, "cached"
    out.mkdir(parents=True, exist_ok=True)
    if a.stage == "score":
        if not detect_done(out, a, keys=("params_sha256", "no_ml", "drop_source")):
            return run_id, f"FAILED (no finished detection output with this params/code in {out})"
        jsonl = out / "output.jsonl"
        flog = out / "dropped.jsonl" if getattr(a, "drop_source", None) else None
        try:
            xlog = exp3_fault_log(a, run_id)
        except FileNotFoundError as e:
            return run_id, f"FAILED ({e})"
        try:
            gunzip(gz, jsonl)
            if flog:
                gunzip(out / "dropped.jsonl.gz", flog)
        except (OSError, EOFError) as e:
            return run_id, f"FAILED (unreadable {gz} or its dropped.jsonl.gz: {e})"
        mlog = merged_log(out, flog, xlog)
        with open(out / "score.log", "w") as log:
            r = score_output(run_id, a, out, jsonl, log, mlog)
        jsonl.unlink()
        if flog:
            flog.unlink()
        if mlog and mlog.name == "faults_merged.jsonl":
            mlog.unlink()
        if r.returncode != 0:
            return run_id, f"FAILED (exit {r.returncode}, see {out / 'score.log'})"
        finish_scores(out)
        return run_id, "ok"
    run_dir = Path(a.pilot) / run_id
    jsonl = out / "output.jsonl"
    flog = out / "dropped.jsonl" if getattr(a, "drop_source", None) else None
    cmd = [sys.executable, "-m", "mtcore.harness.offline", str(run_dir), "--out", str(jsonl),
           "--params", a.params, "--orch-params", a.params] + (["--no-ml"] if a.no_ml else []) + \
          (["--drop-source", a.drop_source, "--fault-log", str(flog)] if flog else [])
    with open(out / "offline.log", "w") as log:
        r = timed(cmd, out, log, a)
        if r.returncode == 0 and a.stage == "all":
            try:
                xlog = exp3_fault_log(a, run_id)
            except FileNotFoundError as e:
                return run_id, f"FAILED ({e})"
            mlog = merged_log(out, flog, xlog)
            r = score_output(run_id, a, out, jsonl, log, mlog)
            if mlog and mlog.name == "faults_merged.jsonl":
                mlog.unlink()
    if r.returncode != 0:
        return run_id, f"FAILED (exit {r.returncode}, see {out / 'offline.log'})"
    if flog:
        gzip_to(flog, out / "dropped.jsonl.gz")  # before the output, so a finished gz implies both
    gzip_to(jsonl, gz)
    if a.stage == "all":
        finish_scores(out)
    return run_id, "ok"


def run_sage(a, runs):
    """One SAGE call over the SCORE runs' cached findings (skipped if done)."""
    out = Path(a.out_dir) / "sage"
    if (out / "run.json").exists():
        st = json.loads((out / "run.json").read_text())
        if st.get("sage_status") != "failed":
            return 0
        shutil.rmtree(out)                       # a failed SAGE call is redone, never reused
    # score_pilot.py's layout (runs/<run_id>/output.jsonl.gz) or twin_safety's
    # (<run_id>.output.jsonl[.gz]), as fit_sage.py reads them.
    inputs, missing = [], []
    for r in runs:
        hits = sorted(glob.glob(os.path.join(a.findings_from, "runs", r, "output.jsonl*")) +
                      glob.glob(os.path.join(a.findings_from, r + ".output.jsonl*")))
        (inputs.append(hits[0]) if hits else missing.append(r))
    if missing:
        raise SystemExit(f"{len(missing)} runs have no cached findings under {a.findings_from}, e.g. {missing[0]}")
    return subprocess.run([sys.executable, "-m", "mtcore.baselines.sage.run", "--out", str(out),
                           "--params", a.sage_params, *inputs], cwd=PY).returncode


def score_sage_one(run_id, a):
    out = Path(a.out_dir) / "runs" / run_id
    if (out / "score.json").exists():
        return run_id, "cached"
    if a.stage == "detect":
        return run_id, "ok (SAGE output only)"
    out.mkdir(parents=True, exist_ok=True)
    try:
        xlog = exp3_fault_log(a, run_id)
    except FileNotFoundError as e:
        return run_id, f"FAILED ({e})"
    with open(out / "score.log", "w") as log:
        r = score_output(run_id, a, out, Path(a.out_dir) / "sage" / a.sage_variant / f"{run_id}.jsonl", log, xlog)
    if r.returncode != 0:
        return run_id, f"FAILED (exit {r.returncode}, see {out / 'score.log'})"
    finish_scores(out)
    return run_id, "ok"


def prf(c):
    p = c["tp"] / (c["tp"] + c["fp"]) if c["tp"] + c["fp"] else None
    r = c["tp"] / c["present"] if c["present"] else None
    f = 2 * p * r / (p + r) if p and r else None
    return {k: (round(v, 4) if v is not None else None) for k, v in (("precision", p), ("recall", r), ("f1", f))}


def summarize(a, runs):
    manifests = {r: json.load(open(Path(a.pilot) / r / "manifest.json")) for r in runs}
    total = defaultdict(int)
    per_type = defaultdict(lambda: defaultdict(int))
    per_profile = defaultdict(lambda: defaultdict(int))
    links = defaultdict(int)
    links_x = defaultdict(int)                   # without same-process continuity rows (D-2)
    paths = defaultdict(int)
    by_length = defaultdict(lambda: defaultdict(int))
    incidents = defaultdict(int)
    scored, missing = 0, []
    for r in runs:
        f = Path(a.out_dir) / "runs" / r / "score.json"
        if not f.exists():
            missing.append(r)
            continue
        s = json.load(open(f))
        scored += 1
        fo = s["findings"]
        prof = manifests[r]["observability_profile"]
        for k in COUNTS:
            total[k] += fo["overall"].get(k) or 0
            per_profile[prof][k] += fo["overall"].get(k) or 0
        total["unobservable_opportunities"] += fo.get("unobservable_opportunities") or 0
        total["abstained_evaluations"] += fo.get("abstained") or 0
        for t, c in fo["per_type"].items():
            for k in COUNTS:
                per_type[t][k] += c.get(k) or 0
        lk = s["links"]
        for k in ("present", "tp", "fp", "fn", "unobservable_links", "scored_links"):
            links[k] += lk.get(k) or 0
        for k in ("present", "tp", "fp", "fn"):
            links_x[k] += (lk.get("without_same_process") or {}).get(k) or 0
        links["violated_nonlinks"] += len(lk.get("violated_nonlinks") or [])
        links["unscored_proposed"] += len(lk.get("unscored_proposed") or [])
        for st, n in (lk.get("unscored_links") or {}).items():
            links[f"unscored_{st.lower()}"] += n
        p = s["paths"]
        for k in ("reference_paths", "recovered", "recovered_loose", "false_chains", "retained_multi", "incidents"):
            paths[k] += p.get(k) or 0
        for n, c in (p.get("by_length") or {}).items():           # rule A' and the loose diagnostic
            for k in ("reference", "recovered", "recovered_loose"):
                by_length[int(n)][k] += c.get(k) or 0
        for k, v in (s.get("incidents") or {}).items():          # B1: merges and fragmentation
            if isinstance(v, int):
                incidents[k] += v
    drop = getattr(a, "drop_source", None)
    twice = drop or getattr(a, "fault_log_root", None)
    nf_total, nf_type = defaultdict(int), defaultdict(lambda: defaultdict(int))
    if twice:
        for r in runs:
            f = Path(a.out_dir) / "runs" / r / NOFAULT
            if not f.exists():
                continue
            fo = json.load(open(f))["findings"]
            for k in COUNTS:
                nf_total[k] += fo["overall"].get(k) or 0
            for t, c in fo["per_type"].items():
                for k in COUNTS:
                    nf_type[t][k] += c.get(k) or 0

    def lost(adj, nf):
        """Opportunities PRESENT without the adjustment but UNOBSERVABLE with it, split by whether
        a finding still matched them (matching is the same in both scores)."""
        n = nf["present"] - adj["present"]
        det = nf["tp"] - adj["tp"]
        return {"unresolved": n, "unresolved_detected": det, "unresolved_missed": n - det}

    def group(types):
        c = {k: sum(per_type[t][k] for t in types if t in per_type) for k in COUNTS}
        return dict(c, **prf(c), types=sorted(t for t in types if t in per_type))
    agents = defaultdict(list)
    for t in per_type:
        agents[t[0]].append(t)               # a finding type's first letter names its agent
    summary = {
        "runs_scored": scored, "runs_missing": missing, "params": a.params, "split": a.split, "half": a.half,
        "correlator": a.correlator if a.correlator == "go" else f"sage-{a.sage_variant}",
        "findings": dict(total, **prf(total)),
        "per_type": {t: dict(c, **prf(c)) for t, c in sorted(per_type.items())},
        "per_profile": {p: dict(c, **prf(c)) for p, c in sorted(per_profile.items())},
        "per_agent": {g: group(ts) for g, ts in sorted(agents.items())},
        "host_steps": group(HOST_TYPES),
        "drop_source": drop,
        "fault_log_root": getattr(a, "fault_log_root", None),
        "links": dict(links, **prf(links), without_same_process=dict(links_x, **prf(links_x))),
        "paths": dict(paths, top_k_path_recall=round(paths["recovered"] / paths["reference_paths"], 4)
                      if paths["reference_paths"] else None,
                      top_k_path_recall_loose=round(paths["recovered_loose"] / paths["reference_paths"], 4)
                      if paths["reference_paths"] else None,
                      by_length={str(n): dict(c, recall=round(c["recovered"] / c["reference"], 4)
                                              if c["reference"] else None)
                                 for n, c in sorted(by_length.items())},
                      false_chain_rate=round(paths["false_chains"] / paths["retained_multi"], 4)
                      if paths["retained_multi"] else None),
        "incidents": dict(incidents),
    }
    if twice:
        nf_agents = {}
        for g, ts in sorted(agents.items()):
            c = {k: sum(nf_type[t][k] for t in set(ts) | {t for t in nf_type if t[0] == g}) for k in COUNTS}
            nf_agents[g] = dict(c, **prf(c), **lost(summary["per_agent"][g], c))
        for t in nf_type:                    # an agent with opportunities only before the adjustment
            if t[0] not in nf_agents:
                ts = [u for u in nf_type if u[0] == t[0]]
                c = {k: sum(nf_type[u][k] for u in ts) for k in COUNTS}
                zero = {k: 0 for k in COUNTS}
                nf_agents[t[0]] = dict(c, **prf(c), **lost(zero, c))
        summary["end_to_end"] = {
            "note": "recall over the Full row's opportunities: the same output scored without the fault log",
            "findings": dict(nf_total, **prf(nf_total), **lost(total, nf_total)),
            "per_agent": dict(sorted(nf_agents.items())),
            "runs_scored": sum((Path(a.out_dir) / "runs" / r / NOFAULT).exists() for r in runs)}
    Path(a.out_dir, "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    lines = [f"# {a.half} results, {summary['correlator']} ({scored} runs scored, {len(missing)} missing)",
             "",
             f"Params: `{a.params}`  ", f"Split: `{a.split}`", "",
             "Findings are rules-only unless the params set has ML models. PILOT numbers are for development only.",
             "", "| Finding | PRESENT | TP | FN | FP (lookalike) | FP (background) | Precision | Recall | F1 |",
             "|---|---|---|---|---|---|---|---|---|"]
    for t, c in [("ALL", summary["findings"])] + list(summary["per_type"].items()):
        lines.append(f"| {t} | {c['present']} | {c['tp']} | {c['fn']} | {c['fp_absent']} | {c['fp_background']} | "
                     f"{c['precision']} | {c['recall']} | {c['f1']} |")
    lines += ["", "| Profile | PRESENT | TP | FP | Precision | Recall |", "|---|---|---|---|---|---|"]
    for p, c in summary["per_profile"].items():
        lines.append(f"| {p} | {c['present']} | {c['tp']} | {c['fp']} | {c['precision']} | {c['recall']} |")
    lk, pa = summary["links"], summary["paths"]
    lines += ["", f"Links: PRESENT {lk['present']}, TP {lk['tp']}, FP {lk['fp']}, precision {lk['precision']}, "
              f"recall {lk['recall']}, violated non-links {lk['violated_nonlinks']}",
              f"Links without same-process continuity: PRESENT {lk['without_same_process']['present']}, "
              f"TP {lk['without_same_process']['tp']}, precision {lk['without_same_process']['precision']}, "
              f"recall {lk['without_same_process']['recall']}",
              f"Paths: reference {pa['reference_paths']}, recovered {pa['recovered']}, "
              f"top-K recall {pa['top_k_path_recall']}, false-chain rate {pa['false_chain_rate']}",
              f"Paths, loose rule (diagnostic, false steps allowed inside the match): recovered "
              f"{pa['recovered_loose']}, top-K recall {pa['top_k_path_recall_loose']}",
              "", "| Path length | Reference | Recovered | Recovered (loose) | Recall |", "|---|---|---|---|---|"]
    for n, c in pa["by_length"].items():
        lines.append(f"| {n} | {c['reference']} | {c['recovered']} | {c['recovered_loose']} | {c['recall']} |")
    Path(a.out_dir, "summary.md").write_text("\n".join(lines) + "\n")
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser(description="Score the PILOT SCORE half offline.")
    ap.add_argument("--pilot", required=True)
    ap.add_argument("--split", required=True)
    ap.add_argument("--params", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--no-ml", action="store_true")
    ap.add_argument("--drop-source", choices=("EBPF", "GATEWAY", "KYVERNO", "AUDIT", "PATH_FLOW"), default=None,
                    help="Exp. 1 telemetry ablation (PATH_FLOW: Exp. 3 No-OffNode): drop this source, "
                         "declared as not shipped")
    ap.add_argument("--correlator", choices=("go", "sage"), default="go")
    ap.add_argument("--findings-from", default=None, help="sage: a GO run's --out-dir with cached findings")
    ap.add_argument("--sage-variant", choices=("ag", "seq"), default="ag")
    ap.add_argument("--sage-params", default=str(REPO / "src" / "params" / "sage.v0.yaml"))
    ap.add_argument("--half", default="score",
                    help="which list of the split file to run (score, fit, or a held-out key)")
    ap.add_argument("--stage", choices=("all", "detect", "score"), default="all",
                    help="detect: pipeline only, truth never opened; score: score earlier outputs")
    ap.add_argument("--truth-root", default=None, help="folder holding <run_id>/restricted (default --pilot)")
    ap.add_argument("--fault-log-root", default=None,
                    help="Exp. 3, score stage: folder holding <run_id>/faults.jsonl (the injector's fault log)")
    a = ap.parse_args(argv)
    if a.fault_log_root and a.stage == "detect":
        ap.error("--fault-log-root is truth-side material: score or all stage only")
    if a.fault_log_root and a.drop_source and a.drop_source != "PATH_FLOW":
        ap.error("--fault-log-root goes with --drop-source PATH_FLOW only (Exp. 3 No-OffNode)")
    a.fault_log_root = os.path.abspath(a.fault_log_root) if a.fault_log_root else None
    a.params, a.split = os.path.abspath(a.params), os.path.abspath(a.split)
    a.pilot, a.out_dir = os.path.abspath(a.pilot), os.path.abspath(a.out_dir)   # subprocesses run in src/python
    a.truth_root = os.path.abspath(a.truth_root) if a.truth_root else None
    runs = json.load(open(a.split))[a.half]
    one = run_one
    if a.correlator == "sage":
        if not a.findings_from:
            ap.error("--correlator sage needs --findings-from")
        a.findings_from, a.sage_params = os.path.abspath(a.findings_from), os.path.abspath(a.sage_params)
        if a.stage != "score" and run_sage(a, runs) != 0:
            print(f"SAGE failed; see {Path(a.out_dir) / 'sage'}", flush=True)
            return 1
        one = score_sage_one
    failed = 0
    with ThreadPoolExecutor(max_workers=a.workers) as pool:
        for i, (r, status) in enumerate(pool.map(lambda r: one(r, a), runs), 1):
            failed += status.startswith("FAILED")
            print(f"{i}/{len(runs)} {r} {status}", flush=True)
    if a.stage == "detect":
        return 1 if failed else 0
    s = summarize(a, runs)
    print(json.dumps(s["findings"]), flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
