"""Run SAGE over a batch of runs' cached findings and write scorer input.

    python -m mtcore.baselines.sage.run --sage-home $MT_SAGE_HOME --out OUT \\
        [--params src/params/sage.v0.yaml] [--t T --w W] FINDINGS...

FINDINGS are cached offline outputs, one per run: ``<run_id>.output.jsonl``
(twin_safety, ablation_cases) or ``.../<run_id>/output.jsonl[.gz]``
(score_pilot). Only their findings.v0 lines are read. All runs go to one SAGE
invocation, one alert file ("team") per run, as SAGE learns its S-PDFA over
all teams together.

Writes OUT/<variant>/<run_id>.jsonl for each variant (project.VARIANTS): the
run's findings.v0 lines followed by SAGE's witness.decisions.v0 and
incidents.v0 lines, so ``python -m mtcore.harness.score --truth RUN/restricted
--output OUT/ag/<run_id>.jsonl`` scores SAGE as it scores the GO. A run
SAGE links nothing in still gets its file (findings only). OUT/run.json holds
the parameters, mapping hash, skip counts and SAGE's exit status.

SAGE runs in its own venv ($MT_SAGE_HOME/venv, built by
src/scripts/baselines/fetch-sage.sh) with the pinned IANA port table.
"""
import argparse
import gzip
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

import yaml
from google.protobuf import json_format

from mtcore import REPO
from mtcore.baselines.sage import alerts as A
from mtcore.baselines.sage import mapping as M
from mtcore.baselines.sage import project as P
from mtcore.harness.score import FINDINGS, Output

DEFAULT_PARAMS = os.path.join(REPO, "src", "params", "sage.v0.yaml")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def run_id_of(path):
    """The run ID in a cached output's file name or parent directory."""
    for part in (os.path.basename(path), os.path.basename(os.path.dirname(os.path.abspath(path)))):
        m = UUID.search(part)
        if m:
            return m.group(0)
    raise SystemExit(f"no run ID in {path}")


def _open(path):
    return gzip.open(path, "rt", encoding="utf-8") if path.endswith(".gz") else open(path, encoding="utf-8")


def read_findings(path):
    """(the findings.v0 lines as written, {finding_id: Finding})."""
    with _open(path) as fh:
        lines = [ln for ln in fh if FINDINGS in ln and json.loads(ln).get("topic") == FINDINGS]
    return lines, Output.parse(lines).findings


def load_params(path):
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def run_sage(sage_home, work, teams, mapping, t, w, python=None):
    """Write the alert files, run sage.py in work/, return (exit code, seconds)."""
    alerts_dir = os.path.join(work, "alerts")
    os.makedirs(alerts_dir, exist_ok=True)
    for run_id, alerts in teams.items():
        with open(os.path.join(alerts_dir, run_id + ".json"), "w", encoding="utf-8") as fh:
            json.dump(alerts, fh)
    extra = os.path.join(work, "extra-signatures.json")
    with open(extra, "w", encoding="utf-8") as fh:
        json.dump(mapping.extra_signatures(), fh, sort_keys=True)
    ff = os.path.join(work, "FlexFringe")
    if not os.path.exists(ff):
        os.symlink(os.path.join(sage_home, "FlexFringe"), ff)
    env = dict(os.environ, SAGE_EXTRA_SIGNATURES=extra, SAGE_SKIP_RENDER="1", MPLBACKEND="Agg",
               SAGE_IANA_CSV=os.path.join(sage_home, "iana-service-names-port-numbers.csv"))
    python = python or os.path.join(sage_home, "venv", "bin", "python")
    cmd = [python, os.path.join(sage_home, "SAGE", "sage.py"), "alerts", "exp",
           "-t", str(t), "-w", str(int(w)), "--dataset", "other", "--keep-files"]
    t0 = time.time()
    with open(os.path.join(work, "sage.log"), "w", encoding="utf-8") as log:
        r = subprocess.run(cmd, cwd=work, env=env, stdout=log, stderr=subprocess.STDOUT)
    return r.returncode, round(time.time() - t0, 1)


def trace_count(work):
    """Episode traces SAGE handed to FlexFringe (first field of exp.txt), None if absent."""
    try:
        with open(os.path.join(work, "exp.txt"), encoding="utf-8") as fh:
            return int(fh.readline().split()[0])
    except (FileNotFoundError, IndexError, ValueError):
        return None


def run(paths, out, sage_home, mapping, t, w, k, python=None, keep_work=False):
    found = {}
    for p in paths:
        rid = run_id_of(p)
        if rid in found:
            raise SystemExit(f"run {rid} given twice")
        found[rid] = read_findings(p)
    teams, ips, skipped = A.build({r: list(f.values()) for r, (_l, f) in found.items()}, mapping)
    os.makedirs(out, exist_ok=True)
    work = tempfile.mkdtemp(prefix="sage-", dir=out)
    code, secs = run_sage(sage_home, work, teams, mapping, t, w, python) if teams else (None, 0.0)
    traces = trace_count(work)
    status = "no_alerts" if not teams else "ok" if code == 0 else "failed"
    if code not in (0, None) and traces == 0 and os.path.exists(os.path.join(work, "exp-sequences.json")):
        # No episode subsequence of 3 or more: FlexFringe has nothing to learn
        # (it crashes on an empty trace file) and SAGE builds no attack graph.
        # A result (no ag links), not a failure; the seq export is complete.
        status = "no_traces"
    labels, paths_x, seqs = P.load_exports(os.path.join(work, "exp"))
    run_of_team = dict(enumerate(labels))
    if labels and sorted(labels) != sorted(teams):
        raise SystemExit(f"SAGE teams {len(labels)} != alert files {len(teams)}; see {work}/sage.log")
    stats = {"runs": len(found), "runs_with_alerts": len(teams), "t": t, "w": int(w), "k": k,
             "mapping": mapping.version, "mapping_sha256": mapping.sha256, "sage_commit": mapping.sage_commit,
             "sage_exit": code, "sage_status": status, "episode_traces": traces, "sage_seconds": secs,
             "skipped": dict(sorted(skipped.items())),
             "alerts": sum(len(a) for a in teams.values()), "attack_graph_paths": len(paths_x),
             "subsequences": len(seqs), "variants": {}}
    for variant in P.VARIANTS:
        records = P.project(variant, run_of_team, paths_x, seqs, k)
        vdir = os.path.join(out, variant)
        os.makedirs(vdir, exist_ok=True)
        n_w = 0
        for rid, (lines, _f) in sorted(found.items()):
            with open(os.path.join(vdir, rid + ".jsonl"), "w", encoding="utf-8") as fh:
                fh.writelines(ln if ln.endswith("\n") else ln + "\n" for ln in lines)
                for topic, rec in records.get(rid, ()):
                    fh.write(json.dumps({"topic": topic, "record": rec}, sort_keys=True) + "\n")
                    n_w += topic == P.WITNESSES
        stats["variants"][variant] = {"witnesses": n_w}
    with open(os.path.join(out, "run.json"), "w", encoding="utf-8") as fh:
        json.dump(stats, fh, indent=2, sort_keys=True)
        fh.write("\n")
    if keep_work:
        stats["work"] = work
    else:
        shutil.rmtree(work, ignore_errors=True)
    return stats


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run the SAGE baseline over cached findings.")
    ap.add_argument("findings", nargs="+", help="cached offline outputs, one per run")
    ap.add_argument("--out", required=True)
    ap.add_argument("--sage-home", default=os.environ.get("MT_SAGE_HOME"), help="default $MT_SAGE_HOME")
    ap.add_argument("--sage-python", default=None, help="default <sage-home>/venv/bin/python")
    ap.add_argument("--params", default=DEFAULT_PARAMS)
    ap.add_argument("--mapping", default=None, help="default: the params file's mapping")
    ap.add_argument("--t", type=float, default=None, help="override the params' alert filtering window")
    ap.add_argument("--w", type=int, default=None, help="override the params' episode window")
    ap.add_argument("--keep-work", action="store_true", help="keep SAGE's work directory under --out")
    a = ap.parse_args(argv)
    if not a.sage_home:
        ap.error("--sage-home or MT_SAGE_HOME is required")
    prm = load_params(a.params)
    mapping = M.load(a.mapping or os.path.join(REPO, prm["mapping"]))
    if mapping.sha256 != prm.get("mapping_sha256", mapping.sha256) and a.mapping is None:
        raise SystemExit(f"mapping hash {mapping.sha256} != params mapping_sha256 {prm['mapping_sha256']}")
    stats = run(a.findings, a.out, a.sage_home, mapping, a.t if a.t is not None else prm["t"],
                a.w if a.w is not None else prm["w"], prm["k"], a.sage_python, a.keep_work)
    print(json.dumps({k: v for k, v in stats.items() if k != "skipped"}), file=sys.stderr)
    return 1 if stats["sage_status"] == "failed" else 0


if __name__ == "__main__":
    sys.exit(main())
