"""Build, verify and nuisance-check every run of a PILOT run matrix.

Writes into --out:
  <run_id>/                  one directory per run (python -m mtgen build)
  _logs/<run_id>.{build,verify}.log
  pilot_metrics.json         per run: wall time, peak working set, disk size,
                             envelopes, events per source, truth counts, warnings
  verify_results.json        {overall_pass, runs: {run_id: {passed, checks}}}
  nuisance_results.json      python -m mtgen nuisance --json
  label_coverage.json        PRESENT / ABSENT / UNOBSERVABLE per finding and
                             per link witness ("link:<WITNESS>")
  label_balance.json         per finding and profile: labels kept and lost to
                             degradation, with asymmetric-loss warnings

Resumable: a run whose manifest.json exists is not rebuilt (pass --rebuild to
force). Builds and verifies run as parallel subprocesses; keep --workers and
--verify-workers within memory (a 600 s Reference build peaks near 0.5 GB,
a 3600 s one near 2 GB; verify loads the whole base stream).

Usage (from the repository root):
    python src/scripts/pilot/run_pilot.py --matrix spec/generator/run-matrix.pilot.yaml \\
        --out datasets/generated/pilot --workers 3 --verify-workers 2
"""
import argparse
import json
import os
import subprocess
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[3]
PY_SRC = REPO / "src" / "python"


# ---------------------------------------------------------------------------
# Peak memory of the build (Windows; None elsewhere)
# ---------------------------------------------------------------------------

# The build runs inside this wrapper, which prints its own peak working set
# on exit (a venv python.exe is a launcher, so measuring the child handle
# would measure the launcher, not the interpreter doing the work).
_BUILD_WRAPPER = r'''
import atexit, ctypes, sys
class _PMC(ctypes.Structure):
    _fields_ = [("cb", ctypes.c_ulong), ("PageFaultCount", ctypes.c_ulong),
                ("PeakWorkingSetSize", ctypes.c_size_t)] + [
                (n, ctypes.c_size_t) for n in ("WorkingSetSize",
                 "QuotaPeakPagedPoolUsage", "QuotaPagedPoolUsage",
                 "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage",
                 "PagefileUsage", "PeakPagefileUsage")]
def _report():
    try:
        pmc = _PMC(); pmc.cb = ctypes.sizeof(_PMC)
        k = ctypes.windll.kernel32; k.GetCurrentProcess.restype = ctypes.c_void_p
        if ctypes.windll.psapi.GetProcessMemoryInfo(
                ctypes.c_void_p(k.GetCurrentProcess()), ctypes.byref(pmc), pmc.cb):
            print(f"PEAK_WORKING_SET_MB={pmc.PeakWorkingSetSize / 2**20:.1f}", flush=True)
    except Exception:
        pass
atexit.register(_report)
import runpy
sys.argv = ["mtgen"] + sys.argv[1:]
runpy.run_module("mtgen", run_name="__main__")
'''


def _peak_from_log(text):
    for line in reversed(text.splitlines()):
        if line.startswith("PEAK_WORKING_SET_MB="):
            try:
                return float(line.split("=", 1)[1])
            except ValueError:
                return None
    return None


def _env():
    # SOURCE_DATE_EPOCH: mtgen's BUILD_EPOCH (2026-10-25), set explicitly so
    # a caller's environment cannot change the manifests' generated_at.
    return dict(os.environ, PYTHONPATH=str(PY_SRC), PYTHONHASHSEED="1",
                SOURCE_DATE_EPOCH="1792886400")


def _dir_size(d: Path) -> int:
    return sum(f.stat().st_size for f in d.rglob("*") if f.is_file())


def _log(msg):
    print(time.strftime("%H:%M:%S"), msg, flush=True)


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def build_one(run, out: Path, logs: Path, rebuild: bool):
    rid = run["run_id"]
    run_dir = out / rid
    manifest = run_dir / "manifest.json"
    metrics_path = logs / f"{rid}.metrics.json"
    if manifest.exists() and metrics_path.exists() and not rebuild:
        return json.loads(metrics_path.read_text(encoding="utf-8"))

    cmd = [sys.executable, "-c", _BUILD_WRAPPER, "build",
           "--world", run["world_name"],
           "--shape", run.get("observability_profile", "clean"),
           "--scenarios", run["scenario_id"],
           "--split", run["split"],
           "--seed", str(run["seed_generator"]),
           "--duration-s", str(run["duration_s"]),
           "--variants", run.get("scenario_variants", ""),
           "--flags", ",".join(run.get("generator_flags", [])),
           "--out", str(run_dir)]
    for rel in run.get("catalogue_overlays", []):
        cmd += ["--catalogue-overlay", rel]
    log_path = logs / f"{rid}.build.log"
    t0 = time.perf_counter()
    with open(log_path, "w", encoding="utf-8") as fh:
        proc = subprocess.Popen(cmd, stdout=fh, stderr=subprocess.STDOUT,
                                env=_env(), cwd=str(REPO))
        proc.wait()
    elapsed = round(time.perf_counter() - t0, 1)
    text = log_path.read_text(encoding="utf-8", errors="replace")
    peak = _peak_from_log(text)
    m = {
        "run_id": rid, "world": run["world_name"],
        "profile": run.get("observability_profile", "clean"),
        "scenario_id": run["scenario_id"], "duration_s": run["duration_s"],
        "seed": run["seed_generator"], "build_ok": proc.returncode == 0,
        "build_time_s": elapsed, "peak_memory_mb": peak,
        "warnings": [ln.strip() for ln in text.splitlines() if "WARNING" in ln],
    }
    if proc.returncode == 0 and manifest.exists():
        mf = json.loads(manifest.read_text(encoding="utf-8"))
        if mf.get("run_id") != rid:
            m["warnings"].append(f"manifest run_id {mf.get('run_id')} != matrix run_id")
        stats = mf.get("stream_statistics", {})
        truth = mf.get("truth_statistics", {})
        m.update({
            "disk_size_bytes": _dir_size(run_dir),
            "total_envelopes": stats.get("total_envelopes", 0),
            "events_per_source": stats.get("events_per_source_family", {}),
            "truth_actions": truth.get("total_actions", 0),
            "truth_findings": truth.get("total_findings", 0),
        })
    else:
        m["error_tail"] = text[-1500:]
    metrics_path.write_text(json.dumps(m, indent=2), encoding="utf-8")
    return m


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------

def verify_one(rid, out: Path, logs: Path, reverify: bool):
    run_dir = out / rid
    jpath = logs / f"{rid}.verify.json"
    if jpath.exists() and not reverify:
        return rid, json.loads(jpath.read_text(encoding="utf-8"))
    with open(logs / f"{rid}.verify.log", "w", encoding="utf-8") as fh:
        rc = subprocess.run(
            [sys.executable, "-m", "mtgen", "verify", str(run_dir),
             "--json", str(jpath), "--verbose"],
            stdout=fh, stderr=subprocess.STDOUT, env=_env(), cwd=str(REPO),
        ).returncode
    if not jpath.exists():
        return rid, {"error": f"verify exited {rc} without JSON", "ok": False}
    return rid, json.loads(jpath.read_text(encoding="utf-8"))


def _summarise_verify(raw: dict) -> dict:
    if "error" in raw:
        return {"passed": False, "error": raw["error"], "checks": {}}
    checks = raw.get("checks", [])
    if isinstance(checks, dict):
        named = {k: bool(v.get("ok", v) if isinstance(v, dict) else v)
                 for k, v in checks.items()}
        fails = {}
    else:
        named = {c["name"]: bool(c.get("ok", c.get("passed"))) for c in checks}
        fails = {c["name"]: c.get("failures", [])[:5] for c in checks
                 if not c.get("ok", c.get("passed"))}
    passed = bool(raw.get("ok", raw.get("passed", all(named.values()))))
    out = {"passed": passed, "checks": named}
    if fails:
        out["failures"] = fails
    return out


# ---------------------------------------------------------------------------
# Label coverage
# ---------------------------------------------------------------------------

def label_coverage(out: Path, run_ids):
    sys.path.insert(0, str(PY_SRC))
    import mtgen  # noqa: F401
    from mtgen.verify import _load_truth_files
    from microtrace.v0 import witness_pb2
    names = {1: "PRESENT", 2: "ABSENT", 3: "UNOBSERVABLE"}
    cov = defaultdict(Counter)
    for rid in run_ids:
        if not (out / rid / "manifest.json").exists():
            continue
        _, opps, links = _load_truth_files(out / rid)
        for o in opps:
            cov[o.finding_type][names.get(o.expected_state, "?")] += 1
        # Links, keyed "link:<WITNESS>"; links joining one process or one
        # socket, or two findings of one benign incident (continuity) are
        # counted apart.
        for lk in links:
            key = "link:" + witness_pb2.WitnessType.Name(lk.witness_type)
            if lk.reason.startswith(("same-process continuity", "same-socket continuity",
                                     "benign continuity")):
                key += ":continuity"
            cov[key][names.get(lk.expected_state, "?")] += 1
    return {ft: dict(c) for ft, c in sorted(cov.items())}


def label_balance(out: Path, run_ids):
    """Per finding and profile: labels kept and labels lost to degradation.

    A positive lost to degradation (UNOBSERVABLE, "Missing required sources")
    while no negative was ever lost ("Lookalike evidence dropped") is the
    asymmetry that once leaked E2: the profile predicts the label. It is
    returned as a warning; the nuisance check only catches it by chance.
    """
    sys.path.insert(0, str(PY_SRC))
    import mtgen  # noqa: F401
    from mtgen.verify import _load_truth_files
    from microtrace.v0 import witness_pb2
    bal = defaultdict(Counter)
    for rid in run_ids:
        mf = out / rid / "manifest.json"
        if not mf.exists():
            continue
        profile = json.loads(mf.read_text(encoding="utf-8")).get(
            "observability_profile", "clean")
        _, opps, links = _load_truth_files(out / rid)
        for o in opps:
            if o.expected_state == 1:
                key = "present"
            elif o.expected_state == 2:
                key = "absent"
            elif o.reason.startswith("Missing required sources"):
                key = "present_lost"
            elif o.reason.startswith("Lookalike evidence dropped"):
                key = "absent_lost"
            else:
                continue
            bal[(o.finding_type, profile)][key] += 1
        # Links lost to degradation carry "Link witness evidence dropped
        # (...); catalogue PRESENT|ABSENT" (truth.py _build_links).
        for lk in links:
            if lk.expected_state == 1:
                key = "present"
            elif lk.expected_state == 2:
                key = "absent"
            elif lk.reason.startswith("Link witness evidence dropped"):
                key = "present_lost" if lk.reason.endswith("PRESENT") else "absent_lost"
            else:
                continue
            bal[("link:" + witness_pb2.WitnessType.Name(lk.witness_type), profile)][key] += 1
    table, warnings = {}, []
    for (ft, profile), c in sorted(bal.items()):
        table.setdefault(ft, {})[profile] = dict(c)
        if c["present_lost"] and not c["absent_lost"] and c["absent"]:
            warnings.append(
                f"{ft} {profile}: {c['present_lost']} PRESENT lost, 0 ABSENT lost "
                f"(kept PRESENT={c['present']} ABSENT={c['absent']})")
    return {"by_finding": table, "warnings": warnings}


# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--matrix", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--verify-workers", type=int, default=2)
    ap.add_argument("--rebuild", action="store_true")
    ap.add_argument("--reverify", action="store_true")
    ap.add_argument("--skip-verify", action="store_true")
    args = ap.parse_args(argv)

    matrix = yaml.safe_load(Path(args.matrix).read_text(encoding="utf-8"))
    runs = matrix["runs"]
    out = Path(args.out)
    logs = out / "_logs"
    logs.mkdir(parents=True, exist_ok=True)
    _log(f"{len(runs)} runs -> {out} ({args.workers} build workers)")

    # Largest worlds first so the long builds overlap the short ones.
    order = {"Large": 0, "Reference": 1, "Small": 2}
    queue = sorted(runs, key=lambda r: (order.get(r["world_name"], 3), r["run_id"]))
    metrics = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futs = [pool.submit(build_one, r, out, logs, args.rebuild) for r in queue]
        for n, f in enumerate(futs, 1):
            m = f.result()
            metrics.append(m)
            status = "ok" if m.get("build_ok", True) else "FAILED"
            _log(f"build {n}/{len(runs)} {m['run_id'][:8]} {m['world']:9s} "
                 f"{m['profile']:16s} {status} {m.get('build_time_s')}s "
                 f"peak={m.get('peak_memory_mb')}MB warnings={len(m.get('warnings', []))}")
    by_id = {m["run_id"]: m for m in metrics}
    metrics = [by_id[r["run_id"]] for r in runs]
    (out / "pilot_metrics.json").write_text(
        json.dumps({"matrix": str(args.matrix), "runs": metrics}, indent=2),
        encoding="utf-8")
    failed_builds = [m["run_id"] for m in metrics if not m.get("build_ok", True)]
    if failed_builds:
        _log(f"FAILED builds: {failed_builds}")

    if not args.skip_verify:
        built = [m["run_id"] for m in metrics if m.get("build_ok", True)]
        results = {}
        with ThreadPoolExecutor(max_workers=args.verify_workers) as pool:
            futs = [pool.submit(verify_one, rid, out, logs, args.reverify or args.rebuild)
                    for rid in built]
            for n, f in enumerate(futs, 1):
                rid, raw = f.result()
                results[rid] = _summarise_verify(raw)
                _log(f"verify {n}/{len(built)} {rid[:8]} "
                     f"{'PASS' if results[rid]['passed'] else 'FAIL'}")
        overall = bool(results) and all(r["passed"] for r in results.values()) \
            and not failed_builds
        (out / "verify_results.json").write_text(
            json.dumps({"overall_pass": overall, "runs": results}, indent=2),
            encoding="utf-8")
        _log(f"verify overall: {'PASS' if overall else 'FAIL'}")

    rc = subprocess.run(
        [sys.executable, "-m", "mtgen", "nuisance", str(out),
         "--json", str(out / "nuisance_results.json")],
        env=_env(), cwd=str(REPO),
    ).returncode
    _log(f"nuisance exit {rc}")

    cov = label_coverage(out, [r["run_id"] for r in runs])
    (out / "label_coverage.json").write_text(json.dumps(cov, indent=2), encoding="utf-8")
    for ft, c in cov.items():
        _log(f"labels {ft:4s} {c}")

    bal = label_balance(out, [r["run_id"] for r in runs])
    (out / "label_balance.json").write_text(json.dumps(bal, indent=2), encoding="utf-8")
    for w in bal["warnings"]:
        _log(f"label balance WARN {w}")
    _log(f"label balance: {len(bal['warnings'])} warning(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
