"""Regenerate a built dataset's truth with the current generator, keeping its
streams (2026-10-25: a stateless finding's evidence is its own step).

    python src/scripts/pilot/retruth_pilot.py backup  RUNS_DIR [--zip PATH]
    python src/scripts/pilot/retruth_pilot.py run     RUNS_DIR --scratch DIR [--workers N]
    python src/scripts/pilot/retruth_pilot.py check   RUNS_DIR
    python src/scripts/pilot/retruth_pilot.py restore RUNS_DIR [--run RUN_ID ...]

backup: copy every run's restricted/ and manifest.json to
RUNS_DIR/_gates/pre-retruth/<run_id>/, write SHA256SUMS there and check it;
--zip also writes the copy to a zip outside the dataset.

run: per run, `mtgen from-manifest` into the scratch directory; only when the
rebuilt base stream hash equals the run's are its restricted/ files and then
its manifest.json replaced, each written to a temporary name and renamed into
place. A run whose stream differs, or whose build fails, is left as it was and
listed. Resumable: a run is done when its marker in _gates/retruth/ exists.

check: every run's restricted/ truth files match its manifest truth_sha256.

restore: copy the backups back (all runs, or those given): retruth_gt's
_gates/pre-retruth-gt/ first, then _gates/pre-retruth/; fails unless each
run's base.pb and truth match its manifest afterwards.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
TRUTH = ("truth_actions.pb", "truth_findings.pb", "truth_links.pb")   # emit.compute_truth_sha256


def runs(d):
    # absolute: the builds run from src/python
    return sorted(p.parent for p in Path(d).resolve().glob("*/manifest.json"))


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def truth_sha(run):
    h = hashlib.sha256()
    for f in TRUTH:
        p = run / "restricted" / f
        if p.exists():
            h.update(p.read_bytes())
    return h.hexdigest()


def files_of(run):
    """manifest.json and every file under restricted/, relative to the run."""
    out = [Path("manifest.json")]
    out += sorted(p.relative_to(run) for p in (run / "restricted").rglob("*") if p.is_file())
    return out


def backup(a):
    root = Path(a.runs_dir)
    dst = root / "_gates" / "pre-retruth"
    if (dst / "SHA256SUMS").exists():
        sys.exit(f"{dst} already holds a backup; not overwriting it")
    lines = []
    for run in runs(root):
        for rel in files_of(run):
            out = dst / run.name / rel
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(run / rel, out)
            lines.append(f"{sha(run / rel)}  {run.name}/{rel.as_posix()}")
    (dst / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
    bad = [ln for ln in lines if sha(dst / ln.split("  ", 1)[1]) != ln.split("  ", 1)[0]]
    print(f"backup: {len(lines)} files of {len(runs(root))} runs -> {dst}; mismatches: {len(bad)}")
    if a.zip:
        with zipfile.ZipFile(a.zip, "w", zipfile.ZIP_DEFLATED) as z:
            for p in sorted(dst.rglob("*")):
                if p.is_file():
                    z.write(p, p.relative_to(dst).as_posix())
        with zipfile.ZipFile(a.zip) as z:
            zbad = [ln for ln in lines if hashlib.sha256(z.read(ln.split("  ", 1)[1])).hexdigest()
                    != ln.split("  ", 1)[0]]
        print(f"zip: {a.zip}; mismatches: {len(zbad)}")
        bad += zbad
    return 1 if bad else 0


def _replace(src, dst):
    tmp = dst.with_name(dst.name + ".retruth-tmp")
    tmp.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, tmp)
    os.replace(tmp, dst)


def run_one(run, scratch, done_dir):
    marker = done_dir / f"{run.name}.json"
    if marker.exists():
        return run.name, "cached"
    out = scratch / run.name
    shutil.rmtree(out, ignore_errors=True)
    log = done_dir / f"{run.name}.log"
    with open(log, "w", encoding="utf-8") as fh:
        r = subprocess.run([sys.executable, "-m", "mtgen", "from-manifest", str(run), "--out", str(out),
                            "--allow-spec-change"],      # re-truth rebuilds with the current catalogue
                           cwd=REPO / "src" / "python", stdout=fh, stderr=subprocess.STDOUT)
    try:
        if r.returncode:
            return run.name, f"FAILED build (exit {r.returncode}, see {log})"
        old, new = (json.loads((d / "manifest.json").read_text(encoding="utf-8")) for d in (run, out))
        if old["hashes"]["base_stream_sha256"] != new["hashes"]["base_stream_sha256"]:
            return run.name, "SKIPPED: rebuilt base stream differs"
        if new["hashes"]["truth_sha256"] != truth_sha(out):
            return run.name, "SKIPPED: rebuilt truth does not match its manifest"
        new_files = set(files_of(out))
        for rel in sorted(new_files - {Path("manifest.json")}):
            _replace(out / rel, run / rel)
        for rel in set(files_of(run)) - new_files:            # a truth file the new build no longer writes
            (run / rel).unlink()
        _replace(out / "manifest.json", run / "manifest.json")   # last: the run is consistent again
        marker.write_text(json.dumps({"old_truth_sha256": old["hashes"]["truth_sha256"],
                                      "new_truth_sha256": new["hashes"]["truth_sha256"]}), encoding="utf-8")
        log.unlink()
        return run.name, "ok" if old["hashes"]["truth_sha256"] != new["hashes"]["truth_sha256"] else "ok (unchanged)"
    finally:
        shutil.rmtree(out, ignore_errors=True)


def run(a):
    root = Path(a.runs_dir)
    if not (root / "_gates" / "pre-retruth" / "SHA256SUMS").exists():
        sys.exit("no backup: run `backup` first")
    scratch, done_dir = Path(a.scratch).resolve(), root.resolve() / "_gates" / "retruth"
    scratch.mkdir(parents=True, exist_ok=True)
    done_dir.mkdir(parents=True, exist_ok=True)
    rs = runs(root)
    bad = []
    with ThreadPoolExecutor(a.workers) as ex:
        for n, (rid, st) in enumerate(ex.map(lambda r: run_one(r, scratch, done_dir), rs), 1):
            print(f"{n}/{len(rs)} {rid} {st}", flush=True)
            if not st.startswith("ok") and st != "cached":
                bad.append((rid, st))
    print(f"done: {len(rs) - len(bad)} of {len(rs)}; not replaced: {bad}")
    return 1 if bad else 0


def check(a):
    bad = []
    rs = runs(a.runs_dir)
    for r in rs:
        m = json.loads((r / "manifest.json").read_text(encoding="utf-8"))
        if m["hashes"]["truth_sha256"] != truth_sha(r):
            bad.append(r.name)
    print(f"check: {len(rs) - len(bad)} of {len(rs)} runs consistent; inconsistent: {bad}")
    return 1 if bad else 0


def _restore_from(backup, run, dirs):
    """Copy a run's backup back; remove files under dirs that it lacks (a
    file the rebuild added)."""
    kept = {p.relative_to(backup) for p in backup.rglob("*") if p.is_file() and p.name != "SHA256SUMS"}
    for rel in sorted(kept):
        _replace(backup / rel, run / rel)
    for d in dirs:
        for p in sorted((run / d).rglob("*")):
            if p.is_file() and p.relative_to(run) not in kept:
                p.unlink()


def restore(a):
    """Undo retruth_gt's replacements (base.pb, shipper/, restricted/,
    manifest.json from pre-retruth-gt) first, then this script's (restricted/
    and manifest.json from pre-retruth). Fails unless every restored run's
    base.pb and truth match its manifest again."""
    root = Path(a.runs_dir)
    src, src_gt = root / "_gates" / "pre-retruth", root / "_gates" / "pre-retruth-gt"
    names = a.run or sorted({p.name for d in (src, src_gt) if d.is_dir() for p in d.iterdir() if p.is_dir()})
    bad = []
    for name in names:
        run = root / name
        if (src_gt / name).is_dir():
            _restore_from(src_gt / name, run, ("shipper", "restricted"))
        if (src / name).is_dir():
            _restore_from(src / name, run, ("restricted",))
        (root / "_gates" / "retruth" / f"{name}.json").unlink(missing_ok=True)
        m = json.loads((run / "manifest.json").read_text(encoding="utf-8"))["hashes"]
        if m["truth_sha256"] != truth_sha(run) or m["base_stream_sha256"] != sha(run / "base.pb"):
            bad.append(name)
    print(f"restored {len(names)} runs; inconsistent with their manifest: {bad}")
    return 1 if bad else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("cmd", choices=("backup", "run", "check", "restore"))
    ap.add_argument("runs_dir")
    ap.add_argument("--zip")
    ap.add_argument("--scratch")
    ap.add_argument("--workers", type=int, default=1)
    ap.add_argument("--run", action="append")
    a = ap.parse_args(argv)
    if a.cmd == "run" and not a.scratch:
        ap.error("run needs --scratch")
    return {"backup": backup, "run": run, "check": check, "restore": restore}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
