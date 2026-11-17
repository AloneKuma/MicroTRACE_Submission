"""Regenerate the truth of runs that retruth_pilot.py skipped because their
rebuilt base stream differs, when the only stream difference is the
ground-truth action records' expected findings.

The 2026-10-25 truth change (a stateless finding's evidence is its own step)
turns a PRESENT whose own evidence a degraded profile dropped into
UNOBSERVABLE. GroundTruthAction.expected_finding_types lists a step's PRESENT
findings and is shipped in the stream (topic ground.truth.v0), so those runs'
base.pb and one shipper file change too. No agent reads that topic, so the
agents' findings on the run are unchanged.

    python src/scripts/pilot/retruth_gt.py check RUNS_DIR --scratch DIR [--run RUN_ID ...]
    python src/scripts/pilot/retruth_gt.py apply RUNS_DIR --scratch DIR [--run RUN_ID ...]

Runs: those given, else those retruth.log lists as "SKIPPED: rebuilt base
stream differs". check: rebuild each into the scratch directory and compare:
the same files; base.pb envelope by envelope, where a differing pair must be
two ground-truth action records with one logical ID that are equal apart from
expected_finding_types; shipper files line by line, a differing line on topic
ground.truth.v0 only; manifest.json equal apart from its hashes (output,
code, spec files, catalogue and build date, as for any rebuild). apply: the
same check, then copy the run's base.pb, shipper/, restricted/ and
manifest.json to RUNS_DIR/_gates/pre-retruth-gt/<run_id>/ (with SHA256SUMS),
replace them (manifest last) and write the run's retruth marker.
"""
import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "src" / "python"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import mtgen  # noqa: E402,F401  (puts the generated protos on the path)
from mtgen.verify import _load_base_stream  # noqa: E402
from microtrace.v0 import envelope_pb2  # noqa: E402

import retruth_pilot as RP  # noqa: E402

GT = envelope_pb2.RecordKind.Value("GROUND_TRUTH_ACTION")
SKIP = re.compile(r"^\d+/\d+ (\S+) SKIPPED: rebuilt base stream differs$")


def skipped(root):
    log = root / "_gates" / "retruth.log"
    return sorted({m.group(1) for ln in log.read_text(encoding="utf-8").splitlines()
                   if (m := SKIP.match(ln))})


def _gt_only(x, y):
    if x.kind != GT or y.kind != GT or x.logical_id != y.logical_id:
        return False
    x2, y2 = envelope_pb2.Envelope(), envelope_pb2.Envelope()
    x2.CopyFrom(x)
    y2.CopyFrom(y)
    del x2.ground_truth_action.expected_finding_types[:]
    del y2.ground_truth_action.expected_finding_types[:]
    return x2.SerializeToString() == y2.SerializeToString()


def _eol_only(a, b):
    """The two files are equal apart from CRLF versus LF line endings (a run
    built on Windows, rebuilt on Linux)."""
    return a.read_bytes().replace(b"\r\n", b"\n") == b.read_bytes().replace(b"\r\n", b"\n")


def compare(run, out):
    """Problems that stop the replacement ([] when only GT records differ),
    and the count of differing ground-truth records."""
    problems, n_gt = [], 0
    fa = {p.relative_to(run) for p in run.rglob("*") if p.is_file()}
    fb = {p.relative_to(out) for p in out.rglob("*") if p.is_file()}
    if fa != fb:
        problems.append(f"file sets differ: {sorted(map(str, fa ^ fb))[:5]}")
    for rel in sorted(fa & fb):
        if RP.sha(run / rel) == RP.sha(out / rel) or _eol_only(run / rel, out / rel):
            continue
        top = rel.parts[0]
        if rel == Path("base.pb"):
            a, _ = _load_base_stream(run)
            b, _ = _load_base_stream(out)
            if len(a) != len(b):
                problems.append(f"base.pb: {len(a)} vs {len(b)} envelopes")
                continue
            for x, y in zip(a, b):
                if x.SerializeToString() != y.SerializeToString():
                    if _gt_only(x, y):
                        n_gt += 1
                    else:
                        problems.append(f"base.pb: envelope {x.logical_id} differs beyond expected findings")
                        break
        elif top == "shipper":
            la = (run / rel).read_text(encoding="utf-8").splitlines()
            lb = (out / rel).read_text(encoding="utf-8").splitlines()
            if len(la) != len(lb) or any(
                    x != y and not (json.loads(x).get("topic") == json.loads(y).get("topic") == "ground.truth.v0")
                    for x, y in zip(la, lb)):
                problems.append(f"{rel.as_posix()}: differs beyond ground.truth.v0 lines")
        elif rel == Path("manifest.json"):
            ma, mb = (json.loads((d / rel).read_text(encoding="utf-8")) for d in (run, out))
            # What every rebuild records anew, as retruth_pilot.py replaced it in
            # 168 manifests: output, code and spec hashes, the catalogue hash of
            # runs built before a catalogue edit that left them unchanged, and
            # the build date (b06e722: no longer 1970), and artifact_versions
            # (the artifact spec files' hashes), and truth_statistics (counts of
            # the truth a re-truth changes, e.g. links added to the catalogue).
            for m in (ma, mb):
                for k in ("hashes", "code_sha256", "spec_file_sha256", "scenario_catalogue_version",
                          "generated_at", "artifact_versions", "truth_statistics"):
                    m.pop(k, None)
                # catalogue overlays (pilot-cases): which overlays, not their hashes
                if "catalogue_overlays" in m:
                    m["catalogue_overlays"] = sorted(m["catalogue_overlays"])
            if ma != mb:
                problems.append("manifest.json differs beyond its hashes")
        elif top != "restricted":
            problems.append(f"{rel.as_posix()} differs")
    if not n_gt and not problems:
        problems.append("no ground-truth record differs (not a skipped run?)")
    return problems, n_gt


def _backup(run, dst):
    rels = [Path("base.pb"), Path("manifest.json")]
    rels += sorted(p.relative_to(run) for d in ("shipper", "restricted")
                   for p in (run / d).rglob("*") if p.is_file())
    lines = []
    for rel in rels:
        (dst / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(run / rel, dst / rel)
        lines.append(f"{RP.sha(run / rel)}  {rel.as_posix()}")
    (dst / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
    bad = [ln for ln in lines if RP.sha(dst / ln.split("  ", 1)[1]) != ln.split("  ", 1)[0]]
    if bad:
        raise SystemExit(f"{run.name}: backup mismatch {bad[:3]}")
    return rels


def one(run, scratch, root, apply):
    out = scratch / run.name
    shutil.rmtree(out, ignore_errors=True)
    try:
        r = subprocess.run([sys.executable, "-m", "mtgen", "from-manifest", str(run), "--out", str(out),
                            "--allow-spec-change"],      # re-truth rebuilds with the current catalogue
                           cwd=REPO / "src" / "python", capture_output=True, text=True)
        if r.returncode:
            return f"FAILED build (exit {r.returncode}): {r.stderr[-300:]}"
        new = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
        if new["hashes"]["truth_sha256"] != RP.truth_sha(out):
            return "NOT REPLACED: rebuilt truth does not match its manifest"
        problems, n_gt = compare(run, out)
        if problems:
            return "NOT REPLACED: " + "; ".join(problems)
        if not apply:
            return f"replaceable ({n_gt} ground-truth records differ)"
        dst = root / "_gates" / "pre-retruth-gt" / run.name
        if (dst / "SHA256SUMS").exists():
            return f"NOT REPLACED: {dst} already holds a backup"
        old = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
        rels = _backup(run, dst)
        new_rels = sorted(p.relative_to(out) for p in out.rglob("*") if p.is_file())
        for rel in new_rels:
            # a file equal apart from its line endings stays as it was
            if rel != Path("manifest.json") and not ((run / rel).exists() and _eol_only(run / rel, out / rel)):
                RP._replace(out / rel, run / rel)
        for rel in set(rels) - set(new_rels):
            (run / rel).unlink()
        RP._replace(out / "manifest.json", run / "manifest.json")   # last
        (root / "_gates" / "retruth" / f"{run.name}.json").write_text(json.dumps({
            "old_truth_sha256": old["hashes"]["truth_sha256"],
            "new_truth_sha256": new["hashes"]["truth_sha256"],
            "old_base_stream_sha256": old["hashes"]["base_stream_sha256"],
            "new_base_stream_sha256": new["hashes"]["base_stream_sha256"],
            "ground_truth_records_changed": n_gt}), encoding="utf-8")
        return f"ok ({n_gt} ground-truth records changed)"
    finally:
        shutil.rmtree(out, ignore_errors=True)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("cmd", choices=("check", "apply"))
    ap.add_argument("runs_dir")
    ap.add_argument("--scratch", required=True)
    ap.add_argument("--run", action="append")
    a = ap.parse_args(argv)
    root = Path(a.runs_dir).resolve()
    scratch = Path(a.scratch).resolve()
    scratch.mkdir(parents=True, exist_ok=True)
    names = a.run or skipped(root)
    bad = []
    for n, name in enumerate(names, 1):
        st = one(root / name, scratch, root, a.cmd == "apply")
        print(f"{n}/{len(names)} {name} {st}", flush=True)
        if not (st.startswith("ok") or st.startswith("replaceable")):
            bad.append(name)
    print(f"{a.cmd}: {len(names) - len(bad)} of {len(names)}; not replaceable: {bad}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
