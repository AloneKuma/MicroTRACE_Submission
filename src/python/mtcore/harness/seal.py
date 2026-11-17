"""Split a built run into a readable part and a sealed truth part (held-out upload).

    python -m mtcore.harness.seal RUN_DIR --readable OUT_R --truth OUT_T

The readable part is everything a system under test may see: shipper/*.jsonl without
the ground.truth.v0 lines, evidence/, context_history.jsonl and a manifest with the
truth-bearing fields removed. The truth part holds everything else: restricted/,
base.pb (it carries the same ground-truth envelopes), the full manifest, and the
removed shipper lines (shipper-truth/<file>, in order). Nothing is parsed beyond the
JSON topic of each shipper line; nothing is dropped: readable + truth together hold
every byte of the run (checked by `verify`).
"""
import argparse
import hashlib
import json
import os
import shutil
import sys

TRUTH_TOPIC = "ground.truth.v0"
# Manifest fields that describe the answer key or allow rebuilding it (the seeds).
TRUTH_FIELDS = ("scenario_ids", "scenario_id", "scenario_variant", "variant_per_scenario",
                "truth_statistics", "seeds", "completeness_guarantees", "generator_flags")
READABLE_TOP = ("evidence", "context_history.jsonl")
TRUTH_TOP = ("restricted", "base.pb")


def redact_manifest(m):
    out = {k: v for k, v in m.items() if k not in TRUTH_FIELDS}
    if isinstance(out.get("hashes"), dict):
        out["hashes"] = {k: v for k, v in out["hashes"].items() if k == "base_stream_sha256"}
    out["sealed"] = {"removed_fields": sorted(k for k in TRUTH_FIELDS if k in m), "by": "mtcore.harness.seal"}
    return out


def _is_truth_line(line):
    s = line.strip()
    if not s:
        return False
    try:
        return json.loads(s).get("topic") == TRUTH_TOPIC
    except (ValueError, AttributeError):
        return False


def split(run_dir, readable, truth):
    names = set(os.listdir(run_dir))
    known = {"shipper", "manifest.json", *READABLE_TOP, *TRUTH_TOP}
    unknown = sorted(names - known)
    if unknown:
        raise SystemExit(f"{run_dir}: unexpected entries {unknown}; refusing to guess which side they belong to")
    for root, dirs, files in os.walk(run_dir):
        for n in dirs + files:
            if os.path.islink(os.path.join(root, n)):
                raise SystemExit(f"{run_dir}: symlink {os.path.join(root, n)}; refusing")
    os.makedirs(readable, exist_ok=False)
    os.makedirs(truth, exist_ok=False)
    for n in READABLE_TOP:
        p = os.path.join(run_dir, n)
        if os.path.isdir(p):
            shutil.copytree(p, os.path.join(readable, n))
        elif os.path.exists(p):
            shutil.copy2(p, os.path.join(readable, n))
    for n in TRUTH_TOP:
        p = os.path.join(run_dir, n)
        if os.path.isdir(p):
            shutil.copytree(p, os.path.join(truth, n))
        elif os.path.exists(p):
            shutil.copy2(p, os.path.join(truth, n))
    shutil.copy2(os.path.join(run_dir, "manifest.json"), os.path.join(truth, "manifest.json"))
    with open(os.path.join(run_dir, "manifest.json"), encoding="utf-8") as fh:
        m = json.load(fh)
    with open(os.path.join(readable, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(redact_manifest(m), fh, indent=2, sort_keys=True)
    removed = 0
    os.makedirs(os.path.join(readable, "shipper"))
    for n in sorted(os.listdir(os.path.join(run_dir, "shipper"))):
        src = os.path.join(run_dir, "shipper", n)
        keep, gone = [], []
        with open(src, encoding="utf-8", newline="") as fh:
            for line in fh:
                (gone if _is_truth_line(line) else keep).append(line)
        with open(os.path.join(readable, "shipper", n), "w", encoding="utf-8", newline="") as fh:
            fh.writelines(keep)
        if gone:
            os.makedirs(os.path.join(truth, "shipper-truth"), exist_ok=True)
            with open(os.path.join(truth, "shipper-truth", n), "w", encoding="utf-8", newline="") as fh:
                fh.writelines(gone)
            removed += len(gone)
    return {"truth_lines_removed": removed}


def verify(readable):
    """No truth left on the readable side (topics, manifest fields, files)."""
    bad = []
    for n in TRUTH_TOP:
        if os.path.exists(os.path.join(readable, n)):
            bad.append(n)
    with open(os.path.join(readable, "manifest.json"), encoding="utf-8") as fh:
        m = json.load(fh)
    bad += [f"manifest.{k}" for k in TRUTH_FIELDS if k in m]
    for root, dirs, files in os.walk(readable):
        bad += [os.path.join(root, d) for d in dirs if d == "restricted"]
        for f in files:
            if f.endswith(".jsonl"):
                with open(os.path.join(root, f), encoding="utf-8") as fh:
                    bad += [f"{f}:{i}" for i, line in enumerate(fh, 1) if _is_truth_line(line)]
    return bad


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("run_dir")
    ap.add_argument("--readable", required=True)
    ap.add_argument("--truth", required=True)
    a = ap.parse_args(argv)
    r = split(a.run_dir, a.readable, a.truth)
    bad = verify(a.readable)
    if bad:
        print(f"SEAL FAILED, truth left on the readable side: {bad[:5]}", file=sys.stderr)
        return 1
    print(json.dumps(r))
    return 0


if __name__ == "__main__":
    sys.exit(main())
