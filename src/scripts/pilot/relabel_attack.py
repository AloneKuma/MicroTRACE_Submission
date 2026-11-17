"""Set is_attack in a built dataset's truth by the generator's current rule
(decision T-1, 2026-11-02: a degraded scenario is an attack with lost evidence),
without rebuilding the runs. Only truth_actions.pb, truth_incidents.pb and the
manifest's truth_sha256 change; streams and every other truth field are kept.

    python src/scripts/pilot/relabel_attack.py backup  RUNS_DIR
    python src/scripts/pilot/relabel_attack.py apply   RUNS_DIR
    python src/scripts/pilot/relabel_attack.py diff    RUNS_DIR
    python src/scripts/pilot/relabel_attack.py sample  RUNS_DIR [--gt-log RETRUTH_LOG]
    python src/scripts/pilot/relabel_attack.py compare RUNS_DIR --scratch DIR RUN_ID ...

backup: copy each run's manifest.json, truth_actions.pb and truth_incidents.pb to
RUNS_DIR/_gates/pre-relabel/<run_id>/ with SHA256SUMS, and check the copy.

apply: per run, an action is an attack if scenarios.is_attack_scenario holds for
its scenario (the catalogue and overlays named in the run's manifest) and its
catalogue step is not benign; an incident is an attack if its scenario is and it
holds a non-benign step (truth.py _build_incidents). Stops on any change other
than false -> true. Files are written to a temporary name and renamed; the
manifest last.

diff: every run against its backup: the protos differ only in is_attack, the
manifest only in truth_sha256, and the manifest matches the truth files.

sample: runs to rebuild as a check: the first run of each attack scenario whose
labels changed, two runs retruth_gt replaced (base stream differs), two runs
with no change.

compare: rebuild each run with `mtgen from-manifest` (as retruth_pilot run) into
--scratch and require byte-equal truth_actions.pb and truth_incidents.pb, and,
when the rebuilt base stream equals the run's, byte-equal truth findings and links.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "src" / "python"))

import mtgen  # noqa: E402,F401  (registers gen/ on sys.path)
from microtrace.v0 import dataset_pb2  # noqa: E402
from mtgen import specs  # noqa: E402
from mtgen.scenarios import is_attack_scenario  # noqa: E402
from mtgen.truth import read_ld_protos, write_ld_protos  # noqa: E402

TRUTH = ("truth_actions.pb", "truth_findings.pb", "truth_links.pb")   # emit.compute_truth_sha256
FILES = (Path("manifest.json"), Path("restricted/truth_actions.pb"), Path("restricted/truth_incidents.pb"))


def runs(d):
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


def manifest_text(m):
    return json.dumps(m, indent=2, sort_keys=True)                      # emit.write_manifest


_catalogues = {}


def catalogue(manifest):
    overlays = tuple(manifest.get("catalogue_overlays", {}))
    if overlays not in _catalogues:
        cat = specs.load_scenario_catalogue(list(overlays))
        _catalogues[overlays] = {s["id"]: s for s in cat["scenarios"]}
    return _catalogues[overlays]


def benign(scenario, label):
    step = next((s for s in scenario.get("steps", []) if str(s.get("step")) == str(label)), None)
    if step is None:
        raise ValueError(f"{scenario['id']}: no step {label!r}")
    return bool(step.get("benign"))


def relabel(run):
    """(new actions, new incidents, flips) for one run; flips lists (kind, scenario, label/id)."""
    m = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    cat = catalogue(m)
    r = run / "restricted"
    acts = read_ld_protos(r / "truth_actions.pb", dataset_pb2.GroundTruthAction)
    incs = read_ld_protos(r / "truth_incidents.pb", dataset_pb2.GroundTruthIncident) \
        if (r / "truth_incidents.pb").exists() else []
    flips = []
    step_benign = {}
    for a in acts:
        sc = cat[a.scenario_id]
        step_benign[a.action_seq] = benign(sc, a.step_label)
        new = is_attack_scenario(sc) and not step_benign[a.action_seq]
        if new != a.is_attack:
            flips.append(("action", a.scenario_id, a.step_label, a.is_attack, new))
            a.is_attack = new
    for i in incs:
        sc = cat[i.scenario_id]
        new = is_attack_scenario(sc) and any(not step_benign[s] for s in i.action_seqs)
        if new != i.is_attack:
            flips.append(("incident", i.scenario_id, i.incident_id, i.is_attack, new))
            i.is_attack = new
    return m, acts, incs, flips


def _write(path, data):
    tmp = path.with_name(path.name + ".relabel-tmp")
    if isinstance(data, str):
        tmp.write_text(data, encoding="utf-8", newline="\n")
    else:
        write_ld_protos(tmp, data)
    os.replace(tmp, path)


def backup(a):
    root = Path(a.runs_dir)
    dst = root / "_gates" / "pre-relabel"
    if (dst / "SHA256SUMS").exists():
        sys.exit(f"{dst} already holds a backup; not overwriting it")
    lines = []
    rs = runs(root)
    for run in rs:
        for rel in FILES:
            if (run / rel).exists():
                out = dst / run.name / rel
                out.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(run / rel, out)
                lines.append(f"{sha(run / rel)}  {run.name}/{rel.as_posix()}")
    (dst / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
    bad = [ln for ln in lines if sha(dst / ln.split("  ", 1)[1]) != ln.split("  ", 1)[0]]
    print(f"backup: {len(lines)} files of {len(rs)} runs -> {dst}; mismatches: {len(bad)}")
    return 1 if bad else 0


def apply(a):
    root = Path(a.runs_dir)
    if not (root / "_gates" / "pre-relabel" / "SHA256SUMS").exists():
        sys.exit("no backup: run `backup` first")
    rs = runs(root)
    plans, bad = [], []
    for run in rs:                                   # check every run before writing any
        m, acts, incs, flips = relabel(run)
        if manifest_text(m) != (run / "manifest.json").read_text(encoding="utf-8"):
            bad.append((run.name, "manifest does not round-trip"))
        if m["hashes"]["truth_sha256"] != truth_sha(run):
            bad.append((run.name, "manifest truth_sha256 does not match the truth files"))
        for f in flips:
            if f[3] or not f[4]:
                bad.append((run.name, f"not a false -> true change: {f}"))
        plans.append((run, m, acts, incs, flips))
    if bad:
        print(f"STOP, nothing written: {bad[:20]}")
        return 1
    n_act = n_inc = n_runs = 0
    by_scenario = {}
    for run, m, acts, incs, flips in plans:
        if not flips:
            continue
        r = run / "restricted"
        _write(r / "truth_actions.pb", acts)
        if incs:
            _write(r / "truth_incidents.pb", incs)
        m["hashes"]["truth_sha256"] = truth_sha(run)
        _write(run / "manifest.json", manifest_text(m))
        n_runs += 1
        for f in flips:
            n_act += f[0] == "action"
            n_inc += f[0] == "incident"
            by_scenario[f[1]] = by_scenario.get(f[1], 0) + (f[0] == "action")
    print(f"apply: {n_runs} of {len(rs)} runs changed; actions {n_act}, incidents {n_inc} set to attack; "
          f"actions by scenario: {dict(sorted(by_scenario.items()))}")
    return 0


def _strip(msgs):
    out = []
    for x in msgs:
        y = type(x)()
        y.CopyFrom(x)
        y.is_attack = False
        out.append(y.SerializeToString(deterministic=True))
    return out


def diff(a):
    root = Path(a.runs_dir)
    bk = root / "_gates" / "pre-relabel"
    bad, changed = [], 0
    rs = runs(root)
    for run in rs:
        old_m = json.loads((bk / run.name / "manifest.json").read_text(encoding="utf-8"))
        new_m = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
        old_t, new_t = old_m["hashes"].pop("truth_sha256"), new_m["hashes"].pop("truth_sha256")
        if old_m != new_m:
            bad.append((run.name, "manifest differs beyond truth_sha256"))
        if new_t != truth_sha(run):
            bad.append((run.name, "manifest truth_sha256 does not match the truth files"))
        for rel, cls in ((FILES[1], dataset_pb2.GroundTruthAction), (FILES[2], dataset_pb2.GroundTruthIncident)):
            if not (bk / run.name / rel).exists():
                continue
            o, n = read_ld_protos(bk / run.name / rel, cls), read_ld_protos(run / rel, cls)
            if _strip(o) != _strip(n):
                bad.append((run.name, f"{rel.name} differs beyond is_attack"))
        changed += old_t != new_t
    print(f"diff: {len(rs)} runs, {changed} with new truth; problems: {bad[:20]}")
    return 1 if bad else 0


def sample(a):
    root = Path(a.runs_dir)
    bk = root / "_gates" / "pre-relabel"
    first, plain = {}, []
    for run in runs(root):
        o = read_ld_protos(bk / run.name / FILES[1], dataset_pb2.GroundTruthAction)
        n = read_ld_protos(run / FILES[1], dataset_pb2.GroundTruthAction)
        flipped = {x.scenario_id for x, y in zip(o, n) if x.is_attack != y.is_attack}
        for s in sorted(flipped):
            first.setdefault(s, run.name)
        if not flipped and len(plain) < 2:
            plain.append(run.name)
    gt = []
    if a.gt_log and Path(a.gt_log).exists():
        for line in Path(a.gt_log).read_text(encoding="utf-8").splitlines():
            if "SKIPPED: rebuilt base stream differs" in line and len(gt) < 2:
                gt.append(line.split()[1])
    picked = sorted(set(first.values()) | set(gt) | set(plain))
    print(" ".join(picked))
    print(f"# {len(first)} scenarios {first}; gt {gt}; unchanged {plain}", file=sys.stderr)
    return 0


def compare(a):
    root, scratch = Path(a.runs_dir).resolve(), Path(a.scratch).resolve()
    scratch.mkdir(parents=True, exist_ok=True)
    bad = []
    for rid in a.run_ids:
        run, out = root / rid, scratch / rid
        shutil.rmtree(out, ignore_errors=True)
        r = subprocess.run([sys.executable, "-m", "mtgen", "from-manifest", str(run), "--out", str(out),
                            "--allow-spec-change"], cwd=REPO / "src" / "python",
                           stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        try:
            if r.returncode:
                bad.append((rid, f"build exit {r.returncode}"))
                continue
            same_stream = (json.loads((run / "manifest.json").read_text(encoding="utf-8"))["hashes"]["base_stream_sha256"]
                           == json.loads((out / "manifest.json").read_text(encoding="utf-8"))["hashes"]["base_stream_sha256"])
            names = ["truth_actions.pb", "truth_incidents.pb"] + (["truth_findings.pb", "truth_links.pb"] if same_stream else [])
            diffs = [f for f in names if sha(run / "restricted" / f) != sha(out / "restricted" / f)]
            print(f"{rid} stream {'same' if same_stream else 'differs (GT run)'}; compared {len(names)} files; "
                  f"different: {diffs}", flush=True)
            if diffs:
                bad.append((rid, diffs))
        finally:
            shutil.rmtree(out, ignore_errors=True)
    print(f"compare: {len(a.run_ids) - len(bad)} of {len(a.run_ids)} equal; problems: {bad}")
    return 1 if bad else 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("backup", "apply", "diff", "sample", "compare"):
        s = sub.add_parser(name)
        s.add_argument("runs_dir")
        if name == "sample":
            s.add_argument("--gt-log")
        if name == "compare":
            s.add_argument("--scratch", required=True)
            s.add_argument("run_ids", nargs="+")
    a = p.parse_args(argv)
    return {"backup": backup, "apply": apply, "diff": diff, "sample": sample, "compare": compare}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
