"""Twin safety check (link-twin-decoys-plan.md, phase D).

A twin or decoy step must not create an unlabelled finding opportunity: no
rule may fire on a scenario step unless an opportunity of that finding type
covers the event. For each run directory, this runs the step-9 offline
pipeline (mtcore.harness.offline: agents, then GO) and reports every finding
whose input events include a scenario action's events but match no
FindingOpportunity of the finding's type (any expected state). Findings on
background events only are not this check's concern (the findings nuisance
and the PILOT score report them).

With --catalogue, a finding also counts as declared when the catalogue as it
is now gives one of its scenario steps an expects entry of the finding's type.
This checks a catalogue edit against outputs already computed, before the
runs are rebuilt with the new labels (twin-safety-labels-plan.md step 2).

    python src/scripts/pilot/twin_safety.py RUN_DIR [RUN_DIR ...] \\
        --params PILOT_PARAMS.yaml [--out-dir OUT] [--no-ml] [--catalogue CATALOGUE.yaml]

Exit status 1 when any run has such a finding.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[3]
PY = REPO / "src" / "python"
sys.path.insert(0, str(PY))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import cached_output  # noqa: E402
from mtcore.harness.score import FINDINGS, Output, Truth  # noqa: E402


def load_findings(jsonl: Path) -> list:
    """The findings of an offline output. Only finding lines are parsed: the
    file is almost all rule evaluations (one run: 4 findings in 493,481 lines),
    and parsing every line took minutes per run."""
    tag = f'"{FINDINGS}"'
    with cached_output.open_text(jsonl) as fh:
        return list(Output.parse(line for line in fh if tag in line).findings.values())


def declared_findings(catalogue: dict) -> dict:
    """(scenario id, step label) -> finding types the catalogue declares on it."""
    return {(sc["id"], str(st["step"])): {e["finding"] for e in st.get("expects") or []}
            for sc in catalogue["scenarios"] for st in sc["steps"]}


def unlabelled(actions, opportunities, findings, run: str, declared: dict = None) -> list:
    """Findings on a scenario step that no opportunity of their type covers."""
    ev_action = {ev: a for a in actions for ev in a.rendered_event_ids}
    covered = {(o.finding_type, ev) for o in opportunities for ev in o.evidence_event_ids}
    bad = []
    for f in findings:
        acts = {ev_action[ev].action_seq: ev_action[ev] for ev in f.input_event_ids if ev in ev_action}
        if not acts or any((f.finding_type, ev) in covered for ev in f.input_event_ids):
            continue
        if declared is not None and any(
                f.finding_type in declared.get((a.scenario_id, a.step_label), ())
                for a in acts.values()):
            continue
        bad.append({"run": run, "finding": f.finding_type, "finding_id": f.finding_id,
                    "steps": sorted(f"{a.scenario_id}/{a.step_label}" + ("" if a.is_attack else " (benign)")
                                    for a in acts.values())})
    return bad


def check_run(run_dir: Path, out_dir: Path, params: str, no_ml: bool,
              declared: dict = None) -> list:
    out_dir.mkdir(parents=True, exist_ok=True)
    jsonl = cached_output.find(out_dir, run_dir.name) or out_dir / f"{run_dir.name}.output.jsonl"
    if not jsonl.exists():
        cmd = [sys.executable, "-m", "mtcore.harness.offline", str(run_dir.resolve()),
               "--out", str(jsonl.resolve()), "--params", params, "--orch-params", params]
        cmd += ["--no-ml"] if no_ml else []
        with open(out_dir / f"{run_dir.name}.offline.log", "w") as log:
            r = subprocess.run(cmd, cwd=PY, stdout=log, stderr=subprocess.STDOUT)
        if r.returncode != 0:
            raise SystemExit(f"{run_dir}: offline pipeline failed (exit {r.returncode})")
    truth = Truth.load(str(run_dir / "restricted"))
    return unlabelled(truth.actions, truth.opportunities, load_findings(jsonl),
                      run_dir.name, declared)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("run_dirs", nargs="+", type=Path)
    ap.add_argument("--params", required=True, help="fitted PILOT parameter set")
    ap.add_argument("--out-dir", type=Path, default=Path("twin_safety"))
    ap.add_argument("--no-ml", action="store_true")
    ap.add_argument("--catalogue", type=Path,
                    help="also count findings the catalogue now declares on their steps")
    ap.add_argument("--json", type=Path,
                    help="report path (default OUT/twin_safety.json)")
    args = ap.parse_args(argv)
    params = str(Path(args.params).resolve())
    declared = (declared_findings(yaml.safe_load(args.catalogue.read_text(encoding="utf-8")))
                if args.catalogue else None)
    bad = []
    for run_dir in args.run_dirs:
        found = check_run(run_dir, args.out_dir, params, args.no_ml, declared)
        print(f"{run_dir.name}: {len(found)} finding(s) on scenario steps without an opportunity",
              flush=True)
        bad += found
    for b in bad:
        print(f"  {b['run'][:8]} {b['finding']} {b['finding_id']}: {', '.join(b['steps'])}")
    (args.json or args.out_dir / "twin_safety.json").write_text(json.dumps(bad, indent=2), encoding="utf-8")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
