"""KAIROS and the ORTHRUS context row from their own detections (B3), around
experiments/baselines/pidsmaker/mt_detected.py, which writes flagged.csv
(node_uuid, index_id, node_type, score) for the epoch chosen on validation loss.

    python -m mtcore.baselines.provenance.detected kairos --conv CONV --group pilot \\
        --data RUNS_DIR --flagged flagged.csv --out kairos-pilot.json
    python -m mtcore.baselines.provenance.detected kairos-nodes --conv CONV --group pilot \\
        --data RUNS_DIR --flagged flagged.csv --out kairos-nodes-pilot.json
    python -m mtcore.baselines.provenance.detected seeds --conv CONV --group pilot \\
        --flagged flagged.csv --out seeds.json
    (seeded_tracing.py, then seeded records and score_pilot.py, as for the seeded row)

kairos scores the flagged nodes with the B2 rule (provenance/score.py,
kairos_run and kairos_summary) over every run of the group.

seeds is the ORTHRUS context row's detection-to-reconstruction step, the
authors' rule (orthrus e7f25df, attack_reconstruction/tracing_methods/
depimpact.py): every flagged node is traced, and the attack graph of a time
window is the union of its traces. A run is one window here, so each run gets
one seed entry holding all its flagged nodes, and seeded records makes one graph
of it. Runs with no flagged node get an empty entry and so no graph.
"""
import argparse
import csv
import json
import os
from collections import Counter

from mtcore.baselines.provenance import score as PS
from mtcore.baselines.provenance import seeded as SD

SEED = "orthrus-detected"


def read_flagged(path):
    """[(node_uuid, index_id)] from mt_detected.py's flagged.csv."""
    with open(path, newline="", encoding="utf-8") as fh:
        return [(r["node_uuid"], r["index_id"]) for r in csv.DictReader(fh)]


def run_of_node(event_nodes):
    """{node_uuid: run_id} from load_event_map's output (node UUIDs carry their run)."""
    return {n: r for r, ev in event_nodes.items() for pair in ev.values() for n in pair if n}


def seeds_by_run(flagged, node_run, runs):
    """{run_id: {"date", "seeds"}} for seeded_tracing.py: one seed entry per run with flagged nodes."""
    out = {r: {"date": d, "seeds": {}} for r, d in runs.items()}
    for u, i in flagged:
        r = node_run.get(u)
        if r in out:
            out[r]["seeds"].setdefault(SEED, []).append(str(i))
    for v in out.values():
        for k in v["seeds"]:
            v["seeds"][k] = sorted(set(v["seeds"][k]), key=int)
    return out


def cmd_kairos(a):
    runs = SD.group_runs(a.conv, a.group)
    events = PS.load_event_map(os.path.join(a.conv, "event_map.csv"), set(runs))
    flagged = {u for u, _ in read_flagged(a.flagged)}
    node_run = run_of_node(events)
    total, per_run = Counter(), {}
    for r in sorted(runs):
        c = PS.kairos_run(os.path.join(a.data, r), events[r], flagged)
        per_run[r] = dict(c)
        total += c
    out = {"system": "kairos", "group": a.group, "runs": len(runs),
           "flagged_outside_group": len([u for u in flagged if u not in node_run]),
           **PS.kairos_summary(total), "per_run": per_run}
    with open(a.out, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"{a.group}: steps {out['steps']} nodes {out['nodes']}", flush=True)


def cmd_kairos_nodes(a):
    runs = SD.group_runs(a.conv, a.group)
    events = PS.load_event_map(os.path.join(a.conv, "event_map.csv"), set(runs))
    flagged = {u for u, _ in read_flagged(a.flagged)}
    per_run = {r: PS.kairos_nodes(os.path.join(a.data, r), events[r], flagged) for r in sorted(runs)}
    out = {"system": "kairos", "group": a.group, **PS.kairos_nodes_summary(per_run),
           "per_run": {r: v for r, v in per_run.items() if v}}
    with open(a.out, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"{a.group}: {out['nodes_covering_steps']} of {out['flagged_nodes']} flagged nodes cover "
          f"{out['steps_covered']} steps", flush=True)


def cmd_seeds(a):
    runs = SD.group_runs(a.conv, a.group)
    events = PS.load_event_map(os.path.join(a.conv, "event_map.csv"), set(runs))
    out = seeds_by_run(read_flagged(a.flagged), run_of_node(events), runs)
    with open(a.out, "w") as fh:
        json.dump(out, fh)
    n = sum(len(v["seeds"].get(SEED, [])) for v in out.values())
    print(f"{len(out)} runs, {sum(bool(v['seeds']) for v in out.values())} with flagged nodes, {n} seed nodes",
          flush=True)


def main(argv=None):
    ap = argparse.ArgumentParser(description="KAIROS and the ORTHRUS context row from their own detections.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("kairos", "kairos-nodes", "seeds"):
        p = sub.add_parser(name)
        p.add_argument("--conv", required=True)
        p.add_argument("--group", required=True)
        p.add_argument("--flagged", required=True)
        p.add_argument("--out", required=True)
    for name in ("kairos", "kairos-nodes"):
        sub.choices[name].add_argument("--data", required=True,
                                       help="directory holding <run>/restricted/ (the group's truth)")
    a = ap.parse_args(argv)
    {"kairos": cmd_kairos, "kairos-nodes": cmd_kairos_nodes, "seeds": cmd_seeds}[a.cmd](a)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
