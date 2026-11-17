"""The seeded ORTHRUS row of Exp. 2, around experiments/baselines/pidsmaker/seeded_tracing.py.

    python -m mtcore.baselines.provenance.seeded seeds --conv CONV --group pilot \\
        --findings-from DIR --out seeds.json
    (seeded_tracing.py, in the PIDSMaker container: seeds.json -> traced.json)
    python -m mtcore.baselines.provenance.seeded records --conv CONV --group pilot \\
        --findings-from DIR --traced traced.json --out-dir OUT [--k 2]

CONV is a convert.py output. seeds.json holds, per run of the group, its date
and each finding's evidence nodes as graph node IDs (index_id); a finding with
no eBPF event has none and is no seed. traced.json holds the traced node IDs per
seed finding. "records" turns them into one graph per seed finding (the rule in
provenance/score.py) and writes OUT/sage/ag/<run_id>.jsonl and OUT/sage/run.json,
so score_pilot.py --correlator sage --sage-variant ag --out-dir OUT scores
ORTHRUS through the same path as SAGE.
"""
import argparse
import csv
import glob
import json
import os

from mtcore.baselines.provenance import score as PS
from mtcore.baselines.sage import run as R

NODE_TABLES = ("subject_node_table.csv", "file_node_table.csv", "netflow_node_table.csv")


def node_index(conv):
    """{node_uuid: index_id} from the node tables (uuid first, index_id last)."""
    out = {}
    for t in NODE_TABLES:
        with open(os.path.join(conv, t), newline="", encoding="utf-8") as fh:
            for row in csv.reader(fh):
                out[row[0]] = row[-1]
    return out


def group_runs(conv, group):
    """{run_id: date} of a convert.py test group."""
    with open(os.path.join(conv, "manifest.json")) as fh:
        return {r["run_id"]: r["date"] for r in json.load(fh)["runs"] if r["group"] == group}


def findings_path(root, run_id):
    """A run's cached output in score_pilot.py's or twin_safety's layout."""
    hits = (glob.glob(os.path.join(root, "runs", run_id, "output.jsonl*")) +
            glob.glob(os.path.join(root, run_id + ".output.jsonl*")))
    if not hits:
        raise SystemExit(f"no cached findings for run {run_id} under {root}")
    return sorted(hits)[0]


def seeds_of(findings, event_nodes, index):
    """{finding_id: sorted node IDs} of the findings whose events touch a node of the graph tables."""
    out = {}
    for fid, f in findings.items():
        ids = sorted({index[n] for n in PS.nodes_of(f.input_event_ids, event_nodes) if n in index})
        if ids:
            out[fid] = ids
    return out


def graphs_of(traced, index):
    """Traced node IDs per seed finding -> one set of node UUIDs per seed finding."""
    uuid_of = {v: k for k, v in index.items()}
    return [{uuid_of[n] for n in traced[fid]} for fid in sorted(traced)]


def cmd_seeds(a):
    runs = group_runs(a.conv, a.group)
    events = PS.load_event_map(os.path.join(a.conv, "event_map.csv"), set(runs))
    index = node_index(a.conv)
    out = {}
    for r, date in sorted(runs.items()):
        _lines, findings = R.read_findings(findings_path(a.findings_from, r))
        out[r] = {"date": date, "seeds": seeds_of(findings, events[r], index)}
    with open(a.out, "w") as fh:
        json.dump(out, fh)
    print(f"{len(out)} runs, {sum(len(v['seeds']) for v in out.values())} seed findings", flush=True)


def cmd_records(a):
    runs = group_runs(a.conv, a.group)
    events = PS.load_event_map(os.path.join(a.conv, "event_map.csv"), set(runs))
    index = node_index(a.conv)
    with open(a.traced) as fh:
        traced = json.load(fh)
    out = os.path.join(a.out_dir, "sage")
    for r in sorted(runs):
        lines, findings = R.read_findings(findings_path(a.findings_from, r))
        recs = PS.orthrus_records(r, graphs_of(traced[r]["traced"], index), findings, events[r], a.k)
        PS.write_records(os.path.join(out, "ag", r + ".jsonl"), lines, recs)
    with open(os.path.join(out, "run.json"), "w") as fh:
        json.dump({"system": "orthrus-seeded", "k": a.k, "runs": len(runs)}, fh)
    print(f"{len(runs)} runs written to {out}", flush=True)


def main(argv=None):
    ap = argparse.ArgumentParser(description="The seeded ORTHRUS row of Exp. 2.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("seeds", "records"):
        p = sub.add_parser(name)
        p.add_argument("--conv", required=True)
        p.add_argument("--group", required=True)
        p.add_argument("--findings-from", required=True)
    sub.choices["seeds"].add_argument("--out", required=True)
    sub.choices["records"].add_argument("--traced", required=True)
    sub.choices["records"].add_argument("--out-dir", required=True)
    sub.choices["records"].add_argument("--k", type=int, default=2, help="the GO's K, as SAGE's k")
    a = ap.parse_args(argv)
    (cmd_seeds if a.cmd == "seeds" else cmd_records)(a)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
