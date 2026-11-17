"""KAIROS and ORTHRUS outputs -> our metrics (docs/plans/kairos-orthrus-our-data-plan.md, B2).

Both tools report nodes of the graphs convert.py writes; convert.py's
event_map.csv ties every eBPF event (edge or not) to its process node and its
object node, so their output is scored by the nodes of our events. The rules
were fixed on 2026-11-01, before any run on our data:

KAIROS (Exp. 1), at its own unit, the node:
- A step is a PRESENT finding opportunity of a host type (convert.HOST_TYPES)
  in a test run. It is detected if KAIROS flags a node of one of the step's
  own evidence events. Recall = detected steps / steps, per type and overall.
- Node precision: a flagged node is a true positive if an event rendered for
  an attack step (truth_actions, is_attack) touches it, else a false positive.
  Benign lookalike steps are not attacks, so flagging them counts against it.

ORTHRUS (Exp. 2 main row): its reconstruction is seeded with the evidence
nodes of our Phase 2 findings. One reconstructed attack graph is the union of
the traces from one seed finding's evidence nodes, a set of nodes; graphs are
not merged. (Decided 2026-11-01, before any run: a run fits one 15-minute
window, so the authors' union per window would hold every seeded finding and
only order them by time.) A finding belongs to a graph if one of its input
events touches a node of it. Within a graph, member findings are ordered by
event_start (equal times form one step) and linked step to step, as SAGE's
episodes are (decision S-4, mtcore.baselines.sage.project, variant "ag"); a
link found in several graphs counts once. One graph is one incident, graphs
with the same member findings are one incident, and the best K expansions are
its ranked paths. The records are scored by mtcore.harness.score like the GO's.
"""
import csv
import json
import os
from collections import Counter, defaultdict

import mtcore  # noqa: F401  (puts src/python/gen on the path)
from microtrace.v0 import dataset_pb2
from mtcore.baselines.provenance import convert as C
from mtcore.baselines.sage import project as P


def load_event_map(path, runs=None):
    """{run_id: {event_id: (subject_uuid, object_uuid or "")}} from convert.py's event_map.csv."""
    out = defaultdict(dict)
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            if runs is None or row["run_id"] in runs:
                out[row["run_id"]][row["event_id"]] = (row["subject_uuid"], row["object_uuid"])
    return out


def nodes_of(events, event_nodes):
    """The node UUIDs the given event IDs touch."""
    out = set()
    for e in events:
        for n in event_nodes.get(e, ()):
            if n:
                out.add(n)
    return out


def _truth(run_dir):
    """A run's truth; missing files are an error (a wrong truth root would otherwise score 0)."""
    r = os.path.join(run_dir, "restricted")
    paths = [os.path.join(r, f) for f in ("truth_findings.pb", "truth_actions.pb")]
    missing = [p for p in paths if not os.path.exists(p)]
    if missing:
        raise FileNotFoundError(f"truth missing: {missing}")
    opps = C._read_ld(paths[0], dataset_pb2.FindingOpportunity)
    acts = C._read_ld(paths[1], dataset_pb2.GroundTruthAction)
    return opps, acts


def kairos_run(run_dir, event_nodes, flagged):
    """Counts for one test run: steps per type (present, detected) and flagged nodes (tp, fp)."""
    opps, acts = _truth(run_dir)
    c = Counter()
    for o in opps:
        if o.finding_type not in C.HOST_TYPES or o.expected_state != dataset_pb2.PRESENT:
            continue
        hit = bool(nodes_of(o.evidence_event_ids, event_nodes) & flagged)
        c[f"present:{o.finding_type}"] += 1
        c[f"detected:{o.finding_type}"] += hit
    attack_nodes = nodes_of([e for a in acts if a.is_attack for e in a.rendered_event_ids], event_nodes)
    run_nodes = {n for pair in event_nodes.values() for n in pair if n}
    mine = flagged & run_nodes
    c["flagged_tp"] += len(mine & attack_nodes)
    c["flagged_fp"] += len(mine - attack_nodes)
    return c


def kairos_nodes(run_dir, event_nodes, flagged):
    """Per flagged node of one run: the present host-type steps it covers (the same
    rule as kairos_run) and whether an attack event touches it. Reported beside step
    recall (decided 2026-11-04): how many distinct flagged nodes cover how many steps."""
    opps, acts = _truth(run_dir)
    attack_nodes = nodes_of([e for a in acts if a.is_attack for e in a.rendered_event_ids], event_nodes)
    run_nodes = {n for pair in event_nodes.values() for n in pair if n}
    out = {n: {"steps": [], "attack_node": n in attack_nodes} for n in sorted(flagged & run_nodes)}
    for o in opps:
        if o.finding_type not in C.HOST_TYPES or o.expected_state != dataset_pb2.PRESENT:
            continue
        for n in sorted(nodes_of(o.evidence_event_ids, event_nodes) & flagged):
            out[n]["steps"].append(f"{o.finding_type}:{o.opportunity_id}")
    return out


def kairos_nodes_summary(per_run):
    """{run: kairos_nodes(...)} -> distinct flagged nodes against the steps they cover."""
    nodes = [(r, n, v) for r, d in per_run.items() for n, v in d.items()]
    covering = [x for x in nodes if x[2]["steps"]]
    steps = {(r, s) for r, _, v in covering for s in v["steps"]}
    by_non_attack = {(r, s) for r, _, v in covering if not v["attack_node"] for s in v["steps"]}
    by_attack = {(r, s) for r, _, v in covering if v["attack_node"] for s in v["steps"]}
    hist = Counter(len(v["steps"]) for _, _, v in covering)
    return {"flagged_nodes": len(nodes), "nodes_covering_steps": len(covering),
            "attack_nodes_covering_steps": sum(v["attack_node"] for _, _, v in covering),
            "steps_covered": len(steps), "runs_with_covering_nodes": len({r for r, _, _ in covering}),
            "steps_only_by_non_attack_nodes": len(by_non_attack - by_attack),
            "steps_per_covering_node": {str(k): hist[k] for k in sorted(hist)},
            "top_nodes": [{"run": r, "node": n, "steps": len(v["steps"]), "attack_node": v["attack_node"]}
                          for r, n, v in sorted(covering, key=lambda x: (-len(x[2]["steps"]), x[0], x[1]))[:20]]}


def kairos_summary(counts):
    """Recall per type and overall, and node precision, from summed kairos_run counts."""
    types = sorted({k.split(":", 1)[1] for k in counts if k.startswith("present:")})
    per_type = {}
    for t in types:
        p, d = counts[f"present:{t}"], counts[f"detected:{t}"]
        per_type[t] = {"present": p, "detected": d, "recall": round(d / p, 4) if p else None}
    p = sum(v["present"] for v in per_type.values())
    d = sum(v["detected"] for v in per_type.values())
    tp, fp = counts["flagged_tp"], counts["flagged_fp"]
    return {"steps": {"present": p, "detected": d, "recall": round(d / p, 4) if p else None},
            "per_type": per_type,
            "nodes": {"flagged": tp + fp, "tp": tp, "fp": fp,
                      "precision": round(tp / (tp + fp), 4) if tp + fp else None}}


def orthrus_records(run_id, graphs, findings, event_nodes, k):
    """[(topic, record)] of witnesses and incidents for one run.

    graphs: reconstructed attack graphs, each a set of node UUIDs.
    findings: {finding_id: Finding} of the run (the same Phase 2 findings as the GO's).
    """
    fnodes = {fid: nodes_of(f.input_event_ids, event_nodes) for fid, f in findings.items()}
    paths, seen = [], set()
    for gi, g in enumerate(graphs):
        members = sorted((findings[fid].event_start.ToNanoseconds(), fid)
                         for fid, ns in fnodes.items() if ns & g)
        if tuple(members) in seen:
            continue
        seen.add(tuple(members))
        steps = []
        for t, fid in members:
            if steps and steps[-1]["start"] == t:
                steps[-1]["alert_ids"].append(fid)
            else:
                steps.append({"start": t, "alert_ids": [fid]})
        if steps:
            paths.append({"attacker": "t0-orthrus", "victim": f"graph{gi}", "objective": "reconstruction",
                          "episodes": steps})
    return P.project("ag", {0: run_id}, paths, {}, k).get(run_id, [])


def write_records(path, finding_lines, records):
    """One run's output as SAGE's run.py writes it: the run's findings.v0 lines
    as cached (sage.run.read_findings), then the witnesses and incidents, so
    mtcore.harness.score scores the same findings as for the GO and SAGE."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.writelines(ln if ln.endswith("\n") else ln + "\n" for ln in finding_lines)
        for topic, rec in records:
            fh.write(json.dumps({"topic": topic, "record": rec}, sort_keys=True) + "\n")
