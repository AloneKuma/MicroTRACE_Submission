"""Development-data audit of the KAIROS / ORTHRUS comparison (items 5 and 6, 2026-11-17).

    python experiments/sanity/provenance_audit.py --conv CONV --group pilot --data RUNS_DIR \
        --kairos kairos_pilot/flagged.csv --orthrus orthrus_pilot/flagged.csv \
        [--go-runs GO_OUT/runs] --out audit-pilot.json

Development test groups only (PILOT SCORE, Targeted dev); held-out data is never read.
Inputs are the converter's event_map.csv (every eBPF event, its process node and object
node, and whether it became an edge of the graph the tools read: kept) and the flagged
nodes of the B3 development session (results/mt-dev-2026-11-02).

Item 5, what the tools can see. Per PRESENT host-type opportunity (the steps KAIROS is
scored on, convert.HOST_TYPES):
- in_graph: at least one evidence event is an edge of the tools' graph (kept = 1);
  node_only: no evidence edge, but a node of an evidence event exists in the graph;
  not_in_graph: neither.
- exclusive: at least one node of the step's evidence events is touched only by attack
  events (truth_actions is_attack rendered_event_ids) in that run. A node-level anomaly
  detector can single such a step out; a step whose nodes all also carry benign or
  background events (e.g. a long-lived server process) can only be flagged with them.
- busy: the median number of events touching the step's nodes.

Item 6, matching rules more lenient than the frozen B2 rule (reported beside it, never
replacing it):
- hop h (0 = the B2 rule, 1, 2): a step is detected if a flagged node is within h hops,
  in the run's graph (kept edges, undirected), of a node of one of its evidence events.
  The same rule on ABSENT host-type opportunities (benign lookalikes) gives the false
  alarm counterpart.
- run level (KAIROS's own unit is a time window; a run is one window here): an attack run
  is detected if it holds any flagged node; benign runs (no attack action) with a flagged
  node are false alarms. MicroTRACE's run-level row (--go-runs): an attack run is detected
  if it has a true-positive finding; a benign run with any false-positive finding is a
  false alarm.
"""
import argparse
import csv
import json
import os
import statistics
import sys
from collections import Counter, defaultdict

import mtcore  # noqa: F401
from microtrace.v0 import dataset_pb2
from mtcore.baselines.provenance import convert as C
from mtcore.baselines.provenance import seeded as SD

HOPS = (0, 1, 2)


def load_events(path, runs):
    """{run: {event_id: (subject, object, kept)}}."""
    out = defaultdict(dict)
    with open(path, newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            if r["run_id"] in runs:
                out[r["run_id"]][r["event_id"]] = (r["subject_uuid"], r["object_uuid"], r["kept"] == "1")
    return out


def flagged_set(path):
    if not path or not os.path.exists(path):
        return set()
    with open(path, newline="", encoding="utf-8") as fh:
        return {r["node_uuid"] for r in csv.DictReader(fh)}


def within(adj, seeds, h):
    seen, frontier = set(seeds), set(seeds)
    for _ in range(h):
        nxt = set()
        for n in frontier:
            nxt.update(adj.get(n, ()))
        frontier = nxt - seen
        seen |= frontier
    return seen


def audit_run(run_dir, ev, flagged_by_sys):
    opps = C._read_ld(os.path.join(run_dir, "restricted", "truth_findings.pb"), dataset_pb2.FindingOpportunity)
    acts = C._read_ld(os.path.join(run_dir, "restricted", "truth_actions.pb"), dataset_pb2.GroundTruthAction)
    attack_ev = {e for a in acts if a.is_attack for e in a.rendered_event_ids}
    node_events, graph_nodes, adj = defaultdict(int), set(), defaultdict(set)
    node_attack_only = defaultdict(lambda: True)
    for e, (s, o, kept) in ev.items():
        for n in (s, o):
            if n:
                node_events[n] += 1
                node_attack_only[n] = node_attack_only[n] and e in attack_ev
        if kept and s and o:
            graph_nodes.update((s, o))
            adj[s].add(o)
            adj[o].add(s)
    run_nodes = set(node_events)
    reach = {sysname: {h: within(adj, fl & run_nodes, h) for h in HOPS} for sysname, fl in flagged_by_sys.items()}
    c = Counter()
    busy = []
    for o in opps:
        if o.finding_type not in C.HOST_TYPES:
            continue
        state = {dataset_pb2.PRESENT: "present", dataset_pb2.ABSENT: "absent"}.get(o.expected_state)
        if state is None:
            continue
        evs = [e for e in o.evidence_event_ids if e in ev]
        nodes = {n for e in evs for n in ev[e][:2] if n}
        if state == "present":
            t = o.finding_type
            c["steps"] += 1
            c[f"steps:{t}"] += 1
            if any(ev[e][2] for e in evs):
                cat = "in_graph"
            elif nodes & graph_nodes:
                cat = "node_only"
            else:
                cat = "not_in_graph"
            c[cat] += 1
            c[f"{cat}:{t}"] += 1
            if any(node_attack_only[n] for n in nodes):
                c["exclusive"] += 1
                c[f"exclusive:{t}"] += 1
            if nodes:
                busy.append(statistics.median(node_events[n] for n in nodes))
        for sysname in flagged_by_sys:
            for h in HOPS:
                c[f"{sysname}:{state}:hop{h}"] += bool(nodes & reach[sysname][h])
        if state == "absent":
            c["absent_steps"] += 1
    is_attack_run = bool(attack_ev)
    c["attack_runs" if is_attack_run else "benign_runs"] += 1
    for sysname, fl in flagged_by_sys.items():
        hit = bool(fl & run_nodes)
        c[f"{sysname}:run_flagged:{'attack' if is_attack_run else 'benign'}"] += hit
    return c, busy, is_attack_run


def ratio(a, b):
    return round(a / b, 4) if b else None


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--conv", required=True)
    ap.add_argument("--group", required=True)
    ap.add_argument("--data", required=True)
    ap.add_argument("--kairos")
    ap.add_argument("--orthrus")
    ap.add_argument("--go-runs")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    runs = sorted(SD.group_runs(a.conv, a.group))
    events = load_events(os.path.join(a.conv, "event_map.csv"), set(runs))
    flagged = {"kairos": flagged_set(a.kairos), "orthrus": flagged_set(a.orthrus)}
    tot, busy = Counter(), []
    go_run = Counter()
    for r in runs:
        c, b, is_attack = audit_run(os.path.join(a.data, r), events[r], flagged)
        tot += c
        busy += b
        if a.go_runs:
            s = json.load(open(os.path.join(a.go_runs, r, "score.json")))["findings"]["overall"]
            go_run["attack_runs" if is_attack else "benign_runs"] += 1
            if is_attack:
                go_run["attack_detected"] += s["tp"] > 0
            else:
                go_run["benign_alarm"] += s["fp"] > 0
    n = tot["steps"]
    types = sorted(k.split(":", 1)[1] for k in tot if k.startswith("steps:"))
    out = {"group": a.group, "runs": len(runs), "flagged_nodes": {k: len(v) for k, v in flagged.items()},
           "item5_visibility": {
               "steps": n,
               "in_graph": ratio(tot["in_graph"], n), "node_only": ratio(tot["node_only"], n),
               "not_in_graph": ratio(tot["not_in_graph"], n),
               "exclusive_node": ratio(tot["exclusive"], n),
               "median_events_on_step_nodes": statistics.median(busy) if busy else None,
               "per_type": {t: {"steps": tot[f"steps:{t}"],
                                "in_graph": ratio(tot[f"in_graph:{t}"], tot[f"steps:{t}"]),
                                "exclusive_node": ratio(tot[f"exclusive:{t}"], tot[f"steps:{t}"])}
                            for t in types}},
           "item6_lenient": {}}
    for sysname in flagged:
        row = {f"hop{h}": {"step_recall": ratio(tot[f"{sysname}:present:hop{h}"], n),
                           "steps_detected": tot[f"{sysname}:present:hop{h}"],
                           "recall_of_in_graph_steps": ratio(tot[f"{sysname}:present:hop{h}"], tot["in_graph"]),
                           "lookalike_hit_rate": ratio(tot[f"{sysname}:absent:hop{h}"], tot["absent_steps"])}
               for h in HOPS}
        row["run_level"] = {"attack_runs": tot["attack_runs"],
                            "attack_runs_flagged": tot[f"{sysname}:run_flagged:attack"],
                            "detection_rate": ratio(tot[f"{sysname}:run_flagged:attack"], tot["attack_runs"]),
                            "benign_runs": tot["benign_runs"],
                            "benign_runs_flagged": tot[f"{sysname}:run_flagged:benign"]}
        out["item6_lenient"][sysname] = row
    if a.go_runs:
        out["item6_lenient"]["microtrace_run_level"] = {
            **go_run, "detection_rate": ratio(go_run["attack_detected"], go_run["attack_runs"]),
            "benign_alarm_rate": ratio(go_run["benign_alarm"], go_run["benign_runs"])}
    out["absent_steps"] = tot["absent_steps"]
    with open(a.out, "w") as fh:
        json.dump(out, fh, indent=1)
    print(json.dumps(out, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
