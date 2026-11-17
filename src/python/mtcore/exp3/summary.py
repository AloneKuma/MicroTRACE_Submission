"""Exp. 3 summary table over every (condition, pass) score (score_pilot.py summary.json).

    python -m mtcore.exp3.summary --work W [--conditions c1,c2]

Writes W/exp3-summary.json and W/exp3-summary.md. Every number is one score_pilot.py
summary.json reports (no new scoring definition); beside them, how many runs each fault plan
applied to (W/splits) and the GO's witness statuses as output (descriptive counts, e.g.
POST_COMPROMISE and UNPROVEN, read from the detection output, not scored).

Two descriptive metrics of the paper's Exp. 3 table (definitions decided by the user 2026-11-16,
worklog Q-7; mtcore.harness.score is unchanged):
  UR  = end_to_end.findings.unresolved / end_to_end.findings.present of score_pilot's summary.json:
        opportunities PRESENT without the fault-log adjustment but UNOBSERVABLE with it, over the
        Full row's opportunities (the same output scored without the fault log).
  PCC = per compromise condition (compromise-*) and GO pass: the number of links (source finding,
        target finding) whose latest witness status in the GO output is CONFIRMED and whose source
        finding has an eBPF input event on a node the injector compromised. Compromised nodes: the
        nodes whose fault log (truth side, --faultlogs) holds a stop, blind or forge entry, plus the
        plan's target node (plans/<cond>/<run>/meta.json, base/<run>/base.json) in case the fault
        left no entry. Event nodes are read from the received stream of that condition.
"""
import argparse
import glob
import gzip
import json
import os
import sys
from collections import Counter

COMPROMISE_KINDS = ("stop", "blind", "forge")
DEFINITIONS = {
    "UR": "unresolved / present of score_pilot end_to_end.findings: opportunities PRESENT without the "
          "fault-log adjustment but UNOBSERVABLE with it, over the Full row's opportunities",
    "PCC": "compromise conditions, GO passes: links whose latest witness status is CONFIRMED and whose "
           "source finding has an eBPF input event on a node the injector compromised (fault-log stop/blind/"
           "forge entries plus the plan's target node); summed over runs",
}


def _open(p):
    if p and not os.path.exists(p) and os.path.exists(p + ".gz"):
        p += ".gz"
    if not p or not os.path.exists(p):
        return None
    return gzip.open(p, "rt", encoding="utf-8") if p.endswith(".gz") else open(p, encoding="utf-8")


def compromised_nodes(faultlog_dir, plan_dir=None, base_dir=None):
    """Node IDs the injector compromised in one run: fault-log headers followed by a stop, blind or
    forge entry, plus the plan's target node (mapped to its node ID through base.json)."""
    out, node = set(), None
    fh = _open(os.path.join(faultlog_dir, "faults.jsonl")) if faultlog_dir else None
    if fh is not None:
        with fh:
            for line in fh:
                if not line.strip():
                    continue
                e = json.loads(line)
                if "header" in e:
                    node = e["header"].get("node")
                elif e.get("kind") in COMPROMISE_KINDS and node:
                    out.add(node)
    mp = os.path.join(plan_dir, "meta.json") if plan_dir else None
    bp = os.path.join(base_dir, "base.json") if base_dir else None
    if mp and bp and os.path.exists(mp) and os.path.exists(bp):
        meta = json.load(open(mp, encoding="utf-8"))
        ids = {n["node"]: n["node_id"] for n in json.load(open(bp, encoding="utf-8"))["nodes"]}
        for name, faults in (meta.get("faults_per_node") or {}).items():
            if meta.get("target") == name and faults and name in ids:
                out.add(ids[name])
    return out


def confirmed_links(output_gz):
    """({(source, target)} with a CONFIRMED latest witness status, {finding ID: input event IDs})."""
    last, inputs = {}, {}
    fh = _open(output_gz)
    if fh is None:
        return set(), {}
    with fh:
        for line in fh:
            o = json.loads(line)
            r = o.get("record")
            if r is None:
                continue
            if o.get("topic") == "witness.decisions.v0":
                last[r.get("witnessId")] = (r.get("status"), r.get("sourceFindingId"), r.get("targetFindingId"))
            elif o.get("topic") == "findings.v0" and r.get("findingId"):
                inputs.setdefault(r["findingId"], r.get("inputEventIds") or [])
    return {(a, b) for st, a, b in last.values() if st == "CONFIRMED"}, inputs


def event_nodes(received, want):
    """{event ID: eBPF node ID} for the wanted events, from a received stream (.jsonl or .jsonl.gz)."""
    out = {}
    if not want:
        return out
    fh = _open(received)
    if fh is None:
        return out
    with fh:
        for line in fh:
            ne = (json.loads(line).get("envelope") or {}).get("normalized_event") or {}
            eid = ne.get("event_id")
            if eid in want and ne.get("ebpf"):
                out[eid] = ne["ebpf"].get("node_id")
    return out


def pcc(work, cond, pass_dir, faultlogs):
    """(PCC summed over runs, runs counted, runs with a compromised node)."""
    total = runs = with_target = 0
    for gz in sorted(glob.glob(os.path.join(pass_dir, "runs", "*", "output.jsonl.gz"))):
        run = os.path.basename(os.path.dirname(gz))
        nodes = compromised_nodes(os.path.join(faultlogs, cond, run) if faultlogs else None,
                                  os.path.join(work, "plans", cond, run), os.path.join(work, "base", run))
        runs += 1
        if not nodes:
            continue
        with_target += 1
        links, inputs = confirmed_links(gz)
        want = {e for a, _b in links for e in inputs.get(a, [])}
        where = event_nodes(os.path.join(work, "received", cond, run, "shipper", "received.jsonl"), want)
        total += sum(1 for a, _b in links if any(where.get(e) in nodes for e in inputs.get(a, [])))
    return total, runs, with_target


def witness_status(pass_dir):
    c = Counter()
    for f in glob.glob(os.path.join(pass_dir, "runs", "*", "output.jsonl.gz")):
        last = {}
        with gzip.open(f, "rt", encoding="utf-8") as fh:
            for line in fh:
                o = json.loads(line)
                if o.get("topic") == "witness.decisions.v0" and "record" in o:
                    last[o["record"].get("witnessId")] = o["record"].get("status")
        c.update(last.values())
    return dict(sorted(c.items()))


def row(cond, name, s, split, pass_dir, work=None, faultlogs=None):
    f, lk, pa = s["findings"], s["links"], s["paths"]
    e2e = (s.get("end_to_end") or {}).get("findings") or {}
    ur = round(e2e["unresolved"] / e2e["present"], 4) if e2e.get("present") and "unresolved" in e2e else None
    go = s.get("correlator", "go") == "go" and not name.startswith("sage")
    pc = pcc(work, cond, pass_dir, faultlogs) if go and work and cond.startswith("compromise-") else None
    return {"condition": cond, "pass": name, "runs_scored": s["runs_scored"], "runs_applied": len(split.get("runs", [])),
            "runs_not_applied": len(split.get("not_applied", [])),
            "finding_p": f.get("precision"), "finding_r": f.get("recall"), "finding_f1": f.get("f1"),
            "unobservable_opportunities": f.get("unobservable_opportunities"),
            "finding_r_end_to_end": e2e.get("recall"), "unresolved": e2e.get("unresolved"),
            "full_row_opportunities": e2e.get("present"), "ur": ur,
            "pcc": pc[0] if pc else None, "pcc_runs": pc[1] if pc else None,
            "pcc_runs_compromised": pc[2] if pc else None,
            "link_p": lk.get("precision"), "link_r": lk.get("recall"), "link_f1": lk.get("f1"),
            "unobservable_links": lk.get("unobservable_links"),
            "path_recall": pa.get("top_k_path_recall"), "fcr": pa.get("false_chain_rate"),
            "witness_status": witness_status(pass_dir) if not name.startswith("sage") else None}


def write_summary(work, conditions=None, faultlogs=None):
    """faultlogs: the fault-log root (truth side; scoring only), for PCC."""
    faultlogs = faultlogs or os.path.join(work, "faultlogs")
    rows = []
    det = os.path.join(work, "detect")
    for cond in sorted(conditions or os.listdir(det)):
        split = {}
        sp = os.path.join(work, "splits", cond + ".json")
        if os.path.exists(sp):
            split = json.load(open(sp, encoding="utf-8"))
        for sj in sorted(glob.glob(os.path.join(det, cond, "*", "summary.json"))):
            name = os.path.basename(os.path.dirname(sj))
            rows.append(row(cond, name, json.load(open(sj, encoding="utf-8")), split, os.path.dirname(sj),
                            work, faultlogs))
    with open(os.path.join(work, "exp3-summary.json"), "w", encoding="utf-8") as fh:
        json.dump({"definitions": DEFINITIONS, "rows": rows}, fh, indent=2)
    cols = ("condition", "pass", "runs_scored", "finding_r", "finding_r_end_to_end", "link_p", "link_r",
            "path_recall", "fcr", "unobservable_links", "ur", "pcc")

    def fmt(v):
        return f"{v:.3f}" if isinstance(v, float) else ("-" if v is None else str(v))
    lines = ["# Exp. 3 summary (development numbers unless stated otherwise)", "",
             f"- UR: {DEFINITIONS['UR']}.", f"- PCC: {DEFINITIONS['PCC']}.", "",
             "| " + " | ".join(cols) + " | witness statuses |", "|" + "---|" * (len(cols) + 1)]
    for r in rows:
        ws = ", ".join(f"{k} {v}" for k, v in (r["witness_status"] or {}).items())
        lines.append("| " + " | ".join(fmt(r[c]) for c in cols) + f" | {ws} |")
    with open(os.path.join(work, "exp3-summary.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--work", required=True)
    ap.add_argument("--conditions", default="")
    ap.add_argument("--faultlogs", default=None, help="fault-log root for PCC (default W/faultlogs)")
    a = ap.parse_args(argv)
    rows = write_summary(a.work, [c for c in a.conditions.split(",") if c] or None, a.faultlogs)
    print(json.dumps({"rows": len(rows)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
