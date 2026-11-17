"""Development-data sanity checks of the Exp. 1-2 scoring (items 1 and 2, 2026-11-17).

    python experiments/sanity/sanity_dev.py --data PILOT_DIR --split SPLIT.json \
        --score-out GO_SCORE_OUT --fit-out GO_FIT_OUT --out result.json [--workers 4] [--seeds 5]

Development data only (PILOT, FIT and SCORE halves). Held-out data is never read.
Every row is scored by mtcore.harness.score, the same scorer as the paper's rows, on the
GO's own Phase 2 findings (GO_OUT/runs/<run_id>/output.jsonl.gz, as SAGE and seeded
ORTHRUS get them), so only the step under test changes.

Rows:
- go: the GO's output as is (must reproduce the dev summary; a self-check of this script).
Item 1, null rows (would a careless or lucky detector score well?):
- null_type_shuffle: the run's finding types permuted among its findings (events kept).
- null_random_events: each finding keeps its type and number of input events, but the
  events are drawn at random from the events its own rule evaluated in that run
  (rule.evaluations.v0 input_event_ids of rule_id == finding type; all evaluated events
  if that rule logged none).
- null_rewire: the GO's findings and number of confirmed links, each link between a random
  pair of the run's findings, directed by time (links only).
- null_random_group: findings dealt at random into as many groups as the GO has incidents
  in the run; each group chained in time order (links and paths).
Item 2, naive correlators (no witnesses, no contradiction checks):
- naive_time_W: findings in time order, a new group after a gap > W seconds; each group
  chained in time order.
- naive_entity_W: two findings are in one group when they share an entity (type and UID,
  or type, namespace and name) and start within W seconds (transitively); each group
  chained in time order.
Chaining, ranked paths and K are those of the SAGE "ag" projection
(mtcore.baselines.sage.project, as seeded ORTHRUS uses it): findings with equal start
times form one step, every finding of a step links to every finding of the next, K = 10.
W is chosen on the FIT half by link F1 (grid WINDOWS); every W is also reported on SCORE.
"""
import argparse
import gzip
import json
import os
import random
import sys
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor

import mtcore  # noqa: F401
from microtrace.v0 import witness_pb2
from mtcore.baselines.sage import project as P
from mtcore.harness import score as S

WINDOWS = (5, 15, 30, 60, 120, 300, 900)
K = 10
EVAL_TAG = '"topic": "rule.evaluations.v0"'


def load_output(gz):
    """(Output with findings, witnesses and incidents; {rule_id: [event ids]} evaluated)."""
    keep, pool = [], defaultdict(set)
    with gzip.open(gz, "rt", encoding="utf-8") as fh:
        for line in fh:
            if EVAL_TAG in line:
                rec = json.loads(line)["record"]
                pool[rec.get("ruleId", "")].update(rec.get("inputEventIds", ()))
            else:
                keep.append(line)
    return S.Output.parse(keep), {k: sorted(v) for k, v in pool.items()}


def start_ns(f):
    return f.event_start.ToNanoseconds()


def with_findings(findings, records=()):
    out = S.Output(findings={f.finding_id: f for f in findings})
    for topic, rec in records:
        o = S.Output.parse([json.dumps({"topic": topic, "record": rec})])
        out.witnesses.update(o.witnesses)
        for inc in o.incidents.values():
            out._incident(inc)
    return out


def chain_groups(run_id, findings, groups):
    """SAGE "ag" projection records for groups of finding IDs (each chained in time order)."""
    by_id = {f.finding_id: f for f in findings}
    paths = []
    for gi, g in enumerate(groups):
        steps = []
        for t, fid in sorted((start_ns(by_id[x]), x) for x in g):
            if steps and steps[-1]["start"] == t:
                steps[-1]["alert_ids"].append(fid)
            else:
                steps.append({"start": t, "alert_ids": [fid]})
        if steps:
            paths.append({"attacker": "t0-naive", "victim": f"g{gi}", "objective": "naive", "episodes": steps})
    return P.project("ag", {0: run_id}, paths, {}, K).get(run_id, [])


def entity_keys(f):
    out = set()
    for e in f.entities:
        if e.HasField("uid") and e.uid:
            out.add((e.type, "uid", e.uid))
        elif e.name:
            out.add((e.type, e.namespace, e.name))
    return out


def groups_time(findings, w):
    fs = sorted(findings, key=start_ns)
    groups, last = [], None
    for f in fs:
        t = start_ns(f)
        if last is None or t - last > w * 1e9:
            groups.append([])
        groups[-1].append(f.finding_id)
        last = t
    return groups


def groups_entity(findings, w):
    fs = sorted(findings, key=start_ns)
    parent = {f.finding_id: f.finding_id for f in fs}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    keys = [entity_keys(f) for f in fs]
    for i, f in enumerate(fs):
        for j in range(i + 1, len(fs)):
            if start_ns(fs[j]) - start_ns(f) > w * 1e9:
                break
            if keys[i] & keys[j]:
                parent[find(f.finding_id)] = find(fs[j].finding_id)
    out = defaultdict(list)
    for f in fs:
        out[find(f.finding_id)].append(f.finding_id)
    return list(out.values())


def counts(s, parts=("findings", "links", "paths")):
    c = {}
    if "findings" in parts:
        o = s["findings"]["overall"]
        c.update({"f_tp": o["tp"], "f_fp": o["fp"], "f_fn": o["fn"]})
    if "links" in parts:
        lk = s["links"]
        c.update({"l_tp": lk["tp"], "l_fp": lk["fp"], "l_fn": lk["fn"]})
    if "paths" in parts:
        p = s["paths"]
        c.update({"p_ref": p["reference_paths"], "p_rec": p["recovered"], "p_false": p["false_chains"],
                  "p_multi": p["retained_multi"]})
        for n, r in p["by_length"].items():
            c[f"len{n}_ref"] = r["reference"]
            c[f"len{n}_rec"] = r["recovered"]
    return c


def one_run(args):
    run_id, data, out_dir, seeds, half = args
    truth = S.Truth.load(os.path.join(data, run_id, "restricted"))
    go, pool = load_output(os.path.join(out_dir, "runs", run_id, "output.jsonl.gz"))
    findings = sorted(go.findings.values(), key=lambda f: f.finding_id)
    res = {"go": counts(S.score(truth, go))}
    for w in WINDOWS:
        res[f"naive_time_{w}"] = counts(S.score(truth, with_findings(findings, chain_groups(
            run_id, findings, groups_time(findings, w)))), ("links", "paths"))
        res[f"naive_entity_{w}"] = counts(S.score(truth, with_findings(findings, chain_groups(
            run_id, findings, groups_entity(findings, w)))), ("links", "paths"))
    if half == "score":
        allev = sorted({e for v in pool.values() for e in v})
        n_links = sum(1 for w in go.witnesses.values() if w.status == S.CONFIRMED)
        n_inc = max(1, len(go.incidents))
        for sd in range(1, seeds + 1):
            rng = random.Random(f"{sd}|{run_id}")
            types = [f.finding_type for f in findings]
            rng.shuffle(types)
            shuf = []
            for f, t in zip(findings, types):
                g = type(f)()
                g.CopyFrom(f)
                g.finding_type = t
                shuf.append(g)
            res[f"null_type_shuffle_s{sd}"] = counts(S.score(truth, with_findings(shuf)), ("findings",))
            rnd = []
            for f in findings:
                src = pool.get(f.finding_type) or allev
                g = type(f)()
                g.CopyFrom(f)
                del g.input_event_ids[:]
                g.input_event_ids.extend(rng.sample(src, min(len(f.input_event_ids), len(src))))
                rnd.append(g)
            res[f"null_random_events_s{sd}"] = counts(S.score(truth, with_findings(rnd)), ("findings",))
            recs = []
            if len(findings) > 1:
                for i in range(n_links):
                    a, b = rng.sample(findings, 2)
                    if start_ns(b) < start_ns(a):
                        a, b = b, a
                    w = witness_pb2.Witness(witness_id=f"rw-{sd}-{i}", source_finding_id=a.finding_id,
                                            target_finding_id=b.finding_id, status=S.CONFIRMED)
                    from google.protobuf import json_format
                    recs.append((S.WITNESSES, json_format.MessageToDict(w)))
            res[f"null_rewire_s{sd}"] = counts(S.score(truth, with_findings(findings, recs)), ("links",))
            groups = defaultdict(list)
            for f in findings:
                groups[rng.randrange(n_inc)].append(f.finding_id)
            res[f"null_random_group_s{sd}"] = counts(S.score(truth, with_findings(findings, chain_groups(
                run_id, findings, list(groups.values())))), ("links", "paths"))
    return run_id, res


def ratio(a, b):
    return round(a / b, 4) if b else None


def metrics(c):
    m = {}
    if "f_tp" in c:
        p, r = ratio(c["f_tp"], c["f_tp"] + c["f_fp"]), ratio(c["f_tp"], c["f_tp"] + c["f_fn"])
        m["findings"] = {"P": p, "R": r, "F1": ratio(2 * p * r, p + r) if p and r else 0.0,
                         "tp": c["f_tp"], "fp": c["f_fp"], "fn": c["f_fn"]}
    if "l_tp" in c:
        p, r = ratio(c["l_tp"], c["l_tp"] + c["l_fp"]), ratio(c["l_tp"], c["l_tp"] + c["l_fn"])
        m["links"] = {"P": p, "R": r, "F1": ratio(2 * p * r, p + r) if p and r else 0.0,
                      "tp": c["l_tp"], "fp": c["l_fp"], "fn": c["l_fn"]}
    if "p_ref" in c:
        m["paths"] = {"recall": ratio(c["p_rec"], c["p_ref"]), "FCR": ratio(c["p_false"], c["p_multi"]),
                      "recovered": c["p_rec"], "reference": c["p_ref"], "retained_multi": c["p_multi"],
                      "by_length": {n: ratio(c.get(f"len{n}_rec", 0), c.get(f"len{n}_ref", 0))
                                    for n in ("2", "3", "4", "5")}}
    return m


def pool_rows(per_run):
    tot = defaultdict(lambda: defaultdict(int))
    for res in per_run.values():
        for row, c in res.items():
            for k, v in c.items():
                tot[row][k] += v
    return {row: metrics(c) for row, c in sorted(tot.items())}


def run_half(a, half, out_dir, runs):
    jobs = [(r, a.data, out_dir, a.seeds, half) for r in runs]
    per_run = {}
    with ProcessPoolExecutor(a.workers) as ex:
        for run_id, res in ex.map(one_run, jobs):
            per_run[run_id] = res
            print(f"{half} {len(per_run)}/{len(runs)} {run_id}", flush=True)
    return pool_rows(per_run)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--split", required=True)
    ap.add_argument("--score-out", required=True)
    ap.add_argument("--fit-out", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--seeds", type=int, default=5)
    a = ap.parse_args(argv)
    split = json.load(open(a.split))
    fit = run_half(a, "fit", a.fit_out, sorted(split["fit"]))
    best = {}
    for kind in ("time", "entity"):
        best[kind] = max(WINDOWS, key=lambda w: (fit[f"naive_{kind}_{w}"]["links"]["F1"] or 0, -w))
    score = run_half(a, "score", a.score_out, sorted(split["score"]))
    out = {"windows": WINDOWS, "chosen_on_fit_by_link_f1": best, "fit": fit, "score": score}
    with open(a.out, "w") as fh:
        json.dump(out, fh, indent=1)
    print(json.dumps({"chosen": best, "go_score": score["go"]}), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
