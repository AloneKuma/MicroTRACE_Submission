#!/usr/bin/env python3
"""Randomized tests of the paper's Section IV claims on the reference correlator.

For each claim: the paper design must show ZERO violations, and the matching
weaker variant must show at least one (so each test is able to fail).

  P1  forgery invariance            must-fail: no_origin
  P2  suppression monotonicity      must-fail: covered_witness_only, no_eps_cap
  L1  retrieval completeness        must-fail: short horizon, truncated postings, watermark eviction
  P3  order invariance (links,grp)  must-fail: single_eval, first_arrival_dedup
  PATH top-K order dependence (K=2 example; divergence rate; K=1 search)
  TAC superseded tactic-pair window makes a tactic label remove a link

Usage: python test_props.py --cases 2000 --seed 1 [--out evidence]
Exit code 0 only if every expectation holds. Stdlib only; Python >= 3.10.
"""

import argparse
import itertools
import json
import math
import os
import platform
import random
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import correlator_ref as R  # noqa: E402
import targeted  # noqa: E402

NODES = ("n1", "n2")
INSTS = ("i1", "i2", "i3", "i4")
TACTICS = (None, None, "CA", "DI", "LM", "EX")
SOURCES = ("agent@n1", "agent@n2", "audit", "admission", "offnode", "ctx")


# ---------------------------------------------------------------- generator
def gen(rng, P):
    n = rng.randint(6, 14)
    ts = sorted(round(rng.uniform(0, 300), 1) for _ in range(n))
    findings, events, actions, contras, clocks, losses, triggers = {}, [], [], [], [], [], []
    uid = itertools.count()

    def recv(t):
        return round(t + rng.uniform(0, P.beta), 2)

    for f, t in enumerate(ts):
        node = rng.choice(NODES)
        keys, wkeys = {}, {}
        for w in R.TYPES:
            if rng.random() < 0.65:
                keys[w] = f"{w}{rng.randint(0, 1)}"
            if w in R.AGENT_TYPES and rng.random() < 0.6:
                wkeys[w] = f"tr{rng.randint(0, 2)}"
            if w in keys and rng.random() < 0.9:
                et = round(t + rng.uniform(-P.A, P.A), 1)
                src = f"agent@{node}" if w in R.AGENT_TYPES else R.TYPE_SRC[w]
                events.append(dict(id=next(uid), fid=f, w=w, t=et, src=src,
                                   dirrank=round(et + rng.uniform(-6, 6), 1), recv=recv(et)))
        findings[f] = dict(t=t, node=node, inst=rng.choice(INSTS), tactic=rng.choice(TACTICS),
                           keys=keys, wkeys=wkeys)
        if rng.random() < 0.6:
            actions.append(dict(id=next(uid), fid=f, kind="aid", val=f"a{rng.randint(0, 5)}",
                                t=t, src="audit", recv=recv(t)))
        if rng.random() < 0.75:
            actions.append(dict(id=next(uid), fid=f, kind="opsig", val=f"o{rng.randint(0, 3)}",
                                t=t, src="audit", recv=recv(t)))
    sparse = rng.random() < 0.3             # 30%: sparse clock records (large, growing eps)
    for s in SOURCES:                       # clock-quality records (deletable)
        starts = [rng.uniform(-60, 300) for _ in range(rng.randint(1, 3))] if sparse else range(-60, 360, 60)
        for t0 in starts:
            t = round(t0 + rng.uniform(0, 20), 1)
            clocks.append(dict(id=next(uid), src=s, t=t, eps=round(rng.uniform(0.2, 1.5), 2), recv=recv(t)))
    base = R.Evidence(findings, events, actions, [], clocks, [], [], set())
    linked = sorted(R.exhaustive(base, P, dedup=False))   # aim most contradictions at linkable pairs
    for _ in range(rng.randint(0, 5)):
        a, b = rng.choice(linked) if linked and rng.random() < 0.7 else rng.sample(range(n), 2)
        w = None if rng.random() < 0.35 else rng.choice(R.TYPES)
        origin = "sensor" if rng.random() < 0.6 else "workload"
        if w is None:
            src = "ctx"
        elif w in R.AGENT_TYPES:
            src = f"agent@{findings[rng.choice((a, b))]['node']}"
        else:
            src = R.TYPE_SRC[w]
        lo = min(ts[a], ts[b]) - P.A
        hi = max(ts[a], ts[b]) + P.A
        t = round(rng.uniform(lo, hi), 1)
        contras.append(dict(id=next(uid), a=a, b=b, w=w, origin=origin, src=src, t=t, recv=recv(t),
                            producer=findings[a]["inst"]))
    for s in SOURCES:
        p = 0.04 if s.startswith("agent@") else 0.12
        if rng.random() < p:
            lo = round(rng.uniform(0, 300), 1)
            hi = round(lo + rng.uniform(1, 30), 1)
            losses.append(dict(id=next(uid), src=s, lo=lo, hi=hi, tau=lo, t=hi, recv=hi))
    if rng.random() < 0.3:
        node = rng.choice(NODES)
        t = round(rng.uniform(50, 300), 1)
        triggers.append(dict(id=next(uid), node=node, t=t, eps=1.0, recv=recv(t), src=f"agent@{node}"))
    if rng.random() < 0.3:                  # a C1b-like trigger: evidence of finding f, at f's time
        f = rng.randrange(n)
        node, t = findings[f]["node"], ts[f]
        triggers.append(dict(id=next(uid), node=node, t=t, eps=1.0, recv=recv(t), src=f"agent@{node}", fid=f))
    C = set(rng.sample(INSTS, rng.randint(1, 2)))
    return R.Evidence(findings, events, actions, contras, clocks, losses, triggers, C)


def random_arrivals(E, rng, P, adversarial=False):
    arr = {("finding", f): E.findings[f]["t"] + (0 if adversarial else rng.uniform(0, P.lateness))
           for f in E.findings}
    for k, it in list(E.items()) + [("losses", l) for l in E.losses]:
        arr[(k, it["id"])] = it["t"] + (P.lateness if adversarial else rng.uniform(0, P.lateness))
    return arr


# ---------------------------------------------------------------- P1
def forge(E, rng):
    """Change only workload-asserted fields of records produced by workloads in C."""
    pool = [k for f in E.findings.values() for k in f["wkeys"].values()] + ["trX"]
    findings = {}
    for fid, f in E.findings.items():
        g = dict(f, keys=dict(f["keys"]), wkeys=dict(f["wkeys"]))
        if f["inst"] in E.C:
            for w in R.AGENT_TYPES:
                r = rng.random()
                if r < 0.4:
                    g["wkeys"][w] = rng.choice(pool)        # copy / graft
                elif r < 0.6:
                    g["wkeys"].pop(w, None)                 # strip
        findings[fid] = g
    contras = [c for c in E.contras if not (c["origin"] == "workload" and c["producer"] in E.C)]
    cfids = [f for f in E.findings if E.findings[f]["inst"] in E.C]
    uid = max([it["id"] for _, it in E.items()] + [l["id"] for l in E.losses] + [0]) + 1
    for _ in range(rng.randint(0, 3)):
        if not cfids:
            break
        a = rng.choice(cfids)
        b = rng.choice([f for f in E.findings if f != a])
        t = E.findings[a]["t"]
        contras.append(dict(id=uid, a=a, b=b, w=rng.choice((None,) + R.TYPES), origin="workload",
                            src=f"agent@{E.findings[a]['node']}", t=t, recv=t + 1,
                            producer=E.findings[a]["inst"]))
        uid += 1
    return E.copy(findings=findings, contras=contras)


def check_p1(E, rng, P, res):
    E2 = forge(E, rng)
    for name, V in (("paper", R.Variant()), ("no_origin", R.Variant(no_origin=True))):
        a, b = R.exhaustive(E, P, V), R.exhaustive(E2, P, V)
        res["P1"][name]["cases"] += 1
        t_of = {f: E.findings[f]["t"] for f in E.findings}
        if a != b or R.groups(a, t_of) != R.groups(b, t_of):
            res["P1"][name]["violations"] += 1
            if res["P1"][name]["example"] is None:
                res["P1"][name]["example"] = {"gained": sorted(b - a), "lost": sorted(a - b)}


# ---------------------------------------------------------------- P2
def suppress(E, rng, allow):
    cands = [(k, it) for k, it in E.items() if k in allow]
    if not cands:
        return None, None
    dele = rng.sample(cands, min(len(cands), rng.randint(1, 3)))
    gone = {(k, it["id"]) for k, it in dele}
    keep = {k: [it for it in getattr(E, k) if (k, it["id"]) not in gone]
            for k in ("events", "actions", "contras", "clocks", "triggers")}
    remaining = [it for k in keep for it in keep[k]]
    losses = list(E.losses)
    uid = max([it["id"] for _, it in E.items()] + [l["id"] for l in E.losses] + [0]) + 1
    for k, it in dele:
        prev = [r["recv"] for r in remaining if r["src"] == it["src"] and r["recv"] < it["recv"]]
        prev_recv = max(prev) if prev else it["t"]          # receipt of last record before the gap
        losses.append(dict(id=uid, src=it["src"], lo=min(it["t"], prev_recv), hi=it["recv"],
                           tau=prev_recv, t=it["recv"], recv=it["recv"]))
        uid += 1
    return E.copy(losses=losses, **keep), dele


def classify(E, E2, P, V, pair):
    """Explain a suppression-created link by clock slack, epoch slack, or neither."""
    i, j = pair
    t1, t2 = R.epochs(E), R.epochs(E2)
    # Only LATER onsets (a deleted trigger replaced by a suspected epoch) are a bounded exception.
    # Undo just those; an onset that became EARLIER must never create a link.

    def link_with(eps_src, tau_src):
        cx = R.Ctx(E2, P, V, eps_E=eps_src)
        if tau_src is not None:
            cx.tau = tau_src
        return R.link(cx, i, j)

    tau_later_undone = {n: min(t2.get(n, math.inf), t1.get(n, math.inf)) for n in set(t1) | set(t2)}
    clock_fix = not link_with(E, None)
    epoch_fix = not link_with(None, tau_later_undone)
    both_fix = not link_with(E, tau_later_undone)
    out = {"clock": clock_fix, "epoch": epoch_fix, "unexplained": not both_fix}
    cx = R.Ctx(E2, P, V)
    out["eps_beyond_cap"] = any(R.time_gap(cx, i, j, w)[1] > P.eps_bar for w in R.admissible(cx, i, j))
    slack = max([t2[n] - t1[n] for n in t1 if n in t2 and t2[n] > t1[n]] + [0.0])
    trig_eps = max([g["eps"] for g in E.triggers] + [0.0])
    out["epoch_slack"] = slack
    out["epoch_slack_ok"] = slack <= P.beta + trig_eps + 1e-9
    return out


def check_p2(E, rng, P, res):
    variants = (("paper", R.Variant()), ("covered_witness_only", R.Variant(covered_witness_only=True)),
                ("no_eps_cap", R.Variant(no_eps_cap=True)),
                ("distinct_no_coverage", R.Variant(distinct_no_coverage=True)))
    for mode, allow in (("fixed_eps", ("events", "actions", "contras")),
                        ("all", ("events", "actions", "contras", "clocks", "triggers"))):
        E2, dele = suppress(E, rng, allow)
        if E2 is None:
            continue
        for name, V in variants:
            a, b = R.exhaustive(E, P, V, dedup=False), R.exhaustive(E2, P, V, dedup=False)
            r = res["P2"][f"{name}/{mode}"]
            r["cases"] += 1
            for pair in sorted(b - a):
                c = classify(E, E2, P, V, pair)
                r["new_links"] += 1
                bad = c["unexplained"] or (c["clock"] and c["eps_beyond_cap"]) or \
                    (c["epoch"] and not c["epoch_slack_ok"]) or mode == "fixed_eps"
                if c["clock"] and not c["unexplained"]:
                    r["clock_explained"] += 1
                if c["epoch"] and not c["unexplained"]:
                    r["epoch_explained"] += 1
                if bad:
                    r["violations"] += 1
                    if r["example"] is None:
                        r["example"] = {"pair": pair, "deleted": [k for k, _ in dele], **c}


# ---------------------------------------------------------------- L1 / P3 / paths
def check_stream(E, rng, P, res):
    full = R.exhaustive(E, P)
    orders = [random_arrivals(E, rng, P) for _ in range(3)] + [random_arrivals(E, rng, P, adversarial=True)]
    # L1 retrieval completeness (paper design and index-weakening variants)
    for name, V in (("paper", R.Variant()), ("short_horizon", R.Variant(horizon_scale=0.3)),
                    ("truncate_1", R.Variant(truncate=1)), ("evict_by_watermark", R.Variant(evict_by_watermark=True))):
        r = res["L1"][name]
        r["cases"] += 1
        links, _ = R.stream(E, P, V, orders[-1] if name == "evict_by_watermark" else orders[0])
        if links != full:
            r["violations"] += 1
            if r["example"] is None:
                r["example"] = {"missed": sorted(full - links), "extra": sorted(links - full)}
    # P3 order invariance of links and groups
    cx = R.Ctx(E, P, R.Variant())
    for name, V in (("paper", R.Variant()), ("single_eval", R.Variant(single_eval=True)),
                    ("first_arrival_dedup", R.Variant(first_arrival_dedup=True))):
        r = res["P3"][name]
        r["cases"] += 1
        outs = [R.stream(E, P, V, a) for a in orders]
        t_all = {f: E.findings[f]["t"] for f in E.findings}
        sets = {(frozenset(l), R.groups(l, t_all)) for l, _ in outs}
        if len(sets) > 1 or (name == "paper" and outs[0][0] != full):
            r["violations"] += 1
            if r["example"] is None:
                r["example"] = {"distinct_outcomes": len(sets)}
        if name == "paper" and full:
            s = {p: R.score(cx, *p) for p in full}
            t_of = {f: E.findings[f]["t"] for f in E.findings}
            pathsets = {R.topk_paths(c, s, t_of, P) for _, c in outs}
            res["PATH"]["groups_with_links"] += len(R.groups(full, t_of))
            res["PATH"]["scenarios_with_links"] += 1
            if len(pathsets) > 1:
                res["PATH"]["scenarios_paths_differ"] += 1


def path_examples(P, rng, trials):
    # Exact K=2 example from the paper.
    s = {("a", "c"): 0.9, ("c", "b"): 0.5, ("b", "d"): 0.6}
    t_of = {x: 0 for x in "abcd"}
    P2 = R.Params(K=2)
    o1 = R.topk_paths([("a", "c"), ("c", "b"), ("b", "d")], s, t_of, P2)
    o2 = R.topk_paths([("c", "b"), ("b", "d"), ("a", "c")], s, t_of, P2)
    k2 = {"order1": sorted(o1), "order2": sorted(o2),
          "full_path_only_in_order2": ("a", "c", "b", "d") in o2 and ("a", "c", "b", "d") not in o1}
    # K=1 search for order dependence (report only).
    P1 = R.Params(K=1)
    found = None
    for _ in range(trials):
        nodes = list(range(rng.randint(3, 6)))
        edges = rng.sample([(x, y) for x in nodes for y in nodes if x != y], rng.randint(2, 5))
        sc = {e: rng.choice((0.3, 0.5, 0.6, 0.8, 0.9)) for e in edges}
        t = {x: 0 for x in nodes}
        perms = list(itertools.permutations(edges))
        rng.shuffle(perms)
        outs = {R.topk_paths(list(p), sc, t, P1) for p in perms[:24]}
        if len(outs) > 1:
            found = {"edges": edges, "scores": {str(k): v for k, v in sc.items()}}
            break
    return k2, found


def tactic_check():
    P = R.Params()
    P.W = dict(P.W, credential=3600.0)
    P.pair_window = 1800.0
    f = {0: dict(t=0.0, node="n1", inst="i1", tactic="CA", keys={"credential": "tok"}, wkeys={}),
         1: dict(t=2400.0, node="n1", inst="i2", tactic="DI", keys={"credential": "tok"}, wkeys={}),
         2: dict(t=2400.0, node="n1", inst="i3", tactic=None, keys={"credential": "tok"}, wkeys={})}
    ev = [dict(id=10 + k, fid=k, w="credential", t=f[k]["t"], src="audit", dirrank=f[k]["t"], recv=f[k]["t"] + 1)
          for k in f]
    act = [dict(id=20 + k, fid=k, kind="aid", val=f"a{k}", t=f[k]["t"], src="audit", recv=f[k]["t"]) for k in f]
    clk = [dict(id=30, src="audit", t=f[k]["t"], eps=0.5, recv=f[k]["t"]) for k in f]
    for n, c in enumerate(clk):
        c["id"] = 30 + n
    P.cover_end = 10_000
    E = R.Evidence(f, ev, act, [], clk, [], [], set())
    out = {}
    for name, V in (("paper", R.Variant()), ("tactic_pair_window", R.Variant(tactic_pair_window=True))):
        cx = R.Ctx(E, P, V)
        out[name] = {"D1->B1": R.link(cx, 0, 1), "D1->G1a": R.link(cx, 0, 2)}
    return out


# ---------------------------------------------------------------- main
def blank():
    return {"cases": 0, "violations": 0, "example": None}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", type=int, default=500)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "evidence", "proofs"))
    args = ap.parse_args()
    P = R.Params()
    rng = random.Random(args.seed)
    res = {
        "P1": {k: blank() for k in ("paper", "no_origin")},
        "P2": {f"{v}/{m}": dict(blank(), new_links=0, clock_explained=0, epoch_explained=0)
               for v in ("paper", "covered_witness_only", "no_eps_cap", "distinct_no_coverage")
               for m in ("fixed_eps", "all")},
        "L1": {k: blank() for k in ("paper", "short_horizon", "truncate_1", "evict_by_watermark")},
        "P3": {k: blank() for k in ("paper", "single_eval", "first_arrival_dedup")},
        "PATH": {"scenarios_with_links": 0, "scenarios_paths_differ": 0, "groups_with_links": 0},
    }
    t0 = time.time()
    links_total = 0
    for _ in range(args.cases):
        E = gen(rng, P)
        links_total += len(R.exhaustive(E, P))
        check_p1(E, rng, P, res)
        check_p2(E, rng, P, res)
        check_stream(E, rng, P, res)
    k2, k1 = path_examples(P, rng, trials=max(200, args.cases // 5))
    res["PATH"]["k2_example"] = k2
    res["PATH"]["k1_counterexample"] = k1
    res["TAC"] = tactic_check()
    res["P2_targeted_epoch_onset"] = targeted.epoch_onset_case()
    res["P2_targeted_self_trigger"] = targeted.self_trigger_case()
    res["P3_targeted_clock_tie"] = targeted.clock_tie_case()

    expect = {
        "P1 paper: 0 violations": res["P1"]["paper"]["violations"] == 0,
        "P1 no_origin: >0 violations": res["P1"]["no_origin"]["violations"] > 0,
        "P2 paper/fixed_eps: 0 violations": res["P2"]["paper/fixed_eps"]["violations"] == 0,
        "P2 paper/all: 0 unbounded or unexplained": res["P2"]["paper/all"]["violations"] == 0,
        "P2 covered_witness_only: >0 violations": res["P2"]["covered_witness_only/fixed_eps"]["violations"]
        + res["P2"]["covered_witness_only/all"]["violations"] > 0,
        "P2 no_eps_cap/all: >0 violations": res["P2"]["no_eps_cap/all"]["violations"] > 0,
        "P2 distinct_no_coverage: >0 violations": res["P2"]["distinct_no_coverage/fixed_eps"]["violations"]
        + res["P2"]["distinct_no_coverage/all"]["violations"] > 0,
        "L1 paper: 0 violations": res["L1"]["paper"]["violations"] == 0,
        "L1 short_horizon: >0": res["L1"]["short_horizon"]["violations"] > 0,
        "L1 truncate_1: >0": res["L1"]["truncate_1"]["violations"] > 0,
        "P3 paper: 0 violations": res["P3"]["paper"]["violations"] == 0,
        "P3 single_eval: >0": res["P3"]["single_eval"]["violations"] > 0,
        "P3 first_arrival_dedup: >0": res["P3"]["first_arrival_dedup"]["violations"] > 0,
        "PATH K=2 example reproduces": k2["full_path_only_in_order2"],
        "P2 targeted epoch-onset: paper holds": res["P2_targeted_epoch_onset"]["paper"]["after_suppression"] is False,
        "P2 targeted epoch-onset: event-time Covered fails": res["P2_targeted_epoch_onset"]["covered_epoch_event_time"]["after_suppression"] is True,
        "P2 targeted self-trigger: link into the trigger confirms": res["P2_targeted_self_trigger"]["paper"]["clean"] is True,
        "P2 targeted self-trigger: unproven without the exemption": res["P2_targeted_self_trigger"]["no_trigger_exemption"]["clean"] is False,
        "P2 targeted self-trigger: a degraded contradiction still blocks": res["P2_targeted_self_trigger"]["paper"]["degraded_contradiction"] is False,
        "P2 targeted self-trigger: suppressing that contradiction creates no link": res["P2_targeted_self_trigger"]["paper"]["after_suppression"] is False,
        "P3 targeted clock tie: decision independent of clock-record order":
            res["P3_targeted_clock_tie"]["small_first"] == res["P3_targeted_clock_tie"]["large_first"],
        "P3 targeted clock tie: the tie takes the larger uncertainty":
            res["P3_targeted_clock_tie"]["small_first"] is False and res["P3_targeted_clock_tie"]["small_only"] is True,
        "TAC paper accepts both": all(res["TAC"]["paper"].values()),
        "TAC old window rejects D1->B1 only": res["TAC"]["tactic_pair_window"] == {"D1->B1": False, "D1->G1a": True},
    }
    meta = {"utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "cases": args.cases,
            "seed": args.seed, "python": platform.python_version(), "host": platform.node(),
            "seconds": round(time.time() - t0, 1), "confirmed_links_total": links_total,
            "note": "L1 evict_by_watermark is reported, not asserted"}
    report = {"meta": meta, "expectations": expect, "results": res}
    os.makedirs(args.out, exist_ok=True)
    stamp = meta["utc"].replace("-", "").replace(":", "")
    path = os.path.join(args.out, f"props-{stamp}-seed{args.seed}-n{args.cases}.json")
    with open(path, "w") as fh:
        json.dump(report, fh, indent=1, default=str)
    for k, ok in expect.items():
        print(("PASS " if ok else "FAIL ") + k)
    print(json.dumps({k: v for k, v in res.items() if k in ("P1", "L1", "P3")}, default=str)[:3000])
    print("P2", json.dumps(res["P2"], default=str)[:3000])
    print("PATH", json.dumps({k: v for k, v in res["PATH"].items()}, default=str)[:800])
    print("TAC", res["TAC"], "| links:", links_total, "| s:", meta["seconds"], "|", path)
    return 0 if all(expect.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
