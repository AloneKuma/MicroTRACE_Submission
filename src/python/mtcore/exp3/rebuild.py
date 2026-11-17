"""Rebuild the eBPF part of an Exp. 3 received stream from the base stream and the fault log.

    python -m mtcore.exp3.rebuild --base W/base --faultlogs FL/<cond> --received W/received/<cond> \\
        --runs RUN [RUN ...] --out OUT/<cond> [--check-against W/received/<cond>]

For the seeded ORTHRUS row of Exp. 3 (added 2026-11-17, after the scored GO rows): the received
dumps of loss-transit-05/10 and of exp3-b's nofault were not kept (mtcore.exp3.run keeps a
condition's dumps only when every detection pass exits 0), but each run's base node streams
(W/base/<run>/nodes/*.jsonl) and the injector's fault log (FL/<cond>/<run>/*.jsonl, one line per
record it dropped, by logical_id) were. What arrived is the base stream without the dropped
records, in the order each node sent them (the shipper keeps per-lane order and loss removes
records, it never reorders). Only norm.events.v0 records are written, the only topic
mtcore.baselines.provenance.convert reads.

Checks per run, written to OUT/rebuild-check.json; the command exits 1 if any run fails:
  - the kept norm.events.v0 count equals the receiver's own count in
    received/<cond>/<run>/transport.json (received.by_topic["norm.events.v0"]);
  - every dropped logical_id is in the base stream (the log and the base belong together);
  - with --check-against (a condition whose real dump was kept): each node's rebuilt logical_ids
    equal the real dump's.
The fault log is the injector's record of what it did, not truth about the attack, and the rebuilt
stream holds only events that really arrived; ORTHRUS still never sees which records were lost.
"""
import argparse
import glob
import gzip
import json
import os
import sys
from collections import defaultdict

NORM = "norm.events.v0"


def _open(p):
    return gzip.open(p, "rt", encoding="utf-8") if p.endswith(".gz") else open(p, encoding="utf-8")


def dropped_ids(fault_dir):
    """logical_ids of norm.events.v0 records the injector dropped (any stage, any 'dropped*' action)."""
    out = set()
    for p in sorted(glob.glob(os.path.join(fault_dir, "*.jsonl"))):
        with open(p, encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                o = json.loads(line)
                if o.get("topic") == NORM and str(o.get("action", "")).startswith("dropped") and o.get("logical_id"):
                    out.add(o["logical_id"])
    return out


def node_of(o):
    """The eBPF node an event came from (per-node order is what convert depends on); every
    non-eBPF event is in one group 'other', compared as a set only."""
    ebpf = o["envelope"].get("normalized_event", {}).get("ebpf")
    return ebpf.get("node_id") if ebpf else "other"


def real_sequences(received_dir):
    """{node: [logical_id, ...]} of the norm events in a kept received dump."""
    seq = defaultdict(list)
    hits = sorted(glob.glob(os.path.join(received_dir, "shipper", "received.jsonl*")))
    if not hits:
        return None
    with _open(hits[0]) as fh:
        for line in fh:
            if not line.strip():
                continue
            o = json.loads(line)
            if o.get("topic") == NORM and "envelope" in o:
                seq[node_of(o)].append(o["envelope"]["logical_id"])
    return seq


def rebuild_run(base_run, fault_dir, transport_json, out_run, check_dir=None):
    drop = dropped_ids(fault_dir) if fault_dir and os.path.isdir(fault_dir) else set()
    seen_drop, kept, seq = set(), 0, defaultdict(list)
    os.makedirs(os.path.join(out_run, "shipper"), exist_ok=True)
    tmp = os.path.join(out_run, "shipper", "received.jsonl.tmp")
    with open(tmp, "w", encoding="utf-8") as out:
        for p in sorted(glob.glob(os.path.join(base_run, "nodes", "*.jsonl"))):
            with open(p, encoding="utf-8") as fh:
                for line in fh:
                    if not line.strip() or f'"topic":"{NORM}"' not in line:
                        continue
                    o = json.loads(line)
                    if o.get("topic") != NORM or "envelope" not in o:
                        continue
                    lid = o["envelope"].get("logical_id")
                    if lid in drop:
                        seen_drop.add(lid)
                        continue
                    out.write(line if line.endswith("\n") else line + "\n")
                    kept += 1
                    if check_dir:
                        seq[node_of(o)].append(lid)
    os.replace(tmp, os.path.join(out_run, "shipper", "received.jsonl"))
    want = None
    if transport_json and os.path.exists(transport_json):
        want = json.load(open(transport_json, encoding="utf-8")).get("received", {}).get("by_topic", {}).get(NORM)
    res = {"kept": kept, "dropped_logged": len(drop), "dropped_found_in_base": len(seen_drop),
           "receiver_count": want}
    ok = want is not None and kept == want and len(seen_drop) == len(drop)
    if check_dir:
        real = real_sequences(check_dir)
        res["real_dump"] = real is not None
        if real is not None:
            # Sets per node, not order: the real dump interleaves Kafka partitions, so its order
            # within a node is not reproducible either. Checked 2026-11-17 on exp3-a nofault run
            # 03c55ec4: convert.py gives the same nodes, attributes and edges (with timestamps)
            # from the rebuilt stream as from the real dump (1,553 nodes, 8,486 edges).
            same = set(real) == set(seq) and all(sorted(real[n]) == sorted(seq[n]) for n in real)
            res["same_as_real_dump"] = same
            ok = ok and same
    res["ok"] = ok
    return res


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--base", required=True, help="W/base (one folder per run, nodes/*.jsonl)")
    ap.add_argument("--faultlogs", required=True, help="the condition's fault-log folder (one folder per run)")
    ap.add_argument("--received", required=True, help="W/received/<cond> (transport.json per run)")
    ap.add_argument("--runs", nargs="+", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--check-against", help="W/received/<cond> holding real dumps to compare with")
    ap.add_argument("--workers", type=int, default=1)
    a = ap.parse_args(argv)
    jobs = [(os.path.join(a.base, r), os.path.join(a.faultlogs, r), os.path.join(a.received, r, "transport.json"),
             os.path.join(a.out, r), os.path.join(a.check_against, r) if a.check_against else None) for r in a.runs]
    if a.workers > 1:
        from multiprocessing import Pool
        with Pool(a.workers) as pool:
            results = pool.starmap(rebuild_run, jobs)
    else:
        results = [rebuild_run(*j) for j in jobs]
    report, bad = {}, 0
    for r, res in zip(a.runs, results):
        report[r] = res
        bad += not res["ok"]
        print(r, json.dumps(res), flush=True)
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "rebuild-check.json"), "w", encoding="utf-8") as fh:
        json.dump({"runs": report, "failed": bad}, fh, indent=2, sort_keys=True)
    print(f"REBUILD {len(a.runs)} runs, {bad} failed", flush=True)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
