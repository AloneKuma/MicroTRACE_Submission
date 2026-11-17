"""Exp. 3 fault-log consistency: what the log says was lost or made is what the stream shows.

    python -m mtcore.exp3.check --base BASE_ROOT --received RECEIVED_ROOT/<condition> \
        --faultlogs FAULTLOG_ROOT/<condition> [--runs r1,r2] [--out check.json]

Per run (base stream, fault log, received dump), every check must hold:
  dropped_absent     no record the log lists as dropped reached Kafka
  forged_present     every forged record reached Kafka
  accounting         base records - dropped + forged == records that reached Kafka (by logical ID;
                     receiver-made records and heartbeats aside)
  transit_reported   every transit drop's (node, lane, seq) lies in a DROPPED_BEFORE record the
                     receiver wrote for that node and lane ("transport seq a-b")
  no_unlogged_gap    every DROPPED_BEFORE seq the receiver wrote is a logged transit drop
                     (no loss the injector did not cause)
The fault log is truth-side material; this runs in the scoring step (or a local dry run), never
on the detection side.
"""
import argparse
import json
import os
import re
import sys
from collections import defaultdict

SEQ = re.compile(r"transport seq (\d+)-(\d+)")
NODE = re.compile(r"(?:^|/)node=([^/]+)")
LANE = re.compile(r"(?:^|/)lane=([^/]+)")
DROPPED = ("dropped_unreported", "dropped_reported")
RECEIVER = "ingest-receiver"     # receiver.ProducerID (src/go/internal/receiver)


def base_ids(base_dir):
    ids = set()
    node_of_file = {}
    meta = json.load(open(os.path.join(base_dir, "base.json"), encoding="utf-8"))
    for n in meta["nodes"]:
        node_of_file[n["file"]] = n["node_id"]
        with open(os.path.join(base_dir, "nodes", n["file"]), encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                o = json.loads(line)
                env = o.get("envelope")
                if not env or "heartbeat" in env:
                    continue
                ids.add(env.get("logical_id") or env.get("logicalId"))
    return ids, meta


def read_log(path):
    entries, headers = [], []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                e = json.loads(line)
                (headers if "header" in e else entries).append(e)
    return headers, entries


def lane_ends(transport_file, meta):
    """(node ID, lane) -> last sequence the shipper appended, from transport.json's shipper stats."""
    if not transport_file or not os.path.exists(transport_file):
        return {}
    tj = json.load(open(transport_file, encoding="utf-8"))
    ids = {n["node"]: n["node_id"] for n in meta["nodes"]}
    out = {}
    for name, lanes in ((tj.get("sender") or {}).get("shipper_stats") or {}).items():
        for lane, st in lanes.items():
            out[(ids.get(name, name), lane)] = int(st.get("next_seq", 1)) - 1
    return out


def held_tail(missing, last):
    """The missing sequences that form the lane's tail (a contiguous run ending at its last item)."""
    tail, s = set(), last
    while s in missing:
        tail.add(s)
        s -= 1
    return tail


def check_run(base_dir, received_file, faultlog_dir, transport_file=None):
    ids, meta = base_ids(base_dir)
    heads, entries = read_log(os.path.join(faultlog_dir, "faults.jsonl"))
    node_of_header = []
    dropped = {e["logical_id"] for e in entries if e.get("action") in DROPPED}
    forged = {e["logical_id"] for e in entries if e.get("action") == "forged"}
    # Transit drops per (node, lane): the transit log of node X sits under X's header.
    transit = defaultdict(set)
    path = os.path.join(faultlog_dir, "faults.jsonl")
    node = None
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            e = json.loads(line)
            if "header" in e:
                node = e["header"].get("node")
                node_of_header.append(node)
                continue
            if e.get("stage") == "transit" and e.get("action") == "dropped_reported":
                transit[(node, e["lane"])].add(int(e["seq"]))
    got, gaps = set(), defaultdict(set)
    import gzip
    if not os.path.exists(received_file) and os.path.exists(received_file + ".gz"):
        received_file += ".gz"
    op = gzip.open if received_file.endswith(".gz") else open
    with op(received_file, "rt", encoding="utf-8") as fh:
        for line in fh:
            o = json.loads(line)
            env = o["envelope"]
            if (env.get("producer_id") or "").startswith(RECEIVER):
                sc = env.get("source_completeness") or {}
                scope = sc.get("scope", "")
                n, l = NODE.search(scope), LANE.search(scope)
                for g in sc.get("gaps") or []:
                    m = SEQ.search(g.get("detail", ""))
                    if g.get("reason") == "DROPPED_BEFORE" and m and n and l:
                        gaps[(n.group(1), l.group(1))].update(range(int(m.group(1)), int(m.group(2)) + 1))
                continue
            got.add(env.get("logical_id"))
    reported = {k: set(v) for k, v in gaps.items()}
    # A transit drop of the lane's last items with no event time is held by the receiver until the
    # next item or the node's idleness (ship-contract.md, "Gap times"); a fast replay ends before
    # either, so that tail is reported as held_at_stream_end, not as a failure.
    ends, held = lane_ends(transport_file, meta), {}
    for k, seqs in transit.items():
        miss = {s for s in seqs if s not in reported.get(k, set())}
        if miss and k in ends:
            t = held_tail(miss, ends[k])
            if t:
                held[f"{k[0]}/{k[1]}"] = sorted(t)
    missing_report = sorted(f"{k[0]}/{k[1]}:{s}" for k, seqs in transit.items() for s in seqs
                            if s not in reported.get(k, set()) and s not in held.get(f"{k[0]}/{k[1]}", ()))
    unlogged = sorted(f"{k[0]}/{k[1]}:{s}" for k, seqs in reported.items() for s in seqs
                      if s not in transit.get(k, set()))
    checks = {
        "dropped_absent": sorted(dropped & got)[:10],
        "forged_present": sorted(forged - got)[:10],
        "accounting": None if len(ids) - len(dropped & ids) + len(forged) == len(got) else
        {"base": len(ids), "dropped": len(dropped & ids), "forged": len(forged), "received": len(got),
         "unexpected": sorted(got - ids - forged)[:5], "lost": sorted(ids - got - dropped)[:5]},
        "transit_reported": missing_report[:10],
        "no_unlogged_gap": unlogged[:10],
    }
    ok = all(not v for v in checks.values())
    return {"ok": ok, "base_records": len(ids), "received": len(got), "dropped": len(dropped),
            "forged": len(forged), "transit_dropped": sum(len(v) for v in transit.values()),
            "receiver_gap_seqs": sum(len(v) for v in reported.values()), "log_nodes": node_of_header,
            "held_at_stream_end": held,
            "failures": {k: v for k, v in checks.items() if v}}


def _check(args):
    return check_run(*args)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base", required=True)
    ap.add_argument("--received", required=True, help="RECEIVED_ROOT/<condition>")
    ap.add_argument("--faultlogs", required=True, help="FAULTLOG_ROOT/<condition>")
    ap.add_argument("--runs", default="", help="comma-separated run IDs (default every received run)")
    ap.add_argument("--out", default=None)
    ap.add_argument("--workers", type=int, default=4)
    a = ap.parse_args(argv)
    runs = [r for r in a.runs.split(",") if r] or sorted(
        d for d in os.listdir(a.received) if any(os.path.exists(os.path.join(a.received, d, "shipper", f))
                                                 for f in ("received.jsonl", "received.jsonl.gz")))
    from concurrent.futures import ProcessPoolExecutor
    args = [(os.path.join(a.base, r), os.path.join(a.received, r, "shipper", "received.jsonl"),
             os.path.join(a.faultlogs, r), os.path.join(a.received, r, "transport.json")) for r in runs]
    with ProcessPoolExecutor(max_workers=max(1, a.workers)) as pool:
        res = dict(zip(runs, pool.map(_check, args)))
    out = {"ok": all(v["ok"] for v in res.values()), "runs": res}
    text = json.dumps(out, indent=2, sort_keys=True)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    print(json.dumps({"ok": out["ok"], "runs": len(res),
                      "failed": [r for r, v in res.items() if not v["ok"]]}))
    return 0 if out["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
