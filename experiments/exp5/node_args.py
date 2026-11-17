"""Shipper node IDs for an Exp. 5 input: the eBPF node_id of each node stream (the agents tie a
receiver gap's "node=<id>" scope to eBPF events by it, agents/completeness.py; the generator's file
names cut the UID short), or the file name for a stream without eBPF (the off-node observers).
Same rule as mtcore/exp3/base.py shipper_node_id (found 2026-11-16).

    python node_args.py --flag input <run dir>               # --input <id>=<run>/shipper/<n>.jsonl ...
    python node_args.py --flag prefill <run dir> <hist dir>  # --prefill <id>=<hist>/<n>.jsonl, ids of <run>
Prints the arguments on one line.
"""
import glob
import json
import os
import sys


def node_id(path):
    ids = set()
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if '"ebpf"' not in line:
                continue
            env = json.loads(line).get("envelope") or {}
            ne = env.get("normalized_event") or env.get("normalizedEvent") or {}
            e = ne.get("ebpf") or {}
            nid = e.get("node_id") or e.get("nodeId")
            if nid:
                ids.add(nid)
    if len(ids) > 1:
        sys.exit(f"{path}: eBPF records of several nodes {sorted(ids)[:3]}")
    return ids.pop() if ids else os.path.basename(path)[:-len(".jsonl")]


def main(argv):
    flag, run = argv[1], argv[2]
    files = sorted(glob.glob(os.path.join(run, "shipper", "*.jsonl")))
    if not files:
        sys.exit(f"no shipper files in {run}")
    ids = {os.path.basename(f)[:-len(".jsonl")]: node_id(f) for f in files}
    if len(set(ids.values())) != len(ids):
        sys.exit(f"duplicate node IDs in {run}: {ids}")
    out = []
    if flag == "input":
        out = [f"--input {ids[n]}={f}" for n, f in zip(ids, files)]
    else:
        hist = argv[3]
        for f in sorted(glob.glob(os.path.join(hist, "*.jsonl"))):
            n = os.path.basename(f)[:-len(".jsonl")]
            if n in ids:
                out.append(f"--prefill {ids[n]}={f}")
    print(" ".join(out))


if __name__ == "__main__":
    main([sys.argv[0]] + sys.argv[2:] if sys.argv[1:2] == ["--flag"] else sys.argv)
