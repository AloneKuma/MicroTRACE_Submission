"""ORTHRUS reconstruction seeded with our findings' evidence nodes (Exp. 2 main row).

Runs in the PIDSMaker container, on graphs from its builder (mt_construct.py),
with the authors' tracer unchanged: DEPIMPACT from ubc-provenance/orthrus e7f25df,
component + degree as in their config/orthrus.yml. That pair reads the graph and
the seed only, so no model is involved. It takes the place of their get_tasks(),
which seeds from detected nodes.

    python seeded_tracing.py --seeds seeds.json --graphs NX_DIR --orthrus-src DIR --out traced.json

A seed absent from a run's graph is skipped and counted: event_map.csv also
lists nodes of events that are no edges, and DEPIMPACT raises KeyError on them.
"""
import argparse
import contextlib
import glob
import io
import json
import multiprocessing
import os
import sys
import time

import torch


def trace_run(job):
    run_id, date, seeds, graphs_dir = job
    from depimpact_utils import DEPIMPACT
    files = sorted(glob.glob(os.path.join(graphs_dir, f"graph_{date}", "*")))
    graphs = [torch.load(f) for f in files]
    cache, skipped, traced, t0 = {}, 0, {}, time.time()
    for fid, nodes in sorted(seeds.items()):
        out = set()
        for n in nodes:
            found = False
            for gi, g in enumerate(graphs):
                if n not in g:
                    continue
                found = True
                if (gi, n) not in cache:
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        cache[(gi, n)] = DEPIMPACT(g, str(n), {}, "component", "degree").run()
                out |= cache[(gi, n)]
            skipped += not found
        traced[fid] = sorted(out)
    return run_id, {"traced": traced, "graphs": len(files), "seed_nodes_absent": skipped,
                    "traces": len(cache), "seconds": round(time.time() - t0, 2)}


def main():
    ap = argparse.ArgumentParser(description="Seeded ORTHRUS reconstruction.")
    ap.add_argument("--seeds", required=True)
    ap.add_argument("--graphs", required=True, help="PIDSMaker construction nx/ directory")
    ap.add_argument("--orthrus-src", required=True, help="directory with the authors' depimpact_utils.py")
    ap.add_argument("--out", required=True)
    ap.add_argument("--workers", type=int, default=4)
    a = ap.parse_args()
    sys.path.insert(0, a.orthrus_src)
    with open(a.seeds) as fh:
        seeds = json.load(fh)
    jobs = [(r, v["date"], v["seeds"], a.graphs) for r, v in sorted(seeds.items())]
    with multiprocessing.Pool(a.workers) as pool:
        out = {}
        for i, (r, res) in enumerate(pool.imap_unordered(trace_run, jobs), 1):
            out[r] = res
            print(f"{i}/{len(jobs)} {r} graphs {res['graphs']} traces {res['traces']} "
                  f"absent {res['seed_nodes_absent']} {res['seconds']} s", flush=True)
    with open(a.out, "w") as fh:
        json.dump(out, fh)


if __name__ == "__main__":
    main()
