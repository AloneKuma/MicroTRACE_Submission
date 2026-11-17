"""How many true links can SAGE's grouping reach at all? (dev data, 2026-11-17)

    python experiments/sanity/sage_ceiling.py --data PILOT_DIR --split SPLIT.json --go-out GO_OUT --out x.json

SAGE groups alerts by the unordered (source, destination) endpoint pair (frozen mapping
spec/baselines/sage-mapping.v2.yaml, mtcore.baselines.sage.alerts.select). A link can only be
proposed by SAGE when some finding on its from-action and some finding on its to-action get
the same endpoint pair. For every scored PRESENT link of the PILOT SCORE half (the links in
link recall), this counts: both ends detected by a finding, and an endpoint pair shared.
Same findings as the paper's SAGE rows (GO v2 SCORE outputs). No SAGE run, no parameter.
"""
import argparse
import json
import os
from collections import Counter

import mtcore  # noqa: F401
from mtcore.baselines.sage import alerts as A
from mtcore.baselines.sage import mapping as M
from mtcore.harness import score as S
from sanity_dev import load_output  # same folder


def pair_of(f, mp):
    row = mp.rows.get(f.finding_type)
    if row is None:
        return None
    src = A.select(f, row.source)
    if src is None:
        return None
    dst = A.select(f, row.destination, source=src)
    return None if dst is None else frozenset((src, dst))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--split", required=True)
    ap.add_argument("--go-out", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    mp = M.load()
    c, why = Counter(), Counter()
    for r in sorted(json.load(open(a.split))["score"]):
        truth = S.Truth.load(os.path.join(a.data, r, "restricted"))
        out, _ = load_output(os.path.join(a.go_out, "runs", r, "output.jsonl.gz"))
        acts = S.finding_actions(truth, out)
        on_action = {}
        for fid, aset in acts.items():
            for x in aset:
                on_action.setdefault(x, []).append(out.findings[fid])
        scored = S.scored_link_ids(truth)
        for lk in truth.links:
            if lk.link_id not in scored or lk.expected_state != S.PRESENT:
                continue
            c["links"] += 1
            fa, fb = on_action.get(lk.from_action_seq, []), on_action.get(lk.to_action_seq, [])
            if not fa or not fb:
                why["an end has no finding"] += 1
                continue
            c["both_ends_found"] += 1
            pa = {pair_of(f, mp) for f in fa} - {None}
            pb = {pair_of(f, mp) for f in fb} - {None}
            if pa & pb:
                c["same_endpoint_pair"] += 1
            else:
                kinds = (sorted({f.finding_type for f in fa})[0], sorted({f.finding_type for f in fb})[0])
                why[f"pair differs {kinds[0]}->{kinds[1]}"] += 1
    res = {"links": c["links"], "both_ends_found": c["both_ends_found"],
           "same_endpoint_pair": c["same_endpoint_pair"],
           "reachable_share": round(c["same_endpoint_pair"] / c["links"], 4),
           "top_reasons": why.most_common(15)}
    json.dump(res, open(a.out, "w"), indent=1)
    print(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
