"""Choice per RULE-confirmB3.md, plus side numbers and the priority report. Usage: confirm_select.py <ml dir>"""
import json, os, sys
from collections import Counter

W = sys.argv[1]
LARGE = "226278d9-aff7-5a1d-8778-96ee1ee40480"
ARMS = [("qmax_gnone", os.path.join(W, "cv", "qmax_gnone")),
        ("qmax_veto0.5", os.path.join(W, "cv-veto", "qmax_veto0.5")),
        ("qmax_veto0.25", os.path.join(W, "cv-veto", "qmax_veto0.25")),
        ("qmax_veto0.1", os.path.join(W, "cv-veto", "qmax_veto0.1")),
        ("qmax_confirmB3", os.path.join(W, "cv-veto", "qmax_confirmB3"))]   # tie-break order (3)
runs = json.load(open(os.path.join(W, "folds.json")))["all"]
f1 = lambda tp, fp, fn: round(2 * tp / (2 * tp + fp + fn), 4) if tp else 0.0


def pool(d, skip=()):
    c, per, n = Counter(), {}, 0
    for r in runs:
        if r in skip:
            continue
        s = json.load(open(os.path.join(d, "runs", r, "score.json")))
        n += 1
        o, l = s["findings"]["overall"], s["links"]
        for k in ("tp", "fp", "fn"):
            c["f" + k] += o[k]; c["l" + k] += l[k]
        for t, v in s["findings"]["per_type"].items():
            p = per.setdefault(t, Counter()); p["tp"] += v["tp"]; p["fp"] += v["fp"]
    return n, c, per


rows, side = [], {}
for order, (name, d) in enumerate(ARMS):
    n, c, per = pool(d)
    if n != len(runs):
        raise SystemExit(f"{name}: {n} of {len(runs)} runs scored")
    _, c2, _ = pool(d, skip=(LARGE,))
    rows.append({"config": name, "order": order, "findings_f1": f1(c["ftp"], c["ffp"], c["ffn"]),
                 "links_f1": f1(c["ltp"], c["lfp"], c["lfn"]), "tp": c["ftp"], "fp": c["ffp"], "fn": c["ffn"]})
    side[name] = {"without_large": {"findings_f1": f1(c2["ftp"], c2["ffp"], c2["ffn"]),
                                    "links_f1": f1(c2["ltp"], c2["lfp"], c2["lfn"])},
                  "per_type": {t: dict(v) for t, v in per.items() if t in ("B1", "B3", "H1")}}
base = side["qmax_gnone"]["per_type"]
for name in side:
    side[name]["removed_vs_gnone"] = {t: {"tp": base[t]["tp"] - v["tp"], "fp": base[t]["fp"] - v["fp"]}
                                      for t, v in side[name]["per_type"].items()}
best = max(r["findings_f1"] for r in rows)
near = sorted([r for r in rows if r["findings_f1"] >= best - 0.005], key=lambda r: (-r["links_f1"], r["order"]))

# Priority report: precision above vs below gamma(0.001), per type, confirmB3 arm.
folds = json.load(open(os.path.join(W, "folds.json")))
prio = {}
for F in ("A", "B"):
    g = json.load(open(os.path.join(W, "models", f"fold{F}-max", "train.json")))["gamma"]["0.001"]
    for r in folds[F]:
        rd = os.path.join(W, "cv-veto", "qmax_confirmB3", "runs", r)
        false = set(json.load(open(os.path.join(rd, "score.json")))["findings"]["false_findings"])
        for f in json.load(open(os.path.join(rd, "findings.json"))):
            t, s = f["findingType"], f["anomalyScore"]
            if t not in ("B1", "B3", "H1"):
                continue
            band = "unscored" if s is None else ("above" if s >= g[t] else "below")
            p = prio.setdefault(t, {}).setdefault(band, Counter())
            p["n"] += 1; p["false"] += f["findingId"] in false
for t in prio:
    for band, p in prio[t].items():
        p["precision"] = round(1 - p["false"] / p["n"], 3) if p["n"] else None
        prio[t][band] = dict(p)
out = {"rule": "RULE-confirmB3.md", "candidates": rows, "within_0.005": [r["config"] for r in near],
       "chosen": near[0], "side": side, "priority": prio}
json.dump(out, open(os.path.join(W, "selection-confirm.json"), "w"), indent=1)
print(json.dumps({"chosen": near[0]["config"], "candidates": [(r["config"], r["findings_f1"], r["links_f1"]) for r in rows]}))
