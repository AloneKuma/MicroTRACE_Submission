"""Choice per RULE-veto.md, plus the disclosed side numbers. Usage: veto_select.py <ml dir>"""
import glob, json, os, sys
from collections import Counter

W = sys.argv[1]
LARGE = "226278d9-aff7-5a1d-8778-96ee1ee40480"
ARMS = {"qmax_gnone": (os.path.join(W, "cv", "qmax_gnone"), None),
        "qmax_veto0.5": (os.path.join(W, "cv-veto", "qmax_veto0.5"), 0.5),
        "qmax_veto0.25": (os.path.join(W, "cv-veto", "qmax_veto0.25"), 0.25),
        "qmax_veto0.1": (os.path.join(W, "cv-veto", "qmax_veto0.1"), 0.1)}
runs = json.load(open(os.path.join(W, "folds.json")))["all"]


def f1(tp, fp, fn):
    return round(2 * tp / (2 * tp + fp + fn), 4) if tp else 0.0


def pool(d, skip=()):
    c, per = Counter(), {}
    n = 0
    for r in runs:
        if r in skip:
            continue
        s = json.load(open(os.path.join(d, "runs", r, "score.json")))
        n += 1
        o, l = s["findings"]["overall"], s["links"]
        for k in ("tp", "fp", "fn"):
            c["f" + k] += o[k]
            c["l" + k] += l[k]
        for t, v in s["findings"]["per_type"].items():
            p = per.setdefault(t, Counter())
            p["tp"] += v["tp"]; p["fp"] += v["fp"]
    return n, c, per


rows, side = [], {}
for name, (d, av) in ARMS.items():
    n, c, per = pool(d)
    if n != len(runs):
        raise SystemExit(f"{name}: {n} of {len(runs)} runs scored")
    _, c2, _ = pool(d, skip=(LARGE,))
    rows.append({"config": name, "alpha_veto": av, "findings_f1": f1(c["ftp"], c["ffp"], c["ffn"]),
                 "links_f1": f1(c["ltp"], c["lfp"], c["lfn"]), "fp": c["ffp"], "tp": c["ftp"]})
    side[name] = {"without_large": {"findings_f1": f1(c2["ftp"], c2["ffp"], c2["ffn"]),
                                    "links_f1": f1(c2["ltp"], c2["lfp"], c2["lfn"])},
                  "per_type": {t: dict(v) for t, v in per.items() if t in ("B3", "H1")}}
base = side["qmax_gnone"]["per_type"]
for name in side:
    side[name]["removed_vs_gnone"] = {t: {"tp": base[t]["tp"] - v["tp"], "fp": base[t]["fp"] - v["fp"]}
                                      for t, v in side[name]["per_type"].items()}
best = max(r["findings_f1"] for r in rows)
near = [r for r in rows if r["findings_f1"] >= best - 0.005]
near.sort(key=lambda r: (-r["links_f1"], r["alpha_veto"] is not None, -(r["alpha_veto"] or 0)))
out = {"rule": "RULE-veto.md", "candidates": rows, "within_0.005": [r["config"] for r in near],
       "chosen": near[0], "side": side}
json.dump(out, open(os.path.join(W, "selection-veto.json"), "w"), indent=1)
print(json.dumps({"chosen": near[0]["config"], "candidates": [(r["config"], r["findings_f1"], r["links_f1"])
                                                              for r in rows]}))
