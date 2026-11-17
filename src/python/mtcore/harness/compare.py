"""Compare a crash run X with the no-crash reference A (Exp. 5 part A).

    python -m mtcore.harness.compare diff --reference A.jsonl --run X.jsonl --noise A2.jsonl [--band 2]
    python -m mtcore.harness.compare tally result1.json result2.json ...

Per field, `missing` (in A, not in X) and `extra` (in X, not in A). An item
that also differs between A and A' (either direction) is noise: listed under
`noise`, never counted against X.

- Band 1 (outage below max_idle; any GO or TGS failure): the sealed
  projections are identical on every field but current_excluded_sources.
- Band 2 (above max_idle, within the posting horizon): X records an
  exclusion A does not have, and X's latest projection equals A's on every
  field but the exclusion lists, which are reported. A's latest projection
  is used, not its sealed one: they are equal unless A itself amended after
  seal (a post-seal merge or late finding), and then only the latest one can
  match a correct X. `reference_amended` says whether that happened.
- Band 3 (beyond the posting horizon, or a shipper spool overflow): scored
  separately; differences are reported, verdict "separate".

Paths, timestamps and open-record counts are reported, never scored.
Exit status of `diff`: 0 identical, 1 different, 3 separate.
"""
import argparse
import json
import math
import sys

from mtcore.harness import project as P

BAND1_FIELDS = tuple(f for f in P.FIELDS if f != "current_excluded_sources")
BAND2_FIELDS = tuple(f for f in P.FIELDS if f not in P.EXCLUSION_FIELDS)


def band_for(outage_s, max_idle_s, posting_horizon_s, component="receiver"):
    """Outage band (1, 2, 3). GO and TGS failures are always band 1: nothing
    excludes them from a watermark."""
    if component in ("go", "tgs") or outage_s < max_idle_s:
        return 1
    return 2 if outage_s <= posting_horizon_s else 3


def diff(ref, run, fields):
    return {f: {"missing": ref[f] - run[f], "extra": run[f] - ref[f]} for f in fields}


def _counted(d, noise):
    out = {}
    for f, v in d.items():
        nz = noise.get(f, frozenset())
        out[f] = {"missing": sorted(v["missing"] - nz), "extra": sorted(v["extra"] - nz),
                  "noise": {"missing": sorted(v["missing"] & nz), "extra": sorted(v["extra"] & nz)}}
    return out


def _noise(ref, alt, fields):
    if alt is None:
        return {}
    return {f: ref[f] ^ alt[f] for f in fields}


def _clean(fields):
    return all(not v["missing"] and not v["extra"] for v in fields.values())


def _report(ref, run):
    rt, xt = ref.report["timestamps"], run.report["timestamps"]
    times = {iid: {k: [rt[iid][k], xt[iid][k]] for k in rt[iid] if rt[iid][k] != xt[iid][k]}
             for iid in sorted(set(rt) & set(xt))}
    rp, xp = set(ref.report["paths"]), set(run.report["paths"])
    return {"paths": {"missing": sorted(rp - xp), "extra": sorted(xp - rp)},
            "timestamps": {k: v for k, v in times.items() if v},
            "open_records": {"reference": ref.report["open_records"], "run": run.report["open_records"]}}


def compare(ref, run, alt=None, band=1):
    """ref, run, alt: Projection of A, X and A'. Returns a JSON-able dict."""
    out = {"band": band, "noise_floor": alt is not None, "reference_amended": ref.sealed != ref.latest,
           "report": _report(ref, run)}
    if band == 1:
        fields = _counted(diff(ref.sealed, run.sealed, BAND1_FIELDS),
                          _noise(ref.sealed, alt.sealed if alt else None, BAND1_FIELDS))
        out.update(view="sealed", fields=fields, identical=_clean(fields))
    else:
        fields = _counted(diff(ref.latest, run.latest, BAND2_FIELDS),
                          _noise(ref.latest, alt.latest if alt else None, BAND2_FIELDS))
        excl = {"at_seal_excluded_sources": diff(ref.sealed, run.sealed, ["at_seal_excluded_sources"]),
                "current_excluded_sources": diff(ref.latest, run.latest, ["current_excluded_sources"])}
        excl = {f: {k: sorted(v) for k, v in d[f].items()} for f, d in excl.items()}
        recorded = any(v["extra"] for v in excl.values())
        out.update(view="latest", fields=fields, exclusions=excl, exclusion_recorded=recorded,
                   identical=recorded and _clean(fields))
    if band == 3:
        out["verdict"] = "separate"
    else:
        out["verdict"] = "identical" if out["identical"] else "different"
    return out


def _binom_cdf(f, n, p):
    return sum(math.comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(f + 1))


def failure_upper_bound(failures, n, conf=0.95):
    """Exact one-sided Clopper-Pearson upper bound on the failure rate."""
    if n <= 0:
        raise ValueError("n must be positive")
    if failures >= n:
        return 1.0
    lo, hi = failures / n, 1.0
    for _ in range(200):
        mid = (lo + hi) / 2
        if _binom_cdf(failures, n, mid) > 1 - conf:
            lo = mid
        else:
            hi = mid
    return hi


def k_of_n(k, n, conf=0.95):
    """'k of N identical' with the upper bound on the failure rate
    (0 failures of N gives 1 - 0.05^(1/N), about 3/N)."""
    return {"identical": k, "runs": n, "failures": n - k, "confidence": conf,
            "failure_rate_upper": failure_upper_bound(n - k, n, conf)}


def tally(results, conf=0.95):
    """k of N over compare() outputs; band-3 ('separate') runs are counted apart."""
    scored = [r for r in results if r["verdict"] != "separate"]
    if not scored:
        return {"runs": 0, "separate": len(results)}
    out = k_of_n(sum(r["verdict"] == "identical" for r in scored), len(scored), conf)
    out["separate"] = len(results) - len(scored)
    return out


def _load_tgs(path):
    if not path:
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Compare an Exp. 5 run with its reference.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("diff")
    d.add_argument("--reference", required=True, help="run A output (JSONL)")
    d.add_argument("--run", required=True, help="run X output (JSONL)")
    d.add_argument("--noise", help="run A' output (JSONL), for the noise floor")
    d.add_argument("--band", type=int, choices=(1, 2, 3), default=1)
    for who in ("reference", "run", "noise"):
        d.add_argument(f"--tgs-{who}", help=f"TGS hashes of {who} as a JSON object {{name: hash}}")
    t = sub.add_parser("tally")
    t.add_argument("results", nargs="+", help="diff outputs (JSON)")
    t.add_argument("--confidence", type=float, default=0.95)
    a = ap.parse_args(argv)
    if a.cmd == "tally":
        results = []
        for path in a.results:
            with open(path, encoding="utf-8") as fh:
                results.append(json.load(fh))
        print(json.dumps(tally(results, a.confidence), sort_keys=True))
        return 0
    ref = P.project_file(a.reference, _load_tgs(a.tgs_reference))
    run = P.project_file(a.run, _load_tgs(a.tgs_run))
    alt = P.project_file(a.noise, _load_tgs(a.tgs_noise)) if a.noise else None
    res = compare(ref, run, alt, a.band)
    print(json.dumps(res, sort_keys=True))
    return {"identical": 0, "different": 1, "separate": 3}[res["verdict"]]


if __name__ == "__main__":
    sys.exit(main())
