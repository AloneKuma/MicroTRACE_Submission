"""Label split of the scored links per kind pair, before a build (B9b).

Link nuisance (link_nuisance.py) fails when the step kinds at a link's two
ends predict its label. This script computes the split it will see from the
catalogue and a run matrix, so a catalogue change can be checked before
anything is built: for every scenario, the links link nuisance scores (a
checked witness, not a continuity link, PRESENT or ABSENT, a PRESENT finding
at both ends: D-20), times the scenario's runs in the matrix.

Truth downgrades some of those links per run (gaps, degraded profiles,
post-compromise epochs: D-23), which the catalogue cannot show. With
--build, each link is weighted by its decidable share in a built split
(truth files only; base.pb is not read): the PRESENT or ABSENT links truth
kept with a PRESENT opportunity at both ends, over the runs of its
scenario. A link the build does not know (new in the catalogue) takes the
mean share of the built links of its scenario that share an endpoint with
it, else of its scenario; such rows are marked "~".

Pass: every pair with at least --min-links links has a PRESENT share within
[--low, --high] (default 30-70 %).

    python src/scripts/pilot/link_pair_balance.py \\
        --matrix spec/generator/run-matrix.pilot-multistep.yaml \\
        [--build datasets/generated/pilot-multistep] [--by-link]
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "src" / "python"))

CONTINUITY_PREFIXES = ("same-process continuity", "same-socket continuity", "benign continuity")
CHECKED_WITNESSES = {"PROCESS_ANCESTRY", "NETWORK_FLOW", "REQUEST_IDENTITY",
                     "CREDENTIAL_READ_TO_USE"}
# Known exceptions, reported but not failing. read_token_file -> egress_transfer:
# the true link token theft 3 -> 10, added by review fix A (2026-10-28), has no
# ABSENT pair of its kind; fix B adds a real one (a token read and a
# non-descendant's egress, both with findings).
KNOWN_UNBALANCED = {("read_token_file", "egress_transfer")}


def workload_key_only(lk: dict) -> bool:
    """D-30: a REQUEST_IDENTITY nonlink resting on a workload-set request ID
    alone, ABSENT by construction (a workload key never confirms a link);
    reported apart, as continuity links are."""
    return (lk["witness"] == "REQUEST_IDENTITY" and lk.get("expected", "PRESENT") == "ABSENT"
            and list(lk.get("shared_keys", [])) == ["request_id"])


def scored_links(scenario: dict) -> list:
    """(from, to, from kind, to kind, label) of the links link nuisance scores."""
    kinds = {st["step"]: st["action"] for st in scenario["steps"]}
    found = {st["step"] for st in scenario["steps"]
             if any(e.get("state") == "PRESENT" for e in st.get("expects") or [])}
    out = []
    for lk in scenario.get("links", []):
        label = lk.get("expected", "PRESENT")
        if (lk["witness"] not in CHECKED_WITNESSES or label == "UNOBSERVABLE"
                or lk["from"] not in found or lk["to"] not in found
                or lk.get("reason", "").startswith(CONTINUITY_PREFIXES) or workload_key_only(lk)):
            continue
        out.append((lk["from"], lk["to"], kinds[lk["from"]], kinds[lk["to"]], label))
    return out


def matrix_runs(matrix: dict) -> Counter:
    """Runs per scenario in the matrix (a run lists its scenarios comma-joined)."""
    return Counter(s for r in matrix["runs"] for s in r["scenario_id"].split(","))


def built_shares(build: Path) -> tuple:
    """Per (scenario, from step, to step): decidable count and the runs of the
    scenario, from a built split's truth files; and the links truth knows."""
    import mtgen  # noqa: F401 — puts the generated protos on the path
    from mtgen.verify import _load_truth_files
    from microtrace.v0 import dataset_pb2

    decidable, known, runs = Counter(), set(), Counter()
    for mf in sorted(build.glob("*/manifest.json")):
        actions, opps, links = _load_truth_files(mf.parent)
        by_seq = {a.action_seq: a for a in actions}
        has_opp = {o.action_seq for o in opps if o.expected_state == dataset_pb2.PRESENT}
        for scen in {a.scenario_id for a in actions}:
            runs[scen] += 1
        for lk in links:
            a, b = by_seq[lk.from_action_seq], by_seq[lk.to_action_seq]
            key = (a.scenario_id, a.step_label, b.step_label)
            known.add(key)
            if (lk.expected_state in (dataset_pb2.PRESENT, dataset_pb2.ABSENT)
                    and lk.from_action_seq in has_opp and lk.to_action_seq in has_opp):
                decidable[key] += 1
    return decidable, known, runs


def balance(catalogue: dict, n_runs: Counter, shares=None) -> tuple:
    """Per (from kind, to kind): [PRESENT, ABSENT] link counts; and the rows
    (scenario, from, to, label, count, estimated) behind them."""
    pairs = defaultdict(lambda: [0.0, 0.0])
    rows = []
    for s in catalogue["scenarios"]:
        n = n_runs.get(s["id"], 0)
        if not n:
            continue
        links = scored_links(s)
        rate, est = {}, set()
        if shares is not None:
            decidable, known, runs = shares
            built = runs.get(s["id"], 0)
            for f, t, *_ in links:
                key = (s["id"], str(f), str(t))
                if built and key in known:
                    rate[(f, t)] = decidable[key] / built
            for f, t, *_ in links:
                if (f, t) in rate:
                    continue
                near = [r for (a, b), r in rate.items() if {a, b} & {f, t}]
                pool = near or list(rate.values())
                rate[(f, t)] = sum(pool) / len(pool) if pool else 1.0
                est.add((f, t))
        for f, t, fk, tk, label in links:
            c = n * rate.get((f, t), 1.0)
            pairs[(fk, tk)][label == "ABSENT"] += c
            rows.append((s["id"], f, t, fk, tk, label, c, (f, t) in est))
    return pairs, rows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--matrix", type=Path, required=True)
    ap.add_argument("--catalogue", type=Path,
                    help="default: catalogue.v0.yaml and the overlays the matrix runs name")
    ap.add_argument("--build", type=Path, help="built split whose truth gives each link's decidable share")
    ap.add_argument("--min-links", type=int, default=10)
    ap.add_argument("--low", type=float, default=0.30)
    ap.add_argument("--high", type=float, default=0.70)
    ap.add_argument("--by-link", action="store_true", help="list the links behind each pair")
    ap.add_argument("--json", type=Path)
    args = ap.parse_args(argv)

    matrix = yaml.safe_load(args.matrix.read_text(encoding="utf-8"))
    if args.catalogue:
        catalogue = yaml.safe_load(args.catalogue.read_text(encoding="utf-8"))
    else:
        import mtgen  # noqa: F401 — puts the generated protos on the path
        from mtgen.specs import catalogue_of_runs
        catalogue = catalogue_of_runs(matrix["runs"])
    shares = built_shares(args.build) if args.build else None
    pairs, rows = balance(catalogue, matrix_runs(matrix), shares)

    table, out_of_range = [], []
    print(f"{'pair':<46} {'PRESENT':>8} {'ABSENT':>8} {'P %':>6}")
    for (fk, tk), (p, a) in sorted(pairs.items(), key=lambda kv: -sum(kv[1])):
        n = p + a
        share = p / n if n else 0.0
        bad = n >= args.min_links and not args.low <= share <= args.high
        known = bad and (fk, tk) in KNOWN_UNBALANCED
        if bad and not known:
            out_of_range.append(f"{fk}->{tk}")
        table.append({"from_kind": fk, "to_kind": tk, "PRESENT": round(p, 1),
                      "ABSENT": round(a, 1), "present_share": round(share, 3),
                      **({"known_exception": True} if known else {})})
        print(f"{fk + '->' + tk:<46} {p:8.1f} {a:8.1f} {100 * share:6.1f}"
              + ("  OUT OF RANGE (known exception)" if known else "  OUT OF RANGE" if bad else ""))
        if args.by_link:
            for s, f, t, rfk, rtk, label, c, est in rows:
                if (rfk, rtk) == (fk, tk):
                    print(f"    {'~' if est else ' '} {s} {f}->{t} {label} {c:.1f}")
    totals = Counter()
    for p, a in pairs.values():
        totals["PRESENT"] += p
        totals["ABSENT"] += a
    apart = sum(matrix_runs(matrix).get(s["id"], 0) for s in catalogue["scenarios"]
                for lk in s.get("links", []) if workload_key_only(lk))
    print(f"total PRESENT {totals['PRESENT']:.1f} ABSENT {totals['ABSENT']:.1f}; "
          f"out of range: {out_of_range or 'none'}; "
          f"workload-key-only nonlinks reported apart (D-30): {apart}")
    if args.json:
        args.json.write_text(json.dumps({"pairs": table, "out_of_range": out_of_range},
                                        indent=2), encoding="utf-8")
    return 1 if out_of_range else 0


if __name__ == "__main__":
    sys.exit(main())
