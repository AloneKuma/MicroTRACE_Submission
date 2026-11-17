"""PILOT does not change with REQUEST_IDENTITY on (exp2-conflict-origin-cases-plan P2).

For each run, the GO is replayed on the run's GO inputs and the agents'
findings of an earlier offline output (twin safety's), with the
REQUEST_IDENTITY gate off (the fitted parameters) and on, under the full
design and under No-Origin. Pass: per configuration, the witness and
incident records are the same with the gate on as with it off. Every request
ID on PILOT is gateway-minted and unique per request, so the only pairs the
key can propose are two findings on one gateway event, which never support
a witness.

Runs without a cached output are skipped and listed; the check fails if it
replayed no run, or not --expect runs when given (a wrong cache directory
must not pass on nothing).

    python src/scripts/pilot/request_identity_rescore.py RUNS_DIR CACHED_OUTPUT_DIR \\
        --params FIT.yaml [--json out.json] [--shard I/N] [--expect N]
"""
import argparse
import json
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "src" / "python"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import cached_output  # noqa: E402

from ablation_cases import _findings  # noqa: E402
from mtcore.harness import offline as OFF  # noqa: E402
from mtcore.orchestrator.engine import Engine  # noqa: E402
from mtcore.orchestrator.keys import REQUEST_IDENTITY  # noqa: E402
from mtcore.orchestrator.params import OrchParams  # noqa: E402

CONFIGS = ("full", "no_origin")


def configs(base):
    gates = dict(base.params.data["orchestrator"].get("gates") or {})
    out = {}
    for name in CONFIGS:
        abl = [] if name == "full" else [name]
        for on in (False, True):
            out[(name, on)] = base.with_overrides(gates=dict(gates, REQUEST_IDENTITY=on), ablations=abl)
    return out


def records(engine):
    """Sorted serialized witness and incident records of a finished engine."""
    out = []
    for _t, _k, env in engine.drain():
        if env.HasField("witness") or env.HasField("incident"):
            out.append(env.SerializeToString(deterministic=True))
    return sorted(out)


def run_one(run, cached, params):
    engines = {k: Engine(p) for k, p in params.items()}
    offsets = Counter()
    for topic, env in OFF.read_shipper(str(run)):
        if topic in OFF.GO_INPUTS:
            for e in engines.values():
                e.feed(env, topic, 0, offsets[topic])
            offsets[topic] += 1
    for env in _findings(cached):
        for e in engines.values():
            e.feed(env, "findings.v0", 0, offsets["findings.v0"])
        offsets["findings.v0"] += 1
    recs, ri = {}, {}
    for k, e in engines.items():
        e.finish()
        OFF._hook(e, OFF._now(e, 0))
        ri[k] = sum(1 for d in e.decisions if d[2] == REQUEST_IDENTITY)
        recs[k] = records(e)
    res = {}
    for name in CONFIGS:
        off, on = recs[(name, False)], recs[(name, True)]
        res[name] = {"records": len(off), "same": off == on,
                     "ri_pairs_tested": ri[(name, True)], "ri_pairs_gate_off": ri[(name, False)]}
    return res


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("runs_dir", type=Path)
    ap.add_argument("cached_dir", type=Path, help="offline outputs holding the agents' findings")
    ap.add_argument("--params", required=True)
    ap.add_argument("--json", type=Path)
    ap.add_argument("--shard", default="0/1", help="I/N: only every N-th run, from I (merge the JSONs after)")
    ap.add_argument("--expect", type=int, help="runs this shard must replay")
    a = ap.parse_args(argv)
    shard, shards = (int(x) for x in a.shard.split("/"))
    params = configs(OrchParams.load(a.params))
    per_run, total, missing = {}, Counter(), []
    for n, mf in enumerate(sorted(a.runs_dir.glob("*/manifest.json"))):
        if n % shards != shard:
            continue
        run = mf.parent
        cached = cached_output.find(a.cached_dir, run.name)
        if cached is None:
            missing.append(run.name)
            continue
        r = run_one(run, cached, params)
        per_run[run.name] = r
        total["runs"] += 1
        for name in CONFIGS:
            total[f"{name}_records"] += r[name]["records"]
            total[f"{name}_ri_pairs_tested"] += r[name]["ri_pairs_tested"]
            total[f"{name}_ri_pairs_gate_off"] += r[name]["ri_pairs_gate_off"]
            total[f"{name}_changed_runs"] += not r[name]["same"]
        print(run.name, json.dumps(r), flush=True)
    changed = [r for r, v in per_run.items() if not all(v[c]["same"] for c in CONFIGS)]
    replayed = len(per_run)
    count_ok = replayed > 0 and (a.expect is None or replayed == a.expect)
    result = {"total": dict(total), "changed_runs": changed, "replayed": replayed, "expect": a.expect,
              "no_cached_output": missing, "passed": count_ok and not changed, "runs": per_run}
    print(json.dumps({k: result[k] for k in ("total", "changed_runs", "replayed", "expect", "passed")}, indent=2))
    if not count_ok:
        print(f"FAIL: replayed {replayed} runs (expected {a.expect if a.expect is not None else 'at least 1'}); "
              f"{len(missing)} without a cached output in {a.cached_dir}", file=sys.stderr)
    if a.json:
        a.json.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
