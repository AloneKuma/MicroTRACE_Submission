"""Sensitive cases per ablation (exp2-gaps-plan B8).

For each run, the GO is replayed on the run's GO inputs and the agents'
findings of an earlier offline output (twin safety's), once with the full
design and once per ablation switch, all from one read of the run. A case
is a labelled finding pair whose witness decision the switch changes:

  - a scored link (PRESENT or ABSENT at both ends, score.scored_link_ids) for
    which some witness between the two findings has another status, or
    exists under only one of the two configurations;
  - for No-Distinct, also a pair of findings of one action (the switch
    links two findings of one action; scoring reports them as intra-action);
  - for No-Tactic (which changes path ranks, not links), a ranked path that
    only one configuration keeps or that both keep at another rank, split
    into helps, hurts and reorder (tactic_cases; per run as
    "no_tactic:<kind>").

Pass: at least --min cases per ablation (default 20) over the runs given.
Runs without a cached output are skipped and listed (PILOT caches only its
SCORE runs); the check fails if it replayed no run, or not --expect runs
when given.

    python src/scripts/pilot/ablation_cases.py RUNS_DIR CACHED_OUTPUT_DIR \\
        --params FIT.yaml [--ablation no_witness ...] [--json out.json]
"""
import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "src" / "python"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import cached_output  # noqa: E402

from google.protobuf import json_format  # noqa: E402

from mtcore.harness import offline as OFF  # noqa: E402
from mtcore.harness import score as S  # noqa: E402
from mtcore.orchestrator.engine import SCHEMA_MAJOR, Engine  # noqa: E402
from mtcore.orchestrator.params import OrchParams  # noqa: E402
from microtrace.v0 import envelope_pb2, finding_pb2, witness_pb2  # noqa: E402

PAPER = ("no_witness", "no_conflict", "no_distinct", "no_origin", "no_tactic")
STATUS = witness_pb2.WitnessStatus


def _findings(path):
    tag = '"findings.v0"'
    out = []
    with cached_output.open_text(path) as fh:
        for line in fh:
            if tag in line:
                f = json_format.ParseDict(json.loads(line)["record"], finding_pb2.Finding())
                env = envelope_pb2.Envelope(schema_major=SCHEMA_MAJOR, logical_id=f.finding_id,
                                            kind=envelope_pb2.RecordKind.Value("FINDING"))
                env.finding.CopyFrom(f)
                out.append(env)
    return out


def decisions(engine):
    """(source finding, target finding) -> sorted (type, status) of its witnesses,
    and the incidents' path scores by path (No-Tactic changes ranks, not links)."""
    pairs, ranks = defaultdict(set), {}
    for _t, _k, env in engine.drain():
        if env.HasField("witness"):
            w = env.witness
            pairs[(w.source_finding_id, w.target_finding_id)].add((w.relationship_type, w.status))
        elif env.HasField("incident"):
            for i, p in enumerate(env.incident.ranked_paths):
                ranks[tuple(p.finding_ids)] = i
    return {k: tuple(sorted(v)) for k, v in pairs.items()}, ranks


def run_one(run, cached, base, switches):
    engines = {"full": Engine(base)}
    for a in switches:
        engines[a] = Engine(base.with_overrides(ablations=[a]))
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
    out = {}
    for name, e in engines.items():
        e.finish()
        OFF._hook(e, OFF._now(e, 0))
        out[name] = decisions(e)
    return out


def cases(run, decided, switches):
    truth = S.Truth.load(str(run / "restricted"))
    findings = {}
    for env in _findings(cached_path(run)):
        findings[env.finding.finding_id] = env.finding
    acts = S.finding_actions(truth, S.Output(findings))
    scored = S.scored_link_ids(truth)
    labelled = {(lk.from_action_seq, lk.to_action_seq) for lk in truth.links if lk.link_id in scored}
    full, full_ranks = decided["full"]
    counts = {}
    for a in switches:
        abl, abl_ranks = decided[a]
        n = 0
        for pair in set(full) | set(abl):
            if full.get(pair) == abl.get(pair):
                continue
            x, y = acts.get(pair[0], set()), acts.get(pair[1], set())
            if any((i, j) in labelled for i in x for j in y):
                n += 1
            elif a == "no_distinct" and x & y:
                n += 1                                     # two findings of one action
        if a == "no_tactic":
            split = tactic_cases(full_ranks, abl_ranks, true_path(truth, acts))
            counts.update({f"no_tactic:{k}": v for k, v in split.items()})
            n += sum(split.values())
        counts[a] = n
    return counts


def true_path(truth, acts):
    """Path (finding IDs) -> every step a supported link (score._step_ok, as
    the false-chain rate)."""
    link_states = S.effective_link_states(truth, S.effective_states(truth, set()))
    state = {(lk.from_action_seq, lk.to_action_seq): link_states[lk.link_id] for lk in truth.links}
    return lambda p: all(S._step_ok(f, g, acts, state) for f, g in zip(p, p[1:]))


def tactic_cases(full_ranks, abl_ranks, true):
    """No-Tactic changes path ranks only (no-tactic-cases-plan T0). Cases:
    reorder, a multi-finding path both keep at another rank; helps, a true
    path only Full keeps or a false one only No-Tactic keeps; hurts, the
    reverse."""
    multi_full = {p for p in full_ranks if len(p) > 1}
    multi_abl = {p for p in abl_ranks if len(p) > 1}
    out = {"reorder": sum(1 for p in multi_full & multi_abl if full_ranks[p] != abl_ranks[p]),
           "helps": 0, "hurts": 0}
    for p in multi_full - multi_abl:
        out["helps" if true(p) else "hurts"] += 1
    for p in multi_abl - multi_full:
        out["hurts" if true(p) else "helps"] += 1
    return out


_CACHED = {}


def cached_path(run):
    return _CACHED[run.name]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("runs_dir", type=Path)
    ap.add_argument("cached_dir", type=Path, help="offline outputs holding the agents' findings")
    ap.add_argument("--params", required=True)
    ap.add_argument("--ablation", action="append", default=None, help="default: the paper's five")
    ap.add_argument("--min", type=int, default=20)
    ap.add_argument("--json", type=Path)
    ap.add_argument("--shard", default="0/1", help="I/N: only every N-th run, from I (merge the JSONs after)")
    ap.add_argument("--expect", type=int, help="runs this shard must replay")
    a = ap.parse_args(argv)
    shard, shards = (int(x) for x in a.shard.split("/"))
    switches = a.ablation or list(PAPER)
    base = OrchParams.load(a.params)
    total, per_run, missing = Counter(), {}, []
    for n, mf in enumerate(sorted(a.runs_dir.glob("*/manifest.json"))):
        if n % shards != shard:
            continue
        run = mf.parent
        cached = cached_output.find(a.cached_dir, run.name)
        if cached is None:
            missing.append(run.name)
            continue
        _CACHED[run.name] = cached
        c = cases(run, run_one(run, cached, base, switches), switches)
        per_run[run.name] = c
        total.update(c)
        print(run.name, c, flush=True)
    replayed = len(per_run)
    count_ok = replayed > 0 and (a.expect is None or replayed == a.expect)
    result = {"min": a.min, "total": {s: total[s] for s in switches}, "runs": per_run,
              "replayed": replayed, "expect": a.expect, "no_cached_output": missing,
              "passed": count_ok and all(total[s] >= a.min for s in switches)}
    if "no_tactic" in switches:
        result["tactic_cases"] = {k: total[f"no_tactic:{k}"] for k in ("helps", "hurts", "reorder")}
    result["failed"] = [s for s in switches if total[s] < a.min]
    print(json.dumps({k: result[k] for k in ("total", "tactic_cases", "replayed", "passed", "failed")
                      if k in result}, indent=2))
    if not count_ok:
        print(f"FAIL: replayed {replayed} runs (expected {a.expect if a.expect is not None else 'at least 1'}); "
              f"{len(missing)} without a cached output in {a.cached_dir}", file=sys.stderr)
    if a.json:
        a.json.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
