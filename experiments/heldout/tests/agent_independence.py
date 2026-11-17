"""Exp. 1 check (decided 2026-11-15): the "Agent X only" rows are the full run scored on agent
X's own finding types, which is valid only if no agent changes another agent's findings. For
each run, run the agents (no GO) once with all of A-H and once with each agent alone, and
compare agent X's findings and rule evaluations in both. Truth is never read.

    python experiments/heldout/tests/agent_independence.py --params P OUT.json RUN_DIR [RUN_DIR ...]

Exit 0 when every agent's records are identical in every run; OUT.json lists counts and any
difference (first few record IDs per side).
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src" / "python"))

from google.protobuf import json_format  # noqa: E402

from mtcore.agents import routing  # noqa: E402
from mtcore.agents.engine import Engine  # noqa: E402
from mtcore.agents.events import Ev  # noqa: E402
from mtcore.agents.params import Params  # noqa: E402
from mtcore.agents.rules import for_agents  # noqa: E402
from mtcore.agents.run import make_scorer  # noqa: E402
from mtcore.harness.offline import AGENTS, read_shipper  # noqa: E402


def agent_records(run_dir, params, agents):
    """{agent letter: sorted canonical JSON of its findings and rule evaluations}."""
    eng = Engine(for_agents(agents), params, scorer=make_scorer(params, False))
    for topic, env in read_shipper(run_dir):
        if topic == "norm.events.v0" and env.HasField("normalized_event"):
            for atopic, key in routing.routes(Ev(env)):
                if key is not None:
                    eng.feed(env, atopic, key=key)
        else:
            eng.feed(env, topic)
    eng.finish()
    out = {a: [] for a in agents}
    for topic, _key, env in eng.drain():
        msg = env.finding if env.HasField("finding") else env.rule_evaluation
        d = json_format.MessageToDict(msg)
        d.pop("publishTime", None)           # wall-clock emit time: differs on every run, not scored
        ftype = d.get("findingType") or d.get("ruleId") or ""
        out.setdefault(ftype[:1], []).append(json.dumps({"topic": topic, "record": d}, sort_keys=True))
    return {a: sorted(v) for a, v in out.items()}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--params", required=True)
    ap.add_argument("out")
    ap.add_argument("runs", nargs="+")
    a = ap.parse_args(argv)
    params = Params.load(a.params)
    report, bad = {}, 0
    for run in a.runs:
        full = agent_records(run, params, AGENTS)
        rep = {}
        for x in AGENTS:
            alone = agent_records(run, params, [x]).get(x, [])
            together = full.get(x, [])
            same = alone == together
            bad += not same
            rep[x] = {"records_full": len(together), "records_alone": len(alone), "identical": same}
            if not same:
                sa, st = set(alone), set(together)
                rep[x]["only_alone"] = [json.loads(r)["record"].get("findingId") or json.loads(r)["record"].get(
                    "evaluationId") for r in sorted(sa - st)[:5]]
                rep[x]["only_full"] = [json.loads(r)["record"].get("findingId") or json.loads(r)["record"].get(
                    "evaluationId") for r in sorted(st - sa)[:5]]
        unknown = sorted(k for k in full if k not in AGENTS)
        if unknown:
            rep["unattributed_prefixes"] = unknown
        report[Path(run).name] = rep
        print(Path(run).name, "OK" if all(v["identical"] for k, v in rep.items() if k in AGENTS) else "DIFF",
              flush=True)
    Path(a.out).write_text(json.dumps({"differences": bad, "runs": report}, indent=2) + "\n")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
