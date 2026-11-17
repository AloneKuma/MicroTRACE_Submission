"""Offline pipeline over one generated run (build step 9): agents, then GO.

    python -m mtcore.harness.offline RUN_DIR --out output.jsonl [--no-ml] [--params P] [--orch-params P]

Reads every RUN_DIR/shipper/*.jsonl (the shipper's input format), keeps the
lines with an envelope and drops ground.truth.v0 (the answer key travels on
its own topic; no detector reads it). Agents A-H evaluate the records as
mtcore.agents.run --offline does; their findings, with the norm.events.v0,
source.completeness.v0 and context.cluster.v0 records, then feed the GO as
mtcore.orchestrator.run --offline does. Both engines see the end of input as
their only watermark. Output: {"topic", "record"} lines for findings.v0,
rule.evaluations.v0, witness.decisions.v0 and incidents.v0, the input of
mtcore.harness.score. A stats line goes to stderr.

Exp. 1 telemetry ablation (--drop-source EBPF|GATEWAY|KYVERNO|AUDIT, decided
2026-11-15): every norm.events.v0 record of that source and every
source.completeness.v0 record about it is dropped before the agents and the GO
see the stream, and one declared record says the source is not shipped
(source.completeness.v0, an open-ended POLICY_EXCLUDED gap on the whole source),
so rules that need it abstain instead of reading silence as "nothing happened".
--fault-log FILE lists the dropped records' IDs in the injector's fault-log
format; mtcore.harness.score --fault-log then marks every opportunity whose
evidence lost a record UNOBSERVABLE (the Exp. 3 rule: what the data lost, read
from the input stream, never from truth). Only the four security sources can be
dropped for Exp. 1; CLUSTER_CONTEXT and DB_AUDIT always stay.

Exp. 3 No-OffNode (decided 2026-11-16): --drop-source PATH_FLOW drops the flow export S_F by
the same mechanism (declared not shipped, dropped IDs in the fault log).

restricted/ is never opened here.
"""
import argparse
import glob
import json
import os
import sys
import time

from google.protobuf import json_format

from microtrace.v0 import common_pb2, envelope_pb2, stream_pb2

from mtcore.agents import emit, routing
from mtcore.agents.engine import Engine as AgentEngine
from mtcore.agents.events import Ev
from mtcore.agents.params import DEV_PARAMS, Params
from mtcore.agents.rules import for_agents
from mtcore.agents.run import make_scorer
from mtcore.orchestrator import ablations
from mtcore.orchestrator.engine import Engine as OrchEngine
from mtcore.orchestrator.params import OrchParams
from mtcore.orchestrator.run import _hook, _now

AGENTS = list("ABCDEFGH")
TRUTH_TOPIC = "ground.truth.v0"
FINDINGS = "findings.v0"
GO_INPUTS = ("norm.events.v0", "source.completeness.v0", "context.cluster.v0")
SECURITY = ("EBPF", "GATEWAY", "KYVERNO", "AUDIT")      # the four security sources (Exp. 1)
OFFNODE = "PATH_FLOW"                                   # flow export S_F (Exp. 3 No-OffNode, decided 2026-11-16)
DROPPABLE = SECURITY + (OFFNODE,)
COMPLETENESS = "source.completeness.v0"


def not_shipped(source_name):
    """The declared record of a dropped source: an open-ended POLICY_EXCLUDED gap on all of it."""
    sc = stream_pb2.SourceCompleteness(source=common_pb2.Source.Value(source_name),
                                       scope=f"ablation=drop-source/{source_name}",
                                       status=stream_pb2.CompletenessStatus.Value("INCOMPLETE"))
    sc.gaps.add(reason=common_pb2.GapReason.Value("POLICY_EXCLUDED"), scope="",
                detail="Exp. 1 telemetry ablation: source not shipped" if source_name in SECURITY
                else "Exp. 3 No-OffNode ablation: flow export not shipped")
    return envelope_pb2.Envelope(schema_major=emit.SCHEMA_MAJOR, schema_minor=emit.SCHEMA_MINOR,
                                 producer_id="mtcore.harness.offline", source=sc.source,
                                 logical_id=f"ablation-drop-source-{source_name}", source_completeness=sc)


def dropped_ids(env):
    """IDs a fault log lists for one dropped record (the envelope's and the event's)."""
    ids = {env.logical_id}
    if env.HasField("normalized_event"):
        ids.add(env.normalized_event.event_id)
    return sorted(i for i in ids if i)


def drop_filter(records, source_name, fault_log):
    """records without the dropped source; fault_log gets one line per dropped record ID."""
    src = common_pb2.Source.Value(source_name)
    fault_log.write(json.dumps({"header": {"ablation": "drop-source", "source": source_name}}) + "\n")
    yield COMPLETENESS, not_shipped(source_name)
    n = 0
    for topic, env in records:
        if env.HasField("normalized_event"):
            hit = (env.normalized_event.source or env.source) == src
        elif env.HasField("source_completeness"):
            hit = env.source_completeness.source == src
        else:
            hit = False
        if not hit:
            yield topic, env
            continue
        n += 1
        if env.HasField("normalized_event"):
            for i in dropped_ids(env):
                fault_log.write(json.dumps({"logical_id": i, "action": "dropped_reported"}) + "\n")
    drop_filter.dropped = n


def read_shipper(run_dir):
    """(topic, envelope) for every enveloped line of the run's shipper files."""
    files = sorted(glob.glob(os.path.join(run_dir, "shipper", "*.jsonl")))
    if not files:
        raise SystemExit(f"no shipper files under {run_dir}")
    dropped = 0
    for path in files:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                obj = json.loads(line)
                if "envelope" not in obj:
                    continue                 # lane watermark line
                if obj["topic"] == TRUTH_TOPIC:
                    dropped += 1
                    continue
                yield obj["topic"], json_format.ParseDict(obj["envelope"], envelope_pb2.Envelope())
    read_shipper.truth_dropped = dropped


def run(run_dir, out, params, oparams, no_ml=False, drop_source=None, fault_log=None):
    if drop_source is not None and drop_source not in DROPPABLE:
        raise SystemExit(f"--drop-source must be one of {DROPPABLE}, not {drop_source!r}")
    if no_ml:
        params = params.with_overrides(ml={"enabled": False})
    ablations.validate(oparams.ablations)
    agents = AgentEngine(for_agents(AGENTS), params, scorer=make_scorer(params, no_ml))
    go = OrchEngine(oparams)
    offsets = {}

    def go_feed(env, topic):
        off = offsets.get(topic, 0)
        offsets[topic] = off + 1
        go.feed(env, topic, 0, off)

    t0 = time.time()
    n = 0
    records = read_shipper(run_dir)
    if drop_source is not None:
        records = drop_filter(records, drop_source, fault_log)
    for topic, env in records:
        n += 1
        if topic == "norm.events.v0" and env.HasField("normalized_event"):
            for atopic, key in routing.routes(Ev(env)):
                if key is not None:
                    agents.feed(env, atopic, key=key)
        else:
            agents.feed(env, topic)
        if topic in GO_INPUTS:
            go_feed(env, topic)
    t_read = time.time() - t0
    agents.finish()
    findings = 0
    for topic, _key, env in agents.drain():
        msg = env.finding if env.HasField("finding") else env.rule_evaluation
        out.write(json.dumps({"topic": topic, "record": json_format.MessageToDict(msg)}, sort_keys=True) + "\n")
        if topic == FINDINGS:
            findings += 1
            go_feed(env, FINDINGS)
    t_agents = time.time() - t0
    go.finish()
    _hook(go, _now(go, 0))
    decisions = 0
    for topic, _key, env in go.drain():
        msg = env.witness if env.HasField("witness") else env.incident
        out.write(json.dumps({"topic": topic, "record": json_format.MessageToDict(msg)}, sort_keys=True) + "\n")
        decisions += 1
    return {"records": n, "truth_dropped": getattr(read_shipper, "truth_dropped", 0), "findings": findings,
            "decisions": decisions, "drop_source": drop_source,
            "dropped_records": getattr(drop_filter, "dropped", 0) if drop_source else 0, "agent_stats": dict(agents.stats), "go_stats": dict(go.stats),
            "seconds": {"read": round(t_read, 1), "agents": round(t_agents, 1),
                        "total": round(time.time() - t0, 1)}}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run agents and GO offline over one generated run.")
    ap.add_argument("run_dir")
    ap.add_argument("--out", required=True, help="output JSONL (input of mtcore.harness.score)")
    ap.add_argument("--no-ml", action="store_true", help="No-ML ablation: predicates only")
    ap.add_argument("--params", default=DEV_PARAMS, help="agent parameters")
    ap.add_argument("--orch-params", default=None, help="GO parameters (default src/params/dev.v0.yaml)")
    ap.add_argument("--drop-source", choices=DROPPABLE, default=None,
                    help="Exp. 1 telemetry ablation (or PATH_FLOW: Exp. 3 No-OffNode): drop this source, "
                         "declared as not shipped")
    ap.add_argument("--fault-log", default=None, help="with --drop-source: write the dropped IDs here")
    a = ap.parse_args(argv)
    if (a.drop_source is None) != (a.fault_log is None):
        ap.error("--drop-source and --fault-log go together")
    flog = open(a.fault_log, "w", encoding="utf-8") if a.fault_log else None
    try:
        with open(a.out, "w", encoding="utf-8") as fh:
            stats = run(a.run_dir, fh, Params.load(a.params), OrchParams.load(a.orch_params), a.no_ml,
                        a.drop_source, flog)
    finally:
        if flog:
            flog.close()
    print(json.dumps(stats, sort_keys=True), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
