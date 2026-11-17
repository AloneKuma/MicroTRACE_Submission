"""Run agents A-H against Kafka, or offline over a file.

    python -m mtcore.agents.run --agent B,G,H [--no-ml] [--bootstrap 127.0.0.1:9092]
    python -m mtcore.agents.run --agent A,B,C,D,E,F,G,H --offline records.jsonl > out.jsonl

Online: consumes the agents' input topics plus source.completeness.v0 and
context.cluster.v0, writes findings.v0 and rule.evaluations.v0, and writes a
Heartbeat to every partition of both. Windows are evaluated only after the
completeness and context topics have been read up to their end offsets as of
the watermark's heartbeats, so a loss or context record written before the
restreamed heartbeat is always seen first. Side records carry their
LogAppendTime; a window knows only those received by the knowledge time of
the update that passed its end (engine module doc, step 7g), and the
snapshot waits until the local clock has passed that time.
Every partition is assigned by hand (restream.assign_all), so a restart does
not wait out a group session timeout. Offsets are committed only up to the
oldest record an open window still needs (its events, and the heartbeats
above the watermark that set later knowledge times), so a restarted agent
rebuilds its windows from Kafka and evaluates them with the same knowledge;
side topics are re-read from the start; re-emitted findings carry the same
IDs and downstream consumers deduplicate them. Read and committed offsets
are logged per commit (restream.log_positions).
The agents never read ground.truth.v0.
Failpoints (mtcore.failpoint, Exp. 5): agent.window_open after a poll while
windows hold state, agent.after_finding_before_commit after the flush that
wrote findings, before the commit.

Offline: lines are {"topic", "envelope"} (Protobuf JSON, the shipper's input
format); norm.events.v0 lines are routed as the restreamer would. Output is
one JSON object per finding or evaluation.
"""
import argparse
import json
import signal
import sys
import time

from google.protobuf import json_format

from mtcore.kafka_produce import produce
from mtcore import failpoint
from mtcore.agents import routing
from mtcore.agents.engine import INF, Engine
from mtcore.agents.events import Ev
from mtcore.agents.ml.scorer import Scorer
from mtcore.agents.params import DEV_PARAMS, Params
from mtcore.agents.rules import for_agents, input_topics
from mtcore.restream import assign_all, log_positions, receipt_ns, start_positions
from microtrace.v0 import envelope_pb2, keys_pb2

SIDE_TOPICS = ["source.completeness.v0", "context.cluster.v0"]
OUT_TOPICS = ["findings.v0", "rule.evaluations.v0"]
PRODUCER_ID = "agents"


def make_scorer(params, no_ml):
    if no_ml or not params.ml_enabled or not params.models:
        return None
    return Scorer.load(params)


def _ts(ns):
    from google.protobuf import timestamp_pb2
    t = timestamp_pb2.Timestamp()
    t.FromNanoseconds(int(ns))
    return t


class AgentRunner:
    def __init__(self, agents, params, bootstrap, instance, no_ml=False, heartbeat_ms=1000, group=None,
                 from_latest=False, positions_log=None):
        from confluent_kafka import Consumer, Producer
        self.agents = agents
        self.instance = instance
        self.heartbeat_s = heartbeat_ms / 1000
        rules = for_agents(agents)
        self.inputs = input_topics(rules)
        group = group or "agents-" + "".join(agents)
        self.from_latest = from_latest
        self.positions_log = positions_log
        self.consumer = Consumer({"bootstrap.servers": bootstrap, "group.id": group,
                                  "enable.auto.commit": False, "auto.offset.reset": "earliest"})
        self.producer = Producer({"bootstrap.servers": bootstrap, "enable.idempotence": True, "acks": "all",
                                  "partitioner": "murmur2_random", "linger.ms": 5})
        md = self.consumer.list_topics(timeout=30).topics
        self.partitions = {t: len(md[t].partitions) for t in self.inputs + SIDE_TOPICS + OUT_TOPICS}
        if no_ml:
            params = params.with_overrides(ml={"enabled": False})
        self.engine = Engine(rules, params, scorer=make_scorer(params, no_ml),
                             input_partitions={t: self.partitions[t] for t in self.inputs}, auto_advance=False)
        self.position = {}       # (topic, partition) -> next offset to read
        self.side_snapshot = None   # (input watermark, side end offsets) awaiting the reads
        self.hb_seq = 0
        self.last_hb = 0.0
        self.uncommitted_findings = 0   # findings published since the last commit (failpoint summary)
        # Every partition assigned by hand (restream.assign_all): a restart
        # does not wait out a session timeout. Completeness and context are
        # history every evaluation may need, so they are always read from the
        # start; inputs resume from the committed offset.
        tps = assign_all(self.consumer, {t: self.partitions[t] for t in self.inputs + SIDE_TOPICS},
                         side=SIDE_TOPICS, from_latest=from_latest)
        self.position.update(start_positions(tps, SIDE_TOPICS))
        print("ready", file=sys.stderr, flush=True)

    # ------------------------------------------------------------------
    def _side_ends(self):
        from confluent_kafka import TopicPartition
        return {(t, p): self.consumer.get_watermark_offsets(TopicPartition(t, p), timeout=10, cached=False)
                for t in SIDE_TOPICS for p in range(self.partitions[t])}

    def safe_watermark(self):
        """A watermark the engine may advance to, or None.

        Takes the input watermark first, then the completeness/context end
        offsets: every side record written before the heartbeats behind that
        watermark lies below those offsets. Once the reads reach them, the
        recorded watermark is safe. Comparing with a snapshot rather than the
        live end lets the agents advance while side topics keep growing."""
        if self.side_snapshot is None:
            wm = self.engine.input_watermark()
            if wm is None:
                return None
            k = self.engine.knowledge_time(wm)
            if k < INF and time.time_ns() <= k:
                return None      # the broker may still append side records received at or before k
            self.side_snapshot = (wm, self._side_ends())
        wm, ends = self.side_snapshot
        if any(self.position.get(k, lo) < hi for k, (lo, hi) in ends.items()):
            return None
        self.side_snapshot = None
        return wm

    def publish(self):
        for topic, key, env in self.engine.drain():
            produce(self.producer, topic, value=env.SerializeToString(), key=key)
            if env.HasField("finding"):
                self.uncommitted_findings += 1

    def heartbeats(self):
        low = self.engine.output_low_watermark()
        if low is None:
            return
        now = time.time_ns()
        key = routing.mtcodec.encode_key(keys_pb2.KeyType.Value("KEY_PRODUCER_INSTANCE"),
                                         [(keys_pb2.KeyComponent.Value("PRODUCER_INSTANCE"), self.instance)])
        for topic in OUT_TOPICS:
            for p in range(self.partitions[topic]):
                self.hb_seq += 1
                env = envelope_pb2.Envelope(schema_major=0, schema_minor=2, producer_id=PRODUCER_ID,
                                            kind=envelope_pb2.RecordKind.Value("HEARTBEAT"))
                hb = env.heartbeat
                hb.producer_id, hb.producer_instance, hb.topic, hb.partition = PRODUCER_ID, self.instance, topic, p
                hb.low_watermark.CopyFrom(_ts(low))
                hb.emitted_at.CopyFrom(_ts(now))
                hb.producer_seq = self.hb_seq
                produce(self.producer, topic, value=env.SerializeToString(), partition=p, key=key)

    def commit(self):
        """Commit, per input partition, the oldest offset an open window needs
        (or the read position when none); side topics at their read position."""
        from confluent_kafka import TopicPartition
        needed = self.engine.needed_offsets()
        commit = {(t, p): min(pos, needed.get((t, p), pos)) for (t, p), pos in self.position.items()
                  if t not in SIDE_TOPICS}
        if commit:
            self.consumer.commit(offsets=[TopicPartition(t, p, o) for (t, p), o in sorted(commit.items())],
                                 asynchronous=False)
        log_positions(self.positions_log, self.position, commit)

    def step(self):
        msgs = self.consumer.consume(500, timeout=0.2)
        for m in msgs:
            if m.error():
                continue
            env = envelope_pb2.Envelope()
            env.ParseFromString(m.value())
            side = m.topic() in SIDE_TOPICS
            self.engine.feed(env, m.topic(), m.partition(), m.offset(), key=m.key(),
                             receipt_ns=receipt_ns(m) if side else None)
            self.position[(m.topic(), m.partition())] = m.offset() + 1
        if msgs:
            # Exp. 5 part A: windows hold events not yet evaluated.
            failpoint.hit("agent.window_open", state=self.engine.open_state, require=lambda: bool(self.engine.pending))
        wm = self.safe_watermark()
        if wm is not None:
            self.engine.advance(wm)
        self.publish()
        if time.time() - self.last_hb >= self.heartbeat_s:
            self.heartbeats()
            self.producer.flush(30)       # findings precede the heartbeat and the commit
            # Exp. 5 part A: findings are in Kafka, their inputs not committed.
            failpoint.hit("agent.after_finding_before_commit",
                          state=lambda: dict(self.engine.open_state(), findings=self.uncommitted_findings),
                          require=lambda: self.uncommitted_findings > 0)
            self.commit()
            self.uncommitted_findings = 0
            self.last_hb = time.time()
        return len(msgs)

    def run(self, stop, idle_exit_s=None):
        # Idle exit counts from the first input, not from start-up (2026-11-17: in Exp. 3 the replay
        # began 37-123 s after the pipeline started, so a 30 s timer from start-up ended 43 of 59
        # live runs before their data arrived). Without any input, stop after STARTUP_IDLE_S.
        started, idle_since = time.time(), None
        while not stop():
            if self.step():
                idle_since = time.time()
            elif idle_exit_s is not None and (
                    (idle_since is not None and time.time() - idle_since > idle_exit_s)
                    or (idle_since is None and time.time() - started > max(idle_exit_s, STARTUP_IDLE_S))):
                break
        self.publish()
        self.heartbeats()
        self.producer.flush(30)
        self.commit()
        self.consumer.close()


STARTUP_IDLE_S = 600.0


def run_file(agents, params, path, no_ml=False, out=sys.stdout):
    if no_ml:
        params = params.with_overrides(ml={"enabled": False})
    eng = Engine(for_agents(agents), params, scorer=make_scorer(params, no_ml))
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            obj = json.loads(line)
            env = json_format.ParseDict(obj["envelope"], envelope_pb2.Envelope())
            if obj["topic"] == "norm.events.v0" and env.HasField("normalized_event"):
                for topic, key in routing.routes(Ev(env)):
                    if key is not None:
                        eng.feed(env, topic, key=key)
            else:
                eng.feed(env, obj["topic"])
    eng.finish()
    for topic, _key, env in eng.drain():
        msg = env.finding if env.HasField("finding") else env.rule_evaluation
        out.write(json.dumps({"topic": topic, "record": json_format.MessageToDict(msg)}, sort_keys=True) + "\n")
    return eng.stats


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run MicroTRACE agents.")
    ap.add_argument("--agent", default="A,B,C,D,E,F,G,H")
    ap.add_argument("--params", default=DEV_PARAMS)
    ap.add_argument("--no-ml", action="store_true", help="No-ML ablation: predicates only")
    ap.add_argument("--bootstrap", default="127.0.0.1:9092")
    ap.add_argument("--instance", default=None)
    ap.add_argument("--heartbeat-ms", type=int, default=1000)
    ap.add_argument("--idle-exit-s", type=float, default=None, help="stop after this long without input (tests)")
    ap.add_argument("--offline", metavar="FILE", help="evaluate a file instead of Kafka")
    ap.add_argument("--group", default=None, help="consumer group (default agents-<letters>)")
    ap.add_argument("--from-latest", action="store_true", help="start inputs at their current end (tests)")
    ap.add_argument("--positions-log", default=None,
                    help="append read/committed offsets here (default $MT_POSITIONS_LOG, else stderr)")
    a = ap.parse_args(argv)
    agents = [x.strip() for x in a.agent.split(",") if x.strip()]
    params = Params.load(a.params)
    if a.offline:
        stats = run_file(agents, params, a.offline, a.no_ml)
        print(dict(stats), file=sys.stderr)
        return 0
    stopping = []
    signal.signal(signal.SIGTERM, lambda *_: stopping.append(1))
    r = AgentRunner(agents, params, a.bootstrap, a.instance or "agents-" + "".join(agents), a.no_ml, a.heartbeat_ms,
                    a.group, a.from_latest, a.positions_log)
    r.run(lambda: bool(stopping), a.idle_exit_s)
    print(dict(r.engine.stats), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
