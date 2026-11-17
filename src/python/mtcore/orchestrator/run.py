"""Run the Global Orchestrator against Kafka, or offline over a file.

    python -m mtcore.orchestrator.run [--bootstrap 127.0.0.1:9092] [--instance orchestrator-1]
                                      [--commit-mode oldest-needed|full-replay|read-position]
                                      [--checkpoint FILE] [--checkpoint-s S] [--positions-log FILE]
    python -m mtcore.orchestrator.run --offline records.jsonl > decisions.jsonl

Online: consumes findings.v0 and norm.events.v0 (plus credential.instance.v0
with gate G_G1b on), and source.completeness.v0 and context.cluster.v0 as side
topics. Every partition is assigned by hand (restream.assign_all), so a
restart never waits out a group session timeout. Writes witness.decisions.v0
and incidents.v0, and a Heartbeat to every partition of both by explicit
partition, low watermark = engine.output_low_watermark() (none until it exists).
The engine advances only to a watermark whose side records have been read: the
input watermark is taken first, then the side topics' end offsets; once the
reads reach those offsets the watermark is safe (as AgentRunner does), so a
loss record written before the heartbeats behind it is always seen first.
Side records carry their LogAppendTime into the engine, which counts one as
known at a decision only if it was received by the knowledge time of the
watermark update making it (engine module doc, step 7g); the snapshot is
taken only after the local clock has passed that time, so no side record
received by then can still be appended (the GO and broker clocks are assumed
to agree; on one host they do).
"now" for amendments and idle exclusion is the newest heartbeat emitted_at
the engine has seen, so a replay stamps the same times; wall clock only before
any heartbeat.

Restarts (--commit-mode, Exp. 5 runs C, B, D):
- oldest-needed (default, step 7g). Per input partition the commit point is
  the smallest offset still held in engine state (Engine.held_offsets:
  pending and still-posted findings, both ends of awaiting pairs, retained
  evidence); earlier records are evicted and cannot affect a later decision.
  With it the checkpoint file stores the read positions, the IDs of the
  held findings, the side records that can still matter (raw, with their
  receipt times; below) and the side read positions, and the state a replay
  cannot rebuild
  (Engine.checkpoint_state: watermark and heartbeat history, node-trust
  epochs, the incident book). A restart loads it, seeks inputs to the
  committed offsets and side topics to their saved positions, re-feeds the
  saved side records, and replays: findings read before the saved read
  position that were not held are only noted as duplicates, and the engine
  does not advance until the replay reaches that position. Decisions then
  follow from the same records and knowledge times, and repeated outputs
  keep their IDs (witness_id, incident_id) for consumers to deduplicate.
  The file is the commit: written to FILE.tmp, fsynced, and renamed over
  FILE (atomic on POSIX and NTFS), then the same offsets are committed to
  Kafka for lag tools only.
  Side records are bounded (Engine.side_bound): at each commit, with T_old
  the oldest event time a decision still to be made can look at (watermark,
  pending and posted findings, retained evidence, open periods of live and
  absorbed incidents) and B = T_old - (max H_w + A + lateness + eps_bar),
  the engine forgets, and the saved log drops, gaps closed before B, Pod
  observations superseded before B, and idle intervals closed before B by
  a record received by knowledge_time(T_old), so no later seal can still
  see them as ongoing. Records not yet known (receipt after the engine's
  knowledge) and open-ended gaps are always kept. The checkpoint therefore
  grows with the open state, not with the history read.
  --checkpoint-s sets the commit interval (default: every heartbeat). A
  longer one writes the checkpoint less often, at the price of more
  reprocessing after a crash (everything read since the last commit).
- full-replay: inputs and side topics from the start on every start.
- read-position: inputs resume at the read position committed to Kafka,
  side topics from the start (the pre-7g behaviour; it loses the open state
  built from records before that position: the negative control).
In every mode the checkpoint keeps the last published output low watermark,
and heartbeats are withheld until the engine's passes it again, so
downstream never sees the watermark move back. Read and committed offsets
are logged once per commit (restream.log_positions), and "start" and the
first heartbeat after it as JSON lines on stderr (restart timing).

Offline: lines are {"topic", "envelope"} (Protobuf JSON, the shipper's input
format), e.g. the agents' offline output merged with norm.events.v0 and
source.completeness.v0 records, with an optional "receipt_ns" per line.
Offline files have no watermark updates: end of input is the only one and
knows every side record in the file. Output is one JSON object per witness
or incident, then a stats line on stderr.

Incidents come from the engine's `incidents_hook(now_ns)` when it has one
(sealing is wired into the engine with groups, step 5d); the runner calls it
after every advance and publishes what the engine queued.
"""
import argparse
import json
import os
import pickle
import signal
import sys
import time

from google.protobuf import json_format

from microtrace.v0 import envelope_pb2

from mtcore.kafka_produce import produce
from mtcore.orchestrator import PRODUCER_ID, ablations, emit
from mtcore.orchestrator.engine import COMPLETENESS, CRED, FINDINGS, INF, NORM, Engine
from mtcore.orchestrator.params import OrchParams
from mtcore.restream import assign_all, log_positions, receipt_ns, start_positions

try:
    from mtcore import failpoint
except ImportError:                  # the crash harness module is optional
    failpoint = None

CONTEXT = "context.cluster.v0"
SIDE_TOPICS = [COMPLETENESS, CONTEXT]
MODES = ("oldest-needed", "full-replay", "read-position")
OFFSET_BEGINNING = -2                # confluent_kafka.OFFSET_BEGINNING
CHECKPOINT_VERSION = 1


def input_topics(oparams):
    """Heartbeat-bearing inputs; credential.instance.v0 only with G_G1b on."""
    return [FINDINGS, NORM] + ([CRED] if oparams.params.gate("G_G1b") else [])


def _hook(engine, now_ns):
    hook = getattr(engine, "incidents_hook", None)
    if hook is not None:
        hook(now_ns)


def _now(engine, fallback):
    now = engine.watermarks.now
    return now if now is not None else fallback


def save_checkpoint(path, data):
    """Write data atomically: FILE.tmp, fsync, rename over FILE."""
    tmp = path + ".tmp"
    with open(tmp, "wb") as fh:
        pickle.dump(data, fh, protocol=pickle.HIGHEST_PROTOCOL)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    try:                              # make the rename durable (not possible on Windows)
        fd = os.open(os.path.dirname(os.path.abspath(path)), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def load_checkpoint(path):
    if not path or not os.path.exists(path):
        return {}
    with open(path, "rb") as fh:
        data = pickle.load(fh)
    if data.get("version") != CHECKPOINT_VERSION:
        raise ValueError(f"{path}: checkpoint version {data.get('version')}, expected {CHECKPOINT_VERSION}")
    return data


def _event(name, **kw):
    print(json.dumps({"event": name, "t": time.time_ns(), **kw}), file=sys.stderr, flush=True)


class OrchRunner:
    def __init__(self, oparams, bootstrap, instance, group=None, from_latest=False, commit_mode="oldest-needed",
                 checkpoint=None, positions_log=None, consumer=None, producer=None, checkpoint_s=None):
        """consumer, producer: injected clients (tests); else confluent_kafka's."""
        if commit_mode not in MODES:
            raise ValueError(f"commit mode {commit_mode!r}, expected one of {MODES}")
        ablations.validate(oparams.ablations)
        self.p = oparams
        self.instance = instance
        self.mode = commit_mode
        # --from-latest (tests) starts fresh at the end: no checkpoint read or written
        self.checkpoint = None if from_latest else (checkpoint or f"{instance}.checkpoint")
        self.positions_log = positions_log
        self.heartbeat_s = oparams.heartbeat_ms / 1000
        self.checkpoint_s = self.heartbeat_s if checkpoint_s is None else checkpoint_s
        self.last_commit = 0.0
        self.inputs = input_topics(oparams)
        self.from_latest = from_latest
        if consumer is None:
            from confluent_kafka import Consumer, Producer
            consumer = Consumer({"bootstrap.servers": bootstrap, "group.id": group or PRODUCER_ID,
                                 "enable.auto.commit": False, "auto.offset.reset": "earliest"})
            producer = Producer({"bootstrap.servers": bootstrap, "enable.idempotence": True, "acks": "all",
                                 "partitioner": "murmur2_random", "linger.ms": 5})
        self.consumer, self.producer = consumer, producer
        md = self.consumer.list_topics(timeout=30).topics
        self.partitions = {t: len(md[t].partitions) for t in self.inputs + SIDE_TOPICS + emit.OUT_TOPICS}
        self.engine = Engine(oparams, input_partitions={t: self.partitions[t] for t in self.inputs})
        self.position = {}          # (topic, partition) -> next offset to read
        self.side_snapshot = None   # (input watermark, side end offsets) awaiting the reads
        self.side_log = []          # (topic, partition, offset, receipt ns, bytes): side records read
        self.replay_until = {}      # (topic, partition) -> read position at the checkpoint
        self.held = set()           # finding IDs the checkpoint held
        self.committed = {}
        self.last_hb = 0.0
        _event("start", instance=instance, mode=commit_mode)
        ck = load_checkpoint(self.checkpoint)
        self.hb_seq = ck.get("hb_seq", 0)
        self.out_low = ck.get("out_low")      # last published output low watermark
        self.first_hb = True
        offsets = {}
        if commit_mode == "full-replay" and not from_latest:
            offsets = {(t, p): OFFSET_BEGINNING for t in self.inputs for p in range(self.partitions[t])}
        elif commit_mode == "oldest-needed" and "state" in ck:
            offsets = self._resume(ck)
        tps = assign_all(self.consumer, {t: self.partitions[t] for t in self.inputs + SIDE_TOPICS},
                         side=SIDE_TOPICS, offsets=offsets, from_latest=from_latest)
        for k, off in start_positions(tps, SIDE_TOPICS).items():
            self.position.setdefault(k, off)
        print("ready", file=sys.stderr, flush=True)

    def _resume(self, ck):
        """Load an oldest-needed checkpoint; returns the start offsets."""
        self.engine.restore(ck["state"])
        for topic, part, off, receipt, raw in ck["side_log"]:
            env = envelope_pb2.Envelope()
            env.ParseFromString(raw)
            self.engine.feed(env, topic, part, off, receipt_ns=receipt)
        self.side_log = list(ck["side_log"])
        self.replay_until = dict(ck["positions"])
        self.held = set(ck["held"])
        self.committed = dict(ck["commit"])
        offsets = {**ck["commit"], **ck["side_positions"]}
        self.position.update(offsets)
        return offsets

    # ------------------------------------------------------------------
    def _side_ends(self):
        from confluent_kafka import TopicPartition
        return {(t, p): self.consumer.get_watermark_offsets(TopicPartition(t, p), timeout=10, cached=False)
                for t in SIDE_TOPICS for p in range(self.partitions[t])}

    def replaying(self):
        """Still re-reading what the checkpointed run had read."""
        if self.replay_until and all(self.position.get(k, 0) >= v for k, v in self.replay_until.items()):
            self.replay_until = {}
            self.held = set()
            _event("replayed", instance=self.instance)
        return bool(self.replay_until)

    def safe_watermark(self):
        """A watermark the engine may advance to, or None: the input watermark
        recorded with a snapshot of the side topics' end offsets, released
        once the reads reach the snapshot (see AgentRunner.safe_watermark)."""
        if self.replaying():
            return None
        if self.side_snapshot is None:
            wm = self.engine.watermarks.watermark()
            if wm is None:
                return None
            k = self.engine.watermarks.knowledge_time(wm)
            if k < INF and time.time_ns() <= k:
                return None      # the broker may still append side records received at or before k
            self.side_snapshot = (wm, self._side_ends())
        wm, ends = self.side_snapshot
        if any(self.position.get(k, lo) < hi for k, (lo, hi) in ends.items()):
            return None
        self.side_snapshot = None
        return wm

    def _fail(self, name):
        if failpoint is not None:
            st = self.engine.open_state()
            failpoint.hit(name, state=st, require=lambda: any(st.values()))

    def publish(self):
        out = self.engine.drain()
        for i, (topic, key, env) in enumerate(out):
            produce(self.producer, topic, value=env.SerializeToString(), key=key)
            if i == 0 and len(out) > 1:
                self._fail("go.mid_group_records")

    def heartbeats(self):
        """Heartbeat every output partition, unless the low watermark is below
        the last one published (also before a restart): never move it back."""
        hook = getattr(self.engine, "output_low_watermark", None)
        low = hook() if hook is not None else self.engine.watermark
        if low is None or (self.out_low is not None and low < self.out_low):
            return
        now = time.time_ns()
        key = emit.instance_key(self.instance)
        for topic in emit.OUT_TOPICS:
            for p in range(self.partitions[topic]):
                self.hb_seq += 1
                env = emit.heartbeat(topic, p, self.instance, self.hb_seq, low, now)
                produce(self.producer, topic, value=env.SerializeToString(), partition=p, key=key)
        self.out_low = low
        if self.first_hb:
            self.first_hb = False
            _event("first_heartbeat", instance=self.instance, low=low)

    def commit(self):
        """Commit per the mode (module doc); the checkpoint file first."""
        inputs = {k: v for k, v in self.position.items() if k[0] not in SIDE_TOPICS}
        ck = {"version": CHECKPOINT_VERSION, "hb_seq": self.hb_seq, "out_low": self.out_low}
        bound = None if self.replaying() else self.engine.side_bound()
        if bound is not None:
            self.engine.prune_side(bound)
            if self.mode == "oldest-needed":
                self.side_log = self.engine.side_keep(self.side_log, bound)
        if self.mode == "oldest-needed" and not self.replaying():
            held = self.engine.held_offsets()
            commit = {k: min(pos, held.get(k, pos)) for k, pos in inputs.items()}
            ck.update(state=self.engine.checkpoint_state(), positions=inputs, commit=commit,
                      held=sorted(self.engine.held()), side_log=self.side_log,
                      side_positions={k: v for k, v in self.position.items() if k[0] in SIDE_TOPICS})
        elif self.mode == "oldest-needed":       # mid-replay: the previous checkpoint still stands
            commit, ck = self.committed, None
        else:
            commit = inputs if self.mode == "read-position" else {}
        if ck is not None and self.checkpoint:
            save_checkpoint(self.checkpoint, ck)
        if commit:
            from confluent_kafka import TopicPartition
            self.consumer.commit(offsets=[TopicPartition(t, p, o) for (t, p), o in sorted(commit.items())],
                                 asynchronous=False)
        self.committed = dict(commit)
        log_positions(self.positions_log, self.position, self.committed)

    def step(self):
        msgs = self.consumer.consume(500, timeout=0.2)
        for m in msgs:
            if m.error():
                continue
            env = envelope_pb2.Envelope()
            env.ParseFromString(m.value())
            t, p, off = m.topic(), m.partition(), m.offset()
            self.position[(t, p)] = off + 1
            if t in SIDE_TOPICS:
                receipt = receipt_ns(m)
                self.side_log.append((t, p, off, receipt, m.value()))
                self.engine.feed(env, t, p, off, key=m.key(), receipt_ns=receipt)
            elif (self.replay_until and env.HasField("finding") and off < self.replay_until.get((t, p), 0)
                  and env.finding.finding_id not in self.held):
                self.engine.skip(env)
            else:
                self.engine.feed(env, t, p, off, key=m.key())
        self._fail("go.after_feed_before_advance")
        wm = self.safe_watermark()
        if wm is not None:
            self.engine.advance(wm)
            _hook(self.engine, _now(self.engine, time.time_ns()))
            if failpoint is not None and self.engine.awaiting and any(
                    not s.sealed for s in self.engine.book.live.values()):
                self._fail("go.sealing_pairs_pending")
        self.publish()
        if time.time() - self.last_hb >= self.heartbeat_s:
            self.checkpoint_now(commit=time.time() - self.last_commit >= self.checkpoint_s)
        return len(msgs)

    def checkpoint_now(self, commit=True):
        """Heartbeats, flush, then (if commit) the commit: decisions precede
        the heartbeat and the commit."""
        self.heartbeats()
        self._fail("go.after_produce_before_flush")
        self.producer.flush(30)
        if commit:
            self._fail("go.after_flush_before_commit")
            self.commit()
            self.last_commit = time.time()
        self.last_hb = time.time()

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
        self.checkpoint_now()
        self.consumer.close()


STARTUP_IDLE_S = 600.0


def run_file(oparams, path, out=sys.stdout):
    ablations.validate(oparams.ablations)
    eng = Engine(oparams)
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            obj = json.loads(line)
            eng.feed(json_format.ParseDict(obj["envelope"], envelope_pb2.Envelope()), obj["topic"],
                     obj.get("partition", 0), obj.get("offset", 0), receipt_ns=obj.get("receipt_ns"))
    eng.finish()
    _hook(eng, _now(eng, 0))
    for topic, _key, env in eng.drain():
        msg = env.witness if env.HasField("witness") else env.incident
        out.write(json.dumps({"topic": topic, "record": json_format.MessageToDict(msg)}, sort_keys=True) + "\n")
    return eng


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run the MicroTRACE Global Orchestrator.")
    ap.add_argument("--params", default=None, help="parameter set (default src/params/dev.v0.yaml)")
    ap.add_argument("--offline", metavar="FILE", help="evaluate a file instead of Kafka")
    ap.add_argument("--bootstrap", default="127.0.0.1:9092")
    ap.add_argument("--instance", default=None, help="producer instance (default orchestrator)")
    ap.add_argument("--group", default=None, help="consumer group (default orchestrator)")
    ap.add_argument("--idle-exit-s", type=float, default=None, help="stop after this long without input (tests)")
    ap.add_argument("--from-latest", action="store_true", help="start inputs at their current end (tests)")
    ap.add_argument("--commit-mode", choices=MODES, default="oldest-needed",
                    help="restart behaviour (module doc; Exp. 5 runs C, B, D)")
    ap.add_argument("--checkpoint", default=None, help="checkpoint file (default <instance>.checkpoint)")
    ap.add_argument("--checkpoint-s", type=float, default=None,
                    help="seconds between commits and checkpoints (default: every heartbeat interval)")
    ap.add_argument("--positions-log", default=None,
                    help="append read/committed offsets here (default $MT_POSITIONS_LOG, else stderr)")
    a = ap.parse_args(argv)
    oparams = OrchParams.load(a.params)
    if a.offline:
        eng = run_file(oparams, a.offline)
        print(json.dumps({"stats": eng.stats, "evidence": eng.evidence.stats, "processed": len(eng.processed)}),
              file=sys.stderr)
        return 0
    stopping = []
    signal.signal(signal.SIGTERM, lambda *_: stopping.append(1))
    r = OrchRunner(oparams, a.bootstrap, a.instance or PRODUCER_ID, a.group, a.from_latest, a.commit_mode,
                   a.checkpoint, a.positions_log, checkpoint_s=a.checkpoint_s)
    r.run(lambda: bool(stopping), a.idle_exit_s)
    print(json.dumps({"stats": r.engine.stats, "processed": len(r.engine.processed)}), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
