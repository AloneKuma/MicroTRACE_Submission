"""Restreamer: copies norm.events.v0 into the keyed agent topics.

    python -m mtcore.restream --bootstrap 127.0.0.1:9092 [--params src/params/dev.v0.yaml]

Each normalized event goes, unchanged, to every agent topic whose selector
matches it (mtcore.agents.routing), keyed as topics.yaml declares and placed
by Kafka's murmur2 partitioner. An event that belongs on a topic but lacks a
key component is not routed; a JOIN_UNCERTAIN SourceCompleteness record
names it instead (kafka-contract.md, "Record keys").

Heartbeats: the restreamer is the producer instance of the agent topics. When
every norm.events.v0 partition has reported a low watermark, it writes a
Heartbeat to every partition of every agent topic with the minimum. Records
are flushed before the heartbeat that covers them, so the promise holds.

credential-join (G1b, conditional): with gate G_G1b on, it also reads
TokenFileVersion records from raw.ebpf.v0 and writes token reads resolved to
a JTI, and audit events that used that JTI, to credential.instance.v0.
"""
import argparse
import signal
import sys
import time

from mtcore.kafka_produce import produce
from mtcore.agents import routing
from mtcore.agents.events import Ev, ts_ns
from mtcore.agents.params import DEV_PARAMS, Params
from microtrace.v0 import common_pb2, envelope_pb2, stream_pb2
from google.protobuf import timestamp_pb2

PRODUCER_ID = "restreamer"
NORM = "norm.events.v0"
RAW_EBPF = "raw.ebpf.v0"
CRED = "credential.instance.v0"
COMPLETENESS = "source.completeness.v0"


def _ts(ns):
    t = timestamp_pb2.Timestamp()
    t.FromNanoseconds(int(ns))
    return t


class CredentialJoin:
    """Resolves token reads to JTIs through the token.jti_index records.

    A read whose TokenFileVersion has not arrived waits. While it waits, the
    heartbeat promise on credential.instance.v0 is held at its event time
    (hold()), so the read is not late when it is resolved. A read that waits
    longer than max_wait_ns of event time, or beyond max_waiting reads, is
    given up and reported (JOIN_UNCERTAIN), never dropped silently.
    """

    def __init__(self, max_wait_ns, max_waiting=10000):
        self.index = {}       # (node, dev, ino, version_dir) -> jti
        self.waiting = []     # reads not yet resolvable: (key tuple, env, event time ns)
        self.given_up = []    # Ev of reads given up since the last hold()
        self.max_wait_ns = max_wait_ns
        self.max_waiting = max_waiting

    def add_version(self, v):
        self.index[(v.node_id, v.dev, v.ino, v.version_dir)] = v.jti
        ready = [w for w in self.waiting if w[0] in self.index]
        self.waiting = [w for w in self.waiting if w[0] not in self.index]
        return [(self.index[k], e) for k, e, _t in ready]

    def route(self, ev):
        """[(jti, env)] for a resolvable read or a use; unresolved reads wait."""
        if ev.audit is not None and ev.ad is not None and ev.ad.HasField("used_credential_id"):
            return [(ev.ad.used_credential_id, ev.env)]
        if ev.family == "file.read" and ev.ed is not None and ev.ed.HasField("token_file"):
            f = ev.detail.file
            k = (ev.ebpf.node_id, f.dev, f.ino, ev.ed.token_file.version_dir)
            if k in self.index:
                return [(self.index[k], ev.env)]
            self.waiting.append((k, ev.env, ev.t or 0))
            if len(self.waiting) > self.max_waiting:
                self.waiting.sort(key=lambda w: w[2])
                self._give_up(self.waiting[:-self.max_waiting])
                del self.waiting[:-self.max_waiting]
        return []

    def hold(self, low):
        """Low watermark for credential.instance.v0 given the input's low:
        give up reads older than low - max_wait_ns, then hold at the oldest
        read still waiting."""
        cutoff = low - self.max_wait_ns
        self._give_up([w for w in self.waiting if w[2] < cutoff])
        self.waiting = [w for w in self.waiting if w[2] >= cutoff]
        return min([low] + [w[2] for w in self.waiting])

    def _give_up(self, items):
        self.given_up += [Ev(e) for _k, e, _t in items]

    def drain_given_up(self):
        out, self.given_up = self.given_up, []
        return out


class Restreamer:
    def __init__(self, bootstrap, params, instance="restreamer-1", heartbeat_ms=1000, group="restreamer",
                 from_latest=False):
        from confluent_kafka import Consumer, Producer
        self.params = params
        self.instance = instance
        self.heartbeat_s = heartbeat_ms / 1000
        # A read waits for its token version at most G1b's own window W_w.
        self.cred = CredentialJoin(params.window_ns("W_w")) if params.gate("G_G1b") else None
        self.consumer = Consumer({"bootstrap.servers": bootstrap, "group.id": group,
                                  "enable.auto.commit": False, "auto.offset.reset": "earliest"})
        self.producer = Producer({"bootstrap.servers": bootstrap, "enable.idempotence": True, "acks": "all",
                                  "partitioner": "murmur2_random", "linger.ms": 5})
        md = self.consumer.list_topics(timeout=30).topics
        self.out_topics = sorted(routing.ROUTES) + ([CRED] if self.cred else [])
        self.partitions = {t: len(md[t].partitions) for t in self.out_topics + [NORM]}
        self.low = {}          # norm partition -> low watermark ns
        self.hb_seq = 0
        self.last_hb = 0.0
        self.stats = {"routed": 0, "unroutable": 0, "heartbeats": 0}
        topics = [NORM] + ([RAW_EBPF] if self.cred else [])
        self.from_latest = from_latest
        self.consumer.subscribe(topics, on_assign=self._on_assign)

    def _on_assign(self, consumer, partitions):
        if self.from_latest:
            pin_to_end(consumer, partitions)
        else:
            consumer.assign(partitions)
        print("ready", file=sys.stderr, flush=True)

    # ------------------------------------------------------------------
    def _produce(self, topic, key, env):
        produce(self.producer, topic, value=env.SerializeToString(), key=key)

    def _unroutable(self, topic, ev, why=None):
        sc = stream_pb2.SourceCompleteness(source=ev.source, scope=f"restream={topic}",
                                           status=stream_pb2.CompletenessStatus.Value("INCOMPLETE"))
        if ev.t is not None:
            sc.interval_start.CopyFrom(_ts(ev.t))
            sc.interval_end.CopyFrom(_ts(ev.t))
        sc.gaps.add(reason=common_pb2.GapReason.Value("JOIN_UNCERTAIN"), scope=f"topic={topic}",
                    detail=f"event {ev.id} {why or 'lacks a key component of ' + topic}")
        env = envelope_pb2.Envelope(schema_major=0, schema_minor=1, producer_id=PRODUCER_ID,
                                    kind=envelope_pb2.RecordKind.Value("SOURCE_COMPLETENESS"), source=ev.source)
        env.source_completeness.CopyFrom(sc)
        produce(self.producer, COMPLETENESS, value=env.SerializeToString(),
                              key=_completeness_key(common_pb2.Source.Name(ev.source), sc.scope))
        self.stats["unroutable"] += 1

    def handle(self, msg):
        env = envelope_pb2.Envelope()
        env.ParseFromString(msg.value())
        kind = env.WhichOneof("payload")
        if msg.topic() == RAW_EBPF:
            if kind == "token_file_version" and self.cred:
                for jti, e in self.cred.add_version(env.token_file_version):
                    self._produce(CRED, routing.encode(CRED, [("JTI", jti)]), e)
            return
        if kind == "heartbeat":
            self.low[msg.partition()] = max(self.low.get(msg.partition(), 0), ts_ns(env.heartbeat.low_watermark) or 0)
            return
        if kind != "normalized_event":
            return
        ev = Ev(env, msg.topic(), msg.partition(), msg.offset())
        for topic, key in routing.routes(ev):
            if key is None:
                self._unroutable(topic, ev)
            else:
                self._produce(topic, key, env)
                self.stats["routed"] += 1
        if self.cred:
            for jti, e in self.cred.route(ev):
                self._produce(CRED, routing.encode(CRED, [("JTI", jti)]), e)

    def heartbeats(self):
        if len(self.low) < self.partitions[NORM]:
            return
        low = min(self.low.values())
        # A token read still waiting for its version holds the credential
        # topic's promise at the read's time; reads given up are reported.
        cred_low = self.cred.hold(low) if self.cred else low
        if self.cred:
            for ev in self.cred.drain_given_up():
                self._unroutable(CRED, ev, why="(token read) was not resolved to a JTI in time")
        self.producer.flush(30)            # every routed record precedes the promise
        now = time.time_ns()
        for topic in self.out_topics:
            for p in range(self.partitions[topic]):
                self.hb_seq += 1
                env = envelope_pb2.Envelope(schema_major=0, schema_minor=1, producer_id=PRODUCER_ID,
                                            kind=envelope_pb2.RecordKind.Value("HEARTBEAT"))
                hb = env.heartbeat
                hb.producer_id, hb.producer_instance, hb.topic, hb.partition = PRODUCER_ID, self.instance, topic, p
                hb.low_watermark.CopyFrom(_ts(cred_low if topic == CRED else low))
                hb.emitted_at.CopyFrom(_ts(now))
                hb.producer_seq = self.hb_seq
                produce(self.producer, topic, value=env.SerializeToString(), partition=p,
                                      key=_instance_key(self.instance))
        self.producer.flush(30)
        self.stats["heartbeats"] += 1

    def run(self, stop, idle_exit_s=None):
        # Idle exit counts from the first input (see mtcore.agents.run); none: stop after 600 s.
        started, idle_since = time.time(), None
        while not stop():
            msgs = self.consumer.consume(500, timeout=0.2)
            for m in msgs:
                if m.error():
                    continue
                self.handle(m)
            if msgs:
                idle_since = time.time()
            if time.time() - self.last_hb >= self.heartbeat_s:
                self.heartbeats()
                self.last_hb = time.time()
                if msgs:
                    self.producer.flush(30)
                    self.consumer.commit(asynchronous=False)
            if idle_exit_s is not None and (
                    (idle_since is not None and time.time() - idle_since > idle_exit_s)
                    or (idle_since is None and time.time() - started > max(idle_exit_s, 600.0))):
                break
        self.heartbeats()
        self.producer.flush(30)
        try:
            self.consumer.commit(asynchronous=False)
        except Exception:     # nothing consumed since the last commit
            pass
        self.consumer.close()


def pin_to_end(consumer, partitions, skip=()):
    """--from-latest: start each newly assigned partition at its current end
    offset (resolved now, so nothing written after this call is skipped)."""
    from confluent_kafka import OFFSET_BEGINNING
    for tp in partitions:
        if tp.topic in skip:
            tp.offset = OFFSET_BEGINNING
            continue
        _lo, hi = consumer.get_watermark_offsets(tp, timeout=10, cached=False)
        tp.offset = hi
    consumer.assign(partitions)


def assign_all(consumer, counts, side=(), offsets=None, from_latest=False):
    """Assign every partition of counts (topic -> partition count) by hand.

    The agents and the GO each run as one instance per role, so a group has
    nothing to balance. Without group membership a killed instance holds no
    partitions and its restart reads at once; subscribe() waits for the old
    member to expire (session.timeout.ms, 45 s by default), longer than
    max_idle. Static membership (group.instance.id) also avoids the wait but
    keeps a coordinator in the restart path; assign() is simpler. group.id
    stays, for committed offsets and lag tools.

    Start offsets: offsets[(topic, partition)] when given, else side topics
    from the beginning, else the group's committed offset (earliest without
    one); from_latest puts inputs without an explicit offset at their end."""
    from confluent_kafka import OFFSET_BEGINNING, OFFSET_STORED, TopicPartition
    offsets = offsets or {}
    tps, latest = [], []
    for t, n in sorted(counts.items()):
        for p in range(n):
            if (t, p) in offsets:
                tps.append(TopicPartition(t, p, offsets[(t, p)]))
            elif t in side:
                tps.append(TopicPartition(t, p, OFFSET_BEGINNING))
            elif from_latest:
                latest.append(TopicPartition(t, p))
            else:
                tps.append(TopicPartition(t, p, OFFSET_STORED))
    for tp in latest:
        tp.offset = consumer.get_watermark_offsets(tp, timeout=10, cached=False)[1]
    consumer.assign(tps + latest)
    return tps + latest


def start_positions(tps, side=()):
    """Read positions an input assignment starts at, where they are concrete
    offsets (from_latest, or explicit). A runner seeds its positions with
    them, so its first commit covers every input partition: without that, a
    runner started at the end and killed before reading a partition would
    restart there from the group's committed offset, which does not exist,
    hence from the earliest record (found while placing the Exp. 5
    failpoints, step 8f)."""
    return {(tp.topic, tp.partition): tp.offset for tp in tps if tp.topic not in side and tp.offset >= 0}


def log_positions(path, positions, committed):
    """One JSON line of read and committed offsets ("topic/partition" ->
    offset) for the Exp. 5 lag metric: appended to path, else
    $MT_POSITIONS_LOG, else stderr. Committed offsets of a restart-safe
    commit stay behind the read position, so lag needs both."""
    import json
    import os
    line = json.dumps({"t": time.time_ns(),
                       "positions": {f"{t}/{p}": o for (t, p), o in sorted(positions.items())},
                       "committed": {f"{t}/{p}": o for (t, p), o in sorted(committed.items())}})
    path = path or os.environ.get("MT_POSITIONS_LOG")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    else:
        print(line, file=sys.stderr, flush=True)


LOG_APPEND_TIME = 2      # confluent_kafka.TIMESTAMP_LOG_APPEND_TIME
_warned = set()


def receipt_ns(msg):
    """Receipt time (ns) of a side record for the step 7g knowledge time:
    its LogAppendTime. None without a timestamp. A side topic left on
    CreateTime still gives an archived, deterministic time (the producer's
    clock, not the broker's); that is reported once per topic."""
    kind, ms = msg.timestamp() if hasattr(msg, "timestamp") else (0, -1)
    if kind == 0 or ms < 0:
        return None
    if kind != LOG_APPEND_TIME and msg.topic() not in _warned:
        _warned.add(msg.topic())
        print(f"warning: {msg.topic()} is not LogAppendTime; knowledge time uses CreateTime", file=sys.stderr)
    return ms * 1_000_000


def _instance_key(instance):
    from microtrace.v0 import keys_pb2
    return routing.mtcodec.encode_key(keys_pb2.KeyType.Value("KEY_PRODUCER_INSTANCE"),
                                      [(keys_pb2.KeyComponent.Value("PRODUCER_INSTANCE"), instance)])


def _completeness_key(source_name, scope):
    from microtrace.v0 import keys_pb2
    return routing.mtcodec.encode_key(keys_pb2.KeyType.Value("KEY_SOURCE_SCOPE"),
                                      [(keys_pb2.KeyComponent.Value("SOURCE_NAME"), source_name),
                                       (keys_pb2.KeyComponent.Value("SCOPE"), scope)])


def main(argv=None):
    ap = argparse.ArgumentParser(description="Restream norm.events.v0 into the keyed agent topics.")
    ap.add_argument("--bootstrap", default="127.0.0.1:9092")
    ap.add_argument("--params", default=DEV_PARAMS)
    ap.add_argument("--instance", default="restreamer-1")
    ap.add_argument("--heartbeat-ms", type=int, default=1000)
    ap.add_argument("--idle-exit-s", type=float, default=None, help="stop after this long without input (tests)")
    ap.add_argument("--group", default="restreamer")
    ap.add_argument("--from-latest", action="store_true", help="start at the current end of the input (tests)")
    a = ap.parse_args(argv)
    stopping = []
    signal.signal(signal.SIGTERM, lambda *_: stopping.append(1))
    r = Restreamer(a.bootstrap, Params.load(a.params), a.instance, a.heartbeat_ms, a.group, a.from_latest)
    r.run(lambda: bool(stopping), a.idle_exit_s)
    print(r.stats, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
